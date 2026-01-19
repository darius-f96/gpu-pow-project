#include <cuda_runtime.h>

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "sha1_core.h"

namespace {

constexpr int MAX_DATA_BYTES = 128;
constexpr int MAX_NONCE_BYTES = 16;

__constant__ uint8_t d_data_bytes[MAX_DATA_BYTES];
__constant__ int d_data_len;
__constant__ int d_nonce_len;
__constant__ uint8_t d_suffix_bytes[2];
__constant__ int d_suffix_len;

struct SearchConfig {
    int blocks = 256;
    int threads_per_block = 256;
    int nonces_per_thread = 8;
    int nonce_len = 4;
    uint64_t start_nonce_lo = 0;
    uint64_t start_nonce_hi = 0;
    uint64_t max_batches = 0;
    int report_every = 100;
    bool bench_mode = false;
    bool use_global_data = false;
};

struct DeviceDeleter {
    void operator()(void *ptr) const noexcept {
        if (ptr) {
            cudaFree(ptr);
        }
    }
};

using DeviceIntPtr = std::unique_ptr<int, DeviceDeleter>;
using DeviceU64Ptr = std::unique_ptr<uint64_t, DeviceDeleter>;
using DeviceBytePtr = std::unique_ptr<uint8_t, DeviceDeleter>;

static inline int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

std::vector<uint8_t> parse_hex(const std::string &input) {
    std::vector<uint8_t> bytes;
    bytes.reserve(input.size() / 2);

    std::string filtered;
    filtered.reserve(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (c == ' ' || c == ':' || c == '\n' || c == '\t' || c == '\r') {
            continue;
        }
        if (c == '0' && i + 1 < input.size() &&
            (input[i + 1] == 'x' || input[i + 1] == 'X')) {
            ++i;
            continue;
        }
        filtered.push_back(c);
    }

    if (filtered.size() % 2 != 0) {
        throw std::runtime_error("Hex string must contain an even number of nibbles");
    }

    for (size_t i = 0; i < filtered.size(); i += 2) {
        int hi = hex_value(filtered[i]);
        int lo = hex_value(filtered[i + 1]);
        if (hi < 0 || lo < 0) {
            throw std::runtime_error("Invalid hexadecimal digit in input");
        }
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return bytes;
}

std::string bytes_to_hex(const std::vector<uint8_t> &bytes) {
    const char *digits = "0123456789abcdef";
    std::string out(bytes.size() * 2, '0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        out[i * 2] = digits[(bytes[i] >> 4) & 0xF];
        out[i * 2 + 1] = digits[bytes[i] & 0xF];
    }
    return out;
}

void print_usage(const char *program) {
    std::fprintf(stderr,
                 "Usage: %s --data <hex> --suffix <hex> [options]\n"
                 "Options:\n"
                 "  --nonce-len <n>      Number of bytes in nonce (1-%d, default 4)\n"
                 "  --blocks <n>         CUDA blocks per launch (default 256)\n"
                 "  --threads <n>        Threads per block (default 256)\n"
                 "  --per-thread <n>     Nonces evaluated by each thread per launch (default 8)\n"
                 "  --start <n>          Starting nonce counter (default 0, little-endian)\n"
                 "  --start-hex <hex>    Starting nonce bytes (little-endian)\n"
                 "  --max-batches <n>    Stop after processing n batches (0 = unlimited)\n"
                 "  --report <n>         Print a progress update every n batches (0 disables)\n"
                 "  --bench             Run fixed batches, ignore early-found nonce\n"
                 "  --bench-batches <n> Run fixed n batches and enable bench mode\n"
                 "  --data-global       Read DATA from global memory instead of constant\n",
                 program, MAX_NONCE_BYTES);
}

#define CHECK_CUDA(call)                                                                \
    do {                                                                                \
        cudaError_t err__ = (call);                                                     \
        if (err__ != cudaSuccess) {                                                     \
            std::fprintf(stderr, "CUDA error %s:%d: %s\n", __FILE__, __LINE__,          \
                         cudaGetErrorString(err__));                                    \
            std::exit(EXIT_FAILURE);                                                    \
        }                                                                               \
    } while (0)

__device__ void encode_nonce(uint64_t lo, uint64_t hi, int nonce_len,
                             uint8_t out[MAX_NONCE_BYTES]) {
    for (int i = 0; i < nonce_len; ++i) {
        if (i < 8) {
            out[i] = static_cast<uint8_t>((lo >> (8 * i)) & 0xFF);
        } else {
            int shift = i - 8;
            out[i] = static_cast<uint8_t>((hi >> (8 * shift)) & 0xFF);
        }
    }
}

__host__ __device__ static inline void add_offset(uint64_t base_lo,
                                                  uint64_t base_hi,
                                                  uint64_t offset,
                                                  uint64_t *out_lo,
                                                  uint64_t *out_hi) {
    uint64_t sum_lo = base_lo + offset;
    uint64_t carry = (sum_lo < base_lo) ? 1ULL : 0ULL;
    *out_lo = sum_lo;
    *out_hi = base_hi + carry;
}

__global__ void sha1_nonce_kernel(uint64_t start_lo,
                                  uint64_t start_hi,
                                  uint64_t batch_size,
                                  uint64_t *result_offset,
                                  volatile int *found_flag,
                                  int nonces_per_thread,
                                  int bench_mode,
                                  uint64_t *match_count,
                                  const uint8_t *data_ptr,
                                  int data_len,
                                  int use_global_data) {
    uint64_t thread_index =
        static_cast<uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    uint64_t per_thread = static_cast<uint64_t>(nonces_per_thread);
    uint64_t thread_start_offset = thread_index * per_thread;

    for (int i = 0; i < nonces_per_thread; ++i) {
        uint64_t offset = thread_start_offset + static_cast<uint64_t>(i);
        if (offset >= batch_size) {
            return;
        }
        if (!bench_mode && *found_flag) {
            return;
        }

        Sha1Ctx ctx;
        uint8_t digest[20];
        uint8_t nonce_bytes[MAX_NONCE_BYTES];
        uint64_t candidate_lo = 0;
        uint64_t candidate_hi = 0;
        add_offset(start_lo, start_hi, offset, &candidate_lo, &candidate_hi);
        sha1_init(&ctx);
        if (use_global_data) {
            sha1_update(&ctx, data_ptr, static_cast<size_t>(data_len));
        } else {
            sha1_update(&ctx, d_data_bytes, static_cast<size_t>(d_data_len));
        }
        encode_nonce(candidate_lo, candidate_hi, d_nonce_len, nonce_bytes);
        sha1_update(&ctx, nonce_bytes, static_cast<size_t>(d_nonce_len));
        sha1_final(&ctx, digest);

        bool match = true;
        for (int j = 0; j < d_suffix_len; ++j) {
            if (digest[20 - d_suffix_len + j] != d_suffix_bytes[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            if (bench_mode) {
                if (match_count) {
                    atomicAdd(reinterpret_cast<unsigned long long *>(match_count),
                              1ULL);
                }
            } else {
                int *flag_ptr = const_cast<int *>(found_flag);
                if (atomicCAS(flag_ptr, 0, 1) == 0) {
                    *result_offset = offset;
                }
                return;
            }
        }
    }
}

}  // namespace

int main(int argc, char **argv) {
    std::string data_hex;
    std::string suffix_hex;
    std::string start_hex;
    SearchConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--data" && i + 1 < argc) {
            data_hex = argv[++i];
        } else if (arg == "--suffix" && i + 1 < argc) {
            suffix_hex = argv[++i];
        } else if (arg == "--nonce-len" && i + 1 < argc) {
            config.nonce_len = std::atoi(argv[++i]);
        } else if (arg == "--blocks" && i + 1 < argc) {
            config.blocks = std::atoi(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            config.threads_per_block = std::atoi(argv[++i]);
        } else if (arg == "--per-thread" && i + 1 < argc) {
            config.nonces_per_thread = std::atoi(argv[++i]);
        } else if (arg == "--start" && i + 1 < argc) {
            config.start_nonce_lo = std::strtoull(argv[++i], nullptr, 0);
            config.start_nonce_hi = 0;
        } else if (arg == "--start-hex" && i + 1 < argc) {
            start_hex = argv[++i];
        } else if (arg == "--max-batches" && i + 1 < argc) {
            config.max_batches = std::strtoull(argv[++i], nullptr, 0);
        } else if (arg == "--report" && i + 1 < argc) {
            config.report_every = std::atoi(argv[++i]);
        } else if (arg == "--bench") {
            config.bench_mode = true;
        } else if (arg == "--bench-batches" && i + 1 < argc) {
            config.bench_mode = true;
            config.max_batches = std::strtoull(argv[++i], nullptr, 0);
        } else if (arg == "--data-global") {
            config.use_global_data = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::fprintf(stderr, "Unknown or incomplete argument: %s\n", arg.c_str());
            print_usage(argv[0]);
            return 1;
        }
    }

    if (data_hex.empty() || suffix_hex.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    if (config.nonce_len < 1 || config.nonce_len > MAX_NONCE_BYTES) {
        std::fprintf(stderr, "nonce_len must be between 1 and %d\n", MAX_NONCE_BYTES);
        return 1;
    }
    if (config.blocks <= 0 || config.threads_per_block <= 0 || config.nonces_per_thread <= 0) {
        std::fprintf(stderr, "blocks, threads, and per-thread counts must be positive\n");
        return 1;
    }
    if (config.bench_mode && config.max_batches == 0) {
        std::fprintf(stderr, "bench mode requires --max-batches > 0\n");
        return 1;
    }

    try {
        std::vector<uint8_t> data_bytes = parse_hex(data_hex);
        std::vector<uint8_t> suffix_bytes = parse_hex(suffix_hex);

        if (!start_hex.empty()) {
            std::vector<uint8_t> start_bytes = parse_hex(start_hex);
            if (start_bytes.size() > static_cast<size_t>(config.nonce_len)) {
                throw std::runtime_error("start-hex length exceeds nonce length");
            }
            config.start_nonce_lo = 0;
            config.start_nonce_hi = 0;
            for (size_t j = 0; j < start_bytes.size(); ++j) {
                if (j < 8) {
                    config.start_nonce_lo |=
                        static_cast<uint64_t>(start_bytes[j]) << (8 * j);
                } else {
                    config.start_nonce_hi |=
                        static_cast<uint64_t>(start_bytes[j]) << (8 * (j - 8));
                }
            }
        }

        if (data_bytes.empty()) {
            throw std::runtime_error("DATA cannot be empty");
        }
        if (data_bytes.size() > MAX_DATA_BYTES) {
            throw std::runtime_error("DATA too large for constant buffer");
        }
        if (suffix_bytes.size() == 0 || suffix_bytes.size() > 2) {
            throw std::runtime_error("SUFFIX length must be 1 or 2 bytes");
        }

        int data_len = static_cast<int>(data_bytes.size());
        const uint8_t *d_data_ptr = nullptr;
        DeviceBytePtr d_data_storage(nullptr);
        if (config.use_global_data) {
            uint8_t *tmp = nullptr;
            CHECK_CUDA(cudaMalloc(&tmp, data_bytes.size()));
            CHECK_CUDA(cudaMemcpy(tmp, data_bytes.data(), data_bytes.size(),
                                  cudaMemcpyHostToDevice));
            d_data_ptr = tmp;
            d_data_storage.reset(tmp);
        } else {
            CHECK_CUDA(cudaMemcpyToSymbol(d_data_bytes, data_bytes.data(), data_bytes.size()));
        }
        CHECK_CUDA(cudaMemcpyToSymbol(d_data_len, &data_len, sizeof(int)));
        CHECK_CUDA(cudaMemcpyToSymbol(d_nonce_len, &config.nonce_len, sizeof(int)));
        int suffix_len = static_cast<int>(suffix_bytes.size());
        CHECK_CUDA(cudaMemcpyToSymbol(d_suffix_len, &suffix_len, sizeof(int)));
        uint8_t suffix_pad[2] = {0, 0};
        std::memcpy(suffix_pad, suffix_bytes.data(), suffix_bytes.size());
        CHECK_CUDA(cudaMemcpyToSymbol(d_suffix_bytes, suffix_pad, sizeof(suffix_pad)));

        DeviceU64Ptr d_result_offset(nullptr);
        DeviceIntPtr d_found_flag(nullptr);
        DeviceU64Ptr d_match_count(nullptr);
        {
            uint64_t *tmp = nullptr;
            CHECK_CUDA(cudaMalloc(&tmp, sizeof(uint64_t)));
            d_result_offset.reset(tmp);
        }
        {
            int *tmp = nullptr;
            CHECK_CUDA(cudaMalloc(&tmp, sizeof(int)));
            d_found_flag.reset(tmp);
        }
        if (config.bench_mode) {
            uint64_t *tmp = nullptr;
            CHECK_CUDA(cudaMalloc(&tmp, sizeof(uint64_t)));
            d_match_count.reset(tmp);
            CHECK_CUDA(cudaMemset(d_match_count.get(), 0, sizeof(uint64_t)));
        }

        uint64_t batch_size =
            static_cast<uint64_t>(config.blocks) * config.threads_per_block *
            static_cast<uint64_t>(config.nonces_per_thread);
        if (batch_size == 0) {
            throw std::runtime_error("Batch size overflow");
        }

        std::printf("Launching search: %d blocks x %d threads, %d nonces/thread "
                    "(batch %llu candidates)\n",
                    config.blocks, config.threads_per_block,
                    config.nonces_per_thread,
                    static_cast<unsigned long long>(batch_size));

        uint64_t batches_launched = 0; 
        uint64_t total_candidates = 0;
        auto start_time = std::chrono::steady_clock::now();
        bool found = false;
        uint64_t found_offset = 0;
        uint64_t current_start_lo = config.start_nonce_lo;
        uint64_t current_start_hi = config.start_nonce_hi;
        cudaEvent_t gpu_start = nullptr;
        cudaEvent_t gpu_stop = nullptr;
        bool use_gpu_timer = false;
        if (config.bench_mode) {
            CHECK_CUDA(cudaEventCreate(&gpu_start));
            CHECK_CUDA(cudaEventCreate(&gpu_stop));
            CHECK_CUDA(cudaEventRecord(gpu_start));
            use_gpu_timer = true;
        }

        while (config.max_batches == 0 || batches_launched < config.max_batches) {
            CHECK_CUDA(cudaMemset(d_found_flag.get(), 0, sizeof(int)));

            sha1_nonce_kernel<<<config.blocks, config.threads_per_block>>>(
                current_start_lo, current_start_hi, batch_size,
                d_result_offset.get(), d_found_flag.get(), config.nonces_per_thread,
                config.bench_mode ? 1 : 0,
                config.bench_mode ? d_match_count.get() : nullptr,
                d_data_ptr, data_len, config.use_global_data ? 1 : 0);
            CHECK_CUDA(cudaGetLastError());
            CHECK_CUDA(cudaDeviceSynchronize());

            int host_found = 0;
            CHECK_CUDA(cudaMemcpy(&host_found, d_found_flag.get(), sizeof(int),
                                  cudaMemcpyDeviceToHost));
            if (host_found && !config.bench_mode) {
                CHECK_CUDA(cudaMemcpy(&found_offset, d_result_offset.get(),
                                      sizeof(uint64_t),
                                      cudaMemcpyDeviceToHost));
                found = true;
                total_candidates =
                    batches_launched * batch_size + found_offset + 1;
                break;
            }

            total_candidates += batch_size;
            ++batches_launched;
            uint64_t next_lo = 0;
            uint64_t next_hi = 0;
            add_offset(current_start_lo, current_start_hi, batch_size,
                       &next_lo, &next_hi);
            current_start_lo = next_lo;
            current_start_hi = next_hi;

            if (config.report_every > 0 &&
                (batches_launched % config.report_every) == 0) {
                auto now = std::chrono::steady_clock::now();
                double seconds =
                    std::chrono::duration_cast<std::chrono::duration<double>>(now -
                                                                               start_time)
                        .count();
                double mhps = seconds > 0.0
                                  ? (total_candidates / 1e6) / seconds
                                  : 0.0;
                std::printf("Checked %llu candidates (%.2f MH/s)\n",
                            static_cast<unsigned long long>(total_candidates), mhps);
            }
        }

        double gpu_seconds = 0.0;
        if (use_gpu_timer) {
            CHECK_CUDA(cudaEventRecord(gpu_stop));
            CHECK_CUDA(cudaEventSynchronize(gpu_stop));
            float elapsed_ms = 0.0f;
            CHECK_CUDA(cudaEventElapsedTime(&elapsed_ms, gpu_start, gpu_stop));
            gpu_seconds = elapsed_ms / 1000.0;
            CHECK_CUDA(cudaEventDestroy(gpu_start));
            CHECK_CUDA(cudaEventDestroy(gpu_stop));
        }

        if (!found) {
            std::printf("Search ended without a matching nonce\n");
        } else {
            std::vector<uint8_t> nonce_bytes(config.nonce_len, 0);
            uint64_t nonce_lo = 0;
            uint64_t nonce_hi = 0;
            add_offset(current_start_lo, current_start_hi, found_offset,
                       &nonce_lo, &nonce_hi);
            for (int i = 0; i < config.nonce_len; ++i) {
                if (i < 8) {
                    nonce_bytes[i] =
                        static_cast<uint8_t>((nonce_lo >> (8 * i)) & 0xFF);
                } else {
                    int shift = i - 8;
                    nonce_bytes[i] =
                        static_cast<uint8_t>((nonce_hi >> (8 * shift)) & 0xFF);
                }
            }

            std::vector<uint8_t> combined = data_bytes;
            combined.insert(combined.end(), nonce_bytes.begin(), nonce_bytes.end());
            uint8_t digest[20];
            Sha1Ctx ctx;
            sha1_init(&ctx);
            sha1_update(&ctx, combined.data(), combined.size());
            sha1_final(&ctx, digest);
            std::vector<uint8_t> digest_vec(digest, digest + 20);

            auto finish_time = std::chrono::steady_clock::now();
            double seconds =
                std::chrono::duration_cast<std::chrono::duration<double>>(finish_time -
                                                                          start_time)
                    .count();
            std::printf("Found nonce after checking %llu candidates in %.6f s "
                        "(%.2f MH/s)\n",
                        static_cast<unsigned long long>(total_candidates), seconds,
                        seconds > 0 ? (total_candidates / 1e6) / seconds : 0.0);
            std::printf("Nonce bytes (little-endian): %s\n",
                        bytes_to_hex(nonce_bytes).c_str());
            std::printf("SHA1(D+nonce): %s\n",
                        bytes_to_hex(digest_vec).c_str());
        }
        if (config.bench_mode) {
            uint64_t matches = 0;
            CHECK_CUDA(cudaMemcpy(&matches, d_match_count.get(),
                                  sizeof(uint64_t),
                                  cudaMemcpyDeviceToHost));
            auto finish_time = std::chrono::steady_clock::now();
            double cpu_seconds =
                std::chrono::duration_cast<std::chrono::duration<double>>(finish_time -
                                                                          start_time)
                    .count();
            double seconds = use_gpu_timer ? gpu_seconds : cpu_seconds;
            std::printf("Bench complete: %llu candidates in %.6f s (%.2f MH/s)\n",
                        static_cast<unsigned long long>(total_candidates),
                        seconds,
                        seconds > 0 ? (total_candidates / 1e6) / seconds : 0.0);
            std::printf("Matches observed: %llu\n",
                        static_cast<unsigned long long>(matches));
        }

    } catch (const std::exception &ex) {
        std::fprintf(stderr, "Error: %s\n", ex.what());
        return 1;
    }

    return 0;
}
