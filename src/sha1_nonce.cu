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
constexpr int MAX_NONCE_BYTES = 8;

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
    uint64_t start_nonce = 0;
    uint64_t max_batches = 0;
    int report_every = 100;
};

struct DeviceDeleter {
    void operator()(void *ptr) const noexcept {
        if (ptr) {
            cudaFree(ptr);
        }
    }
};

using DeviceNoncePtr =
    std::unique_ptr<unsigned long long, DeviceDeleter>;
using DeviceIntPtr = std::unique_ptr<int, DeviceDeleter>;

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
                 "  --start <n>          Starting nonce counter (default 0)\n"
                 "  --max-batches <n>    Stop after processing n batches (0 = unlimited)\n"
                 "  --report <n>         Print a progress update every n batches (0 disables)\n",
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

__device__ void encode_nonce(uint64_t value, int nonce_len, uint8_t out[MAX_NONCE_BYTES]) {
    for (int i = 0; i < nonce_len; ++i) {
        out[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
    }
}

__global__ void sha1_nonce_kernel(uint64_t start_nonce,
                                  uint64_t batch_size,
                                  unsigned long long *result_nonce,
                                  volatile int *found_flag,
                                  int nonces_per_thread) {
    uint64_t thread_index =
        static_cast<uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    uint64_t per_thread = static_cast<uint64_t>(nonces_per_thread);
    uint64_t thread_start = start_nonce + thread_index * per_thread;
    uint64_t limit = (batch_size > (UINT64_MAX - start_nonce)) ? UINT64_MAX
                                                              : start_nonce + batch_size;

    for (int i = 0; i < nonces_per_thread; ++i) {
        uint64_t candidate = thread_start + i;
        if (candidate >= limit || *found_flag) {
            return;
        }

        Sha1Ctx ctx;
        uint8_t digest[20];
        uint8_t nonce_bytes[MAX_NONCE_BYTES];
        sha1_init(&ctx);
        sha1_update(&ctx, d_data_bytes, static_cast<size_t>(d_data_len));
        encode_nonce(candidate, d_nonce_len, nonce_bytes);
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
            int *flag_ptr = const_cast<int *>(found_flag);
            if (atomicCAS(flag_ptr, 0, 1) == 0) {
                *result_nonce = static_cast<unsigned long long>(candidate);
            }
            return;
        }
    }
}

}  // namespace

int main(int argc, char **argv) {
    std::string data_hex;
    std::string suffix_hex;
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
            config.start_nonce = std::strtoull(argv[++i], nullptr, 0);
        } else if (arg == "--max-batches" && i + 1 < argc) {
            config.max_batches = std::strtoull(argv[++i], nullptr, 0);
        } else if (arg == "--report" && i + 1 < argc) {
            config.report_every = std::atoi(argv[++i]);
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

    try {
        std::vector<uint8_t> data_bytes = parse_hex(data_hex);
        std::vector<uint8_t> suffix_bytes = parse_hex(suffix_hex);

        if (data_bytes.empty()) {
            throw std::runtime_error("DATA cannot be empty");
        }
        if (data_bytes.size() > MAX_DATA_BYTES) {
            throw std::runtime_error("DATA too large for constant buffer");
        }
        if (suffix_bytes.size() == 0 || suffix_bytes.size() > 2) {
            throw std::runtime_error("SUFFIX length must be 1 or 2 bytes");
        }

        CHECK_CUDA(cudaMemcpyToSymbol(d_data_bytes, data_bytes.data(), data_bytes.size()));
        int data_len = static_cast<int>(data_bytes.size());
        CHECK_CUDA(cudaMemcpyToSymbol(d_data_len, &data_len, sizeof(int)));
        CHECK_CUDA(cudaMemcpyToSymbol(d_nonce_len, &config.nonce_len, sizeof(int)));
        int suffix_len = static_cast<int>(suffix_bytes.size());
        CHECK_CUDA(cudaMemcpyToSymbol(d_suffix_len, &suffix_len, sizeof(int)));
        uint8_t suffix_pad[2] = {0, 0};
        std::memcpy(suffix_pad, suffix_bytes.data(), suffix_bytes.size());
        CHECK_CUDA(cudaMemcpyToSymbol(d_suffix_bytes, suffix_pad, sizeof(suffix_pad)));

        DeviceNoncePtr d_result_nonce(nullptr);
        DeviceIntPtr d_found_flag(nullptr);
        {
            unsigned long long *tmp = nullptr;
            CHECK_CUDA(cudaMalloc(&tmp, sizeof(unsigned long long)));
            d_result_nonce.reset(tmp);
        }
        {
            int *tmp = nullptr;
            CHECK_CUDA(cudaMalloc(&tmp, sizeof(int)));
            d_found_flag.reset(tmp);
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
        uint64_t found_nonce_value = 0;
        uint64_t current_start = config.start_nonce;

        while (config.max_batches == 0 || batches_launched < config.max_batches) {
            CHECK_CUDA(cudaMemset(d_found_flag.get(), 0, sizeof(int)));

            sha1_nonce_kernel<<<config.blocks, config.threads_per_block>>>(
                current_start, batch_size, d_result_nonce.get(), d_found_flag.get(),
                config.nonces_per_thread);
            CHECK_CUDA(cudaGetLastError());
            CHECK_CUDA(cudaDeviceSynchronize());

            int host_found = 0;
            CHECK_CUDA(cudaMemcpy(&host_found, d_found_flag.get(), sizeof(int),
                                  cudaMemcpyDeviceToHost));
            if (host_found) {
                unsigned long long nonce_value = 0;
                CHECK_CUDA(cudaMemcpy(&nonce_value, d_result_nonce.get(),
                                      sizeof(unsigned long long),
                                      cudaMemcpyDeviceToHost));
                found_nonce_value = nonce_value;
                found = true;
                if (nonce_value >= config.start_nonce) {
                    total_candidates = (nonce_value - config.start_nonce) + 1;
                }
                break;
            }

            total_candidates += batch_size;
            ++batches_launched;
            if (UINT64_MAX - current_start < batch_size) {
                std::printf("Nonce counter overflow, stopping search\n");
                break;
            }
            current_start += batch_size;

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

        if (!found) {
            std::printf("Search ended without a matching nonce\n");
        } else {
            std::vector<uint8_t> nonce_bytes(config.nonce_len, 0);
            for (int i = 0; i < config.nonce_len; ++i) {
                nonce_bytes[i] =
                    static_cast<uint8_t>((found_nonce_value >> (8 * i)) & 0xFF);
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
            std::printf("Found nonce after checking %llu candidates in %.2f s "
                        "(%.2f MH/s)\n",
                        static_cast<unsigned long long>(total_candidates), seconds,
                        seconds > 0 ? (total_candidates / 1e6) / seconds : 0.0);
            std::printf("Nonce bytes (little-endian): %s\n",
                        bytes_to_hex(nonce_bytes).c_str());
            std::printf("SHA1(D+nonce): %s\n",
                        bytes_to_hex(digest_vec).c_str());
        }

    } catch (const std::exception &ex) {
        std::fprintf(stderr, "Error: %s\n", ex.what());
        return 1;
    }

    return 0;
}
