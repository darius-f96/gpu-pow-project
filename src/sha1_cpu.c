#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "sha1_core.h"

#define CPU_MAX_NONCE_BYTES 16

typedef struct {
    uint8_t *data;
    size_t len;
} ByteArray;

typedef struct {
    int nonce_len;
    uint64_t start_nonce_lo;
    uint64_t start_nonce_hi;
    uint64_t max_candidates;
    int report_every;
} CpuSearchConfig;

static void free_byte_array(ByteArray *arr) {
    if (arr->data) {
        free(arr->data);
        arr->data = NULL;
        arr->len = 0;
    }
}

static int hex_value(char c) {
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

static ByteArray parse_hex_string(const char *input) {
    ByteArray out = {0};
    size_t len = strlen(input);
    char *filtered = (char *)malloc(len + 1);
    if (!filtered) {
        fprintf(stderr, "Allocation failure\n");
        exit(EXIT_FAILURE);
    }

    size_t pos = 0;
    for (size_t i = 0; i < len; ++i) {
        char c = input[i];
        if (isspace((unsigned char)c) || c == ':') {
            continue;
        }
        if (c == '0' && (i + 1) < len && (input[i + 1] == 'x' || input[i + 1] == 'X')) {
            ++i;
            continue;
        }
        filtered[pos++] = c;
    }
    filtered[pos] = '\0';

    if (pos % 2 != 0) {
        fprintf(stderr, "Hex string must contain an even number of digits\n");
        free(filtered);
        exit(EXIT_FAILURE);
    }

    out.len = pos / 2;
    out.data = (uint8_t *)malloc(out.len);
    if (!out.data) {
        fprintf(stderr, "Allocation failure\n");
        free(filtered);
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < out.len; ++i) {
        int hi = hex_value(filtered[i * 2]);
        int lo = hex_value(filtered[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "Invalid hexadecimal digit detected\n");
            free(filtered);
            free_byte_array(&out);
            exit(EXIT_FAILURE);
        }
        out.data[i] = (uint8_t)((hi << 4) | lo);
    }

    free(filtered);
    return out;
}

static void print_usage(const char *program) {
    fprintf(stderr,
            "Usage: %s --data <hex> [--nonce <hex>] [--suffix <hex>] [options]\n"
            "Options for CPU search (--suffix provided):\n"
            "  --nonce-len <n>   Nonce length in bytes (1-%d, default 4)\n"
            "  --start <n>       Starting nonce counter (default 0, little-endian)\n"
            "  --start-hex <hex> Starting nonce bytes (little-endian)\n"
            "  --max <n>         Maximum candidates to test (default 16777216)\n"
            "  --report <n>      Print progress every n candidates (0 disables)\n",
            program, CPU_MAX_NONCE_BYTES);
}

static void print_hex(const uint8_t *data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        putchar(digits[(data[i] >> 4) & 0xF]);
        putchar(digits[data[i] & 0xF]);
    }
}

static void encode_nonce(uint64_t lo, uint64_t hi, int nonce_len, uint8_t *out) {
    for (int i = 0; i < nonce_len; ++i) {
        if (i < 8) {
            out[i] = (uint8_t)((lo >> (8 * i)) & 0xFF);
        } else {
            int shift = i - 8;
            out[i] = (uint8_t)((hi >> (8 * shift)) & 0xFF);
        }
    }
}

static void add_offset(uint64_t base_lo, uint64_t base_hi, uint64_t offset,
                       uint64_t *out_lo, uint64_t *out_hi) {
    uint64_t sum_lo = base_lo + offset;
    uint64_t carry = (sum_lo < base_lo) ? 1ULL : 0ULL;
    *out_lo = sum_lo;
    *out_hi = base_hi + carry;
}

int main(int argc, char **argv) {
    const char *data_hex = NULL;
    const char *nonce_hex = NULL;
    const char *suffix_hex = NULL;
    CpuSearchConfig cfg = {
        .nonce_len = 4,
        .start_nonce_lo = 0,
        .start_nonce_hi = 0,
        .max_candidates = 1ULL << 24,
        .report_every = 0,
    };
    const char *start_hex = NULL;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--data") == 0 && (i + 1) < argc) {
            data_hex = argv[++i];
        } else if (strcmp(arg, "--nonce") == 0 && (i + 1) < argc) {
            nonce_hex = argv[++i];
        } else if (strcmp(arg, "--suffix") == 0 && (i + 1) < argc) {
            suffix_hex = argv[++i];
        } else if (strcmp(arg, "--nonce-len") == 0 && (i + 1) < argc) {
            cfg.nonce_len = atoi(argv[++i]);
        } else if (strcmp(arg, "--start") == 0 && (i + 1) < argc) {
            cfg.start_nonce_lo = strtoull(argv[++i], NULL, 0);
            cfg.start_nonce_hi = 0;
        } else if (strcmp(arg, "--start-hex") == 0 && (i + 1) < argc) {
            start_hex = argv[++i];
        } else if (strcmp(arg, "--max") == 0 && (i + 1) < argc) {
            cfg.max_candidates = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(arg, "--report") == 0 && (i + 1) < argc) {
            cfg.report_every = atoi(argv[++i]);
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown or incomplete argument: %s\n", arg);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!data_hex) {
        print_usage(argv[0]);
        return 1;
    }
    if (cfg.nonce_len < 1 || cfg.nonce_len > CPU_MAX_NONCE_BYTES) {
        fprintf(stderr, "Invalid nonce length\n");
        return 1;
    }

    ByteArray data = parse_hex_string(data_hex);
    ByteArray nonce = {0};
    ByteArray suffix = {0};

    if (nonce_hex) {
        nonce = parse_hex_string(nonce_hex);
    }
    if (suffix_hex) {
        suffix = parse_hex_string(suffix_hex);
        if (suffix.len == 0 || suffix.len > 2) {
            fprintf(stderr, "Suffix must contain 1 or 2 bytes\n");
            free_byte_array(&data);
            free_byte_array(&nonce);
            free_byte_array(&suffix);
            return 1;
        }
    }
    if (start_hex) {
        ByteArray start_bytes = parse_hex_string(start_hex);
        if (start_bytes.len > (size_t)cfg.nonce_len) {
            fprintf(stderr, "start-hex length exceeds nonce length\n");
            free_byte_array(&start_bytes);
            goto cleanup;
        }
        cfg.start_nonce_lo = 0;
        cfg.start_nonce_hi = 0;
        for (size_t i = 0; i < start_bytes.len; ++i) {
            if (i < 8) {
                cfg.start_nonce_lo |=
                    ((uint64_t)start_bytes.data[i]) << (8 * i);
            } else {
                cfg.start_nonce_hi |=
                    ((uint64_t)start_bytes.data[i]) << (8 * (i - 8));
            }
        }
        free_byte_array(&start_bytes);
    }

    if (suffix.len > 0) {
        if (cfg.max_candidates == 0) {
            fprintf(stderr, "max candidates must be > 0 for search\n");
            goto cleanup;
        }

        uint8_t nonce_bytes[CPU_MAX_NONCE_BYTES] = {0};
        uint8_t digest[20];
        bool found = false;

        for (uint64_t i = 0; i < cfg.max_candidates; ++i) {
            uint64_t value_lo = 0;
            uint64_t value_hi = 0;
            add_offset(cfg.start_nonce_lo, cfg.start_nonce_hi, i,
                       &value_lo, &value_hi);
            encode_nonce(value_lo, value_hi, cfg.nonce_len, nonce_bytes);

            Sha1Ctx ctx;
            sha1_init(&ctx);
            sha1_update(&ctx, data.data, data.len);
            sha1_update(&ctx, nonce_bytes, (size_t)cfg.nonce_len);
            sha1_final(&ctx, digest);

            bool match = true;
            for (size_t j = 0; j < suffix.len; ++j) {
                if (digest[20 - suffix.len + j] != suffix.data[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                printf("Found CPU nonce after %llu candidates\n",
                       (unsigned long long)(i + 1));
                printf("Nonce bytes: ");
                print_hex(nonce_bytes, (size_t)cfg.nonce_len);
                printf("\nDigest: ");
                print_hex(digest, 20);
                printf("\n");
                found = true;
                break;
            }

            if (cfg.report_every > 0 && ((i + 1) % (uint64_t)cfg.report_every) == 0) {
                printf("Checked %llu candidates\n", (unsigned long long)(i + 1));
            }
        }

        if (!found) {
            printf("CPU search finished without a match\n");
        }
    } else {
        uint8_t digest[20];
        Sha1Ctx ctx;
        sha1_init(&ctx);
        sha1_update(&ctx, data.data, data.len);
        if (nonce.data) {
            sha1_update(&ctx, nonce.data, nonce.len);
        }
        sha1_final(&ctx, digest);
        printf("SHA1 digest: ");
        print_hex(digest, 20);
        printf("\n");
    }

cleanup:
    free_byte_array(&data);
    free_byte_array(&nonce);
    free_byte_array(&suffix);
    return 0;
}
