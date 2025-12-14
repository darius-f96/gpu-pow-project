#ifndef SHA1_CORE_H
#define SHA1_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __CUDACC__
#define SHA1_DEV __device__ __host__ __forceinline__
#else
#define SHA1_DEV static inline
#endif

typedef struct {
    uint32_t state[5];
    uint64_t bitcount;
    uint8_t buffer[64];
} Sha1Ctx;

SHA1_DEV uint32_t sha1_rotl(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32U - bits));
}

SHA1_DEV void sha1_transform(Sha1Ctx *ctx, const uint8_t data[64]) {
    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t w[80];

    for (int i = 0; i < 16; ++i) {
        int idx = i * 4;
        w[i] = ((uint32_t)data[idx] << 24) |
               ((uint32_t)data[idx + 1] << 16) |
               ((uint32_t)data[idx + 2] << 8) |
               (uint32_t)data[idx + 3];
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = sha1_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

#define SHA1_ROUND(fn, k, word)                      \
    {                                                \
        uint32_t temp = sha1_rotl(a, 5) + (fn) + e + \
                         (k) + (word);               \
        e = d;                                       \
        d = c;                                       \
        c = sha1_rotl(b, 30);                        \
        b = a;                                       \
        a = temp;                                    \
    }

    for (int i = 0; i < 20; ++i) {
        SHA1_ROUND((b & c) | ((~b) & d), 0x5A827999U, w[i]);
    }
    for (int i = 20; i < 40; ++i) {
        SHA1_ROUND(b ^ c ^ d, 0x6ED9EBA1U, w[i]);
    }
    for (int i = 40; i < 60; ++i) {
        SHA1_ROUND((b & c) | (b & d) | (c & d), 0x8F1BBCDCU, w[i]);
    }
    for (int i = 60; i < 80; ++i) {
        SHA1_ROUND(b ^ c ^ d, 0xCA62C1D6U, w[i]);
    }

#undef SHA1_ROUND

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

SHA1_DEV void sha1_init(Sha1Ctx *ctx) {
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xEFCDAB89U;
    ctx->state[2] = 0x98BADCFEU;
    ctx->state[3] = 0x10325476U;
    ctx->state[4] = 0xC3D2E1F0U;
    ctx->bitcount = 0;
    for (int i = 0; i < 64; ++i) {
        ctx->buffer[i] = 0;
    }
}

SHA1_DEV void sha1_update(Sha1Ctx *ctx, const uint8_t *data, size_t len) {
    size_t buffer_idx = (size_t)((ctx->bitcount >> 3) & 0x3F);
    ctx->bitcount += ((uint64_t)len) << 3;

    size_t i = 0;
    if (buffer_idx > 0) {
        size_t to_copy = 64 - buffer_idx;
        if (to_copy > len) {
            to_copy = len;
        }
        for (size_t j = 0; j < to_copy; ++j) {
            ctx->buffer[buffer_idx + j] = data[j];
        }
        buffer_idx += to_copy;
        i += to_copy;
        if (buffer_idx == 64) {
            sha1_transform(ctx, ctx->buffer);
            buffer_idx = 0;
        }
    }

    for (; i + 63 < len; i += 64) {
        sha1_transform(ctx, data + i);
    }

    size_t remaining = len - i;
    for (size_t j = 0; j < remaining; ++j) {
        ctx->buffer[j] = data[i + j];
    }
}

SHA1_DEV void sha1_final(Sha1Ctx *ctx, uint8_t digest[20]) {
    size_t buffer_idx = (size_t)((ctx->bitcount >> 3) & 0x3F);

    ctx->buffer[buffer_idx++] = 0x80;
    if (buffer_idx > 56) {
        while (buffer_idx < 64) {
            ctx->buffer[buffer_idx++] = 0;
        }
        sha1_transform(ctx, ctx->buffer);
        buffer_idx = 0;
    }
    while (buffer_idx < 56) {
        ctx->buffer[buffer_idx++] = 0;
    }

    uint64_t bitcount_be = ctx->bitcount;
    for (int i = 7; i >= 0; --i) {
        ctx->buffer[buffer_idx++] = (uint8_t)((bitcount_be >> (8 * i)) & 0xFF);
    }
    sha1_transform(ctx, ctx->buffer);

    for (int i = 0; i < 5; ++i) {
        digest[i * 4] = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xFF);
    }
}

#undef SHA1_DEV

#endif /* SHA1_CORE_H */
