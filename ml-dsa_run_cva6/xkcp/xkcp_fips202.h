#ifndef XKCP_FIPS202_H
#define XKCP_FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define XKCP_SHAKE128_RATE 168
#define XKCP_SHAKE256_RATE 136
#define XKCP_SHA3_224_RATE 144
#define XKCP_SHA3_256_RATE 136
#define XKCP_SHA3_384_RATE 104
#define XKCP_SHA3_512_RATE 72

/* Freestanding 1600-bit state context (25 x 64-bit lanes, zero dynamic memory) */
typedef struct {
    uint64_t s[25];
} xkcp_ctx;

#ifdef __cplusplus
extern "C" {
#endif

/* Single-call FIPS 202 APIs */
void xkcp_sha3_224(uint8_t *output, const uint8_t *input, size_t inlen);
void xkcp_sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void xkcp_sha3_384(uint8_t *output, const uint8_t *input, size_t inlen);
void xkcp_sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);

void xkcp_shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void xkcp_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

/* Block-level APIs (absorb / squeeze) frequently used by ML-DSA */
void xkcp_shake128_absorb(xkcp_ctx *ctx, const uint8_t *input, size_t inlen);
void xkcp_shake128_squeezeblocks(uint8_t *output, size_t nblocks, xkcp_ctx *ctx);

void xkcp_shake256_absorb(xkcp_ctx *ctx, const uint8_t *input, size_t inlen);
void xkcp_shake256_squeezeblocks(uint8_t *output, size_t nblocks, xkcp_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* XKCP_FIPS202_H */
