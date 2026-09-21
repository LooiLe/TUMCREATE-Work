#define _POSIX_C_SOURCE 199309L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "mldsa_native.h"
#include <openssl/evp.h>

#define ITERATIONS 10000
#define BENCH_PAYLOAD_SIZE 4096 /* 4 KB: Realistic TLS cert / firmware block */

int randombytes(void *buf, size_t n);

static int compute_mldsa_prehash(EVP_MD_CTX *ctx,
                                 uint8_t out[64],
                                 size_t *outlen,
                                 const uint8_t *in,
                                 size_t inlen,
                                 int prehash)
{
    const EVP_MD *md = NULL;
    size_t expected_len = 0;
    int is_xof = 0;

    switch (prehash) {
        case MLD_PREHASH_SHA2_224:     md = EVP_sha224();     expected_len = 28; break;
        case MLD_PREHASH_SHA2_256:     md = EVP_sha256();     expected_len = 32; break;
        case MLD_PREHASH_SHA2_384:     md = EVP_sha384();     expected_len = 48; break;
        case MLD_PREHASH_SHA2_512:     md = EVP_sha512();     expected_len = 64; break;
        case MLD_PREHASH_SHA2_512_224: md = EVP_sha512_224(); expected_len = 28; break;
        case MLD_PREHASH_SHA2_512_256: md = EVP_sha512_256(); expected_len = 32; break;

        case MLD_PREHASH_SHA3_224:     md = EVP_sha3_224();   expected_len = 28; break;
        case MLD_PREHASH_SHA3_256:     md = EVP_sha3_256();   expected_len = 32; break;
        case MLD_PREHASH_SHA3_384:     md = EVP_sha3_384();   expected_len = 48; break;
        case MLD_PREHASH_SHA3_512:     md = EVP_sha3_512();   expected_len = 64; break;

        case MLD_PREHASH_SHAKE_128:    md = EVP_shake128();   expected_len = 32; is_xof = 1; break;
        case MLD_PREHASH_SHAKE_256:    md = EVP_shake256();   expected_len = 64; is_xof = 1; break;
        default: return -1;
    }

    /* Reuse existing context to eliminate malloc/free noise */
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
        EVP_DigestUpdate(ctx, in, inlen) != 1) {
        return -1;
    }

    if (is_xof) {
        if (EVP_DigestFinalXOF(ctx, out, expected_len) != 1) return -1;
    } else {
        unsigned int written = 0;
        if (EVP_DigestFinal_ex(ctx, out, &written) != 1 || written != expected_len) return -1;
    }

    *outlen = expected_len;
    return 0;
}

static inline double get_elapsed_us(struct timespec start, struct timespec end)
{
    return (double)(end.tv_sec - start.tv_sec) * 1e6 +
           (double)(end.tv_nsec - start.tv_nsec) / 1e3;
}

static int compare_doubles(const void *a, const void *b)
{
    double diff = *(const double *)a - *(const double *)b;
    return (diff > 0) - (diff < 0);
}

typedef struct {
    const char *name;
    int id;
} HashAlgo;

static const HashAlgo HASH_ALGOS[] = {
    {"SHA2-224",      MLD_PREHASH_SHA2_224},
    {"SHA2-256",      MLD_PREHASH_SHA2_256},
    {"SHA2-384",      MLD_PREHASH_SHA2_384},
    {"SHA2-512",      MLD_PREHASH_SHA2_512},
    {"SHA2-512/224",  MLD_PREHASH_SHA2_512_224},
    {"SHA2-512/256",  MLD_PREHASH_SHA2_512_256},
    {"SHA3-224",      MLD_PREHASH_SHA3_224},
    {"SHA3-256",      MLD_PREHASH_SHA3_256},
    {"SHA3-384",      MLD_PREHASH_SHA3_384},
    {"SHA3-512",      MLD_PREHASH_SHA3_512},
    {"SHAKE-128",     MLD_PREHASH_SHAKE_128},
    {"SHAKE-256",     MLD_PREHASH_SHAKE_256},
};

int main(void)
{
    uint8_t public_key[MLDSA65_PUBLICKEYBYTES];
    uint8_t secret_key[MLDSA65_SECRETKEYBYTES];
    uint8_t signature[MLDSA65_BYTES];
    uint8_t digest[64];
    size_t digest_len = 0;
    uint8_t rnd[32];

    uint8_t message[BENCH_PAYLOAD_SIZE];
    memset(message, 0x5A, sizeof(message));

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 1;

    double hash_times[ITERATIONS];
    double sign_times[ITERATIONS];
    struct timespec t0, t1;

    /* Initialize fixed keypair once */
    if (mldsa_keypair(public_key, secret_key) != 0) return 1;

    printf("========================================================================================\n");
    printf(" ML-DSA-65 Pre-Hash Comparison | Payload: %d bytes | Iterations: %d\n", BENCH_PAYLOAD_SIZE, ITERATIONS);
    printf("========================================================================================\n");
    printf("%-16s | %10s | %10s | %12s | %12s\n",
           "Hash Algorithm", "Hash Med(us)", "Hash P99(us)", "Sign Med(us)", "Throughput (MB/s)");
    printf("----------------------------------------------------------------------------------------\n");

    size_t total_algos = sizeof(HASH_ALGOS) / sizeof(HASH_ALGOS[0]);
    for (size_t a = 0; a < total_algos; a++) {
        int prehash_id = HASH_ALGOS[a].id;

        /* Warmup */
        for (int w = 0; w < 100; w++) {
            int e = compute_mldsa_prehash(ctx, digest, &digest_len, message, sizeof(message), prehash_id);
            randombytes(rnd, sizeof(rnd));
            e = mldsa_signature_pre_hash_internal(signature, digest, digest_len, NULL, 0, rnd, secret_key, prehash_id);
            if (e == 1) {
                return 1;
            }
        }

        for (int i = 0; i < ITERATIONS; i++) {
            /* 1. Time only the hash */
            clock_gettime(CLOCK_MONOTONIC, &t0);
            int e = compute_mldsa_prehash(ctx, digest, &digest_len, message, sizeof(message), prehash_id);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            hash_times[i] = get_elapsed_us(t0, t1);

            randombytes(rnd, sizeof(rnd));

            /* 2. Time the signature with pre-hashed digest */
            clock_gettime(CLOCK_MONOTONIC, &t0);
            e = mldsa_signature_pre_hash_internal(signature, digest, digest_len, NULL, 0, rnd, secret_key, prehash_id);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            sign_times[i] = get_elapsed_us(t0, t1);
            if (e == 1) {
                return 1;
            }
        }

        qsort(hash_times, ITERATIONS, sizeof(double), compare_doubles);
        qsort(sign_times, ITERATIONS, sizeof(double), compare_doubles);

        double hash_med = hash_times[ITERATIONS / 2];
        double hash_p99 = hash_times[(int)(ITERATIONS * 0.99)];
        double sign_med = sign_times[ITERATIONS / 2];
        double throughput = (hash_med > 0) ? ((double)BENCH_PAYLOAD_SIZE / (hash_med * 1e-6)) / (1024.0 * 1024.0) : 0;

        printf("%-16s | %10.2f | %10.2f | %12.1f | %12.1f\n",
               HASH_ALGOS[a].name, hash_med, hash_p99, sign_med, throughput);
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}