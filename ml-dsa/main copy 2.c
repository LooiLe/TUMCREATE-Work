#define _POSIX_C_SOURCE 199309L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "mldsa_native.h"
#include <openssl/evp.h>

#define ITERATIONS 10000

int randombytes(void *buf, size_t n);

/**
 * Computes the pre-hash digest for any supported MLD_PREHASH_* identifier.
 * Automatically maps to the correct EVP_MD primitive and exact output length.
 */
static int compute_mldsa_prehash(uint8_t out[64],
                                 size_t *outlen,
                                 const uint8_t *in,
                                 size_t inlen,
                                 int prehash)
{
    const EVP_MD *md = NULL;
    size_t expected_len = 0;
    int is_xof = 0;

    switch (prehash) {
        /* SHA-2 Family */
        case MLD_PREHASH_SHA2_224:
            md = EVP_sha224();
            expected_len = 28;
            break;
        case MLD_PREHASH_SHA2_256:
            md = EVP_sha256();
            expected_len = 32;
            break;
        case MLD_PREHASH_SHA2_384:
            md = EVP_sha384();
            expected_len = 48;
            break;
        case MLD_PREHASH_SHA2_512:
            md = EVP_sha512();
            expected_len = 64;
            break;
        case MLD_PREHASH_SHA2_512_224:
            md = EVP_sha512_224();
            expected_len = 28;
            break;
        case MLD_PREHASH_SHA2_512_256:
            md = EVP_sha512_256();
            expected_len = 32;
            break;

        /* SHA-3 Family */
        case MLD_PREHASH_SHA3_224:
            md = EVP_sha3_224();
            expected_len = 28;
            break;
        case MLD_PREHASH_SHA3_256:
            md = EVP_sha3_256();
            expected_len = 32;
            break;
        case MLD_PREHASH_SHA3_384:
            md = EVP_sha3_384();
            expected_len = 48;
            break;
        case MLD_PREHASH_SHA3_512:
            md = EVP_sha3_512();
            expected_len = 64;
            break;

        /* SHAKE Family */
        case MLD_PREHASH_SHAKE_128:
            md = EVP_shake128();
            expected_len = 32;
            is_xof = 1;
            break;
        case MLD_PREHASH_SHAKE_256:
            md = EVP_shake256();
            expected_len = 64;
            is_xof = 1;
            break;

        default:
            return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    int ok = 0;
    if (EVP_DigestInit_ex(ctx, md, NULL) == 1 &&
        EVP_DigestUpdate(ctx, in, inlen) == 1) {
        if (is_xof) {
            ok = (EVP_DigestFinalXOF(ctx, out, expected_len) == 1);
        } else {
            unsigned int written = 0;
            ok = (EVP_DigestFinal_ex(ctx, out, &written) == 1 && written == expected_len);
        }
    }

    EVP_MD_CTX_free(ctx);

    if (ok) {
        *outlen = expected_len;
        return 0;
    }
    return -1;
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

static void print_stats(const char *name, double *times, int n)
{
    qsort(times, (size_t)n, sizeof(double), compare_doubles);

    double sum = 0;
    for (int i = 0; i < n; i++) {
        sum += times[i];
    }
    double mean = sum / n;
    double median = times[n / 2];
    double p99 = times[(int)(n * 0.99)];
    double min = times[0];
    double max = times[n - 1];
    double ops_per_sec = (mean > 0) ? (1e6 / mean) : 0;

    printf("%-22s | Min: %6.1f us | Median: %6.1f us | P99: %6.1f us | Max: %6.1f us | Ops/sec: %9.1f\n",
           name, min, median, p99, max, ops_per_sec);
}

int main(void)
{
    /* Select your pre-hash function identifier here:
     * Examples: MLD_PREHASH_SHA2_256, MLD_PREHASH_SHA2_512, MLD_PREHASH_SHA3_512, etc. */
    int prehash_id = MLD_PREHASH_SHAKE_256;

    uint8_t public_key[MLDSA65_PUBLICKEYBYTES];
    uint8_t secret_key[MLDSA65_SECRETKEYBYTES];
    uint8_t signature[MLDSA65_BYTES];
    uint8_t digest[64];
    size_t digest_len = 0;
    uint8_t rnd[32];

    const uint8_t message[] = "Hello from C!";
    size_t message_len = strlen((const char *)message);

    double keygen_times[ITERATIONS];
    double hash_times[ITERATIONS];
    double sign_times[ITERATIONS];
    double verify_times[ITERATIONS];

    struct timespec t0, t1;

    printf("Starting ML-DSA benchmark (%d iterations)...\n", ITERATIONS);

    /* -------------------------------------------------------------
     * Warm-up run (ensures caches and branch predictors are primed)
     * ------------------------------------------------------------- */
    if (mldsa_keypair(public_key, secret_key) != 0) {
        fprintf(stderr, "Warmup keypair failed\n");
        return 1;
    }
    if (compute_mldsa_prehash(digest, &digest_len, message, message_len, prehash_id) != 0) {
        fprintf(stderr, "Warmup hashing failed\n");
        return 1;
    }
    if (randombytes(rnd, sizeof(rnd)) != 0) {
        fprintf(stderr, "Warmup RNG failed\n");
        return 1;
    }
    if (mldsa_signature_pre_hash_internal(signature, digest, digest_len,
                                          NULL, 0, rnd, secret_key, prehash_id) != 0) {
        fprintf(stderr, "Warmup sign failed\n");
        return 1;
    }
    if (mldsa_verify_pre_hash_internal(signature, digest, digest_len,
                                       NULL, 0, public_key, prehash_id) != 0) {
        fprintf(stderr, "Warmup verify failed\n");
        return 1;
    }

    /* -------------------------------------------------------------
     * Benchmark Loop
     * ------------------------------------------------------------- */
    for (int i = 0; i < ITERATIONS; i++) {
        /* 1. Key Generation (measured on each iteration) */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int kret = mldsa_keypair(public_key, secret_key);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (kret != 0) {
            fprintf(stderr, "Keygen failed at iteration %d\n", i);
            return 1;
        }
        keygen_times[i] = get_elapsed_us(t0, t1);

        /* 2. Message Pre-Hashing */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int hret = compute_mldsa_prehash(digest, &digest_len, message, message_len, prehash_id);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (hret != 0) {
            fprintf(stderr, "Hashing failed at iteration %d\n", i);
            return 1;
        }
        hash_times[i] = get_elapsed_us(t0, t1);

        /* Generate fresh randomness for the signature hedging round */
        if (randombytes(rnd, sizeof(rnd)) != 0) {
            fprintf(stderr, "RNG failed at iteration %d\n", i);
            return 1;
        }

        /* 3. Signing */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int sret = mldsa_signature_pre_hash_internal(
            signature, digest, digest_len, NULL, 0, rnd, secret_key, prehash_id);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (sret != 0) {
            fprintf(stderr, "Signing failed at iteration %d\n", i);
            return 1;
        }
        sign_times[i] = get_elapsed_us(t0, t1);

        /* 4. Verification */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int vret = mldsa_verify_pre_hash_internal(
            signature, digest, digest_len, NULL, 0, public_key, prehash_id);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (vret != 0) {
            fprintf(stderr, "Verification failed at iteration %d!\n", i);
            return 1;
        }
        verify_times[i] = get_elapsed_us(t0, t1);
    }

    printf("\nBenchmark Results (in microseconds):\n");
    printf("----------------------------------------------------------------------------------------------------\n");
    print_stats("Key Generation", keygen_times, ITERATIONS);
    print_stats("Message Pre-Hash", hash_times, ITERATIONS);
    print_stats("Sign (Pre-Hashed)", sign_times, ITERATIONS);
    print_stats("Verify (Pre-Hashed)", verify_times, ITERATIONS);

    return 0;
}