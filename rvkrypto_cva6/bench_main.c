#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if !defined(__riscv)
#include <stdio.h>
#endif

#include "riscv_crypto.h"
#include "sha2/sha2_api.h"
#include "sha3/sha3_api.h"
#include "sm3/sm3_api.h"

/* =========================================================================
 * Benchmark Configuration (Matches ml-dsa_run_cva6 exactly)
 * ========================================================================= */
#ifndef BENCH_PAYLOAD_SIZE
#define BENCH_PAYLOAD_SIZE  4096    /* 4 KB test payload */
#endif

#ifndef ITERATIONS
#define ITERATIONS          1       /* Default 1 for cold run, or 50 */
#endif

#ifndef WARMUP_ITERATIONS
#define WARMUP_ITERATIONS   0       /* Warm-up runs to prime caches */
#endif

#ifndef CPU_FREQ_MHZ
#define CPU_FREQ_MHZ        50.0    /* CVA6 target frequency on FPGA */
#endif

#ifndef USE_MCYCLE
#define USE_MCYCLE          1
#endif

/* =========================================================================
 * Hardware Performance Counters (Cycles & Instructions)
 * ========================================================================= */
static inline uint64_t read_cycles(void)
{
    uint64_t cycles;
#if defined(__riscv)
  #if USE_MCYCLE
    #if __riscv_xlen == 64
      __asm__ volatile ("csrr %0, mcycle" : "=r" (cycles));
    #else
      uint32_t high0, high1, low;
      do {
          __asm__ volatile ("csrr %0, mcycleh" : "=r" (high0));
          __asm__ volatile ("csrr %0, mcycle"  : "=r" (low));
          __asm__ volatile ("csrr %0, mcycleh" : "=r" (high1));
      } while (high0 != high1);
      cycles = ((uint64_t)high0 << 32) | low;
    #endif
  #else
    #if __riscv_xlen == 64
      __asm__ volatile ("rdcycle %0" : "=r" (cycles));
    #else
      uint32_t high0, high1, low;
      do {
          __asm__ volatile ("rdcycleh %0" : "=r" (high0));
          __asm__ volatile ("rdcycle  %0" : "=r" (low));
          __asm__ volatile ("rdcycleh %0" : "=r" (high1));
      } while (high0 != high1);
      cycles = ((uint64_t)high0 << 32) | low;
    #endif
  #endif
#else
    cycles = 0;
#endif
    return cycles;
}

static inline uint64_t read_instructions(void)
{
    uint64_t insts;
#if defined(__riscv)
  #if USE_MCYCLE
    #if __riscv_xlen == 64
      __asm__ volatile ("csrr %0, minstret" : "=r" (insts));
    #else
      uint32_t high0, high1, low;
      do {
          __asm__ volatile ("csrr %0, minstreth" : "=r" (high0));
          __asm__ volatile ("csrr %0, minstret"  : "=r" (low));
          __asm__ volatile ("csrr %0, minstreth" : "=r" (high1));
      } while (high0 != high1);
      insts = ((uint64_t)high0 << 32) | low;
    #endif
  #else
    #if __riscv_xlen == 64
      __asm__ volatile ("rdinstret %0" : "=r" (insts));
    #else
      uint32_t high0, high1, low;
      do {
          __asm__ volatile ("rdinstreth %0" : "=r" (high0));
          __asm__ volatile ("rdinstret  %0" : "=r" (low));
          __asm__ volatile ("rdinstreth %0" : "=r" (high1));
      } while (high0 != high1);
      insts = ((uint64_t)high0 << 32) | low;
    #endif
  #endif
#else
    insts = 0;
#endif
    return insts;
}

/* =========================================================================
 * Algorithm Definitions & Identifiers (Identical to wolfSSL benchmark)
 * ========================================================================= */
typedef enum {
    ALGO_SHA2_224        = 0,
    ALGO_SHA2_256        = 1,
    ALGO_SHA2_384        = 2,
    ALGO_SHA2_512        = 3,
    ALGO_SHA3_224        = 6,
    ALGO_SHA3_256        = 7,
    ALGO_SHA3_384        = 8,
    ALGO_SHA3_512        = 9,
    ALGO_SHAKE_128       = 10,
    ALGO_SHAKE_256       = 11,
    ALGO_SM3_256         = 20,
} HashAlgoId;

typedef struct {
    const char *name;
    HashAlgoId id;
    size_t digest_len;
} HashAlgoDesc;

static const HashAlgoDesc HASH_ALGOS[] = {
    {"SHA2-224 (rvk-Zknh)",     ALGO_SHA2_224,     28},
    {"SHA2-256 (rvk-Zknh)",     ALGO_SHA2_256,     32},
    {"SHA2-384 (rvk-Zknh)",     ALGO_SHA2_384,     48},
    {"SHA2-512 (rvk-Zknh)",     ALGO_SHA2_512,     64},
    {"SHA3-224 (rvk-Zbkb)",     ALGO_SHA3_224,     28},
    {"SHA3-256 (rvk-Zbkb)",     ALGO_SHA3_256,     32},
    {"SHA3-384 (rvk-Zbkb)",     ALGO_SHA3_384,     48},
    {"SHA3-512 (rvk-Zbkb)",     ALGO_SHA3_512,     64},
    {"SHAKE-128 (rvk-Zbkb)",    ALGO_SHAKE_128,    32},
    {"SHAKE-256 (rvk-Zbkb)",    ALGO_SHAKE_256,    64},
    {"SM3-256 (rvk-Zksh)",      ALGO_SM3_256,      32},
};

/* Unified compute function using rvkrypto hardware-accelerated functions */
static int compute_hash(uint8_t *out,
                        size_t *outlen,
                        const uint8_t *in,
                        size_t inlen,
                        HashAlgoId algo)
{
    sha3_ctx_t s3;

    switch (algo) {
        case ALGO_SHA2_224:
            sha2_224(out, in, inlen);
            *outlen = 28;
            break;

        case ALGO_SHA2_256:
            sha2_256(out, in, inlen);
            *outlen = 32;
            break;

        case ALGO_SHA2_384:
            sha2_384(out, in, inlen);
            *outlen = 48;
            break;

        case ALGO_SHA2_512:
            sha2_512(out, in, inlen);
            *outlen = 64;
            break;

        case ALGO_SHA3_224:
            sha3(out, 28, in, inlen);
            *outlen = 28;
            break;

        case ALGO_SHA3_256:
            sha3(out, 32, in, inlen);
            *outlen = 32;
            break;

        case ALGO_SHA3_384:
            sha3(out, 48, in, inlen);
            *outlen = 48;
            break;

        case ALGO_SHA3_512:
            sha3(out, 64, in, inlen);
            *outlen = 64;
            break;

        case ALGO_SHAKE_128:
            shake128_init(&s3);
            shake_update(&s3, in, inlen);
            shake_xof(&s3);
            shake_out(out, 32, &s3);
            *outlen = 32;
            break;

        case ALGO_SHAKE_256:
            shake256_init(&s3);
            shake_update(&s3, in, inlen);
            shake_xof(&s3);
            shake_out(out, 64, &s3);
            *outlen = 64;
            break;

        case ALGO_SM3_256:
            sm3_256(out, in, inlen);
            *outlen = 32;
            break;

        default:
            return -1;
    }

    return 0;
}

/* =========================================================================
 * Sorting & Result Structures (Identical to wolfSSL benchmark)
 * ========================================================================= */
static void sort_u64(uint64_t *arr, size_t n)
{
    for (size_t i = 1; i < n; i++) {
        uint64_t key = arr[i];
        int j = (int)i - 1;
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

typedef struct {
    const char *name;
    uint64_t digest_len;
    uint64_t min_cycles;
    uint64_t med_cycles;
    uint64_t instructions;
    uint64_t cyc_per_byte_x100; /* Cycles/Byte * 100 (e.g. 1542 = 15.42 CPB) */
} BenchmarkResult;

#define MAX_BENCHMARK_ALGOS 32
volatile BenchmarkResult g_results[MAX_BENCHMARK_ALGOS];
volatile uint32_t g_results_count = 0;
volatile uint32_t g_benchmark_done = 0;

/* Static buffers to prevent stack overflow on baremetal */
static uint8_t message[BENCH_PAYLOAD_SIZE];
static uint64_t cycle_samples[ITERATIONS];
static uint64_t inst_samples[ITERATIONS];

void benchmark_done(void)
{
    __asm__ volatile ("nop");
}

/* Initialize function pointers for hardware crypto acceleration */
static void init_rvk_crypto_hooks(void)
{
    /* SHA-2 acceleration using Zknh */
    sha256_compress = sha2_cf256_rvk;
#if defined(RVKINTRIN_RV64) || (__riscv_xlen == 64) || defined(__x86_64__)
    sha512_compress = sha2_cf512_rvk64;
    sha3_keccakp    = sha3_f1600_rvb64;
#else
    sha512_compress = sha2_cf512_rvk32;
    sha3_keccakp    = sha3_f1600_rvb32;
#endif

    /* SM3 acceleration using Zksh */
    sm3_compress = sm3_cf256_rvk;
}

int main(void)
{
    uint8_t digest[64];
    size_t digest_len = 0;

    init_rvk_crypto_hooks();

    /* Fill payload with the EXACT same pseudo-random pattern as wolfSSL benchmark */
    for (size_t i = 0; i < BENCH_PAYLOAD_SIZE; i++) {
        message[i] = (uint8_t)((i * 37 + 101) & 0xFF);
    }

#if !defined(__riscv)
    printf("\n=========================================================================================================\n");
    printf("         HOST (x86_64) HARDWARE ACCELERATED HASH BENCHMARK (rvkrypto-fips)\n");
    printf("=========================================================================================================\n");
    printf(" Payload: %d bytes  |  Iterations: %d\n", (int)BENCH_PAYLOAD_SIZE, (int)ITERATIONS);
    printf("---------------------------------------------------------------------------------------------------------\n");
    printf("%-24s | %6s | %11s | %11s | %9s\n",
           "Algorithm", "Digest", "Min Cycles", "Med Cycles", "Cyc/Byte");
    printf("-------------------------+--------+-------------+-------------+-----------\n");
#endif

    size_t total_algos = sizeof(HASH_ALGOS) / sizeof(HASH_ALGOS[0]);

    for (size_t a = 0; a < total_algos; a++) {
        const HashAlgoDesc *desc = &HASH_ALGOS[a];

#ifdef TARGET_ALGO_ID
        /* If a single algorithm was selected (e.g. ALGO=SHA2_256), skip others */
        if ((int)desc->id != TARGET_ALGO_ID) {
            continue;
        }
#endif

        /* Warmup runs (0 for cold RAM-to-register load evaluation) */
        for (int w = 0; w < WARMUP_ITERATIONS; w++) {
            compute_hash(digest, &digest_len, message, sizeof(message), desc->id);
        }

        /* Benchmark runs */
        for (int i = 0; i < ITERATIONS; i++) {
            uint64_t c0 = read_cycles();
            uint64_t ins0 = read_instructions();

            compute_hash(digest, &digest_len, message, sizeof(message), desc->id);

            uint64_t ins1 = read_instructions();
            uint64_t c1 = read_cycles();

            cycle_samples[i] = c1 - c0;
            inst_samples[i] = ins1 - ins0;
        }

        /* Sort samples to find minimum and median */
        sort_u64(cycle_samples, ITERATIONS);
        sort_u64(inst_samples, ITERATIONS);

        uint64_t min_cyc = cycle_samples[0];
        uint64_t med_cyc = cycle_samples[ITERATIONS / 2];
        uint64_t med_ins = inst_samples[ITERATIONS / 2];

        /* Store into global array (identical to wolfSSL benchmark) */
        if (g_results_count < MAX_BENCHMARK_ALGOS) {
            g_results[g_results_count].name = desc->name;
            g_results[g_results_count].digest_len = desc->digest_len;
            g_results[g_results_count].min_cycles = min_cyc;
            g_results[g_results_count].med_cycles = med_cyc;
            g_results[g_results_count].instructions = med_ins;
            g_results[g_results_count].cyc_per_byte_x100 = (med_cyc * 100) / BENCH_PAYLOAD_SIZE;
            g_results_count++;
        }

#if !defined(__riscv)
        double cyc_per_byte = (double)med_cyc / (double)BENCH_PAYLOAD_SIZE;
        printf("%-24s | %4zu B | %11llu | %11llu | %9.2f\n",
               desc->name,
               desc->digest_len,
               (unsigned long long)min_cyc,
               (unsigned long long)med_cyc,
               cyc_per_byte);
#endif
    }

#if defined(__riscv)
    g_benchmark_done = 1;
    benchmark_done();

    while (1) {
        __asm__ volatile ("nop");
    }
#else
    printf("=========================================================================================================\n\n");
#endif

    return 0;
}
