#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* =========================================================================
 * wolfCrypt Baremetal Headers
 * ========================================================================= */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#ifdef WOLFSSL_SHA3
#include <wolfssl/wolfcrypt/sha3.h>
#endif

/* =========================================================================
 * Benchmark Configuration
 * ========================================================================= */
#ifndef ITERATIONS
#define ITERATIONS          50      /* Number of benchmark runs per algorithm */
#endif

#ifndef WARMUP_ITERATIONS
#define WARMUP_ITERATIONS   5       /* Warm-up runs to prime I-cache and D-cache */
#endif

#ifndef BENCH_PAYLOAD_SIZE
#define BENCH_PAYLOAD_SIZE  4096    /* 4 KB test payload */
#endif

#ifndef CPU_FREQ_MHZ
#define CPU_FREQ_MHZ        50.0    /* Target CVA6 clock frequency on FPGA in MHz */
#endif

/* Set to 1 if running in RISC-V Machine Mode (M-mode) directly without U-mode delegation */
#ifndef USE_MCYCLE
#define USE_MCYCLE          0
#endif

/* =========================================================================
 * RISC-V Hardware Performance Counters (Cycle & Instruction Counters)
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
#elif defined(__x86_64__) || defined(_M_X64)
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    cycles = ((uint64_t)hi << 32) | lo;
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
 * Hash Algorithms & Unified Context
 * ========================================================================= */
typedef enum {
    ALGO_SHA2_224,
    ALGO_SHA2_256,
    ALGO_SHA2_384,
    ALGO_SHA2_512,
#if defined(WOLFSSL_SHA512_224)
    ALGO_SHA2_512_224,
#endif
#if defined(WOLFSSL_SHA512_256)
    ALGO_SHA2_512_256,
#endif
#ifdef WOLFSSL_SHA3
    ALGO_SHA3_224,
    ALGO_SHA3_256,
    ALGO_SHA3_384,
    ALGO_SHA3_512,
    ALGO_SHAKE_128,
    ALGO_SHAKE_256,
#endif
} HashAlgoId;

typedef struct {
    const char *name;
    HashAlgoId id;
    size_t digest_len;
} HashAlgoDesc;

/* Unified context union to avoid dynamic memory allocation (malloc/free) */
typedef union {
    wc_Sha256 sha256;
    wc_Sha512 sha512;
#ifdef WOLFSSL_SHA3
    wc_Sha3   sha3;
    wc_Shake  shake;
#endif
} HashCtx;

static int compute_hash(HashCtx *ctx,
                        uint8_t *out,
                        size_t *outlen,
                        const uint8_t *in,
                        size_t inlen,
                        HashAlgoId algo)
{
    int ret = 0;

    switch (algo) {
#ifdef WOLFSSL_SHA224
        case ALGO_SHA2_224:
            ret = wc_InitSha224(&ctx->sha256);
            if (ret == 0) ret = wc_Sha224Update(&ctx->sha256, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha224Final(&ctx->sha256, out);
            *outlen = 28;
            break;
#endif
        case ALGO_SHA2_256:
            ret = wc_InitSha256(&ctx->sha256);
            if (ret == 0) ret = wc_Sha256Update(&ctx->sha256, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha256Final(&ctx->sha256, out);
            *outlen = 32;
            break;

#ifdef WOLFSSL_SHA384
        case ALGO_SHA2_384:
            ret = wc_InitSha384(&ctx->sha512);
            if (ret == 0) ret = wc_Sha384Update(&ctx->sha512, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha384Final(&ctx->sha512, out);
            *outlen = 48;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case ALGO_SHA2_512:
            ret = wc_InitSha512(&ctx->sha512);
            if (ret == 0) ret = wc_Sha512Update(&ctx->sha512, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha512Final(&ctx->sha512, out);
            *outlen = 64;
            break;
#endif
#if defined(WOLFSSL_SHA512_224)
        case ALGO_SHA2_512_224:
            ret = wc_InitSha512_224(&ctx->sha512);
            if (ret == 0) ret = wc_Sha512_224Update(&ctx->sha512, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha512_224Final(&ctx->sha512, out);
            *outlen = 28;
            break;
#endif
#if defined(WOLFSSL_SHA512_256)
        case ALGO_SHA2_512_256:
            ret = wc_InitSha512_256(&ctx->sha512);
            if (ret == 0) ret = wc_Sha512_256Update(&ctx->sha512, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha512_256Final(&ctx->sha512, out);
            *outlen = 32;
            break;
#endif
#ifdef WOLFSSL_SHA3
        case ALGO_SHA3_224:
            ret = wc_InitSha3_224(&ctx->sha3, NULL, INVALID_DEVID);
            if (ret == 0) ret = wc_Sha3_224_Update(&ctx->sha3, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha3_224_Final(&ctx->sha3, out);
            *outlen = 28;
            break;

        case ALGO_SHA3_256:
            ret = wc_InitSha3_256(&ctx->sha3, NULL, INVALID_DEVID);
            if (ret == 0) ret = wc_Sha3_256_Update(&ctx->sha3, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha3_256_Final(&ctx->sha3, out);
            *outlen = 32;
            break;

        case ALGO_SHA3_384:
            ret = wc_InitSha3_384(&ctx->sha3, NULL, INVALID_DEVID);
            if (ret == 0) ret = wc_Sha3_384_Update(&ctx->sha3, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha3_384_Final(&ctx->sha3, out);
            *outlen = 48;
            break;

        case ALGO_SHA3_512:
            ret = wc_InitSha3_512(&ctx->sha3, NULL, INVALID_DEVID);
            if (ret == 0) ret = wc_Sha3_512_Update(&ctx->sha3, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha3_512_Final(&ctx->sha3, out);
            *outlen = 64;
            break;

        case ALGO_SHAKE_128:
            ret = wc_InitShake128(&ctx->shake, NULL, INVALID_DEVID);
            if (ret == 0) ret = wc_Shake128_Update(&ctx->shake, in, (word32)inlen);
            if (ret == 0) ret = wc_Shake128_Final(&ctx->shake, out, 32);
            *outlen = 32;
            break;

        case ALGO_SHAKE_256:
            ret = wc_InitShake256(&ctx->shake, NULL, INVALID_DEVID);
            if (ret == 0) ret = wc_Shake256_Update(&ctx->shake, in, (word32)inlen);
            if (ret == 0) ret = wc_Shake256_Final(&ctx->shake, out, 64);
            *outlen = 64;
            break;
#endif
        default:
            return -1;
    }

    return (ret == 0) ? 0 : -1;
}

static const HashAlgoDesc HASH_ALGOS[] = {
#ifdef WOLFSSL_SHA224
    {"SHA2-224",      ALGO_SHA2_224,     28},
#endif
    {"SHA2-256",      ALGO_SHA2_256,     32},
#ifdef WOLFSSL_SHA384
    {"SHA2-384",      ALGO_SHA2_384,     48},
#endif
#ifdef WOLFSSL_SHA512
    {"SHA2-512",      ALGO_SHA2_512,     64},
#endif
#if defined(WOLFSSL_SHA512_224)
    {"SHA2-512/224",  ALGO_SHA2_512_224, 28},
#endif
#if defined(WOLFSSL_SHA512_256)
    {"SHA2-512/256",  ALGO_SHA2_512_256, 32},
#endif
#ifdef WOLFSSL_SHA3
    {"SHA3-224",      ALGO_SHA3_224,     28},
    {"SHA3-256",      ALGO_SHA3_256,     32},
    {"SHA3-384",      ALGO_SHA3_384,     48},
    {"SHA3-512",      ALGO_SHA3_512,     64},
    {"SHAKE-128",     ALGO_SHAKE_128,    32},
    {"SHAKE-256",     ALGO_SHAKE_256,    64},
#endif
};

/* Freestanding insertion sort (no stdlib qsort dependency for baremetal) */
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

/* Global benchmark results for JTAG / GDB inspection */
typedef struct {
    const char *name;
    uint64_t digest_len;
    uint64_t min_cycles;
    uint64_t med_cycles;
    uint64_t instructions;
    uint64_t cyc_per_byte_x100; /* Cycles/Byte * 100 (e.g. 1542 = 15.42 CPB) */
} BenchmarkResult;

#define MAX_BENCHMARK_ALGOS 16
volatile BenchmarkResult g_results[MAX_BENCHMARK_ALGOS];
volatile uint32_t g_results_count = 0;
volatile uint32_t g_benchmark_done = 0;

/* Static buffers to avoid overflowing small baremetal stack frames */
static uint8_t message[BENCH_PAYLOAD_SIZE];
static uint64_t cycle_samples[ITERATIONS];
static uint64_t inst_samples[ITERATIONS];

int main(void)
{
    HashCtx ctx;
    uint8_t digest[64];
    size_t digest_len = 0;

    /* Fill payload with pseudo-random pattern */
    for (size_t i = 0; i < BENCH_PAYLOAD_SIZE; i++) {
        message[i] = (uint8_t)((i * 37 + 101) & 0xFF);
    }

    wolfCrypt_Init();

    size_t total_algos = sizeof(HASH_ALGOS) / sizeof(HASH_ALGOS[0]);

    for (size_t a = 0; a < total_algos; a++) {
        const HashAlgoDesc *desc = &HASH_ALGOS[a];

        /* Warmup runs */
        for (int w = 0; w < WARMUP_ITERATIONS; w++) {
            compute_hash(&ctx, digest, &digest_len, message, sizeof(message), desc->id);
        }

        /* Benchmark runs */
        for (int i = 0; i < ITERATIONS; i++) {
            uint64_t c0 = read_cycles();
            uint64_t ins0 = read_instructions();

            compute_hash(&ctx, digest, &digest_len, message, sizeof(message), desc->id);

            uint64_t ins1 = read_instructions();
            uint64_t c1 = read_cycles();

            cycle_samples[i] = c1 - c0;
            inst_samples[i] = ins1 - ins0;
        }

        /* Sort samples to find median and min */
        sort_u64(cycle_samples, ITERATIONS);
        sort_u64(inst_samples, ITERATIONS);

        uint64_t min_cyc = cycle_samples[0];
        uint64_t med_cyc = cycle_samples[ITERATIONS / 2];
        uint64_t med_ins = inst_samples[ITERATIONS / 2];

        /* Store into global array for JTAG / GDB inspection */
        if (a < MAX_BENCHMARK_ALGOS) {
            g_results[a].name = desc->name;
            g_results[a].digest_len = desc->digest_len;
            g_results[a].min_cycles = min_cyc;
            g_results[a].med_cycles = med_cyc;
            g_results[a].instructions = med_ins;
            g_results[a].cyc_per_byte_x100 = (med_cyc * 100) / BENCH_PAYLOAD_SIZE;
        }
    }

    g_results_count = (uint32_t)total_algos;

    wolfCrypt_Cleanup();

    /* Signal completion to JTAG / GDB */
    g_benchmark_done = 1;

    /* Halt in infinite loop */
    while (1) {
        __asm__ volatile ("nop");
    }

    return 0;
}