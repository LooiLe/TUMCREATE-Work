//	test_main.c
//	2021-02-13	Markku-Juhani O. Saarinen <mjos@pqshield();om>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== Main driver for the algorithm tests.

#include "riscv_crypto.h"
#include "test_rvkat.h"

//	algorithm tests

int test_aes();		//	test_aes.c
int test_gcm();		//	test_gcm.c
int test_sha2();	//	test_sha2.c
int test_sha3();	//	test_sha3.c
int test_sm3();		//	test_sm3.c
int test_sm4();		//	test_sm4.c
int test_present(); //	test_present.c
int test_zkr(); 	//	test_zkr.c

//	stub main: run unit tests

typedef struct {
	int fail_aes;
	int fail_gcm;
	int fail_sha2;
	int fail_sha3;
	int fail_sm3;
	int fail_sm4;
	int fail_present;
	int total_fails;
	uint64_t cycles_aes;
	uint64_t cycles_gcm;
	uint64_t cycles_sha2;
	uint64_t cycles_sha3;
	uint64_t cycles_sm3;
	uint64_t cycles_sm4;
	uint64_t cycles_present;
	uint64_t total_cycles;
} crypto_bench_results_t;

volatile crypto_bench_results_t g_crypto_results;
volatile int g_test_done = 0;

static inline uint64_t get_cycles(void)
{
	uint64_t c = 0;
#if defined(__riscv)
	#if __riscv_xlen == 64
		__asm__ volatile ("csrr %0, mcycle" : "=r" (c));
	#else
		uint32_t h0, h1, l;
		do {
			__asm__ volatile ("csrr %0, mcycleh" : "=r" (h0));
			__asm__ volatile ("csrr %0, mcycle"  : "=r" (l));
			__asm__ volatile ("csrr %0, mcycleh" : "=r" (h1));
		} while (h0 != h1);
		c = ((uint64_t)h0 << 32) | l;
	#endif
#endif
	return c;
}

void benchmark_done(void)
{
	__asm__ volatile ("nop");
}

int main()
{
	int fail = 0;
	uint64_t t0, t1, start_total, end_total;

	start_total = get_cycles();

	t0 = get_cycles();
	g_crypto_results.fail_aes = test_aes();
	t1 = get_cycles();
	g_crypto_results.cycles_aes = t1 - t0;
	fail += g_crypto_results.fail_aes;

	t0 = get_cycles();
	g_crypto_results.fail_gcm = test_gcm();
	t1 = get_cycles();
	g_crypto_results.cycles_gcm = t1 - t0;
	fail += g_crypto_results.fail_gcm;

	t0 = get_cycles();
	g_crypto_results.fail_sha2 = test_sha2();
	t1 = get_cycles();
	g_crypto_results.cycles_sha2 = t1 - t0;
	fail += g_crypto_results.fail_sha2;

	t0 = get_cycles();
	g_crypto_results.fail_sha3 = test_sha3();
	t1 = get_cycles();
	g_crypto_results.cycles_sha3 = t1 - t0;
	fail += g_crypto_results.fail_sha3;

	t0 = get_cycles();
	g_crypto_results.fail_sm3 = test_sm3();
	t1 = get_cycles();
	g_crypto_results.cycles_sm3 = t1 - t0;
	fail += g_crypto_results.fail_sm3;

	t0 = get_cycles();
	g_crypto_results.fail_sm4 = test_sm4();
	t1 = get_cycles();
	g_crypto_results.cycles_sm4 = t1 - t0;
	fail += g_crypto_results.fail_sm4;

	t0 = get_cycles();
	g_crypto_results.fail_present = test_present();
	t1 = get_cycles();
	g_crypto_results.cycles_present = t1 - t0;
	fail += g_crypto_results.fail_present;

#ifdef RVKINTRIN_ZKR
	fail += test_zkr();
#endif

	end_total = get_cycles();
	g_crypto_results.total_cycles = end_total - start_total;
	g_crypto_results.total_fails = fail;

	if (fail) {
		rvkat_info("RVKAT self-test finished: FAIL (there were errors)");
	} else {
		rvkat_info("RVKAT self-test finished: PASS (no errors)");
	}

	g_test_done = 1;
	benchmark_done();

#if defined(__riscv)
	// On baremetal CVA6, spin gracefully so GDB can inspect results
	while (1) {
		__asm__ volatile ("nop");
	}
#endif

	return fail;
}
