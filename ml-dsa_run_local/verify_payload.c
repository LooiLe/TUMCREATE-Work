#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mldsa_native.h"
#include "../mldsa65_test_vectors.h"

int main(void)
{
    printf("====================================================\n");
    printf("ML-DSA-65 Test Payload Verification (mldsa-native)\n");
    printf("====================================================\n");
    printf("Payload size:   %zu bytes\n", sizeof(mldsa_test_payload));
    printf("Public key size:%zu bytes\n", sizeof(mldsa_public_key));
    printf("Signature size: %zu bytes\n", sizeof(mldsa_signature_with_ctx));
    printf("Context string: \"%s\" (len=%d)\n", MLDSA_CONTEXT_STRING, MLDSA_CONTEXT_LENGTH);

    /* 1. Verify signature with context */
    int ret_ctx = mldsa_verify(
        mldsa_signature_with_ctx,
        mldsa_test_payload,
        sizeof(mldsa_test_payload),
        (const uint8_t *)MLDSA_CONTEXT_STRING,
        MLDSA_CONTEXT_LENGTH,
        mldsa_public_key
    );

    if (ret_ctx == 0) {
        printf("[PASS] Signature WITH context (\"%s\") verified successfully!\n", MLDSA_CONTEXT_STRING);
    } else {
        printf("[FAIL] Signature WITH context verification FAILED (code=%d)\n", ret_ctx);
    }

    /* 2. Verify signature without context (empty ctx) */
    int ret_no_ctx = mldsa_verify(
        mldsa_signature_no_ctx,
        mldsa_test_payload,
        sizeof(mldsa_test_payload),
        NULL,
        0,
        mldsa_public_key
    );

    if (ret_no_ctx == 0) {
        printf("[PASS] Signature WITHOUT context (pure NULL) verified successfully!\n");
    } else {
        printf("[FAIL] Signature WITHOUT context verification FAILED (code=%d)\n", ret_no_ctx);
    }

    /* 3. Tamper check: intentionally alter 1 byte of payload and verify it fails */
    uint8_t tampered_payload[sizeof(mldsa_test_payload)];
    memcpy(tampered_payload, mldsa_test_payload, sizeof(mldsa_test_payload));
    tampered_payload[0] ^= 0x01;

    int ret_tampered = mldsa_verify(
        mldsa_signature_with_ctx,
        tampered_payload,
        sizeof(tampered_payload),
        (const uint8_t *)MLDSA_CONTEXT_STRING,
        MLDSA_CONTEXT_LENGTH,
        mldsa_public_key
    );

    if (ret_tampered != 0) {
        printf("[PASS] Tamper detection check succeeded (tampered payload rejected as expected)\n");
    } else {
        printf("[FAIL] Tamper detection FAILED (tampered payload was accepted!)\n");
    }

    printf("====================================================\n");
    if (ret_ctx == 0 && ret_no_ctx == 0 && ret_tampered != 0) {
        printf("ALL TESTS PASSED: ML-DSA-65 verification is 100%% compliant!\n");
        return 0;
    }

    return 1;
}
