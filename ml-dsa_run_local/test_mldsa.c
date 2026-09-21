#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mldsa_native.h"

int main(void)
{
    uint8_t public_key[MLDSA44_PUBLICKEYBYTES];
    uint8_t secret_key[MLDSA44_SECRETKEYBYTES];
    uint8_t signature[MLDSA44_BYTES];

    const uint8_t message[] = "Hello from C!";
    size_t message_len = strlen((const char *)message);

    printf("Generating ML-DSA-44 keypair...\n");

    if (mldsa44_keypair(public_key, secret_key) != 0)
    {
        printf("Key generation failed!\n");
        return 1;
    }

    printf("Key generation successful!\n");

    printf("Signing message...\n");

    if (mldsa44_signature(
            signature,
            message,
            message_len,
            NULL,
            0,
            secret_key) != 0)
    {
        printf("Signing failed!\n");
        return 1;
    }

    printf("Signing successful!\n");

    printf("Verifying signature...\n");

    if (mldsa44_verify(
            signature,
            message,
            message_len,
            NULL,
            0,
            public_key) != 0)
    {
        printf("Verification FAILED!\n");
        return 1;
    }

    printf("Verification successful!\n");

    return 0;
}