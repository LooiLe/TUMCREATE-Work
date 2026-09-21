// #include <stdint.h>
// #include <stdio.h>
// #include <string.h>

// #include "mldsa_native.h"

// int main(void)
// {
//     uint8_t public_key[MLDSA44_PUBLICKEYBYTES];
//     uint8_t secret_key[MLDSA44_SECRETKEYBYTES];
//     uint8_t signature[MLDSA44_BYTES];

//     const uint8_t message[] = "Hello from C!";
//     size_t message_len = strlen((const char *)message);

//     printf("Generating ML-DSA-44 keypair...\n");

//     if (mldsa_keypair(public_key, secret_key) != 0)
//     {
//         printf("Key generation failed!\n");
//         return 1;
//     }

//     printf("Key generation successful!\n");

//     printf("Signing message...\n");

//     if (mldsa_signature(
//             signature,
//             message,
//             message_len,
//             NULL,
//             0,
//             secret_key) != 0)
//     {
//         printf("Signing failed!\n");
//         return 1;
//     }

//     printf("Signing successful!\n");

//     printf("Verifying signature...\n");

//     const uint8_t wrong_message[] = "Hello from C";

//     if (mldsa_verify(
//             signature,
//             wrong_message,
//             message_len,
//             NULL,
//             0,
//             public_key) != 0)
//     {
//         printf("Verification FAILED!\n");
//         return 1;
//     }

//     printf("Verification successful!\n");

//     return 0;
// }

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mldsa_native.h"
#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

/* Forward declaration for the RNG hook */
int randombytes(void *buf, size_t n);

/**
 * Computes SHA3-512 over `in` and writes the 64-byte digest to `out`.
 * Returns 0 on success, -1 on failure.
 */
static int custom_sha3_512(uint8_t out[64], const uint8_t *in, size_t inlen)
{
    unsigned int outlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, in, inlen) != 1 ||
        EVP_DigestFinal_ex(ctx, out, &outlen) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return (outlen == 64) ? 0 : -1;
}

int main(void)
{
    uint8_t public_key[MLDSA65_PUBLICKEYBYTES];
    uint8_t secret_key[MLDSA65_SECRETKEYBYTES];
    uint8_t signature[MLDSA65_BYTES];

    const uint8_t message[] = "Hello from C!";
    size_t message_len = strlen((const char *)message);

    /* 1. Key generation remains identical (independent of hash choice) */
    printf("Generating ML-DSA-44 keypair...\n");
    if (mldsa_keypair(public_key, secret_key) != 0)
    {
        printf("Key generation failed!\n");
        return 1;
    }
    printf("Key generation successful!\n");

    /* 2. Hash the message yourself using an approved algorithm */
    uint8_t digest[64]; /* SHA3-512 produces 64 bytes */
    custom_sha3_512(digest, message, message_len);

    /* 32 bytes of randomness for signing:
     * - Fill with random bytes for randomized signing (FIPS 204 default)
     * - Or set to all zeroes for deterministic signing */
    uint8_t rnd[32];
    if (randombytes(rnd, sizeof(rnd)) != 0) {
        printf("Failed to generate random bytes for signing!\n");
        return 1;
    }

    printf("Signing pre-hashed message...\n");

    /* 3. Sign using the pre-hash internal API */
    if (mldsa_signature_pre_hash_internal(
            signature,
            digest,
            sizeof(digest),
            NULL,                  /* Optional context string */
            0,                     /* Context string length (<= 255) */
            rnd,                   /* 32-byte randomness */
            secret_key,
            MLD_PREHASH_SHA3_512   /* Approved algorithm identifier */
        ) != 0)
    {
        printf("Signing failed!\n");
        return 1;
    }
    printf("Signing successful!\n");

    printf("Verifying signature...\n");

    /* 4. Verifier side: compute the hash of the received message */
    uint8_t verify_digest[64];
    // const uint8_t wrong_message[] = "I'm not C";
    custom_sha3_512(verify_digest, message, message_len);

    /* 5. Verify using the pre-hash internal API */
    if (mldsa_verify_pre_hash_internal(
            signature,
            verify_digest,
            sizeof(verify_digest),
            NULL,                  /* Must match signing context */
            0,
            public_key,
            MLD_PREHASH_SHA3_512   /* Must match signing algorithm */
        ) != 0)
    {
        printf("Verification FAILED!\n");
        return 1;
    }

    printf("Verification successful!\n");

    return 0;
}