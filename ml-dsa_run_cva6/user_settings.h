#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* =========================================================================
 * Baremetal / Embedded Target Configuration for RISC-V CVA6
 * ========================================================================= */
#define WOLFCRYPT_ONLY
#define NO_TLS
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_NO_SOCK
#define NO_WRITEV
#define NO_DEV_RANDOM
#define WOLFSSL_USER_IO
#define NO_MAIN_FUNCT

/* Target architecture settings */
#define SIZEOF_LONG_LONG 8
#if defined(__riscv)
#define WOLFSSL_RISCV
#endif

/* =========================================================================
 * Hash Algorithms to Benchmark
 * ========================================================================= */
/* SHA-2 Family */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
/* SHA-512/224 and SHA-512/256 truncated variants */
#define WOLFSSL_SHA512_224
#define WOLFSSL_SHA512_256

/* SHA-3 and SHAKE Family (FIPS 202) */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* =========================================================================
 * Disable unused features for minimal code size and zero OS dependency
 * ========================================================================= */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_MD5
#define NO_DES3
#define NO_RC4
#define NO_AES
#define NO_HMAC
#define NO_ASN
#define NO_ASN_TIME
#define USER_TIME
#define NO_PWDBASED
#define NO_CODING
#define NO_CERTS
#define NO_OLD_TLS
#define NO_WOLFSSL_SERVER
#define NO_WOLFSSL_CLIENT

#endif /* USER_SETTINGS_H */
