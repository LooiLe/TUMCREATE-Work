#!/usr/bin/env python3
"""
ML-DSA (FIPS 204) Payload Signing and Verification Utility
Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 using standard cryptography library.
"""

import argparse
import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey, MLDSA44PublicKey,
    MLDSA65PrivateKey, MLDSA65PublicKey,
    MLDSA87PrivateKey, MLDSA87PublicKey,
)

ALGO_MAP = {
    44: (MLDSA44PrivateKey, MLDSA44PublicKey, 1312, 2420),
    65: (MLDSA65PrivateKey, MLDSA65PublicKey, 1952, 3309),
    87: (MLDSA87PrivateKey, MLDSA87PublicKey, 2592, 4627),
}


def format_c_array(name: str, data: bytes, bytes_per_line: int = 16) -> str:
    lines = [f"/* Length: {len(data)} bytes */", f"static const uint8_t {name}[{len(data)}] = {{"]
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_bytes = ", ".join(f"0x{b:02x}" for b in chunk)
        if i + bytes_per_line < len(data):
            lines.append(f"    {hex_bytes},")
        else:
            lines.append(f"    {hex_bytes}")
    lines.append("};\n")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Sign or verify a payload using ML-DSA (FIPS 204)")
    parser.add_argument("payload", help="Path to payload file to sign or verify")
    parser.add_argument("-a", "--algorithm", type=int, choices=[44, 65, 87], default=65,
                        help="ML-DSA security parameter set (default: 65)")
    parser.add_argument("-c", "--context", type=str, default="test-benchmark-v1",
                        help="Context string (default: test-benchmark-v1)")
    parser.add_argument("-s", "--seed", help="Path to 32-byte private key seed file (optional)")
    parser.add_argument("-o", "--output-prefix", default="mldsa65",
                        help="Output prefix for generated artifacts (default: mldsa65)")
    parser.add_argument("--no-context", action="store_true",
                        help="Also generate a signature with empty/null context")
    parser.add_argument("--c-header", action="store_true", default=True,
                        help="Generate C header with byte arrays (default: True)")

    args = parser.parse_args()

    payload_path = Path(args.payload)
    if not payload_path.is_file():
        print(f"Error: Payload file '{args.payload}' does not exist.", file=sys.stderr)
        sys.exit(1)

    payload = payload_path.read_bytes()
    ctx_bytes = args.context.encode("utf-8") if args.context else b""

    priv_cls, pub_cls, pk_len, sig_len = ALGO_MAP[args.algorithm]

    # Load or generate seed
    if args.seed:
        seed_path = Path(args.seed)
        seed = seed_path.read_bytes()
        if len(seed) != 32:
            print(f"Error: Seed must be exactly 32 bytes (got {len(seed)}).", file=sys.stderr)
            sys.exit(1)
        priv = priv_cls.from_seed_bytes(seed)
        print(f"[+] Loaded existing private key seed from '{args.seed}'")
    else:
        seed = os.urandom(32)
        priv = priv_cls.from_seed_bytes(seed)
        print(f"[+] Generated new cryptographic seed (32 bytes)")

    pub = priv.public_key()
    pub_bytes = pub.public_bytes_raw()

    # Sign with specified context
    sig_with_ctx = priv.sign(payload, context=ctx_bytes if ctx_bytes else None)
    pub.verify(sig_with_ctx, payload, context=ctx_bytes if ctx_bytes else None)
    print(f"[+] ML-DSA-{args.algorithm} signature created and verified (ctx='{args.context}', length={len(sig_with_ctx)} bytes)")

    # Sign without context (empty ctx) if requested or by default
    sig_no_ctx = priv.sign(payload, context=None)
    pub.verify(sig_no_ctx, payload, context=None)
    print(f"[+] ML-DSA-{args.algorithm} signature created and verified (ctx=NULL/empty, length={len(sig_no_ctx)} bytes)")

    prefix = args.output_prefix

    # Save artifacts
    seed_file = Path(f"{prefix}_seed.bin")
    seed_file.write_bytes(seed)
    Path(f"{prefix}_seed.hex").write_text(seed.hex() + "\n")

    pub_file = Path(f"{prefix}_public_key.bin")
    pub_file.write_bytes(pub_bytes)
    Path(f"{prefix}_public_key.hex").write_text(pub_bytes.hex() + "\n")

    sig_ctx_file = Path(f"{prefix}_payload_ctx.sig")
    sig_ctx_file.write_bytes(sig_with_ctx)
    Path(f"{prefix}_payload_ctx.hex").write_text(sig_with_ctx.hex() + "\n")

    sig_noctx_file = Path(f"{prefix}_payload_no_ctx.sig")
    sig_noctx_file.write_bytes(sig_no_ctx)
    Path(f"{prefix}_payload_no_ctx.hex").write_text(sig_no_ctx.hex() + "\n")

    print(f"\n[+] Saved binary artifacts:")
    print(f"    - Seed:       {seed_file} ({len(seed)} bytes)")
    print(f"    - Public Key: {pub_file} ({len(pub_bytes)} bytes)")
    print(f"    - Sig (ctx):  {sig_ctx_file} ({len(sig_with_ctx)} bytes)")
    print(f"    - Sig (pure): {sig_noctx_file} ({len(sig_no_ctx)} bytes)")

    # Generate C Header
    if args.c_header:
        header_path = Path(f"{prefix}_test_vectors.h")
        with open(header_path, "w", encoding="utf-8") as f:
            f.write("/* Auto-generated ML-DSA Test Vectors */\n")
            f.write(f"/* Target: ML-DSA-{args.algorithm} (FIPS 204) */\n")
            f.write(f"/* Payload source: {payload_path.name} */\n")
            f.write(f"/* Context string: \"{args.context}\" */\n\n")
            f.write("#ifndef ML_DSA_TEST_VECTORS_H\n")
            f.write("#define ML_DSA_TEST_VECTORS_H\n\n")
            f.write("#include <stdint.h>\n")
            f.write("#include <stddef.h>\n\n")
            f.write(f'#define MLDSA_CONTEXT_STRING "{args.context}"\n')
            f.write(f"#define MLDSA_CONTEXT_LENGTH {len(ctx_bytes)}\n\n")
            f.write(format_c_array("mldsa_test_payload", payload))
            f.write(format_c_array("mldsa_private_seed", seed))
            f.write(format_c_array("mldsa_public_key", pub_bytes))
            f.write(format_c_array("mldsa_signature_with_ctx", sig_with_ctx))
            f.write(format_c_array("mldsa_signature_no_ctx", sig_no_ctx))
            f.write("#endif /* ML_DSA_TEST_VECTORS_H */\n")
        print(f"    - C Header:   {header_path}")

    print("\nVerification check: ALL SIGNATURES VALID.")


if __name__ == "__main__":
    main()
