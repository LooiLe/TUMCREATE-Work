# CVA6 Hardware Scalar Crypto Benchmark (rvkrypto-fips)

This benchmark harness is structured **identically to the wolfSSL / XKCP benchmark** in `ml-dsa_run_cva6/`, using the exact same payload generation, timing methodology, and GDB result structures so you can compare software execution against hardware acceleration directly.

---

## 1. Supported Algorithms

| Algorithm | Algorithm ID | Hardware Extension Used |
| :--- | :--- | :--- |
| **SHA2-224** | `ALGO=SHA2_224` (ID 0) | `Zknh` (`sha256sig0`, `sha256sum0`, etc.) |
| **SHA2-256** | `ALGO=SHA2_256` (ID 1) | `Zknh` (`sha256sig0`, `sha256sum0`, etc.) |
| **SHA2-384** | `ALGO=SHA2_384` (ID 2) | `Zknh` (`sha512sig0`, `sha512sum0`, etc.) |
| **SHA2-512** | `ALGO=SHA2_512` (ID 3) | `Zknh` (`sha512sig0`, `sha512sum0`, etc.) |
| **SHA2-512/224** | `ALGO=SHA2_512_224` (ID 4) | `Zknh` (`sha512sig0`, `sha512sum0`, etc.) |
| **SHA2-512/256** | `ALGO=SHA2_512_256` (ID 5) | `Zknh` (`sha512sig0`, `sha512sum0`, etc.) |
| **SHA3-224** | `ALGO=SHA3_224` (ID 6) | `Zbkb` (64-bit Keccak bit rotations) |
| **SHA3-256** | `ALGO=SHA3_256` (ID 7) | `Zbkb` (64-bit Keccak bit rotations) |
| **SHA3-384** | `ALGO=SHA3_384` (ID 8) | `Zbkb` (64-bit Keccak bit rotations) |
| **SHA3-512** | `ALGO=SHA3_512` (ID 9) | `Zbkb` (64-bit Keccak bit rotations) |
| **SHAKE-128** | `ALGO=SHAKE_128` (ID 10) | `Zbkb` (64-bit Keccak bit rotations) |
| **SHAKE-256** | `ALGO=SHAKE_256` (ID 11) | `Zbkb` (64-bit Keccak bit rotations) |
| **SM3-256** | `ALGO=SM3` (ID 20) | `Zksh` (`sm3p0`, `sm3p1`) |

---

## 2. Compiling (Identical Syntax to wolfSSL)

Navigate to `rvkrypto_cva6/`:

```bash
# Example 1: Run 1 cold iteration of SHA2-256 (Default 4 KB payload)
make -f cva6.mk clean && make -f cva6.mk ALGO=SHA2_256 ITERATIONS=1 WARMUP_ITERATIONS=0

# Example 2: Run 1 cold iteration of SHA3-256
make -f cva6.mk clean && make -f cva6.mk ALGO=SHA3_256 ITERATIONS=1 WARMUP_ITERATIONS=0

# Example 3: Build all algorithms with 50 iterations (steady-state benchmark)
make -f cva6.mk clean && make -f cva6.mk ITERATIONS=50 WARMUP_ITERATIONS=5

# Check all available algorithms:
make -f cva6.mk list_algos
```

*(Note: If your cross-compiler is named `riscv64-linux-gnu-gcc` instead of `riscv64-unknown-elf-gcc`, simply pass `CROSS=riscv64-linux-gnu-`)*.

---

## 3. Running via OpenOCD and GDB

Follow the exact same workflow as documented in `ml-dsa_run_cva6/HOWTO_RUN.md`:

### Terminal 1: OpenOCD
```bash
openocd -f interface/ftdi/digilent_jtag_smt2.cfg -f target/cva6.cfg
# (or: openocd -f ariane.cfg)
```

### Terminal 2: GDB
```gdb
riscv-none-elf-gdb hash_bench.elf

(gdb) target remote :3333

# Reset CVA6 core & flush caches
(gdb) monitor reset halt

# Load the binary
(gdb) load

# Set breakpoint on completion
(gdb) b benchmark_done

# Run
(gdb) continue

# Inspect result (identical struct format as wolfSSL benchmark)
(gdb) set print pretty on
(gdb) print g_results[0]
```

---

## 4. Side-by-Side Comparison Format

The structure printed by GDB:
```c
$1 = {
  name = 0x... "SHA2-256 (rvk-Zknh)",
  digest_len = 32,
  min_cycles = ...,
  med_cycles = ...,
  instructions = ...,
  cyc_per_byte_x100 = ...
}
```

Because the payload pattern, size (4096 B), iteration count, and CSR counter calls (`mcycle`, `minstret`) are **100% identical**, you can compare `g_results[0]` from this hardware run directly against `g_results[0]` from `ml-dsa_run_cva6` to measure the exact speedup from CVA6's hardware scalar crypto extension.
