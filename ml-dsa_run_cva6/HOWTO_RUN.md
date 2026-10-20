# CVA6 / Genesys 2 Experiment Run Guide

This guide documents the full workflow to program the FPGA, compile the optimized benchmark, run it via OpenOCD + GDB, and inspect results.

---

## Step 1: Start Vivado & Flash Bitstream

The bitstream file is located at: `~/Downloads/ariane_xilinx.bit`.

First, source the Vivado environment:
```bash
source /opt/Xilinx/2025.2.1/Vivado/settings64.sh
```

### Option A: Via Terminal (Tcl Mode)
```bash
vivado -mode tcl
```
Inside the Vivado Tcl prompt:
```tcl
open_hw_manager
connect_hw_server
open_hw_target
set_property PROGRAM.FILE {~/Downloads/ariane_xilinx.bit} [get_hw_devices xc7k325t_0]
program_hw_devices [get_hw_devices xc7k325t_0]
exit
```

### Option B: Via Vivado GUI
```bash
vivado
```
1. In the Vivado window, click **Open Hardware Manager**.
2. Click **Auto Connect**.
3. Right-click the FPGA chip (`xc7k325t_0`) $\rightarrow$ **Program Device...**.
4. Browse to `~/Downloads/ariane_xilinx.bit` and click **Program**.
5. Verify the green **`DONE`** LED on the Genesys 2 board is lit.

---

## Step 2: Build the Benchmark

Navigate to `ml-dsa_run_cva6/` and build:

```bash
# Experiment 1: 4 KB Main Payload (Default)
make clean && make BENCH_PAYLOAD_SIZE=4096

# Experiment 2: Small 64 B Header
make clean && make BENCH_PAYLOAD_SIZE=64

# Experiment 3: 16 KB Large Binary
make clean && make BENCH_PAYLOAD_SIZE=16384 ITERATIONS=20
```

---

## Step 3: Start OpenOCD (Terminal 1)

Start the JTAG GDB server:

```bash
openocd -f openocd.cfg
```
*OpenOCD will listen on `localhost:3333`.*

---

---

## Cold RAM-to-Register Single Iteration Mode (Restart between Algorithms)

To measure the **true cold loading latency from RAM to registers** without warm caches or residual state from prior algorithms:

### 1. Build a Specific Algorithm (1 Cold Iteration)
Use `ALGO=<NAME>` or `ALGO_ID=<NUM>` with `ITERATIONS=1` and `WARMUP_ITERATIONS=0`:

```bash
# Check available algorithms:
make list_algos

# Example 1: Run SHA2-256 (ID 1)
make clean && make ALGO=SHA2_256 ITERATIONS=1 WARMUP_ITERATIONS=0

# Example 2: Run SHA3-256 wolfSSL (ID 7)
make clean && make ALGO=SHA3_256 ITERATIONS=1 WARMUP_ITERATIONS=0

# Example 3: Run SHA3-256 XKCP (ID 13)
make clean && make ALGO=XKCP_SHA3_256 ITERATIONS=1 WARMUP_ITERATIONS=0
```

### 2. Fast CVA6 Core Reset & Run in GDB
You **do not need to reflash the FPGA bitstream** to reset CVA6. Use OpenOCD's JTAG reset command `monitor reset halt` inside GDB:

```gdb
(gdb) target remote :3333

# Reset CVA6 core & clear L1 caches:
(gdb) monitor reset halt
(gdb) load

# Run and automatically stop on completion:
(gdb) b benchmark_done
(gdb) continue

# Inspect single-algo result:
(gdb) set print pretty on
(gdb) print g_results[0]
```

### 3. Move to Next Algorithm
Keep GDB open:
1. In Terminal 1: Build next algorithm (`make clean && make ALGO=SHA3_256 ITERATIONS=1 WARMUP_ITERATIONS=0`)
2. In GDB (Terminal 2):
   ```gdb
   (gdb) monitor reset halt
   (gdb) load
   (gdb) continue
   (gdb) print g_results[0]
   ```
*(Every cycle executes from a fresh CVA6 CPU reset, guaranteeing 100% cold RAM-to-register load times).*

---

## Host Verification (Local x86 Testing)

To test algorithm correctness or print formatted tables directly to your terminal without the FPGA:

```bash
# With wolfSSL + XKCP:
make run_host

# wolfSSL only:
make ENABLE_XKCP=0 run_host
```
