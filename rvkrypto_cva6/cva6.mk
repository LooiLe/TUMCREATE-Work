# ==============================================================================
# Makefile for CVA6 Hardware Scalar Crypto (rvkrypto-fips) Benchmark
# Matches ml-dsa_run_cva6/Makefile options and benchmark harness structure
# ==============================================================================

CROSS ?= riscv64-unknown-elf-
CC      := $(CROSS)gcc
OBJDUMP := $(CROSS)objdump
OBJCOPY := $(CROSS)objcopy
SIZE    := $(CROSS)size

TARGET := hash_bench

# CVA6 target architecture with Scalar Crypto (NIST Zkn + ShangMi Zks)
ARCH ?= rv64imafdc_zkn_zks
ABI  ?= lp64d

BENCH_PAYLOAD_SIZE ?= 4096
ITERATIONS         ?= 1
WARMUP_ITERATIONS  ?= 0
CPU_FREQ_MHZ       ?= 50.0
USE_MCYCLE         ?= 1

# Algorithm selection: specify ALGO=<name> or ALGO_ID=<num>
ALGO    ?=
ALGO_ID ?=

ifeq ($(ALGO),SHA2_224)
    ALGO_ID := 0
else ifeq ($(ALGO),SHA2_256)
    ALGO_ID := 1
else ifeq ($(ALGO),SHA2_384)
    ALGO_ID := 2
else ifeq ($(ALGO),SHA2_512)
    ALGO_ID := 3
else ifeq ($(ALGO),SHA3_224)
    ALGO_ID := 6
else ifeq ($(ALGO),SHA3_256)
    ALGO_ID := 7
else ifeq ($(ALGO),SHA3_384)
    ALGO_ID := 8
else ifeq ($(ALGO),SHA3_512)
    ALGO_ID := 9
else ifeq ($(ALGO),SHAKE_128)
    ALGO_ID := 10
else ifeq ($(ALGO),SHAKE_256)
    ALGO_ID := 11
else ifeq ($(ALGO),SM3)
    ALGO_ID := 20
endif

# Source files for benchmark
BENCH_SRCS := \
	bench_main.c \
	sha2/sha2_api.c \
	sha2/sha2_cf256_rvk.c \
	sha2/sha2_cf512_rvk64.c \
	sha2/sha2_cf512_rvk32.c \
	sha3/sha3_api.c \
	sha3/sha3_f1600_rvb64.c \
	sha3/sha3_f1600_rvb32.c \
	sm3/sm3_api.c \
	sm3/sm3_cf256_rvk.c \
	test/test_rvkat_sio.c \
	rvk_emu_intrin.c

OBJS := $(BENCH_SRCS:.c=.o)

CFLAGS := \
	-march=$(ARCH) \
	-mabi=$(ABI) \
	-O2 \
	-g3 \
	-std=c99 \
	-Wall \
	-Wextra \
	-Wno-unused-function \
	-I. \
	-Itest \
	-DRVKINTRIN_ASSEMBLER \
	-DBENCH_PAYLOAD_SIZE=$(BENCH_PAYLOAD_SIZE) \
	-DITERATIONS=$(ITERATIONS) \
	-DWARMUP_ITERATIONS=$(WARMUP_ITERATIONS) \
	-DCPU_FREQ_MHZ=$(CPU_FREQ_MHZ) \
	-DUSE_MCYCLE=$(USE_MCYCLE)

ifneq ($(strip $(ALGO_ID)),)
CFLAGS += -DTARGET_ALGO_ID=$(ALGO_ID)
endif

LDFLAGS := \
	-march=$(ARCH) \
	-mabi=$(ABI)

.PHONY: all elf bin dump clean list_algos help run_host

all: elf dump bin

elf: $(TARGET).elf

$(TARGET).elf: $(OBJS)
	@echo "[LD] $@"
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS)
	$(SIZE) $@

bin: $(TARGET).bin

$(TARGET).bin: $(TARGET).elf
	@echo "[OBJCOPY] $@"
	$(OBJCOPY) -O binary $< $@

dump: $(TARGET).dump

$(TARGET).dump: $(TARGET).elf
	@echo "[OBJDUMP] $@"
	$(OBJDUMP) -d -S $< > $@

%.o: %.c
	@echo "[CC] $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Host execution (x86 emulation)
run_host:
	gcc -O2 -g -I. -Itest \
		-DRVKINTRIN_EMULATE=1 -DRVKINTRIN_RV32 -DRVKINTRIN_RV64 \
		-DBENCH_PAYLOAD_SIZE=$(BENCH_PAYLOAD_SIZE) \
		-DITERATIONS=$(ITERATIONS) \
		-DWARMUP_ITERATIONS=$(WARMUP_ITERATIONS) \
		$(if $(strip $(ALGO_ID)),-DTARGET_ALGO_ID=$(ALGO_ID),) \
		$(BENCH_SRCS) -o $(TARGET)_host
	./$(TARGET)_host

clean:
	rm -f $(OBJS) $(TARGET).elf $(TARGET).bin $(TARGET).dump $(TARGET).map $(TARGET)_host

list_algos:
	@echo "Available Algorithms in rvkrypto for ALGO= or ALGO_ID=:"
	@echo "  ID  0 : SHA2-224        (ALGO=SHA2_224) - accelerated via Zknh"
	@echo "  ID  1 : SHA2-256        (ALGO=SHA2_256) - accelerated via Zknh"
	@echo "  ID  2 : SHA2-384        (ALGO=SHA2_384) - accelerated via Zknh"
	@echo "  ID  3 : SHA2-512        (ALGO=SHA2_512) - accelerated via Zknh"
	@echo "  ID  6 : SHA3-224        (ALGO=SHA3_224) - accelerated via Zbkb"
	@echo "  ID  7 : SHA3-256        (ALGO=SHA3_256) - accelerated via Zbkb"
	@echo "  ID  8 : SHA3-384        (ALGO=SHA3_384) - accelerated via Zbkb"
	@echo "  ID  9 : SHA3-512        (ALGO=SHA3_512) - accelerated via Zbkb"
	@echo "  ID 10 : SHAKE-128       (ALGO=SHAKE_128) - accelerated via Zbkb"
	@echo "  ID 11 : SHAKE-256       (ALGO=SHAKE_256) - accelerated via Zbkb"
	@echo "  ID 20 : SM3-256         (ALGO=SM3)       - accelerated via Zksh"

help:
	@echo "Usage:"
	@echo "  make -f cva6.mk                     Build all algorithms for CVA6"
	@echo "  make -f cva6.mk ALGO=SHA2_256       Build only SHA2-256 (or ALGO_ID=1)"
	@echo "  make -f cva6.mk ALGO=SHA3_256       Build only SHA3-256"
	@echo "  make -f cva6.mk run_host            Test & run natively on host PC"
	@echo "  make -f cva6.mk list_algos          Show supported algorithm names & IDs"
	@echo "  make -f cva6.mk clean               Clean build artifacts"
