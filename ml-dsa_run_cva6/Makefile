# ==============================================================================
# Makefile for CVA6 Baremetal Hash Algorithm Benchmark
# ==============================================================================

# Toolchain configuration (override with: make CROSS_COMPILE=riscv64-unknown-elf-)
CROSS_COMPILE ?= riscv64-unknown-elf-
CC            ?= $(CROSS_COMPILE)gcc
OBJCOPY       ?= $(CROSS_COMPILE)objcopy
OBJDUMP       ?= $(CROSS_COMPILE)objdump

# Target RISC-V Architecture for CVA6 (default RV64GC with double-precision float)
# Change to -march=rv64imac -mabi=lp64 if your CVA6 build lacks hardware FPU
ARCH_FLAGS ?= -march=rv64gc -mabi=lp64d -mcmodel=medany

# Path to wolfSSL directory (override with: make WOLFSSL_ROOT=/path/to/wolfssl)
WOLFSSL_ROOT ?= ./wolfssl

# Compilation flags
CFLAGS := \
	$(ARCH_FLAGS) \
	-O3 \
	-fomit-frame-pointer \
	-Wall \
	-Wextra \
	-Wno-unused-function \
	-std=c99 \
	-DWOLFSSL_USER_SETTINGS \
	-I. \
	-I$(WOLFSSL_ROOT)

# Benchmark parameters (override on command line if desired)
# e.g., make BENCH_PAYLOAD_SIZE=1024 ITERATIONS=100 CPU_FREQ_MHZ=50.0
BENCH_PAYLOAD_SIZE ?= 4096
ITERATIONS         ?= 50
CPU_FREQ_MHZ       ?= 50.0

CFLAGS += -DBENCH_PAYLOAD_SIZE=$(BENCH_PAYLOAD_SIZE) \
          -DITERATIONS=$(ITERATIONS) \
          -DCPU_FREQ_MHZ=$(CPU_FREQ_MHZ)

# Source files
APP_SRCS := main.c

# wolfCrypt source files required for SHA-2, SHA-3, and SHAKE
WOLFCRYPT_SRCS := \
	$(WOLFSSL_ROOT)/wolfcrypt/src/sha.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/sha256.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/sha512.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/sha3.c

# Optional BSP / startup sources (if provided by your baremetal CVA6 environment)
# BSP_SRCS := crt0.S syscalls.c
BSP_SRCS ?=

# Linker flags (add your custom linker script if needed: -Tlink.ld)
LDFLAGS ?=

BUILD_DIR := build
TARGET    := $(BUILD_DIR)/hash_bench.elf
DISASM    := $(BUILD_DIR)/hash_bench.dump
BIN       := $(BUILD_DIR)/hash_bench.bin

ALL_SRCS := $(APP_SRCS) $(WOLFCRYPT_SRCS) $(BSP_SRCS)

.PHONY: all elf bin dump clean help

all: elf dump bin

elf: $(TARGET)

$(TARGET): $(ALL_SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(ALL_SRCS) -o $@ $(LDFLAGS)

bin: $(BIN)

$(BIN): $(TARGET)
	$(OBJCOPY) -O binary $< $@

dump: $(DISASM)

$(DISASM): $(TARGET)
	$(OBJDUMP) -D -S $< > $@

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "Usage:"
	@echo "  make                      Build hash_bench for CVA6 using default settings"
	@echo "  make WOLFSSL_ROOT=<path>  Specify path to wolfssl repository"
	@echo "  make CC=gcc ARCH_FLAGS=   Build for host system (x86_64 testing)"
	@echo "  make clean                Clean build artifacts"