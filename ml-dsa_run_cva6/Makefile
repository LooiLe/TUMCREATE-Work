# ==============================================================================
# Makefile for CVA6 Baremetal wolfSSL Hash Algorithm Benchmark
# ==============================================================================

CROSS ?= riscv64-unknown-elf-

CC := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump
SIZE := $(CROSS)size

TARGET := hash_bench

ARCH := rv64imac
ABI := lp64

WOLFSSL_ROOT ?= wolfssl

BENCH_PAYLOAD_SIZE ?= 4096
ITERATIONS ?= 1
WARMUP_ITERATIONS ?= 0
CPU_FREQ_MHZ ?= 50.0
USE_MCYCLE ?= 1

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
else ifeq ($(ALGO),SHA2_512_224)
    ALGO_ID := 4
else ifeq ($(ALGO),SHA2_512_256)
    ALGO_ID := 5
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
endif

APP_SRCS := \
	main.c \
	baremetal_lib.c

WOLFCRYPT_SRCS := \
	$(WOLFSSL_ROOT)/wolfcrypt/src/wc_port.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/memory.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/sha.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/sha256.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/sha512.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/sha3.c
	
WOLFCRYPT_ASM_SRCS := \
	$(WOLFSSL_ROOT)/wolfcrypt/src/port/riscv64/riscv-64-sha256-asm.S \
	$(WOLFSSL_ROOT)/wolfcrypt/src/port/riscv64/riscv-64-sha512-asm.S \
	$(WOLFSSL_ROOT)/wolfcrypt/src/port/riscv64/riscv-64-sha3-asm.S
	
ASMS := startup.S $(WOLFCRYPT_ASM_SRCS)

SRCS := $(APP_SRCS) $(WOLFCRYPT_SRCS)

OBJS := $(SRCS:.c=.o) $(ASMS:.S=.o)

CFLAGS := \
	-march=$(ARCH) \
	-mabi=$(ABI) \
	-mcmodel=medany \
	-O3 \
	-g3 \
	-std=c99 \
	-ffreestanding \
	-fno-builtin \
	-fno-common \
	-ffunction-sections \
	-fdata-sections \
	-Wall \
	-Wextra \
	-Wno-unused-function \
	-DWOLFSSL_USER_SETTINGS \
	-DBENCH_PAYLOAD_SIZE=$(BENCH_PAYLOAD_SIZE) \
	-DITERATIONS=$(ITERATIONS) \
	-DWARMUP_ITERATIONS=$(WARMUP_ITERATIONS) \
	-DCPU_FREQ_MHZ=$(CPU_FREQ_MHZ) \
	-DUSE_MCYCLE=$(USE_MCYCLE) \
	-I. \
	-I$(WOLFSSL_ROOT) \
	-I$(WOLFSSL_ROOT)/wolfcrypt \
	-I/usr/include/newlib

ifneq ($(strip $(ALGO_ID)),)
CFLAGS += -DTARGET_ALGO_ID=$(ALGO_ID)
endif


ASFLAGS := \
 -march=$(ARCH) \
 -mabi=$(ABI) \
 -mcmodel=medany \
 -g3 \
 -I. \
 -I$(WOLFSSL_ROOT) \
 -I$(WOLFSSL_ROOT)/wolfcrypt \
 -DWOLFSSL_USER_SETTINGS


LDFLAGS := \
	-T link.ld \
	-nostdlib \
	-nostartfiles \
	-Wl,--gc-sections \
	-Wl,-Map=$(TARGET).map

.PHONY: all clean check-sources list_algos help

all: check-sources $(TARGET).elf $(TARGET).dump $(TARGET).bin

check-sources:
	@test -f main.c || (echo "ERROR: main.c missing" && false)
	@test -f startup.S || (echo "ERROR: startup.S missing" && false)
	@test -f baremetal_lib.c || (echo "ERROR: baremetal_lib.c missing" && false)
	@test -f link.ld || (echo "ERROR: link.ld missing" && false)
	@test -f $(WOLFSSL_ROOT)/wolfcrypt/src/sha.c || (echo "ERROR: wolfSSL sources missing" && false)
	@test -f $(WOLFSSL_ROOT)/wolfcrypt/src/sha256.c || (echo "ERROR: wolfSSL SHA-256 source missing" && false)
	@test -f $(WOLFSSL_ROOT)/wolfcrypt/src/sha512.c || (echo "ERROR: wolfSSL SHA-512 source missing" && false)
	@test -f $(WOLFSSL_ROOT)/wolfcrypt/src/sha3.c || (echo "ERROR: wolfSSL SHA-3 source missing" && false)

$(TARGET).elf: $(OBJS) link.ld
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@
	$(SIZE) $@

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

$(TARGET).dump: $(TARGET).elf
	$(OBJDUMP) -d -S $< > $@

%.o: %.c
	@echo "CC $<"
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	@echo "AS $<"
	$(CC) $(ASFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)
	rm -f $(TARGET).elf
	rm -f $(TARGET).bin
	rm -f $(TARGET).dump
	rm -f $(TARGET).map

list_algos:
	@echo "Available Algorithms for ALGO= or ALGO_ID=:"
	@echo "  ID  0 : SHA2-224        (ALGO=SHA2_224)"
	@echo "  ID  1 : SHA2-256        (ALGO=SHA2_256)"
	@echo "  ID  2 : SHA2-384        (ALGO=SHA2_384)"
	@echo "  ID  3 : SHA2-512        (ALGO=SHA2_512)"
	@echo "  ID  4 : SHA2-512/224    (ALGO=SHA2_512_224)"
	@echo "  ID  5 : SHA2-512/256    (ALGO=SHA2_512_256)"
	@echo "  ID  6 : SHA3-224        (ALGO=SHA3_224)"
	@echo "  ID  7 : SHA3-256        (ALGO=SHA3_256)"
	@echo "  ID  8 : SHA3-384        (ALGO=SHA3_384)"
	@echo "  ID  9 : SHA3-512        (ALGO=SHA3_512)"
	@echo "  ID 10 : SHAKE-128       (ALGO=SHAKE_128)"
	@echo "  ID 11 : SHAKE-256       (ALGO=SHAKE_256)"

help:
	@echo "Usage:"
	@echo "  make                                Build all algorithms (default: 1 iteration)"
	@echo "  make ALGO=SHA2_256                  Build only SHA2-256 (or ALGO_ID=1)"
	@echo "  make ALGO=SHA3_256 ITERATIONS=1     Build only SHA3-256 for cold RAM test"
	@echo "  make list_algos                     Show all supported algorithm names & IDs"
	@echo "  make clean                          Clean build artifacts"