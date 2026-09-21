CC ?= gcc

CFLAGS := \
	-Wall \
	-Wextra \
	-Werror=unused-result \
	-Wpedantic \
	-Werror \
	-Wmissing-prototypes \
	-Wshadow \
	-Wpointer-arith \
	-Wredundant-decls \
	-Wconversion \
	-Wsign-conversion \
	-Wno-long-long \
	-Wno-unknown-pragmas \
	-Wno-unused-command-line-argument \
	-O3 \
	-fomit-frame-pointer \
	-std=c99 \
	-pedantic \
	-MMD

# ML-DSA source files
MLD_SOURCE := $(wildcard \
	mldsa-native/examples/basic/mldsa_native/src/*.c \
	mldsa-native/examples/basic/mldsa_native/src/**/*.c \
	mldsa-native/examples/basic/mldsa_native/src/**/**/*.c \
	mldsa-native/examples/basic/mldsa_native/src/**/**/**/*.c)

# ML-DSA headers
INC := -Imldsa-native/examples/basic/mldsa_native

# Testing-only RNG
RNG_SOURCE := $(wildcard \
	mldsa-native/examples/basic/test_only_rng/*.c)

# Your application
APP_SOURCE := main.c

ALL_SOURCE := $(MLD_SOURCE) $(RNG_SOURCE) $(APP_SOURCE)

BUILD_DIR := build
BIN := mldsa_app

CFLAGS += -DMLD_CONFIG_NAMESPACE_PREFIX=mldsa

# Parameter set
PARAMETER_SET ?= 65

TARGET := $(BUILD_DIR)/$(BIN)$(PARAMETER_SET)

.PHONY: all build run clean

.DEFAULT_GOAL := all

all: build

build: $(TARGET)

$(TARGET): $(ALL_SOURCE)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) \
		-DMLD_CONFIG_PARAMETER_SET=$(PARAMETER_SET) \
		$(INC) \
		$^ -o $@ -lcrypto

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(BUILD_DIR)