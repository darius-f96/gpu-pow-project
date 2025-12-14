NVCC      = nvcc
NVCCFLAGS = -O3 -lineinfo -std=c++17
CC        = gcc
CFLAGS    = -O3 -std=c11

.PHONY: all clean

all: sha1_nonce sha1_cpu

sha1_nonce: src/sha1_nonce.cu src/sha1_core.h
	$(NVCC) $(NVCCFLAGS) $< -o $@

sha1_cpu: src/sha1_cpu.c src/sha1_core.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f sha1_nonce sha1_cpu
