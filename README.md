# gpu-pow-project

CUDA playground for experimenting with SHA1-based proof-of-work style nonce
searches. The project ships both a GPU kernel (`sha1_nonce`) and a reference
CPU driver (`sha1_cpu`) that share the same SHA1 implementation.

## Build

```
make          # builds sha1_nonce (CUDA) and sha1_cpu (CPU reference)
make clean    # removes the binaries
```

## GPU nonce search (`sha1_nonce`)

```
./sha1_nonce --data <hex> --suffix <hex> [options]
```

* `--data` – base payload in hexadecimal (whitespace / `0x` prefixes ignored)
* `--suffix` – 1 or 2-byte hexadecimal suffix the SHA1 digest must end with
* `--nonce-len` – nonce size in bytes (1–8, default 4)
* `--blocks`, `--threads`, `--per-thread` – CUDA launch configuration
* `--start` – starting nonce counter (interpreted little-endian)
* `--max-batches` – stop after N kernel batches (0 = unlimited)
* `--report` – print a throughput report every N batches

The kernel keeps the base data and suffix in constant memory, generates nonce
candidates directly on the device, and evaluates
`SHA1(DATA || nonce)` until a digest is produced that ends with the requested
suffix. Once a candidate is found the host prints the nonce bytes (little-
endian) and the resulting digest so you can confirm the match or feed it back
into other tooling.

Example:

```
./sha1_nonce --data 48656c6c6f20574f524c44 --suffix abcd --blocks 512 --threads 256 --per-thread 16
```

Tweak block size, per-thread workload, data placement, etc. to explore how far
you can push your GPU.

## CPU helper (`sha1_cpu`)

```
./sha1_cpu --data <hex> [--nonce <hex>] [--suffix <hex>] [options]
```

If `--suffix` is supplied the CPU version brute-forces nonces of length
`--nonce-len` (default 4) and reports when it finds a match. Otherwise it
simply prints `SHA1(DATA || nonce)` for the provided operands. Use it to
cross-check GPU results or to experiment on hosts without CUDA.
