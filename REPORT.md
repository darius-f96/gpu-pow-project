# Performance Report

This report captures throughput and timing data for different CUDA launch
configurations. Fill in the hardware details and paste the measured runs in
the tables below. The template assumes the GPU search binary is built from
this repo.

## Hardware / software

- GPU: NVIDIA GeForce RTX 5070 Ti
- Driver: 591.74
- CUDA toolkit (nvcc --version): CUDA 12.9 (from nvcc in this environment)
- CPU: Unknown (not queried)
- OS: Ubuntu on WSL
- Power / clocks (if locked): 2542 MHz SM / 14201 MHz memory / 300 W (from nvidia-smi)

## Input parameters

- DATA (hex): 48656c6c6f20574f524c44 (baseline), 706C656173652067697665206D65206120676F6F64206772616465 (longer run)
- SUFFIX (hex, 1-2 bytes): ffff (baseline), 0000 (longer run attempt), BF0F, BF75 (longer run)
- Nonce length (bytes): 4 (baseline), 8, 16 (longer run attempts)

## Method

- Build command: `make`
- Benchmark command(s): `./scripts/benchmark.sh`
- Notes on run duration / warmup: each run found a nonce quickly; throughput likely inflated without bench mode

## Results

| Blocks | Threads | Nonces/thread | Batch size | Max batches | Time (s) | Throughput (MH/s) | Notes |
| ------ | ------- | ------------- | ---------- | ----------- | -------- | ----------------- | ----- |
| 256    | 256     | 8             | 524,288    | 5000        | 0.002823 | 50.70             | DATA=48656c6c6f20574f524c44; SUFFIX=BF0F; NONCE_LEN=8; nonce after 143,097 candidates |
| 512    | 256     | 8             | 1,048,576  | 5000        | 0.002763 | 51.78             | DATA=48656c6c6f20574f524c44; SUFFIX=BF0F; NONCE_LEN=8; nonce after 143,097 candidates |
| 512    | 256     | 16            | 2,097,152  | 5000        | 0.003268 | 114.55            | DATA=48656c6c6f20574f524c44; SUFFIX=BF0F; NONCE_LEN=8; nonce after 374,385 candidates |
| 1024   | 256     | 16            | 4,194,304  | 5000        | 0.002766 | 135.36            | DATA=48656c6c6f20574f524c44; SUFFIX=BF0F; NONCE_LEN=8; nonce after 374,385 candidates |
| 1024   | 512     | 8             | 4,194,304  | 5000        | 0.002684 | 53.31             | DATA=48656c6c6f20574f524c44; SUFFIX=BF0F; NONCE_LEN=8; nonce after 143,097 candidates |
| 256    | 256     | 8             | 524,288    | 10000       | 0.003190 | 46.83             | DATA=706C656173652067697665206D65206120676F6F64206772616465; SUFFIX=BF75; NONCE_LEN=16; nonce after 149,353 candidates |
| 512    | 256     | 8             | 1,048,576  | 10000       | 0.002700 | 55.32             | DATA=706C656173652067697665206D65206120676F6F64206772616465; SUFFIX=BF75; NONCE_LEN=16; nonce after 149,353 candidates |
| 512    | 256     | 16            | 2,097,152  | 10000       | 0.002468 | 258.73            | DATA=706C656173652067697665206D65206120676F6F64206772616465; SUFFIX=BF75; NONCE_LEN=16; nonce after 638,545 candidates |
| 1024   | 256     | 16            | 4,194,304  | 10000       | 0.002756 | 231.66            | DATA=706C656173652067697665206D65206120676F6F64206772616465; SUFFIX=BF75; NONCE_LEN=16; nonce after 638,545 candidates |
| 1024   | 512     | 8             | 4,194,304  | 10000       | 0.002692 | 55.48             | DATA=706C656173652067697665206D65206120676F6F64206772616465; SUFFIX=BF75; NONCE_LEN=16; nonce after 149,353 candidates |
| 256    | 256     | 8             | 524,288    | 200         | 0.002613 | 52.57             | DATA=48656c6c6f20574f524c44; SUFFIX=ffff; NONCE_LEN=4; nonce after 137,351 candidates |
| 512    | 256     | 8             | 1,048,576  | 200         | 0.002567 | 53.52             | DATA=48656c6c6f20574f524c44; SUFFIX=ffff; NONCE_LEN=4; nonce after 137,351 candidates |
| 512    | 256     | 16            | 2,097,152  | 200         | 0.002501 | 271.67            | DATA=48656c6c6f20574f524c44; SUFFIX=ffff; NONCE_LEN=4; nonce after 679,505 candidates |
| 1024   | 256     | 16            | 4,194,304  | 200         | 0.002841 | 239.19            | DATA=48656c6c6f20574f524c44; SUFFIX=ffff; NONCE_LEN=4; nonce after 679,505 candidates |
| 1024   | 512     | 8             | 4,194,304  | 200         | 0.002917 | 88.93             | DATA=48656c6c6f20574f524c44; SUFFIX=ffff; NONCE_LEN=4; nonce after 259,405 candidates |

## Bench results (steady-state)

Input: DATA=48656c6c6f20574f524c44, SUFFIX=ffff, NONCE_LEN=4, MAX_BATCHES=2000, TRIALS=5, `--bench`.

| Blocks | Threads | Nonces/thread | Batch size | Avg MH/s | Min MH/s | Max MH/s | Matches observed | Notes |
| ------ | ------- | ------------- | ---------- | -------- | ------- | ------- | --------------- | ----- |
| 256    | 256     | 8             | 524,288    | 3044.55  | 3023.95 | 3056.73 | 15961           | Bench complete lines from 5 trials |
| 512    | 256     | 8             | 1,048,576  | 3659.03  | 3648.37 | 3678.50 | 31844           | Bench complete lines from 5 trials |
| 512    | 256     | 16            | 2,097,152  | 3879.80  | 3708.70 | 3960.22 | 64129           | Bench complete lines from 5 trials |
| 1024   | 256     | 16            | 4,194,304  | 4084.21  | 4043.42 | 4122.51 | 128196          | Bench complete lines from 5 trials |

## Bench results (data-global)

Input: DATA=48656c6c6f20574f524c44, SUFFIX=ffff, NONCE_LEN=4, MAX_BATCHES=2000, TRIALS=4, `--bench --data-global`.

| Blocks | Threads | Nonces/thread | Batch size | Avg MH/s | Min MH/s | Max MH/s | Matches observed | Notes |
| ------ | ------- | ------------- | ---------- | -------- | ------- | ------- | --------------- | ----- |
| 256    | 256     | 8             | 524,288    | 3032.27  | 2885.05 | 3139.14 | 15961           | Bench complete lines from 4 trials |
| 512    | 256     | 8             | 1,048,576  | 3531.93  | 3493.89 | 3570.41 | 31844           | Bench complete lines from 4 trials |
| 512    | 256     | 16            | 2,097,152  | 3864.76  | 3803.39 | 3903.77 | 64129           | Bench complete lines from 4 trials |
| 1024   | 256     | 16            | 4,194,304  | 4187.73  | 4171.73 | 4208.23 | 128196          | Bench complete lines from 4 trials |
| 1024   | 512     | 8             | 4,194,304  | 3846.83  | 3798.21 | 3880.36 | 128196          | Bench complete lines from 4 trials |

## Bench results (data-global, longer nonce)

Input: DATA=706C656173652067697665206D65206120676F6F64206772616465, SUFFIX=ABF7, NONCE_LEN=16, MAX_BATCHES=2000, TRIALS=4, `--bench --data-global`.

| Blocks | Threads | Nonces/thread | Batch size | Avg MH/s | Min MH/s | Max MH/s | Matches observed | Notes |
| ------ | ------- | ------------- | ---------- | -------- | ------- | ------- | --------------- | ----- |
| 256    | 256     | 8             | 524,288    | 2609.42  | 2553.13 | 2641.44 | 16090           | Bench complete lines from 4 trials |
| 512    | 256     | 8             | 1,048,576  | 3031.58  | 2979.01 | 3088.19 | 32006           | Bench complete lines from 4 trials |
| 512    | 256     | 16            | 2,097,152  | 3358.35  | 3310.50 | 3412.92 | 63797           | Bench complete lines from 4 trials |
| 1024   | 256     | 16            | 4,194,304  | 3682.17  | 3670.65 | 3699.61 | 127647          | Bench complete lines from 4 trials |
| 1024   | 512     | 8             | 4,194,304  | 3538.42  | 3497.60 | 3573.71 | 127647          | Bench complete lines from 4 trials |

## Bench results (constant, longer nonce)

Input: DATA=706C656173652067697665206D65206120676F6F64206772616465, SUFFIX=ABF7, NONCE_LEN=16, MAX_BATCHES=2000, TRIALS=4, `--bench`.

| Blocks | Threads | Nonces/thread | Batch size | Avg MH/s | Min MH/s | Max MH/s | Matches observed | Notes |
| ------ | ------- | ------------- | ---------- | -------- | ------- | ------- | --------------- | ----- |
| 256    | 256     | 8             | 524,288    | 2717.17  | 2589.88 | 2806.66 | 16090           | Bench complete lines from 4 trials |
| 512    | 256     | 8             | 1,048,576  | 3154.85  | 3087.09 | 3287.31 | 32006           | Bench complete lines from 4 trials |
| 512    | 256     | 16            | 2,097,152  | 3453.13  | 3352.38 | 3535.48 | 63797           | Bench complete lines from 4 trials |
| 1024   | 256     | 16            | 4,194,304  | 3695.86  | 3671.75 | 3734.72 | 127647          | Bench complete lines from 4 trials |
| 1024   | 512     | 8             | 4,194,304  | 3474.38  | 3417.51 | 3531.73 | 127647          | Bench complete lines from 4 trials |

## Bench results (constant, nonce_len=8)

Input: DATA=706C656173652067697665206D65206120676F6F64206772616465, SUFFIX=FF23, NONCE_LEN=8, MAX_BATCHES=2000, TRIALS=4, `--bench`.

| Blocks | Threads | Nonces/thread | Batch size | Avg MH/s | Min MH/s | Max MH/s | Matches observed | Notes |
| ------ | ------- | ------------- | ---------- | -------- | ------- | ------- | --------------- | ----- |
| 256    | 256     | 8             | 524,288    | 3092.89  | 2963.89 | 3207.71 | 16179           | Bench complete lines from 4 trials |
| 512    | 256     | 8             | 1,048,576  | 3621.13  | 3567.28 | 3661.49 | 32079           | Bench complete lines from 4 trials |
| 512    | 256     | 16            | 2,097,152  | 3888.93  | 3856.30 | 3960.93 | 64030           | Bench complete lines from 4 trials |
| 1024   | 256     | 16            | 4,194,304  | 4126.72  | 4051.69 | 4154.37 | 128496          | Bench complete lines from 4 trials |
| 1024   | 512     | 8             | 4,194,304  | 3778.15  | 3737.22 | 3819.00 | 128496          | Bench complete lines from 4 trials |

## Bench results (constant, nonce_len=8, w[16] schedule)

Input: DATA=706C656173652067697665206D65206120676F6F64206772616465, SUFFIX=FF23, NONCE_LEN=8, MAX_BATCHES=2000, TRIALS=4, `--bench`.

| Blocks | Threads | Nonces/thread | Batch size | Avg MH/s | Min MH/s | Max MH/s | Matches observed | Notes |
| ------ | ------- | ------------- | ---------- | -------- | ------- | ------- | --------------- | ----- |
| 256    | 256     | 8             | 524,288    | 2951.83  | 2821.93 | 3090.68 | 16179           | Bench complete lines from 4 trials |
| 512    | 256     | 8             | 1,048,576  | 3606.89  | 3544.37 | 3678.53 | 32079           | Bench complete lines from 4 trials |
| 512    | 256     | 16            | 2,097,152  | 3919.42  | 3816.38 | 4039.84 | 64030           | Bench complete lines from 4 trials |
| 1024   | 256     | 16            | 4,194,304  | 4144.81  | 4107.03 | 4227.95 | 128496          | Bench complete lines from 4 trials |
| 1024   | 512     | 8             | 4,194,304  | 3876.91  | 3826.64 | 3921.25 | 128496          | Bench complete lines from 4 trials |

## Bench results (data-global, nonce_len=8)

Input: DATA=706C656173652067697665206D65206120676F6F64206772616465, SUFFIX=FF23, NONCE_LEN=8, MAX_BATCHES=2000, TRIALS=4, `--bench --data-global`.

| Blocks | Threads | Nonces/thread | Batch size | Avg MH/s | Min MH/s | Max MH/s | Matches observed | Notes |
| ------ | ------- | ------------- | ---------- | -------- | ------- | ------- | --------------- | ----- |
| 256    | 256     | 8             | 524,288    | 2727.54  | 2668.80 | 2820.47 | 16179           | Bench complete lines from 4 trials |
| 512    | 256     | 8             | 1,048,576  | 3401.93  | 3347.40 | 3437.51 | 32079           | Bench complete lines from 4 trials |
| 512    | 256     | 16            | 2,097,152  | 3825.97  | 3753.00 | 3997.44 | 64030           | Bench complete lines from 4 trials |
| 1024   | 256     | 16            | 4,194,304  | 4094.34  | 4060.43 | 4130.35 | 128496          | Bench complete lines from 4 trials |
| 1024   | 512     | 8             | 4,194,304  | 3805.68  | 3763.57 | 3828.75 | 128496          | Example trial: 8388608000 candidates in 2.197347 s (3817.61 MH/s); Bench complete lines from 4 trials |

## Bench results (data-global, nonce_len=8, w[16] schedule)

Input: DATA=706C656173652067697665206D65206120676F6F64206772616465, SUFFIX=FF23, NONCE_LEN=8, MAX_BATCHES=2000, TRIALS=4, `--bench --data-global`.

| Blocks | Threads | Nonces/thread | Batch size | Avg MH/s | Min MH/s | Max MH/s | Matches observed | Notes |
| ------ | ------- | ------------- | ---------- | -------- | ------- | ------- | --------------- | ----- |
| 256    | 256     | 8             | 524,288    | 2938.13  | 2656.37 | 3170.83 | 16179           | Bench complete lines from 4 trials |
| 512    | 256     | 8             | 1,048,576  | 3396.49  | 3325.59 | 3476.93 | 32079           | Bench complete lines from 4 trials |
| 512    | 256     | 16            | 2,097,152  | 3723.38  | 3590.66 | 3921.36 | 64030           | Bench complete lines from 4 trials |
| 1024   | 256     | 16            | 4,194,304  | 4069.66  | 4027.63 | 4102.80 | 128496          | Bench complete lines from 4 trials |
| 1024   | 512     | 8             | 4,194,304  | 3813.36  | 3783.93 | 3846.55 | 128496          | Example trial: 8388608000 candidates in 2.202409 s (3808.83 MH/s); Bench complete lines from 4 trials |


## Observations

- Steady-state throughput climbed with larger batches and higher `nonces/thread` up to 16, peaking around ~4.15 GH/s (4154 MH/s) for 1024×256×16.
- Increasing nonces/thread reduces launch overhead per hash, but too large values may reduce responsiveness (and on Windows can risk long kernel execution).
- Constant vs global memory for DATA shows only small differences (typically a few percent) for this data size and nonce length.
- Increasing threads per block to 512 sometimes reduced throughput, suggesting occupancy or register-pressure tradeoffs.
- Bench measurements use CUDA event timing; each trial runs a fixed batch count.

## Best config (steady-state)

- Best observed: 1024 blocks × 256 threads × 16 nonces/thread, ~4.15 GH/s (4154 MH/s)
- Input: DATA=706C656173652067697665206D65206120676F6F64206772616465, SUFFIX=FF23, NONCE_LEN=8
- Memory mode: constant

## Next experiments

- Use `--bench` or `--bench-batches` to run fixed batches and avoid early-stop bias.
- Sweep `nonce-len` and larger `per-thread` values to see how kernel occupancy changes.
