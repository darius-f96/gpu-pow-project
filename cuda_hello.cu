#include <cstdio>
#include <cuda_runtime.h>

__global__ void hello() {
  printf("Hello from GPU: block=%d thread=%d\n", blockIdx.x, threadIdx.x);
}

int main() {
  hello<<<1, 4>>>();
  cudaError_t err = cudaDeviceSynchronize();
  if (err != cudaSuccess) {
    printf("cudaDeviceSynchronize error: %s\n", cudaGetErrorString(err));
    return 1;
  }
  return 0;
}
