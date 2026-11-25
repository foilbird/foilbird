/* Basic CUDA driver-API initialisation (deviceQuery-like, no load): cuInit, driver version, devices, context + 1 MiB alloc.
   Uses dlopen so it needs neither the CUDA toolkit nor headers; libcuda.so.1 comes from the NVIDIA userspace in the image. */
#include <dlfcn.h>
#include <stdio.h>
#include <stddef.h>
typedef int CUresult; typedef int CUdevice; typedef void *CUcontext; typedef unsigned long long CUdeviceptr;
#define SYM(t, n, s) __typeof__(t) n = (__typeof__(t))dlsym(h, s); if (!n) { printf("CUDA-INIT missing %s\n", s); return 2; }
int main(void) {
  void *h = dlopen("libcuda.so.1", RTLD_NOW);
  if (!h) { printf("CUDA-INIT dlopen failed: %s\n", dlerror()); return 2; }
  SYM(CUresult (*)(unsigned), cuInit, "cuInit")
  SYM(CUresult (*)(int *), cuDriverGetVersion, "cuDriverGetVersion")
  SYM(CUresult (*)(int *), cuDeviceGetCount, "cuDeviceGetCount")
  SYM(CUresult (*)(CUdevice *, int), cuDeviceGet, "cuDeviceGet")
  SYM(CUresult (*)(char *, int, CUdevice), cuDeviceGetName, "cuDeviceGetName")
  SYM(CUresult (*)(size_t *, CUdevice), cuDeviceTotalMem, "cuDeviceTotalMem_v2")
  SYM(CUresult (*)(int *, int, CUdevice), cuDeviceGetAttribute, "cuDeviceGetAttribute")
  SYM(CUresult (*)(CUcontext *, unsigned, CUdevice), cuCtxCreate, "cuCtxCreate_v2")
  SYM(CUresult (*)(CUdeviceptr *, size_t), cuMemAlloc, "cuMemAlloc_v2")
  SYM(CUresult (*)(CUdeviceptr), cuMemFree, "cuMemFree_v2")
  SYM(CUresult (*)(CUcontext), cuCtxDestroy, "cuCtxDestroy_v2")
  int v = 0, n = 0;
  CUresult r = cuInit(0); cuDriverGetVersion(&v);
  printf("CUDA-INIT cuInit=%d driverVersion=%d.%d\n", r, v / 1000, (v % 1000) / 10);
  if (r) return 1;
  cuDeviceGetCount(&n); printf("CUDA-INIT devices=%d\n", n);
  for (int i = 0; i < n; i++) {
    CUdevice d; char name[128] = ""; size_t mem = 0; int ma = 0, mi = 0; CUcontext c; CUdeviceptr p;
    cuDeviceGet(&d, i); cuDeviceGetName(name, sizeof name, d); cuDeviceTotalMem(&mem, d);
    cuDeviceGetAttribute(&ma, 75, d); cuDeviceGetAttribute(&mi, 76, d);   /* COMPUTE_CAPABILITY_MAJOR/MINOR */
    CUresult rc = cuCtxCreate(&c, 0, d), ra = -1;
    if (!rc) { ra = cuMemAlloc(&p, 1 << 20); if (!ra) cuMemFree(p); cuCtxDestroy(c); }
    printf("CUDA-INIT dev%d name=%s mem=%zuMiB cc=%d.%d ctx=%d alloc1MiB=%d\n", i, name, mem >> 20, ma, mi, rc, ra);
  }
  return 0;
}
