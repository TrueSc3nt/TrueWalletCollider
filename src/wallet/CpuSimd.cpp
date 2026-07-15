#include "CpuSimd.h"

#include <algorithm>
#include <cstdio>
#include <thread>

#ifdef _WIN32
#include <intrin.h>
#include <windows.h>
#endif

static CpuSimdInfo g_simd;
static bool g_simd_ready = false;

const char* cpu_simd_tier_name(CpuSimdTier t) {
  switch (t) {
    case CpuSimdTier::AVX512: return "AVX-512";
    case CpuSimdTier::AVX2: return "AVX2";
    case CpuSimdTier::AVX: return "AVX";
    case CpuSimdTier::SSE2: return "SSE2";
    default: return "Scalar";
  }
}

CpuSimdInfo cpu_simd_probe() {
  CpuSimdInfo info;
#ifdef _WIN32
  int cpuInfo[4] = {};
  __cpuid(cpuInfo, 0);
  int nIds = cpuInfo[0];
  int info1[4] = {};
  if (nIds >= 1) __cpuidex(info1, 1, 0);
  int info7[4] = {};
  if (nIds >= 7) __cpuidex(info7, 7, 0);

  info.sse2 = (info1[3] & (1 << 26)) != 0;
  bool osxsave = (info1[2] & (1 << 27)) != 0;
  bool avx_hw = (info1[2] & (1 << 28)) != 0;
  bool avx2_hw = (info7[1] & (1 << 5)) != 0;
  bool avx512_hw = (info7[1] & (1 << 16)) != 0; /* AVX512F */

  unsigned long long xcr0 = 0;
  if (osxsave) {
    xcr0 = _xgetbv(0);
  }
  bool xmm_ymm = (xcr0 & 0x6) == 0x6;
  bool zmm = (xcr0 & 0xE0) == 0xE0;

  info.avx = avx_hw && osxsave && xmm_ymm;
  info.avx2 = avx2_hw && info.avx;
  info.avx512f = avx512_hw && info.avx2 && zmm;

  if (info.avx512f)
    info.tier = CpuSimdTier::AVX512;
  else if (info.avx2)
    info.tier = CpuSimdTier::AVX2;
  else if (info.avx)
    info.tier = CpuSimdTier::AVX;
  else if (info.sse2)
    info.tier = CpuSimdTier::SSE2;
  else
    info.tier = CpuSimdTier::Scalar;
#else
  info.sse2 = true;
  info.tier = CpuSimdTier::SSE2;
#endif

  info.label = cpu_simd_tier_name(info.tier);
  unsigned hw = std::thread::hardware_concurrency();
  if (hw == 0) hw = 2;
  /* Scale workers by SIMD tier — SHA-512 KDF itself is scalar; batching uses threads. */
  int base = (int)hw;
  switch (info.tier) {
    case CpuSimdTier::AVX512: info.recommended_workers = (std::min)(base, 32); break;
    case CpuSimdTier::AVX2: info.recommended_workers = (std::min)(base, 16); break;
    case CpuSimdTier::AVX: info.recommended_workers = (std::min)(base, 8); break;
    case CpuSimdTier::SSE2: info.recommended_workers = (std::min)(base, 4); break;
    default: info.recommended_workers = 1; break;
  }
  char buf[128];
  std::snprintf(buf, sizeof(buf), "CPU: %s active (%d KDF workers)", info.label.c_str(),
                info.recommended_workers);
  info.status_line = buf;
  return info;
}

const CpuSimdInfo& cpu_simd_detect() {
  if (!g_simd_ready) {
    g_simd = cpu_simd_probe();
    g_simd_ready = true;
  }
  return g_simd;
}
