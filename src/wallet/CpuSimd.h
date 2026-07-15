#pragma once
#include <string>

enum class CpuSimdTier {
  Scalar = 0,
  SSE2 = 1,
  AVX = 2,
  AVX2 = 3,
  AVX512 = 4,
};

struct CpuSimdInfo {
  bool sse2 = false;
  bool avx = false;
  bool avx2 = false;
  bool avx512f = false;
  CpuSimdTier tier = CpuSimdTier::Scalar;
  std::string label;       /* e.g. "AVX2" */
  std::string status_line; /* "CPU: AVX2 active (8 KDF workers)" */
  int recommended_workers = 1;
};

/** Runtime CPUID / XGETBV detection (Windows x64). Call once at startup. */
const CpuSimdInfo& cpu_simd_detect();

/** Re-query (usually unnecessary). */
CpuSimdInfo cpu_simd_probe();

const char* cpu_simd_tier_name(CpuSimdTier t);
