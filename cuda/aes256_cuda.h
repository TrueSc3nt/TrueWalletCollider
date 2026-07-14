#pragma once
#include <cstdint>
#include <cstddef>
#include <cuda_runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

/** One wallet blob: 48-byte AES-CBC ciphertext (3 blocks). */
struct TargetCipher {
  uint8_t c3[16];       /* last cipher block (offset 32) */
  uint8_t expected[16]; /* AES_dec(C3) must equal this (= C2 XOR 0x10*16) */
};

struct HitRecord {
  int      found;       /* 0/1 */
  int      target_idx;
  uint8_t  key[32];
};

enum CrackModeCuda {
  MODE_RANDOM = 0,
  MODE_SEQUENTIAL = 1,
  MODE_MIXED = 2  /* random base, then walk lower bytes */
};

struct LaunchConfig {
  int device;
  int blocks;
  int threads;
  uint64_t keys_per_launch;
  CrackModeCuda mode;
  uint64_t seq_base[4]; /* 256-bit big-endian words for sequential start */
  uint32_t mixed_span;  /* how many sequential steps after each random base */
  int streams;          /* concurrent CUDA streams (default 4) */
};

int  cuda_aes_init(int device);
void cuda_aes_shutdown();

int  cuda_aes_upload_targets(const TargetCipher* targets, int count);
int  cuda_aes_launch(const LaunchConfig* cfg, HitRecord* host_hit,
                     uint64_t* keys_done_out, uint64_t launch_id);

/** Suggest blocks/threads from device SM count (large grids). */
void cuda_aes_suggest_grid(int device, int* blocks_out, int* threads_out);

/** Host-side AES-256 single-block decrypt (for --try / selftest). */
void host_aes256_check_key(const uint8_t key[32], const TargetCipher* t,
                           int* match_out);

size_t cuda_estimate_keys_for_vram_mb(size_t mb);
size_t cuda_free_vram_bytes(int device);

#ifdef __cplusplus
}
#endif
