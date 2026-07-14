/*
 * CUDA AES-256 decrypt for bitcoin wallet.dat mkey/ckey padding check.
 * Matches crackBTCwallet (AlbertoBSD, MIT): decrypt last CBC block only;
 * compare to expected = C2 XOR PKCS#7 padding (0x10 x 16).
 *
 * Throughput: multi-stream launches, large -g grids, aggressive -M auto
 * keys/launch. AES uses proven byte path.
 */
#include "aes256_cuda.h"
#include "ctaes.h"

#include <cstdio>
#include <cstring>
#include <vector>

#define CUDA_OK(call)                                                          \
  do {                                                                         \
    cudaError_t _e = (call);                                                   \
    if (_e != cudaSuccess) {                                                   \
      fprintf(stderr, "CUDA %s:%d %s\n", __FILE__, __LINE__,                   \
              cudaGetErrorString(_e));                                         \
      return -1;                                                               \
    }                                                                          \
  } while (0)

__constant__ uint8_t d_sbox[256];
__constant__ uint8_t d_inv_sbox[256];
__constant__ uint8_t d_rcon[11];
__constant__ TargetCipher d_targets[64];
__constant__ int d_ntargets;
__constant__ uint64_t d_seq_base[4];

static const uint8_t h_sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t h_inv_sbox[256] = {
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t h_rcon[11] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

__device__ __forceinline__ uint8_t xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

__device__ __forceinline__ uint8_t mul(uint8_t x, uint8_t y) {
  uint8_t r = 0;
  while (y) {
    if (y & 1) r ^= x;
    x = xtime(x);
    y >>= 1;
  }
  return r;
}

__device__ void aes256_key_expansion(const uint8_t key[32], uint8_t rk[240]) {
  uint8_t temp[4];
  int i = 0;
  for (; i < 32; ++i) rk[i] = key[i];
  int bytes = 32;
  int rconi = 1;
  while (bytes < 240) {
    for (int j = 0; j < 4; ++j) temp[j] = rk[bytes - 4 + j];
    if (bytes % 32 == 0) {
      uint8_t t = temp[0];
      temp[0] = (uint8_t)(d_sbox[temp[1]] ^ d_rcon[rconi++]);
      temp[1] = d_sbox[temp[2]];
      temp[2] = d_sbox[temp[3]];
      temp[3] = d_sbox[t];
    } else if (bytes % 32 == 16) {
      temp[0] = d_sbox[temp[0]];
      temp[1] = d_sbox[temp[1]];
      temp[2] = d_sbox[temp[2]];
      temp[3] = d_sbox[temp[3]];
    }
    for (int j = 0; j < 4; ++j) {
      rk[bytes] = (uint8_t)(rk[bytes - 32] ^ temp[j]);
      ++bytes;
    }
  }
}

__device__ void aes256_ecb_decrypt(const uint8_t key[32], const uint8_t in[16],
                                   uint8_t out[16]) {
  uint8_t rk[240];
  aes256_key_expansion(key, rk);

  uint8_t s[16];
  for (int i = 0; i < 16; ++i) s[i] = (uint8_t)(in[i] ^ rk[14 * 16 + i]);

  for (int round = 13; round >= 1; --round) {
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;

    for (int i = 0; i < 16; ++i) s[i] = d_inv_sbox[s[i]];
    for (int i = 0; i < 16; ++i) s[i] ^= rk[round * 16 + i];

    for (int c = 0; c < 4; ++c) {
      uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2],
              a3 = s[4 * c + 3];
      s[4 * c] =
          (uint8_t)(mul(a0, 0x0e) ^ mul(a1, 0x0b) ^ mul(a2, 0x0d) ^ mul(a3, 0x09));
      s[4 * c + 1] =
          (uint8_t)(mul(a0, 0x09) ^ mul(a1, 0x0e) ^ mul(a2, 0x0b) ^ mul(a3, 0x0d));
      s[4 * c + 2] =
          (uint8_t)(mul(a0, 0x0d) ^ mul(a1, 0x09) ^ mul(a2, 0x0e) ^ mul(a3, 0x0b));
      s[4 * c + 3] =
          (uint8_t)(mul(a0, 0x0b) ^ mul(a1, 0x0d) ^ mul(a2, 0x09) ^ mul(a3, 0x0e));
    }
  }

  {
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
  }
  for (int i = 0; i < 16; ++i) s[i] = d_inv_sbox[s[i]];
  for (int i = 0; i < 16; ++i) out[i] = (uint8_t)(s[i] ^ rk[i]);
}

__device__ __forceinline__ void u256_add_u64(uint8_t key[32], const uint64_t base[4],
                                             uint64_t idx) {
  uint64_t w[4] = {base[0], base[1], base[2], base[3]};
  uint64_t carry = idx;
  for (int i = 3; i >= 0; --i) {
    uint64_t sum = w[i] + carry;
    carry = (sum < w[i]) ? 1ull : 0ull;
    w[i] = sum;
  }
  for (int i = 0; i < 4; ++i) {
    uint64_t v = w[i];
    key[i * 8 + 0] = (uint8_t)(v >> 56);
    key[i * 8 + 1] = (uint8_t)(v >> 48);
    key[i * 8 + 2] = (uint8_t)(v >> 40);
    key[i * 8 + 3] = (uint8_t)(v >> 32);
    key[i * 8 + 4] = (uint8_t)(v >> 24);
    key[i * 8 + 5] = (uint8_t)(v >> 16);
    key[i * 8 + 6] = (uint8_t)(v >> 8);
    key[i * 8 + 7] = (uint8_t)(v);
  }
}

__device__ __forceinline__ uint64_t xorshift64(uint64_t& s) {
  s ^= s << 13;
  s ^= s >> 7;
  s ^= s << 17;
  return s;
}

__device__ __forceinline__ int check_targets(const uint8_t key[32], HitRecord* hit) {
  for (int t = 0; t < d_ntargets; ++t) {
    uint8_t plain[16];
    aes256_ecb_decrypt(key, d_targets[t].c3, plain);
    int ok = 1;
#pragma unroll
    for (int b = 0; b < 16; ++b) {
      if (plain[b] != d_targets[t].expected[b]) {
        ok = 0;
        break;
      }
    }
    if (ok) {
      if (atomicCAS(&hit->found, 0, 1) == 0) {
        hit->target_idx = t;
#pragma unroll
        for (int b = 0; b < 32; ++b) hit->key[b] = key[b];
      }
      return 1;
    }
  }
  return 0;
}

__global__ void crack_kernel_seq(uint64_t start_offset, uint64_t nkeys,
                                 HitRecord* hit) {
  uint64_t tid = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
  for (uint64_t i = tid; i < nkeys; i += stride) {
    if (*(volatile int*)&hit->found) return;
    uint8_t key[32];
    u256_add_u64(key, d_seq_base, start_offset + i);
    if (check_targets(key, hit)) return;
  }
}

__global__ void crack_kernel_random(uint64_t seed, uint64_t nkeys, HitRecord* hit) {
  uint64_t tid = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
  for (uint64_t i = tid; i < nkeys; i += stride) {
    if (*(volatile int*)&hit->found) return;
    uint64_t s = seed ^ (0x9e3779b97f4a7c15ULL * (i + 1));
    uint8_t key[32];
#pragma unroll
    for (int w = 0; w < 4; ++w) {
      uint64_t v = xorshift64(s);
      key[w * 8 + 0] = (uint8_t)(v >> 56);
      key[w * 8 + 1] = (uint8_t)(v >> 48);
      key[w * 8 + 2] = (uint8_t)(v >> 40);
      key[w * 8 + 3] = (uint8_t)(v >> 32);
      key[w * 8 + 4] = (uint8_t)(v >> 24);
      key[w * 8 + 5] = (uint8_t)(v >> 16);
      key[w * 8 + 6] = (uint8_t)(v >> 8);
      key[w * 8 + 7] = (uint8_t)(v);
    }
    if (check_targets(key, hit)) return;
  }
}

__global__ void crack_kernel_mixed(uint64_t seed, uint64_t nkeys, uint32_t span,
                                   HitRecord* hit) {
  uint64_t tid = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
  uint32_t steps = span ? span : 256;
  for (uint64_t i = tid; i < nkeys; i += stride) {
    if (*(volatile int*)&hit->found) return;
    uint64_t s = seed ^ (0xbf58476d1ce4e5b9ULL * (i + 1));
    uint8_t key[32];
#pragma unroll
    for (int w = 0; w < 4; ++w) {
      uint64_t v = xorshift64(s);
      key[w * 8 + 0] = (uint8_t)(v >> 56);
      key[w * 8 + 1] = (uint8_t)(v >> 48);
      key[w * 8 + 2] = (uint8_t)(v >> 40);
      key[w * 8 + 3] = (uint8_t)(v >> 32);
      key[w * 8 + 4] = (uint8_t)(v >> 24);
      key[w * 8 + 5] = (uint8_t)(v >> 16);
      key[w * 8 + 6] = (uint8_t)(v >> 8);
      key[w * 8 + 7] = (uint8_t)(v);
    }
    uint32_t base_lo = ((uint32_t)key[28] << 24) | ((uint32_t)key[29] << 16) |
                       ((uint32_t)key[30] << 8) | (uint32_t)key[31];
    for (uint32_t step = 0; step < steps; ++step) {
      if (*(volatile int*)&hit->found) return;
      uint32_t lo = base_lo + step;
      key[28] = (uint8_t)(lo >> 24);
      key[29] = (uint8_t)(lo >> 16);
      key[30] = (uint8_t)(lo >> 8);
      key[31] = (uint8_t)lo;
      if (check_targets(key, hit)) return;
    }
  }
}

static HitRecord* d_hit = nullptr;
static cudaStream_t* g_streams = nullptr;
static int g_nstreams = 0;
static uint8_t* d_vram_pad = nullptr; /* optional VRAM fill for -M auto */

int cuda_aes_init(int device) {
  CUDA_OK(cudaSetDevice(device));
  CUDA_OK(cudaMemcpyToSymbol(d_sbox, h_sbox, sizeof(h_sbox)));
  CUDA_OK(cudaMemcpyToSymbol(d_inv_sbox, h_inv_sbox, sizeof(h_inv_sbox)));
  CUDA_OK(cudaMemcpyToSymbol(d_rcon, h_rcon, sizeof(h_rcon)));
  CUDA_OK(cudaMalloc(&d_hit, sizeof(HitRecord)));
  HitRecord z{};
  CUDA_OK(cudaMemcpy(d_hit, &z, sizeof(z), cudaMemcpyHostToDevice));
  return 0;
}

void cuda_aes_shutdown() {
  if (g_streams) {
    for (int i = 0; i < g_nstreams; ++i) cudaStreamDestroy(g_streams[i]);
    delete[] g_streams;
    g_streams = nullptr;
    g_nstreams = 0;
  }
  if (d_vram_pad) {
    cudaFree(d_vram_pad);
    d_vram_pad = nullptr;
  }
  if (d_hit) {
    cudaFree(d_hit);
    d_hit = nullptr;
  }
}

static int ensure_streams(int n) {
  if (n < 1) n = 1;
  if (n > 8) n = 8;
  if (g_streams && g_nstreams == n) return 0;
  if (g_streams) {
    for (int i = 0; i < g_nstreams; ++i) cudaStreamDestroy(g_streams[i]);
    delete[] g_streams;
    g_streams = nullptr;
  }
  g_nstreams = n;
  g_streams = new cudaStream_t[n];
  for (int i = 0; i < n; ++i) {
    cudaError_t e = cudaStreamCreateWithFlags(&g_streams[i], cudaStreamNonBlocking);
    if (e != cudaSuccess) {
      fprintf(stderr, "cudaStreamCreate: %s\n", cudaGetErrorString(e));
      return -1;
    }
  }
  return 0;
}

int cuda_aes_upload_targets(const TargetCipher* targets, int count) {
  if (count < 1 || count > 64) {
    fprintf(stderr, "[E] targets must be 1..64 (got %d)\n", count);
    return -1;
  }
  CUDA_OK(cudaMemcpyToSymbol(d_targets, targets, sizeof(TargetCipher) * count));
  CUDA_OK(cudaMemcpyToSymbol(d_ntargets, &count, sizeof(int)));
  return 0;
}

void cuda_aes_suggest_grid(int device, int* blocks_out, int* threads_out) {
  cudaDeviceProp prop{};
  cudaGetDeviceProperties(&prop, device);
  int thr = 256;
  /* ~8–16 blocks per SM for large grids */
  int blk = prop.multiProcessorCount * 16;
  if (blk < 256) blk = 256;
  if (blk > 2048) blk = 2048;
  if (blocks_out) *blocks_out = blk;
  if (threads_out) *threads_out = thr;
}

int cuda_aes_launch(const LaunchConfig* cfg, HitRecord* host_hit,
                    uint64_t* keys_done_out, uint64_t launch_id) {
  HitRecord z{};
  CUDA_OK(cudaMemcpy(d_hit, &z, sizeof(z), cudaMemcpyHostToDevice));

  int blocks = cfg->blocks > 0 ? cfg->blocks : 256;
  int threads = cfg->threads > 0 ? cfg->threads : 256;
  int nstreams = cfg->streams > 0 ? cfg->streams : 4;
  if (ensure_streams(nstreams) != 0) return -1;

  uint64_t nkeys_total = cfg->keys_per_launch ? cfg->keys_per_launch
                                              : (uint64_t)blocks * (uint64_t)threads;
  /* Split work across streams; prefer multiple of grid size */
  uint64_t grid = (uint64_t)blocks * (uint64_t)threads;
  if (nkeys_total < grid * (uint64_t)nstreams)
    nkeys_total = grid * (uint64_t)nstreams;
  uint64_t per_stream = nkeys_total / (uint64_t)nstreams;
  per_stream = (per_stream / grid) * grid;
  if (per_stream == 0) per_stream = grid;
  nkeys_total = per_stream * (uint64_t)nstreams;

  if (cfg->mode == MODE_SEQUENTIAL) {
    CUDA_OK(cudaMemcpyToSymbol(d_seq_base, cfg->seq_base, sizeof(cfg->seq_base)));
    for (int s = 0; s < nstreams; ++s) {
      uint64_t off = launch_id * nkeys_total + (uint64_t)s * per_stream;
      crack_kernel_seq<<<blocks, threads, 0, g_streams[s]>>>(off, per_stream, d_hit);
    }
  } else if (cfg->mode == MODE_MIXED) {
    for (int s = 0; s < nstreams; ++s) {
      uint64_t seed = 0xDEADBEEFCAFEBABEULL ^
                      ((launch_id * (uint64_t)nstreams + (uint64_t)s) * 0x100000001B3ULL);
      crack_kernel_mixed<<<blocks, threads, 0, g_streams[s]>>>(seed, per_stream,
                                                               cfg->mixed_span, d_hit);
    }
  } else {
    for (int s = 0; s < nstreams; ++s) {
      uint64_t seed = 0xC0FFEE1234567890ULL ^
                      ((launch_id * (uint64_t)nstreams + (uint64_t)s) * 0x9E3779B97F4A7C15ULL);
      crack_kernel_random<<<blocks, threads, 0, g_streams[s]>>>(seed, per_stream, d_hit);
    }
  }

  for (int s = 0; s < nstreams; ++s) CUDA_OK(cudaGetLastError());
  CUDA_OK(cudaDeviceSynchronize());
  CUDA_OK(cudaMemcpy(host_hit, d_hit, sizeof(HitRecord), cudaMemcpyDeviceToHost));
  if (keys_done_out) {
    if (cfg->mode == MODE_MIXED)
      *keys_done_out =
          nkeys_total * (uint64_t)(cfg->mixed_span ? cfg->mixed_span : 256);
    else
      *keys_done_out = nkeys_total;
  }
  return 0;
}

size_t cuda_free_vram_bytes(int device) {
  size_t free_b = 0, total_b = 0;
  cudaSetDevice(device);
  if (cudaMemGetInfo(&free_b, &total_b) != cudaSuccess) return 0;
  return free_b;
}

size_t cuda_estimate_keys_for_vram_mb(size_t mb) {
  /* Map VRAM budget → keys/launch so each launch is large (occupancy).
     Kernels are compute-bound; we optionally pin a scratch pad elsewhere. */
  if (mb == 0) return 1ull << 22;
  size_t keys = (mb * 1024ull * 1024ull) / 32ull;
  if (keys < (1ull << 20)) keys = 1ull << 20;
  if (keys > (1ull << 30)) keys = 1ull << 30;
  return keys;
}

void host_aes256_check_key(const uint8_t key[32], const TargetCipher* t,
                           int* match_out) {
  AES256_ctx ctx;
  unsigned char plain[16];
  AES256_init(&ctx, key);
  AES256_decrypt(&ctx, 1, plain, t->c3);
  int ok = 1;
  for (int i = 0; i < 16; ++i) {
    if (plain[i] != t->expected[i]) {
      ok = 0;
      break;
    }
  }
  *match_out = ok;
}
