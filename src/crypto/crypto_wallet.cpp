#include "crypto_wallet.h"
#include "ctaes.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

/* ---- SHA-256 (compact, public-domain style) ---- */

struct Sha256Ctx {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t data[64];
  uint32_t datalen;
};

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(Sha256Ctx* ctx, const uint8_t data[64]) {
  static const uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  uint32_t m[64];
  for (int i = 0, j = 0; i < 16; ++i, j += 4)
    m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
           ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
  for (int i = 16; i < 64; ++i) {
    uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
    uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
    m[i] = m[i - 16] + s0 + m[i - 7] + s1;
  }
  uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
  uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + S1 + ch + k[i] + m[i];
    uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void sha256_init(Sha256Ctx* ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(Sha256Ctx* ctx, const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen++] = data[i];
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

static void sha256_final(Sha256Ctx* ctx, uint8_t hash[32]) {
  uint32_t i = ctx->datalen;
  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    std::memset(ctx->data, 0, 56);
  }
  ctx->bitlen += ctx->datalen * 8ull;
  ctx->data[63] = (uint8_t)(ctx->bitlen);
  ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
  ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
  ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
  ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
  ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
  ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
  ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
  sha256_transform(ctx, ctx->data);
  for (i = 0; i < 4; ++i) {
    hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xff;
    hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xff;
    hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xff;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
    hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
    hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
    hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
  }
}

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  Sha256Ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, out);
}

void double_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  uint8_t tmp[32];
  sha256(data, len, tmp);
  sha256(tmp, 32, out);
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out) {
  if (hex.size() % 2) return false;
  out.resize(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    int hi = hex_nibble(hex[i * 2]);
    int lo = hex_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

static std::string bytes_to_hex(const uint8_t* p, size_t n) {
  static const char* hexd = "0123456789abcdef";
  std::string s(n * 2, '0');
  for (size_t i = 0; i < n; ++i) {
    s[i * 2] = hexd[p[i] >> 4];
    s[i * 2 + 1] = hexd[p[i] & 0xf];
  }
  return s;
}

bool aes256_cbc_decrypt(const uint8_t* key32, const uint8_t* iv16,
                        const uint8_t* enc, size_t enc_len, uint8_t* out) {
  if (enc_len == 0 || (enc_len % 16) != 0) return false;
  AES256_ctx ctx;
  AES256_init(&ctx, key32);
  uint8_t prev[16];
  std::memcpy(prev, iv16, 16);
  for (size_t off = 0; off < enc_len; off += 16) {
    uint8_t block[16];
    AES256_decrypt(&ctx, 1, block, enc + off);
    for (int i = 0; i < 16; ++i) out[off + i] = (uint8_t)(block[i] ^ prev[i]);
    std::memcpy(prev, enc + off, 16);
  }
  return true;
}

std::string base58_encode(const uint8_t* data, size_t len) {
  static const char* kAlphabet =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  size_t zeros = 0;
  while (zeros < len && data[zeros] == 0) ++zeros;
  std::vector<uint8_t> b(data, data + len);
  std::string enc;
  enc.reserve(len * 138 / 100 + 2);
  size_t start = zeros;
  while (start < b.size()) {
    int carry = 0;
    for (size_t i = start; i < b.size(); ++i) {
      int x = carry * 256 + b[i];
      b[i] = (uint8_t)(x / 58);
      carry = x % 58;
    }
    enc.push_back(kAlphabet[carry]);
    while (start < b.size() && b[start] == 0) ++start;
  }
  for (size_t i = 0; i < zeros; ++i) enc.push_back('1');
  std::reverse(enc.begin(), enc.end());
  return enc;
}

std::string privkey_to_wif(const uint8_t priv[32], bool compressed) {
  std::vector<uint8_t> payload;
  payload.push_back(0x80);
  payload.insert(payload.end(), priv, priv + 32);
  if (compressed) payload.push_back(0x01);
  uint8_t chk[32];
  double_sha256(payload.data(), payload.size(), chk);
  payload.insert(payload.end(), chk, chk + 4);
  return base58_encode(payload.data(), payload.size());
}

namespace {
uint32_t ripemd_rol(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

void ripemd160_hash(const uint8_t* msg, size_t len, uint8_t out[20]) {
  uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
  auto f = [](int j, uint32_t x, uint32_t y, uint32_t z) -> uint32_t {
    if (j <= 15) return x ^ y ^ z;
    if (j <= 31) return (x & y) | (~x & z);
    if (j <= 47) return (x | ~y) ^ z;
    if (j <= 63) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  };
  static const uint32_t K1[5] = {0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
  static const uint32_t K2[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0};
  static const int R1[80] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                             7,  4,  13, 1,  10, 6,  15, 3,  12, 0,  9,  5,  2,  14, 11, 8,
                             3,  10, 14, 4,  9,  15, 8,  1,  2,  7,  0,  6,  13, 11, 5,  12,
                             1,  9,  11, 10, 0,  8,  12, 4,  13, 3,  7,  15, 14, 5,  6,  2,
                             4,  0,  5,  9,  7,  12, 2,  10, 14, 1,  3,  8,  11, 6,  15, 13};
  static const int R2[80] = {5,  14, 7,  0,  9,  2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
                             6,  11, 3,  7,  0,  13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
                             15, 5,  1,  3,  7,  14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
                             8,  6,  4,  1,  3,  11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
                             12, 15, 10, 4,  1,  5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11};
  static const int S1[80] = {11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
                             7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
                             11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
                             11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
                             9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6};
  static const int S2[80] = {8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
                             9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
                             9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
                             15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
                             8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11};
  size_t new_len = ((len + 8) / 64 + 1) * 64;
  std::vector<uint8_t> buf(new_len, 0);
  std::memcpy(buf.data(), msg, len);
  buf[len] = 0x80;
  uint64_t bitlen = (uint64_t)len * 8;
  std::memcpy(buf.data() + new_len - 8, &bitlen, 8);
  for (size_t i = 0; i < new_len; i += 64) {
    uint32_t X[16];
    for (int j = 0; j < 16; ++j)
      X[j] = (uint32_t)buf[i + j * 4] | ((uint32_t)buf[i + j * 4 + 1] << 8) |
             ((uint32_t)buf[i + j * 4 + 2] << 16) | ((uint32_t)buf[i + j * 4 + 3] << 24);
    uint32_t al = h0, bl = h1, cl = h2, dl = h3, el = h4;
    uint32_t ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (int j = 0; j < 80; ++j) {
      uint32_t t = ripemd_rol(al + f(j, bl, cl, dl) + X[R1[j]] + K1[j / 16], S1[j]) + el;
      al = el;
      el = dl;
      dl = ripemd_rol(cl, 10);
      cl = bl;
      bl = t;
      t = ripemd_rol(ar + f(79 - j, br, cr, dr) + X[R2[j]] + K2[j / 16], S2[j]) + er;
      ar = er;
      er = dr;
      dr = ripemd_rol(cr, 10);
      cr = br;
      br = t;
    }
    uint32_t t = h1 + cl + dr;
    h1 = h2 + dl + er;
    h2 = h3 + el + ar;
    h3 = h4 + al + br;
    h4 = h0 + bl + cr;
    h0 = t;
  }
  auto store = [](uint32_t v, uint8_t* p) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
  };
  store(h0, out);
  store(h1, out + 4);
  store(h2, out + 8);
  store(h3, out + 12);
  store(h4, out + 16);
}
}  // namespace

void hash160(const uint8_t* data, size_t len, uint8_t out20[20]) {
  uint8_t d[32];
  sha256(data, len, d);
  ripemd160_hash(d, 32, out20);
}

std::string pubkey_to_p2pkh(const uint8_t* pubkey, size_t pubkey_len) {
  if (!pubkey || (pubkey_len != 33 && pubkey_len != 65)) return {};
  uint8_t ripe[20];
  hash160(pubkey, pubkey_len, ripe);
  uint8_t payload[25];
  payload[0] = 0x00;
  std::memcpy(payload + 1, ripe, 20);
  uint8_t chk[32];
  double_sha256(payload, 21, chk);
  std::memcpy(payload + 21, chk, 4);
  return base58_encode(payload, 25);
}

bool iv_from_pubkey(const uint8_t* pubkey, size_t pubkey_len, uint8_t iv16[16],
                    uint8_t dsha32[32]) {
  if (!pubkey || pubkey_len < 33 || pubkey_len > 65) return false;
  double_sha256(pubkey, pubkey_len, dsha32);
  std::memcpy(iv16, dsha32, 16);
  return true;
}

PostHitResult post_hit_decrypt_wif(const WalletTarget& tgt, const uint8_t aes_key[32]) {
  PostHitResult r;
  if (tgt.enc48.size() != 48) {
    r.message = "encrypted blob is not 48 bytes";
    return r;
  }
  if (tgt.pubkey.empty()) {
    r.message =
        "no pubkey for this ckey — supply pubkey column or -pubkeys FILE "
        "(IV = first 16 bytes of double-SHA256(pubkey); required by Bitcoin Core / "
        "crackBTCwallet)";
    return r;
  }
  uint8_t iv[16], dsha[32];
  if (!iv_from_pubkey(tgt.pubkey.data(), tgt.pubkey.size(), iv, dsha)) {
    r.message = "invalid pubkey length (need 33 or 65 bytes)";
    return r;
  }
  r.doublesha256_hex = bytes_to_hex(dsha, 32);
  r.iv_hex = bytes_to_hex(iv, 16);

  uint8_t plain[48];
  if (!aes256_cbc_decrypt(aes_key, iv, tgt.enc48.data(), 48, plain)) {
    r.message = "AES-CBC decrypt failed";
    return r;
  }
  r.decrypted_hex = bytes_to_hex(plain, 48);

  for (int i = 32; i < 48; ++i) {
    if (plain[i] != 0x10) {
      r.message = "padding check failed (expected sixteen 0x10 bytes)";
      return r;
    }
  }
  r.privkey_hex = bytes_to_hex(plain, 32);
  r.wif_uncompressed = privkey_to_wif(plain, false);
  r.wif_compressed = privkey_to_wif(plain, true);
  r.ok = true;
  r.message = "OK";
  return r;
}

bool save_found_wallet(const std::string& path, const WalletTarget& tgt,
                       const uint8_t aes_key[32], const PostHitResult& r,
                       int target_index) {
  std::ofstream out(path, std::ios::app);
  if (!out) return false;
  char tbuf[64];
  std::time_t now = std::time(nullptr);
  std::tm tm_buf{};
#ifdef _WIN32
  localtime_s(&tm_buf, &now);
#else
  localtime_r(&now, &tm_buf);
#endif
  std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm_buf);

  out << "=== TrueMkeyCollider FOUND ===\n";
  out << "timestamp: " << tbuf << "\n";
  out << "target_index: " << target_index << "\n";
  out << "kind: " << (tgt.is_mkey ? "mkey" : "ckey") << "\n";
  out << "aes_key: " << bytes_to_hex(aes_key, 32) << "\n";
  out << "encrypted_ckey: " << (tgt.enc_hex.empty() ? bytes_to_hex(tgt.enc48.data(), tgt.enc48.size())
                                                    : tgt.enc_hex)
      << "\n";
  out << "pubkey: " << (tgt.pubkey_hex.empty() ? "(none)" : tgt.pubkey_hex) << "\n";
  out << "doublesha256: " << (r.doublesha256_hex.empty() ? "(n/a)" : r.doublesha256_hex)
      << "\n";
  out << "iv: " << (r.iv_hex.empty() ? "(n/a)" : r.iv_hex) << "\n";
  out << "decrypted_hex: " << (r.decrypted_hex.empty() ? "(n/a)" : r.decrypted_hex) << "\n";
  out << "privkey_hex: " << (r.privkey_hex.empty() ? "(n/a)" : r.privkey_hex) << "\n";
  out << "wif_uncompressed: "
      << (r.wif_uncompressed.empty() ? "(n/a)" : r.wif_uncompressed) << "\n";
  out << "wif_compressed: " << (r.wif_compressed.empty() ? "(n/a)" : r.wif_compressed)
      << "\n";
  out << "padding_ok: " << (r.ok ? "yes" : "no") << "\n";
  out << "note: " << r.message << "\n";
  out << "===\n";
  return true;
}

static void print_post_hit(const PostHitResult& r, const WalletTarget& tgt,
                           const uint8_t aes_key[32]) {
  std::printf("\n--- Auto post-hit pipeline (crackBTCwallet flow) ---\n");
  std::printf("aes_key: %s\n", bytes_to_hex(aes_key, 32).c_str());
  if (!tgt.pubkey_hex.empty())
    std::printf("pubkey:  %s\n", tgt.pubkey_hex.c_str());
  if (!r.ok) {
    std::printf("[!] %s\n", r.message.c_str());
    return;
  }
  std::printf("doublesha256: %s\n", r.doublesha256_hex.c_str());
  std::printf("iv:           %s\n", r.iv_hex.c_str());
  std::printf("encrypted:    %s\n", tgt.enc_hex.c_str());
  std::printf("decrypted:    %s\n", r.decrypted_hex.c_str());
  std::printf("padding:      sixteen 0x10 OK\n");
  std::printf("privkey_hex:  %s\n", r.privkey_hex.c_str());
  std::printf("WIF uncompressed: %s\n", r.wif_uncompressed.c_str());
  std::printf("WIF compressed:   %s\n", r.wif_compressed.c_str());
}

/* Export for main.cpp — declared in header via save + post_hit; also need print helper.
   Keep print in header-less local; main will call post_hit + print itself. */

int run_cmd_mode(int argc, char** argv) {
  /* argv[0]=exe argv[1]=--cmd argv[2]=name ... */
  if (argc < 3) {
    std::fprintf(stderr,
                 "Usage:\n"
                 "  --cmd doublesha256 <hex>\n"
                 "  --cmd aesdecrypt <iv32hex> <key64hex> <enc96hex>\n"
                 "  --cmd privatekeytowif <priv64hex>\n");
    return 1;
  }
  std::string cmd = argv[2];
  if (cmd == "doublesha256") {
    if (argc < 4) {
      std::fprintf(stderr, "doublesha256 needs hex input\n");
      return 1;
    }
    std::vector<uint8_t> in;
    if (!hex_to_bytes(argv[3], in)) {
      std::fprintf(stderr, "bad hex\n");
      return 1;
    }
    uint8_t out[32];
    double_sha256(in.data(), in.size(), out);
    std::printf("double sha256: %s\n", bytes_to_hex(out, 32).c_str());
    std::printf("IV (first 32 hex): %s\n", bytes_to_hex(out, 16).c_str());
    return 0;
  }
  if (cmd == "aesdecrypt") {
    if (argc < 6) {
      std::fprintf(stderr, "aesdecrypt needs IV KEY ENC\n");
      return 1;
    }
    std::vector<uint8_t> iv, key, enc;
    if (!hex_to_bytes(argv[3], iv) || iv.size() != 16) {
      std::fprintf(stderr, "IV must be 32 hex chars\n");
      return 1;
    }
    if (!hex_to_bytes(argv[4], key) || key.size() != 32) {
      std::fprintf(stderr, "key must be 64 hex chars\n");
      return 1;
    }
    if (!hex_to_bytes(argv[5], enc) || enc.empty() || (enc.size() % 16)) {
      std::fprintf(stderr, "enc must be multiple of 16 bytes hex\n");
      return 1;
    }
    std::vector<uint8_t> plain(enc.size());
    if (!aes256_cbc_decrypt(key.data(), iv.data(), enc.data(), enc.size(),
                            plain.data())) {
      std::fprintf(stderr, "decrypt failed\n");
      return 1;
    }
    std::printf("decrypt_iv %s\n", bytes_to_hex(iv.data(), 16).c_str());
    std::printf("decrypt_key %s\n", bytes_to_hex(key.data(), 32).c_str());
    std::printf("decrypt_enc %s\n", bytes_to_hex(enc.data(), enc.size()).c_str());
    std::printf("len: %zu\n", enc.size());
    std::printf("Decrypted: %s\n", bytes_to_hex(plain.data(), plain.size()).c_str());
    return 0;
  }
  if (cmd == "privatekeytowif") {
    if (argc < 4) {
      std::fprintf(stderr, "privatekeytowif needs 64-hex privkey\n");
      return 1;
    }
    std::vector<uint8_t> priv;
    if (!hex_to_bytes(argv[3], priv) || priv.size() != 32) {
      std::fprintf(stderr, "privkey must be 64 hex chars\n");
      return 1;
    }
    std::printf("Private KEY uncompressed %s\n",
                privkey_to_wif(priv.data(), false).c_str());
    std::printf("Private KEY compressed %s\n",
                privkey_to_wif(priv.data(), true).c_str());
    return 0;
  }
  std::fprintf(stderr, "unknown --cmd %s\n", cmd.c_str());
  return 1;
}
