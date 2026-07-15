#include "Passphrase.h"
#include "../crypto/crypto_wallet.h"
#include "../crypto/ctaes.h"

#include <cstring>
#include <sstream>
#include <vector>

/* ---- SHA-512 (compact) ---- */
namespace {
struct Sha512Ctx {
  uint64_t state[8];
  uint64_t bitlen[2];
  uint8_t data[128];
  uint32_t datalen;
};

static uint64_t rotr64(uint64_t x, uint32_t n) { return (x >> n) | (x << (64 - n)); }

static void sha512_transform(Sha512Ctx* ctx, const uint8_t data[128]) {
  static const uint64_t k[80] = {
      0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
      0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
      0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
      0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
      0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
      0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
      0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
      0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
      0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
      0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
      0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
      0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
      0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
      0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
      0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
      0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
      0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
      0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
      0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
      0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};
  uint64_t m[80];
  for (int i = 0, j = 0; i < 16; ++i, j += 8) {
    m[i] = ((uint64_t)data[j] << 56) | ((uint64_t)data[j + 1] << 48) |
           ((uint64_t)data[j + 2] << 40) | ((uint64_t)data[j + 3] << 32) |
           ((uint64_t)data[j + 4] << 24) | ((uint64_t)data[j + 5] << 16) |
           ((uint64_t)data[j + 6] << 8) | ((uint64_t)data[j + 7]);
  }
  for (int i = 16; i < 80; ++i) {
    uint64_t s0 = rotr64(m[i - 15], 1) ^ rotr64(m[i - 15], 8) ^ (m[i - 15] >> 7);
    uint64_t s1 = rotr64(m[i - 2], 19) ^ rotr64(m[i - 2], 61) ^ (m[i - 2] >> 6);
    m[i] = m[i - 16] + s0 + m[i - 7] + s1;
  }
  uint64_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
  uint64_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
  for (int i = 0; i < 80; ++i) {
    uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
    uint64_t ch = (e & f) ^ ((~e) & g);
    uint64_t t1 = h + S1 + ch + k[i] + m[i];
    uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
    uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint64_t t2 = S0 + maj;
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

static void sha512_init(Sha512Ctx* ctx) {
  ctx->datalen = 0;
  ctx->bitlen[0] = ctx->bitlen[1] = 0;
  ctx->state[0] = 0x6a09e667f3bcc908ULL;
  ctx->state[1] = 0xbb67ae8584caa73bULL;
  ctx->state[2] = 0x3c6ef372fe94f82bULL;
  ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
  ctx->state[4] = 0x510e527fade682d1ULL;
  ctx->state[5] = 0x9b05688c2b3e6c1fULL;
  ctx->state[6] = 0x1f83d9abfb41bd6bULL;
  ctx->state[7] = 0x5be0cd19137e2179ULL;
}

static void sha512_update(Sha512Ctx* ctx, const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen++] = data[i];
    if (ctx->datalen == 128) {
      sha512_transform(ctx, ctx->data);
      if (ctx->bitlen[0] > 0xffffffffffffffffULL - 1024ULL) ctx->bitlen[1]++;
      ctx->bitlen[0] += 1024;
      ctx->datalen = 0;
    }
  }
}

static void sha512_final(Sha512Ctx* ctx, uint8_t hash[64]) {
  uint32_t i = ctx->datalen;
  if (ctx->datalen < 112) {
    ctx->data[i++] = 0x80;
    while (i < 112) ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 128) ctx->data[i++] = 0x00;
    sha512_transform(ctx, ctx->data);
    std::memset(ctx->data, 0, 112);
  }
  if (ctx->bitlen[0] > 0xffffffffffffffffULL - (uint64_t)ctx->datalen * 8)
    ctx->bitlen[1]++;
  ctx->bitlen[0] += (uint64_t)ctx->datalen * 8;
  for (int j = 0; j < 8; ++j) {
    ctx->data[127 - j] = (uint8_t)(ctx->bitlen[0] >> (j * 8));
    ctx->data[119 - j] = (uint8_t)(ctx->bitlen[1] >> (j * 8));
  }
  sha512_transform(ctx, ctx->data);
  for (i = 0; i < 8; ++i) {
    hash[i * 8] = (uint8_t)(ctx->state[i] >> 56);
    hash[i * 8 + 1] = (uint8_t)(ctx->state[i] >> 48);
    hash[i * 8 + 2] = (uint8_t)(ctx->state[i] >> 40);
    hash[i * 8 + 3] = (uint8_t)(ctx->state[i] >> 32);
    hash[i * 8 + 4] = (uint8_t)(ctx->state[i] >> 24);
    hash[i * 8 + 5] = (uint8_t)(ctx->state[i] >> 16);
    hash[i * 8 + 6] = (uint8_t)(ctx->state[i] >> 8);
    hash[i * 8 + 7] = (uint8_t)(ctx->state[i]);
  }
}

static void sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
  Sha512Ctx ctx;
  sha512_init(&ctx);
  sha512_update(&ctx, data, len);
  sha512_final(&ctx, out);
}

/** OpenSSL EVP_BytesToKey with SHA512 (Bitcoin Core method 0). */
static void bytes_to_key_sha512_impl(const uint8_t* pass, size_t pass_len, const uint8_t* salt,
                                     size_t salt_len, unsigned rounds, uint8_t* key32,
                                     uint8_t* iv16) {
  uint8_t md_buf[64];
  size_t nkey = 32, niv = 16;
  size_t addmd = 0;
  size_t i;
  for (;;) {
    Sha512Ctx ctx;
    sha512_init(&ctx);
    if (addmd++) sha512_update(&ctx, md_buf, 64);
    sha512_update(&ctx, pass, pass_len);
    sha512_update(&ctx, salt, salt_len);
    sha512_final(&ctx, md_buf);
    for (unsigned r = 1; r < rounds; ++r) {
      sha512(md_buf, 64, md_buf);
    }
    i = 0;
    if (nkey) {
      for (;;) {
        if (nkey == 0 || i == 64) break;
        *(key32++) = md_buf[i++];
        nkey--;
      }
    }
    if (niv && i != 64) {
      for (;;) {
        if (niv == 0 || i == 64) break;
        *(iv16++) = md_buf[i++];
        niv--;
      }
    }
    if (nkey == 0 && niv == 0) break;
  }
}

static std::string to_hex(const uint8_t* p, size_t n) {
  static const char* h = "0123456789abcdef";
  std::string s(n * 2, '0');
  for (size_t i = 0; i < n; ++i) {
    s[i * 2] = h[p[i] >> 4];
    s[i * 2 + 1] = h[p[i] & 0xf];
  }
  return s;
}
}  // namespace

void bitcoin_bytes_to_key_sha512(const uint8_t* pass, size_t pass_len, const uint8_t* salt,
                                 size_t salt_len, unsigned rounds, uint8_t key32[32],
                                 uint8_t iv16[16]) {
  bytes_to_key_sha512_impl(pass, pass_len, salt, salt_len, rounds, key32, iv16);
}

PassphraseAttemptResult try_wallet_passphrase(const MasterKeyInfo& mkey,
                                              const std::string& passphrase) {
  PassphraseAttemptResult r;
  if (!mkey.found || mkey.encrypted48.size() != 48) {
    r.message = "no mkey / incomplete encrypted blob";
    return r;
  }
  if (mkey.salt.size() < 8) {
    r.message = "mkey salt missing (need structured 04mkey parse)";
    return r;
  }
  if (mkey.method != 0) {
    r.message = "unsupported KDF method (only method 0 / SHA512)";
    return r;
  }
  uint32_t rounds = mkey.iterations ? mkey.iterations : 25000;
  uint8_t key[32], iv[16];
  bitcoin_bytes_to_key_sha512(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size(),
                              mkey.salt.data(), 8, rounds, key, iv);
  r.derived_key_hex = to_hex(key, 32);
  r.derived_iv_hex = to_hex(iv, 16);

  uint8_t out[48];
  if (!aes256_cbc_decrypt(key, iv, mkey.encrypted48.data(), 48, out)) {
    r.message = "AES-CBC decrypt failed (wrong passphrase or corrupt mkey)";
    return r;
  }
  /* Master key plaintext should be 32 bytes + 16 bytes PKCS pad (0x10) */
  bool pad_ok = true;
  for (int i = 32; i < 48; ++i)
    if (out[i] != 0x10) pad_ok = false;
  if (!pad_ok) {
    r.message = "padding check failed — passphrase incorrect";
    return r;
  }
  r.ok = true;
  r.decrypted_mkey_hex = to_hex(out, 32);
  r.message = "PASS — master key decrypted";
  return r;
}

static int b58_decode(const std::string& s, std::vector<uint8_t>& out) {
  static const char* alphabet =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  std::vector<uint8_t> digits;
  for (char c : s) {
    const char* p = std::strchr(alphabet, c);
    if (!p) return -1;
    digits.push_back((uint8_t)(p - alphabet));
  }
  size_t zeros = 0;
  while (zeros < digits.size() && digits[zeros] == 0) ++zeros;
  std::vector<uint8_t> b256(digits.size() * 733 / 1000 + 1, 0);
  for (uint8_t d : digits) {
    int carry = d;
    for (int i = (int)b256.size() - 1; i >= 0; --i) {
      carry += 58 * b256[i];
      b256[i] = (uint8_t)(carry % 256);
      carry /= 256;
    }
  }
  size_t i = 0;
  while (i < b256.size() && b256[i] == 0) ++i;
  out.assign(zeros, 0);
  out.insert(out.end(), b256.begin() + i, b256.end());
  return 0;
}

bool craft_encrypted_mkey48(const std::string& passphrase, const uint8_t salt8[8],
                            uint32_t iterations, const uint8_t master32[32],
                            uint8_t out_enc48[48]) {
  uint8_t key[32], iv[16];
  bitcoin_bytes_to_key_sha512(reinterpret_cast<const uint8_t*>(passphrase.data()),
                              passphrase.size(), salt8, 8, iterations, key, iv);
  uint8_t plain[48];
  std::memcpy(plain, master32, 32);
  for (int i = 32; i < 48; ++i) plain[i] = 0x10;
  AES256_ctx ctx;
  AES256_init(&ctx, key);
  uint8_t prev[16];
  std::memcpy(prev, iv, 16);
  for (size_t off = 0; off < 48; off += 16) {
    uint8_t block[16];
    for (int i = 0; i < 16; ++i) block[i] = (uint8_t)(plain[off + i] ^ prev[i]);
    AES256_encrypt(&ctx, 1, out_enc48 + off, block);
    std::memcpy(prev, out_enc48 + off, 16);
  }
  return true;
}

void hmac_sha512(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len,
                 uint8_t out64[64]) {
  uint8_t k0[128];
  std::memset(k0, 0, sizeof(k0));
  if (key_len > 128) {
    sha512(key, key_len, k0);
  } else {
    std::memcpy(k0, key, key_len);
  }
  uint8_t ipad[128], opad[128];
  for (int i = 0; i < 128; ++i) {
    ipad[i] = (uint8_t)(k0[i] ^ 0x36);
    opad[i] = (uint8_t)(k0[i] ^ 0x5c);
  }
  std::vector<uint8_t> inner(128 + data_len);
  std::memcpy(inner.data(), ipad, 128);
  if (data_len) std::memcpy(inner.data() + 128, data, data_len);
  uint8_t ihash[64];
  sha512(inner.data(), inner.size(), ihash);
  uint8_t outer[128 + 64];
  std::memcpy(outer, opad, 128);
  std::memcpy(outer + 128, ihash, 64);
  sha512(outer, sizeof(outer), out64);
}

void pbkdf2_hmac_sha512(const uint8_t* pass, size_t pass_len, const uint8_t* salt, size_t salt_len,
                        unsigned iterations, uint8_t* out, size_t out_len) {
  size_t offset = 0;
  uint32_t block = 1;
  while (offset < out_len) {
    std::vector<uint8_t> msg(salt_len + 4);
    if (salt_len) std::memcpy(msg.data(), salt, salt_len);
    msg[salt_len] = (uint8_t)(block >> 24);
    msg[salt_len + 1] = (uint8_t)(block >> 16);
    msg[salt_len + 2] = (uint8_t)(block >> 8);
    msg[salt_len + 3] = (uint8_t)block;
    uint8_t u[64], t[64];
    hmac_sha512(pass, pass_len, msg.data(), msg.size(), u);
    std::memcpy(t, u, 64);
    for (unsigned i = 1; i < iterations; ++i) {
      hmac_sha512(pass, pass_len, u, 64, u);
      for (int j = 0; j < 64; ++j) t[j] ^= u[j];
    }
    size_t take = (out_len - offset < 64) ? (out_len - offset) : 64;
    std::memcpy(out + offset, t, take);
    offset += take;
    ++block;
  }
}

bool verify_wif(const std::string& wif, std::string* detail_out) {
  std::vector<uint8_t> raw;
  if (b58_decode(wif, raw) != 0 || raw.size() < 5) {
    if (detail_out) *detail_out = "invalid base58";
    return false;
  }
  uint8_t chk[32];
  double_sha256(raw.data(), raw.size() - 4, chk);
  if (std::memcmp(chk, raw.data() + raw.size() - 4, 4) != 0) {
    if (detail_out) *detail_out = "checksum mismatch";
    return false;
  }
  size_t body = raw.size() - 4;
  if (raw[0] != 0x80) {
    if (detail_out) *detail_out = "not mainnet WIF version byte";
    return false;
  }
  bool compressed = (body == 34 && raw[33] == 0x01);
  bool uncompressed = (body == 33);
  if (!compressed && !uncompressed) {
    if (detail_out) *detail_out = "unexpected WIF length";
    return false;
  }
  if (detail_out) {
    std::ostringstream o;
    o << "OK — " << (compressed ? "compressed" : "uncompressed") << " privkey "
      << to_hex(raw.data() + 1, 32);
    *detail_out = o.str();
  }
  return true;
}
