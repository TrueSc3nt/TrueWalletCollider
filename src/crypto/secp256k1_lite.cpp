#include "secp256k1_lite.h"

#include "uECC.h"

#include <cstdio>
#include <cstring>

bool secp256k1_priv_to_pub(const uint8_t priv32[32], uint8_t out_pub[65],
                           size_t* out_len, bool compressed) {
  if (!priv32 || !out_pub || !out_len) return false;
  uint8_t pub64[64];
  if (!uECC_compute_public_key(priv32, pub64, uECC_secp256k1())) return false;
  if (compressed) {
#if uECC_SUPPORT_COMPRESSED_POINT
    uECC_compress(pub64, out_pub, uECC_secp256k1());
    *out_len = 33;
#else
    /* Manual compress: 02/03 || X */
    out_pub[0] = (pub64[63] & 1) ? 0x03 : 0x02;
    std::memcpy(out_pub + 1, pub64, 32);
    *out_len = 33;
#endif
  } else {
    out_pub[0] = 0x04;
    std::memcpy(out_pub + 1, pub64, 64);
    *out_len = 65;
  }
  return true;
}

bool secp256k1_lite_selftest() {
  /* PoC privkey from wallet toolkit (known compressed pubkey) */
  static const uint8_t POC_PRIV[32] = {
      0x3e, 0xa5, 0xea, 0xab, 0xe7, 0xf7, 0xb9, 0x97, 0xce, 0x73, 0x2a, 0xcc,
      0x9c, 0xf0, 0x83, 0x15, 0xa8, 0x05, 0x10, 0x90, 0x03, 0xce, 0x2b, 0xd9,
      0x18, 0xba, 0xc1, 0xb7, 0x3b, 0x82, 0xd7, 0xb7};
  static const uint8_t POC_PUB[33] = {
      0x03, 0x82, 0xca, 0x08, 0xce, 0x78, 0xb0, 0x93, 0x50, 0x99, 0xc7, 0x4d,
      0xb1, 0x28, 0x73, 0xa7, 0xdc, 0x1c, 0xba, 0x10, 0xa4, 0x41, 0x65, 0xce,
      0x8c, 0xc1, 0xd0, 0x60, 0x2f, 0x49, 0xee, 0x97, 0xf5};

  uint8_t pub[65];
  size_t len = 0;
  if (!secp256k1_priv_to_pub(POC_PRIV, pub, &len, true) || len != 33) {
    std::fprintf(stderr, "[E] secp: compute/compress failed (len=%zu)\n", len);
    return false;
  }
  if (std::memcmp(pub, POC_PUB, 33) != 0) {
    std::fprintf(stderr, "[E] secp: pubkey mismatch\n  got ");
    for (int i = 0; i < 33; ++i) std::fprintf(stderr, "%02x", pub[i]);
    std::fprintf(stderr, "\n");
    return false;
  }

  return true;
}
