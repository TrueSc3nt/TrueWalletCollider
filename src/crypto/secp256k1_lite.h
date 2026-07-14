#pragma once
#include <cstdint>
#include <cstddef>

/** Compact secp256k1: private key → compressed / uncompressed public key. */
bool secp256k1_priv_to_pub(const uint8_t priv32[32], uint8_t out_pub[65],
                           size_t* out_len, bool compressed);

/** Self-test: generator G (priv=1) + PoC compressed pubkey. */
bool secp256k1_lite_selftest();
