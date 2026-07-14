#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

struct WalletTarget {
  std::vector<uint8_t> enc48;   /* 48-byte AES-CBC ciphertext */
  std::vector<uint8_t> pubkey;  /* optional; needed for ckey IV */
  std::string enc_hex;
  std::string pubkey_hex;
  bool is_mkey = false;
};

struct PostHitResult {
  bool ok = false;
  std::string message;
  std::string doublesha256_hex;
  std::string iv_hex;
  std::string decrypted_hex;
  std::string privkey_hex;
  std::string wif_uncompressed;
  std::string wif_compressed;
};

void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
void double_sha256(const uint8_t* data, size_t len, uint8_t out[32]);

/** AES-256-CBC decrypt (ctaes). out must hold enc_len bytes. */
bool aes256_cbc_decrypt(const uint8_t* key32, const uint8_t* iv16,
                        const uint8_t* enc, size_t enc_len, uint8_t* out);

std::string base58_encode(const uint8_t* data, size_t len);
std::string privkey_to_wif(const uint8_t priv[32], bool compressed);

/** IV = first 16 bytes of SHA256(SHA256(pubkey)). */
bool iv_from_pubkey(const uint8_t* pubkey, size_t pubkey_len, uint8_t iv16[16],
                    uint8_t dsha32[32]);

/**
 * Full crackBTCwallet post-hit: IV from pubkey, CBC decrypt, verify 0x10*16,
 * strip padding, emit WIFs.
 */
PostHitResult post_hit_decrypt_wif(const WalletTarget& tgt, const uint8_t aes_key[32]);

/** Append full recovery record to path (FOUND_WALLET.txt style). */
bool save_found_wallet(const std::string& path, const WalletTarget& tgt,
                       const uint8_t aes_key[32], const PostHitResult& r,
                       int target_index);

int run_cmd_mode(int argc, char** argv);
