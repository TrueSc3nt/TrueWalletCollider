#pragma once
#include "WalletDat.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/** Bitcoin Core wallet passphrase → AES key (method 0 / EVP_BytesToKey SHA512). */
struct PassphraseAttemptResult {
  bool ok = false;
  std::string message;
  std::string derived_key_hex;
  std::string derived_iv_hex;
  std::string decrypted_mkey_hex;
};

PassphraseAttemptResult try_wallet_passphrase(const MasterKeyInfo& mkey,
                                              const std::string& passphrase);

/** Bitcoin Core method-0 KDF (EVP_BytesToKey SHA-512). salt_len typically 8. */
void bitcoin_bytes_to_key_sha512(const uint8_t* pass, size_t pass_len, const uint8_t* salt,
                                 size_t salt_len, unsigned rounds, uint8_t key32[32],
                                 uint8_t iv16[16]);

/** Craft encrypted mkey48 for research selftests. */
bool craft_encrypted_mkey48(const std::string& passphrase, const uint8_t salt8[8],
                            uint32_t iterations, const uint8_t master32[32],
                            uint8_t out_enc48[48]);

/** HMAC-SHA512 (for BIP39 / BIP32). */
void hmac_sha512(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len,
                 uint8_t out64[64]);

/** PBKDF2-HMAC-SHA512 (BIP39 mnemonic → seed). */
void pbkdf2_hmac_sha512(const uint8_t* pass, size_t pass_len, const uint8_t* salt, size_t salt_len,
                        unsigned iterations, uint8_t* out, size_t out_len);

/** Validate a WIF string (base58 + checksum + length). */
bool verify_wif(const std::string& wif, std::string* detail_out);
