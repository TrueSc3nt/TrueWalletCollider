#pragma once
#include "WalletDat.h"
#include <string>

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

/** Validate a WIF string (base58 + checksum + length). */
bool verify_wif(const std::string& wif, std::string* detail_out);
