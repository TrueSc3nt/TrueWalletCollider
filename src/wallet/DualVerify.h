#pragma once
#include "WalletDat.h"
#include "../crypto/crypto_wallet.h"
#include <string>
#include <vector>

struct DualVerifyResult {
  bool pkcs_mkey = false;
  bool pkcs_ckey = false;
  bool pubkey_match = false;
  bool ok = false; /* preferred: pkcs_ckey && (pubkey_match || no_pubkey) */
  std::string master_hex;
  std::string message;
  PostHitResult ckey_hit;
  int ckey_index = -1;
};

struct MultiCkeyDecryptResult {
  bool ok = false;
  std::string master_hex;
  int decrypted = 0;
  int failed = 0;
  int pubkey_ok = 0;
  std::vector<PostHitResult> hits;
  std::string report;
};

/** PKCS alone is weak; prefer PKCS(mkey) + decrypt ckey + optional EC pubkey match. */
DualVerifyResult dual_verify_master(const uint8_t master32[32],
                                    const WalletParseResult& wallet,
                                    int prefer_ckey = -1);

/** Passphrase path: derive → dual verify → write FOUND_WALLET on success. */
DualVerifyResult dual_verify_passphrase(const MasterKeyInfo& mkey,
                                        const WalletParseResult& wallet,
                                        const std::string& passphrase,
                                        const std::string& found_file = "FOUND_WALLET.txt");

/** After master recovered: decrypt all ckeys, consistency report, WIF dump. */
MultiCkeyDecryptResult decrypt_all_ckeys(const uint8_t master32[32],
                                         const WalletParseResult& wallet,
                                         const std::string& found_file = "FOUND_WALLET.txt");

/** AES-hit path: padding target matched; dual-verify with pubkey if present. */
DualVerifyResult dual_verify_aes_key(const uint8_t aes_key32[32],
                                     const WalletTarget& tgt,
                                     const WalletParseResult* wallet_opt = nullptr);

/** Random-key false-positive rate demo (research). */
std::string experiment_dual_fp_rate(int trials = 10000);
