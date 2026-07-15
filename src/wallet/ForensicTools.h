#pragma once
#include "WalletDat.h"
#include <cstdint>
#include <string>
#include <vector>

struct Bip39Result {
  bool ok = false;
  bool checksum_ok = false;
  int word_count = 0;
  std::string message;
  std::vector<std::string> unknown_words;
};

struct BrainwalletResult {
  bool ok = false;
  std::string passphrase;
  std::string priv_hex;
  std::string wif_uncompressed;
  std::string wif_compressed;
  std::string message;
};

struct HexDumpResult {
  std::string hex_dump;
  double shannon_entropy = 0;
  size_t size = 0;
  std::string summary;
};

struct WalletDiffResult {
  bool ok = false;
  std::string report;
  size_t bytes_differ = 0;
  size_t size_a = 0;
  size_t size_b = 0;
  bool same_mkey = false;
  bool same_ckey_count = false;
  int ckeys_a = 0;
  int ckeys_b = 0;
};

struct StringsHit {
  size_t offset = 0;
  std::string text;
};

struct BalanceLookupResult {
  bool ok = false;
  std::string address;
  std::string raw_json;
  std::string message;
  bool http_attempted = false;
};

/** Load BIP39 English list from data/bip39_english.txt (or bundled path). */
bool bip39_load_wordlist(std::vector<std::string>* words_out, std::string* err = nullptr);

Bip39Result bip39_validate_mnemonic(const std::string& mnemonic);

/** Generate a BIP39 English mnemonic (12 or 24 words). */
bool bip39_generate_mnemonic(int word_count, std::string* mnemonic_out, std::string* err = nullptr);

/** BIP39 mnemonic → 64-byte seed (PBKDF2-HMAC-SHA512, 2048 rounds). */
bool bip39_mnemonic_to_seed(const std::string& mnemonic, const std::string& passphrase,
                            uint8_t seed64[64], std::string* err = nullptr);

BrainwalletResult brainwallet_sha256_to_wif(const std::string& passphrase);

std::string base58_encode_hex(const std::string& hex_payload);
std::string base58check_encode_versioned(uint8_t version, const uint8_t* payload, size_t len);

/** Bech32 encode (BIP173) — hrp + witness program bytes. */
std::string bech32_encode(const std::string& hrp, int witver, const uint8_t* prog, size_t prog_len);

HexDumpResult hex_dump_entropy(const uint8_t* data, size_t len, size_t max_bytes = 4096);
HexDumpResult hex_dump_file(const std::string& path, size_t max_bytes = 4096);

WalletDiffResult wallet_dat_diff(const std::string& path_a, const std::string& path_b);

std::vector<StringsHit> strings_scavenge(const uint8_t* data, size_t len, size_t min_len = 6,
                                         size_t max_hits = 500);
std::vector<StringsHit> strings_scavenge_file(const std::string& path, size_t min_len = 6);

/** Optional read-only HTTP balance via blockchain.info (WinHTTP). Off by default in GUI. */
BalanceLookupResult address_balance_lookup(const std::string& address, bool enable_http);

struct TriageWalletRow {
  std::string path;
  uint32_t iterations = 0;
  int ckeys = 0;
  size_t size = 0;
  bool mkey = false;
  std::string note;
};

std::vector<TriageWalletRow> multi_wallet_triage(const std::string& folder);
