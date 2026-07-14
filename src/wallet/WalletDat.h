#pragma once
/**
 * TrueWalletCollider — Bitcoin Core wallet.dat best-effort parser.
 * Clean-room reimplementation inspired by BitcoinWalletAnalyzer (Mizogg)
 * byte-pattern extraction + additional Berkeley DB / key-name scans.
 */
#include <cstdint>
#include <string>
#include <vector>

struct MasterKeyInfo {
  bool found = false;
  std::vector<uint8_t> encrypted48;   /* 48-byte AES blob used by CUDA cracker */
  std::vector<uint8_t> encrypted49;   /* as stored after 04mkey marker (often 49) */
  std::vector<uint8_t> salt;          /* typically 8 bytes (+ optional pad) */
  uint32_t method = 0;
  uint32_t iterations = 0;
  std::string encrypted_hex;
  std::string salt_hex;
  std::string iv_hex;                 /* bytes [16..32) of encrypted master key */
  std::string ct_hex;                 /* last 16 bytes */
  std::string target_mkey_hex;        /* hashcat-style target string */
  size_t file_offset = 0;
};

struct CKeyInfo {
  std::vector<uint8_t> encrypted48;
  std::vector<uint8_t> pubkey;
  std::string encrypted_hex;
  std::string pubkey_hex;
  std::string address;
  std::string address_raw_hex;        /* version+hash160+checksum */
  std::string sha256_hex;
  std::string ripemd160_hex;
  size_t file_offset = 0;
  bool address_ok = false;
};

struct MetaHit {
  std::string tag;     /* e.g. "version", "bestblock", "name", "pool" */
  size_t offset = 0;
  std::string preview_hex;  /* short surrounding hex */
  std::string note;
};

struct WalletParseResult {
  std::string path;
  size_t file_size = 0;
  bool magic_ok = false;
  std::string magic_hex;
  std::string bdb_note;
  MasterKeyInfo mkey;
  std::vector<CKeyInfo> ckeys;
  std::vector<MetaHit> meta;
  std::vector<std::string> warnings;
  std::vector<std::string> log;

  /* Derived / export helpers */
  int ckey_count() const { return (int)ckeys.size(); }
  bool encrypted() const { return mkey.found || !ckeys.empty(); }
};

class WalletDatParser {
 public:
  WalletParseResult parse_file(const std::string& path);
  WalletParseResult parse_bytes(const uint8_t* data, size_t len,
                                const std::string& path_label = "");

  static std::string export_txt(const WalletParseResult& r);
  static std::string export_json(const WalletParseResult& r);
  static bool write_ckeys_file(const WalletParseResult& r, const std::string& path);
  static bool write_mkeys_file(const WalletParseResult& r, const std::string& path);
};
