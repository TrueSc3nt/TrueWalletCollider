#pragma once
#include "WalletDat.h"
#include "DualVerify.h"
#include "ForensicVerify.h"
#include "ToolBridge.h"
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

struct MnemonicCarveHit {
  size_t offset = 0;
  int word_count = 0;
  bool bip39_checksum_ok = false;
  std::string text;
  std::string note; /* e.g. "BIP39 OK" / "looks like Electrum words" / "not Core-stored" */
};

struct CarveReport {
  bool classic_core_has_no_bip39 = true; /* honesty flag for typical Core wallet.dat */
  std::vector<MasterKeyInfo> mkeys;
  std::vector<CKeyInfo> ckeys;
  std::vector<MnemonicCarveHit> mnemonics;
  std::string summary;
};

/** Carve mkey/ckey + mnemonic-looking strings; honest about Core typically lacking BIP39. */
CarveReport breaker_carve(const uint8_t* data, size_t len, const WalletParseResult* parsed_opt);

enum class BreakStrategy {
  Verify = 0,
  Carve,
  NativeKdf,
  Hashcat11300,
  JohnBitcoin,
  BtcRecover,
  CudaPartial,
};

struct OrchestratorOptions {
  bool do_verify = true;
  bool do_carve = true;
  bool do_native_kdf = true;
  bool do_hashcat = false;
  bool do_john = false;
  bool do_btcrecover = false;
  bool do_cuda_partial = false;
  bool use_cpu = true;
  bool use_gpu = true;
  std::string dict_path;
  std::string tokenlist;
  std::string hash_export_path = "wallet_hash.txt";
  std::string partial_prefix_hex;
  std::vector<std::string> passphrase_candidates;
  int max_native_tries = 50000;
};

struct OrchestratorStepResult {
  BreakStrategy strategy;
  std::string name;
  bool ran = false;
  bool hit = false;
  std::string detail;
};

struct OrchestratorReport {
  VerifyReport verify;
  CarveReport carve;
  DualVerifyResult dual;
  bool has_dual = false;
  std::string master_hex;
  std::string recovered_passphrase;
  std::vector<OrchestratorStepResult> steps;
  std::string log;
  bool success = false;
};

/** Multi-strategy attack orchestrator (authorized owner recovery). */
OrchestratorReport breaker_orchestrate(const WalletParseResult& wallet,
                                       const std::vector<uint8_t>& raw,
                                       const OrchestratorOptions& opt,
                                       ProcessStreamer* hashcat_stream = nullptr,
                                       ProcessStreamer* btc_stream = nullptr);

struct RebuildKeyExport {
  std::string address;
  std::string pubkey_hex;
  std::string priv_hex;
  std::string wif_uncompressed;
  std::string wif_compressed;
};

struct RebuildPackage {
  bool ok = false;
  std::string message;
  std::string new_passphrase_note;
  std::string master_hex;
  std::string new_mkey_enc_hex;
  std::string new_salt_hex;
  uint32_t new_iterations = 0;
  std::vector<RebuildKeyExport> keys;
  std::string json_bundle;
  std::string txt_bundle;
  std::string research_ckey_note;
};

/** Rematerialize: decrypt all keys, optional re-encrypt mkey under new passphrase, export bundles. */
RebuildPackage breaker_rebuild(const uint8_t master32[32], const WalletParseResult& wallet,
                               const std::string& new_passphrase, uint32_t new_iterations = 50000,
                               bool craft_research_mkey = true);

bool breaker_write_package(const RebuildPackage& pkg, const std::string& out_prefix);
