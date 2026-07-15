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

/* ── Force Rebuild (Experimental) ───────────────────────────────────────────
 * Creates a NEW BIP39 key set + research mkey under a new passphrase.
 * Does NOT decrypt original encrypted ckeys. Does NOT unlock original funds.
 * May include UNENCRYPTED_KEY material found during carve (real salvage).
 */
struct ForceRebuildOptions {
  std::string new_mnemonic;           /* empty → generate 12-word BIP39 */
  std::string bip39_passphrase;       /* optional BIP39 passphrase (usually empty) */
  std::string new_wallet_passphrase;  /* e.g. "adam" for research mkey */
  uint32_t new_iterations = 50000;
  std::string export_dir = "rebuilt_NEW_wallet_EXPORT";
  bool write_side_wallet = false;     /* write wallet.dat.reweave_new beside original */
  std::string original_wallet_path;   /* for side-by-side write */
  int sample_address_count = 5;
};

struct ForceRebuildResult {
  bool ok = false;
  bool decrypts_original_ckeys = false; /* always false — honesty stamp */
  std::string warning_banner;
  std::string message;
  std::string mnemonic;
  std::string seed_hex;
  std::string bip32_master_priv_hex;
  std::string bip32_chain_hex;
  std::string xprv;
  std::string xpub;
  std::string research_mkey_enc_hex;
  std::string research_mkey_salt_hex;
  uint32_t research_mkey_iters = 0;
  std::vector<RebuildKeyExport> new_seed_keys;   /* from NEW BIP39 only */
  std::vector<RebuildKeyExport> salvaged_plain;  /* UNENCRYPTED_KEY from carve/parse */
  CarveReport carve;
  std::string inventory_summary;
  std::string json_bundle;
  std::string txt_bundle;
  std::string export_dir_written;
  std::string side_wallet_path;
  bool wrote_side_wallet = false;
};

/** Always rips apart (carve+inventory), then builds NEW-seed rematerialization package. */
ForceRebuildResult force_rebuild_experimental(const WalletParseResult& wallet,
                                              const std::vector<uint8_t>& raw,
                                              const ForceRebuildOptions& opt);

std::string force_rebuild_warning_banner();
