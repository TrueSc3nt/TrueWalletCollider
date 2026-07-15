#pragma once
#include <string>
#include <vector>

struct PipelineHit {
  std::string kind;
  std::string path_or_offset;
  std::string snippet;
  int score = 0;
};

struct PipelineReport {
  bool ok = false;
  std::string summary;
  std::vector<PipelineHit> hits;
  std::string export_path;
  std::string hashcat_hint;
};

/** MetaMask: scan LevelDB folder / dump for vault JSON → write vault extract + mode hint. */
PipelineReport pipeline_metamask_leveldb(const std::string& folder_or_file);

/** Exodus: find seed.seco under path / AppData hint; prepare exodus2hashcat cmdline. */
PipelineReport pipeline_exodus_seco(const std::string& folder_or_file);

/** Electrum wallet file detector + Hashcat mode tips. */
PipelineReport pipeline_electrum_helper(const std::string& path);

/** BIP39 OCR text intake — file of OCR words → validate checksum. */
PipelineReport pipeline_bip39_ocr_intake(const std::string& text_file);

/** Email/mbox/eml scavenger for BIP39 word runs. */
PipelineReport pipeline_mbox_seed_scavenge(const std::string& path);

/** Browser extension walker — common Chrome/Edge/Brave profile IDs. */
PipelineReport pipeline_browser_extension_walker(const std::string& profile_root = "");

/** Heuristic SQLite / modern Core wallet string parse. */
PipelineReport pipeline_sqlite_core_wallet(const std::string& path);

/** Volatility-style user dump scan (reuses Outside Box scavenger honesty). */
PipelineReport pipeline_volatile_dump_scan(const std::string& path);

/** AddressDB builder hook — create folder + README for BTCRecover. */
PipelineReport pipeline_addressdb_builder_hook(const std::string& out_dir);

/** KeePass/CSV already in Outside Box — thin wrapper that calls import. */
PipelineReport pipeline_keepass_csv_bridge(const std::string& csv_path);

/** Orchestrator: path → recommend + run cheap native scans. */
PipelineReport pipeline_orchestrate_intake(const std::string& path);
