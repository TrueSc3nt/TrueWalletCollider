#pragma once
/**
 * Outside Box — maximalist authorized-DFIR wallet.dat recovery modules.
 * Live memory / VSS: guided capture + user-supplied dumps / elevated PowerShell copies only.
 * No silent RAM stealers. No fake-balance scam generators.
 */
#include "WalletDat.h"
#include "DualVerify.h"
#include "PassphraseLab.h"
#include "Salvage.h"
#include "ForensicVerify.h"
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

/* ─── 1. Shadow-copy / VSS harvester ─── */
struct VssShadowEntry {
  std::string id;
  std::string device_object; /* \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN */
  std::string create_time;
  std::string volume;
  std::string note;
};

struct VssHarvestHit {
  std::string shadow_id;
  std::string source_path;
  std::string dest_path;
  size_t size = 0;
  bool copied = false;
  std::string message;
};

struct VssHarvestReport {
  bool elevated_attempted = false;
  bool ok = false;
  std::string summary;
  std::vector<VssShadowEntry> shadows;
  std::vector<VssHarvestHit> hits;
  std::string script_log;
};

/** List VSS via PowerShell (may need elevation). */
VssHarvestReport vss_list_shadows();
/** Copy wallet.dat* from listed shadows into case_out_dir (PowerShell elevate prompt). */
VssHarvestReport vss_harvest_wallets(const std::string& case_out_dir,
                                     const std::vector<std::string>& relative_wallet_paths);

/* ─── 2. NTFS undelete / MFT residual (user dump) ─── */
struct UnallocatedCarveHit {
  size_t offset = 0;
  std::string kind; /* mkey / ckey / wallet_magic / bip39ish */
  int score = 0;
  std::string preview;
};

struct UnallocatedCarveReport {
  std::string path;
  size_t file_size = 0;
  size_t scanned = 0;
  SalvageReport salvage;
  std::vector<UnallocatedCarveHit> extra;
  std::string summary;
};

/** Best-effort carve from unallocated / disk-image dump the user supplies. */
UnallocatedCarveReport carve_unallocated_dump(const std::string& path,
                                              std::atomic<bool>* stop = nullptr,
                                              std::function<void(size_t, size_t)> progress = nullptr);

/* ─── 3. Cloud sync ghost finder ─── */
struct GhostFileHit {
  std::string path;
  size_t size = 0;
  std::string kind; /* wallet.dat / conflict / tmp / numbered */
  uint64_t mtime_unix = 0;
};

struct GhostFinderReport {
  std::vector<GhostFileHit> hits;
  int dirs_walked = 0;
  std::string summary;
};

GhostFinderReport cloud_sync_ghost_find(const std::vector<std::string>& roots, int max_hits = 500);

/* ─── 4. Portable / leftover scanner ─── */
struct PortableScanHit {
  std::string path;
  size_t size = 0;
  std::string source; /* profile / usb / common */
  bool parseable = false;
  uint32_t iterations = 0;
  int ckeys = 0;
};

struct PortableScanReport {
  std::vector<PortableScanHit> hits;
  std::string summary;
};

PortableScanReport portable_leftover_scan(bool scan_usb_letters = true);

/* ─── 5. Unlock-session capture kit ─── */
struct UnlockSessionChecklist {
  bool tip_hibernate_off = false;
  bool tip_taskmgr_dump = false;
  bool tip_procdump = false;
  bool tip_import_only = true;
  std::string guidance_markdown;
};

UnlockSessionChecklist unlock_session_kit_guidance();

struct DumpScavengeHit {
  size_t offset = 0;
  std::string kind; /* string / hex32 / bip39 / passphraseish */
  std::string text;
  int score = 0;
};

struct DumpScavengeReport {
  std::string path;
  size_t file_size = 0;
  size_t scanned = 0;
  std::vector<DumpScavengeHit> hits;
  std::string summary;
};

/** String/key scavenger over user-supplied RAM / process dump. */
DumpScavengeReport scavenge_memory_dump(const std::string& path, size_t max_hits = 400,
                                        std::atomic<bool>* stop = nullptr,
                                        std::function<void(size_t, size_t)> progress = nullptr);

/* ─── 6. pagefile / hiberfil mnemonic+string hunt ─── */
DumpScavengeReport hunt_pagefile_hiberfil(const std::string& path, size_t max_hits = 800,
                                          std::atomic<bool>* stop = nullptr,
                                          std::function<void(size_t, size_t)> progress = nullptr);

/* ─── 7. GPU VRAM residue (experimental) ─── */
DumpScavengeReport scavenge_vram_dump_experimental(const std::string& path, size_t max_hits = 300,
                                                   std::atomic<bool>* stop = nullptr,
                                                   std::function<void(size_t, size_t)> progress = nullptr);

/* ─── 8. Passphrase-change archaeology ─── */
struct MultiMkeyAttackProgress {
  std::atomic<uint64_t> tried{0};
  std::atomic<uint64_t> total{0};
  std::atomic<bool> running{false};
  std::atomic<bool> stop{false};
  std::atomic<bool> hit{false};
  int hit_mkey_index = -1;
  std::string found_pass;
  DualVerifyResult dual;
  std::string message;
};

struct MultiMkeyAttackReport {
  std::vector<MasterKeyInfo> mkeys;
  bool hit = false;
  int hit_index = -1;
  std::string found_pass;
  DualVerifyResult dual;
  std::string summary;
};

std::vector<MasterKeyInfo> extract_all_mkeys(const uint8_t* data, size_t len);
bool attack_all_mkeys_shared_dict(const WalletParseResult& wallet,
                                  const std::vector<MasterKeyInfo>& mkeys,
                                  const std::vector<std::string>& dict,
                                  MultiMkeyAttackProgress& prog,
                                  const std::string& found_file = "FOUND_WALLET.txt");

/* ─── 9. Crash-dump partial AES keys ─── */
struct AesCandidate {
  size_t offset = 0;
  std::string hex32;
  int score = 0;
  DualVerifyResult dual;
  bool verified = false;
};

struct CrashDumpAesReport {
  std::string path;
  std::vector<AesCandidate> candidates;
  int verified_ok = 0;
  std::string summary;
};

CrashDumpAesReport extract_aes_candidates_from_dump(const std::string& path,
                                                    const WalletParseResult& wallet,
                                                    size_t max_cands = 256,
                                                    bool dual_verify = true,
                                                    std::atomic<bool>* stop = nullptr);

/* ─── 10. Descriptor / PSBT scrapyard ─── */
struct DescriptorScrapHit {
  size_t offset = 0;
  std::string kind; /* descriptor / psbt / xpub / xprv */
  std::string text;
};

struct DescriptorScrapReport {
  std::vector<DescriptorScrapHit> hits;
  std::string summary;
};

DescriptorScrapReport carve_descriptor_psbt_scrapyard(const uint8_t* data, size_t len,
                                                      size_t max_hits = 200);
DescriptorScrapReport carve_descriptor_psbt_file(const std::string& path);

/* ─── 11. Multi-wallet correlation / Two-Body ─── */
struct TwoBodyWallet {
  std::string path;
  WalletParseResult parsed;
  bool ok = false;
};

struct TwoBodyProgress {
  std::atomic<uint64_t> tried{0};
  std::atomic<uint64_t> total{0};
  std::atomic<bool> running{false};
  std::atomic<bool> stop{false};
  std::atomic<bool> hit{false};
  int hit_wallet_index = -1;
  std::string found_pass;
  DualVerifyResult dual;
  std::string message;
};

struct TwoBodyReport {
  std::vector<TwoBodyWallet> wallets;
  bool hit = false;
  int hit_index = -1;
  std::string found_pass;
  DualVerifyResult dual;
  std::string summary;
};

std::vector<TwoBodyWallet> twobody_load_case_folder(const std::string& folder);
bool twobody_shared_passphrase_attack(const std::vector<TwoBodyWallet>& wallets,
                                      const std::vector<std::string>& dict,
                                      TwoBodyProgress& prog,
                                      const std::string& found_file = "FOUND_WALLET.txt");

/* ─── 12. Keyboard adjacency / fat-finger masks ─── */
std::vector<std::string> keyboard_adjacency_mutants(const std::string& almost, size_t max_out = 5000);
std::vector<std::string> fat_finger_masks(const std::string& almost, size_t max_out = 5000);

/* ─── 13. Heir interview grammar ─── */
struct HeirInterview {
  std::string person_names;      /* comma / space separated */
  std::string places;
  std::string pets;
  std::string dates;             /* years / DDMMYYYY scraps */
  std::string hobbies;
  std::string free_story;        /* free text → tokenized */
  bool keyboard_walks = true;
  bool case_variants = true;
  bool leet = true;
  bool append_years = true;
};

std::vector<std::string> heir_interview_to_candidates(const HeirInterview& h, size_t max_out = 20000,
                                                     CandidateGenStats* stats = nullptr);

/* ─── 14. Password-manager CSV bridge ─── */
struct CsvBridgeReport {
  int rows = 0;
  int passwords = 0;
  int usernames = 0;
  std::vector<std::string> wordlist;
  std::string summary;
  std::string detected_format; /* chrome / bitwarden / keepass / generic */
};

CsvBridgeReport import_password_manager_csv(const std::string& path, size_t max_words = 100000);

/* ─── 15. Backup stitch surgeon ─── */
struct StitchReport {
  bool ok = false;
  DualVerifyResult dual;
  std::string master_hex;
  MultiCkeyDecryptResult decrypt;
  std::string summary;
};

/** mkey meta from wallet A + ckeys from wallet B → dual-verify with passphrase. */
StitchReport backup_stitch_try(const WalletParseResult& wallet_a_mkey_source,
                               const WalletParseResult& wallet_b_ckey_source,
                               const std::string& passphrase,
                               const std::string& found_file = "FOUND_WALLET.txt");

/* ─── 17. ChipWhisperer / EM trace importer ─── */
struct EmTraceImportReport {
  int candidates = 0;
  std::vector<std::string> hex_keys; /* 64 hex each when possible */
  std::vector<std::string> passphrase_guesses;
  std::string summary;
  bool experimental = true;
};

EmTraceImportReport import_chipwhisperer_csv(const std::string& path, size_t max_cands = 10000);
EmTraceImportReport import_em_trace_bin(const std::string& path, size_t max_cands = 4096);

/* ─── 18. Fault-injection candidate importer ─── */
struct FiCandidateReport {
  std::vector<std::string> hex_keys;
  std::vector<AesCandidate> verified;
  int ok_count = 0;
  std::string summary;
};

FiCandidateReport import_fault_injection_candidates(const std::string& paste_or_file,
                                                    const WalletParseResult& wallet,
                                                    bool dual_verify = true);

/* ─── 19. Fake-wallet detector++ ─── */
struct FakeWalletPlusReport {
  VerifyReport base;
  double entropy_score = 0;
  double consistency_score = 0;
  double overall = 0;
  std::vector<std::string> extras;
  std::string summary;
};

FakeWalletPlusReport fake_wallet_detector_plus(const WalletParseResult& w,
                                               const uint8_t* raw = nullptr, size_t len = 0);
FakeWalletPlusReport fake_wallet_detector_plus_file(const std::string& path);

/* ─── 20. Network timeline (read-only HTTP) ─── */
struct NetworkTimelineEvent {
  std::string address;
  std::string kind; /* balance / first_seen / n_tx */
  std::string value;
  std::string raw_snippet;
};

struct NetworkTimelineReport {
  bool http_ok = false;
  std::vector<NetworkTimelineEvent> events;
  std::string summary;
};

NetworkTimelineReport network_timeline_for_addresses(const std::vector<std::string>& addrs,
                                                     bool enable_http);

/* ─── 21. Time-Slice Crack ─── */
struct TimeSlicePlanItem {
  std::string path;
  uint64_t mtime_unix = 0;
  uint32_t iterations = 0;
  double priority = 0; /* higher = crack first (low iters * recent) */
  std::string reason;
};

struct TimeSlicePlan {
  std::vector<TimeSlicePlanItem> items;
  std::string summary;
};

TimeSlicePlan timeslice_crack_plan(const std::string& folder_or_case);

/* ─── 22. Keyhole mode ─── */
struct KeyholeSpec {
  std::string known_prefix_hex; /* leading known AES master bytes */
  std::string known_suffix_hex; /* optional trailing */
  std::vector<int> known_byte_indices; /* sparse known positions 0..31 */
  std::vector<uint8_t> known_byte_values;
  std::string note;
};

struct KeyholePlan {
  bool ok = false;
  uint64_t free_bytes = 32;
  double space_log2 = 256;
  std::string partial_prefix_for_cuda;
  std::string guidance;
};

KeyholePlan keyhole_build_plan(const KeyholeSpec& spec);

/* ─── 23. Seed Mirage Meter ─── */
struct SeedMirageScore {
  std::string mnemonic;
  bool bip39_checksum = false;
  int word_count = 0;
  double address_overlap = 0; /* 0..1 experimental */
  double score = 0;
  std::string note;
};

struct SeedMirageReport {
  std::vector<SeedMirageScore> ranked;
  std::string summary;
};

SeedMirageReport seed_mirage_meter(const std::vector<std::string>& carved_mnemonics,
                                   const WalletParseResult& wallet);

/* Helpers */
std::vector<std::string> load_dict_lines(const std::string& path, size_t max_lines = 500000);
bool write_text_file(const std::string& path, const std::string& body);
std::string outside_box_module_inventory();
