#pragma once
#include "WalletDat.h"
#include "DualVerify.h"
#include <atomic>
#include <functional>
#include <string>
#include <vector>

struct RecallTokens {
  std::vector<std::string> known_words;
  std::vector<std::string> separators; /* "", " ", "-", "_", "." */
  std::vector<std::string> prefixes;
  std::vector<std::string> suffixes;
  std::vector<std::string> years;
  bool keyboard_walks = false;
  bool case_variants = true;
  bool leet = false;
  bool append_years = true;
};

struct CandidateGenStats {
  size_t count = 0;
  double space_log10 = 0;
  std::string summary;
};

struct PassphraseCrackProgress {
  std::atomic<uint64_t> tried{0};
  std::atomic<uint64_t> total{0};
  std::atomic<bool> running{false};
  std::atomic<bool> stop{false};
  std::atomic<bool> hit{false};
  double rate_hps = 0;
  std::string found_pass;
  std::string message;
  DualVerifyResult dual;
};

/** Rule-based mutants: case, leet, year append — no LLM. */
std::vector<std::string> apply_personality_mutants(const std::vector<std::string>& base,
                                                   const RecallTokens& tok, size_t max_out);

/** Token interview → candidate list. */
std::vector<std::string> generate_recall_candidates(const RecallTokens& tok, size_t max_out,
                                                    CandidateGenStats* stats = nullptr);

/** Simple mask: e.g. pass?d?d?d → pass0..pass9 expansions (digit/?l/?u/?s limited). */
std::vector<std::string> expand_simple_mask(const std::string& mask, size_t max_out);

/** Rough ETA given iterations and measured H/s. */
std::string format_passphrase_eta(uint32_t iterations, uint64_t candidates, double hps);

/** Batch try candidates; dual-verify on hit. */
bool run_passphrase_batch(const WalletParseResult& wallet,
                          const std::vector<std::string>& candidates,
                          PassphraseCrackProgress& prog,
                          const std::string& found_file = "FOUND_WALLET.txt");

/** Measure approximate H/s for this wallet's iteration count. */
double measure_kdf_hps(const MasterKeyInfo& mkey, int samples = 3);
