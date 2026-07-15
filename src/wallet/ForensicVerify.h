#pragma once
#include "WalletDat.h"
#include <string>
#include <vector>

enum class VerifyVerdict { REAL, SUSPECT, FAKE, CORRUPT, UNKNOWN };

struct VerifyCheckItem {
  std::string name;
  bool pass = false;
  std::string detail;
};

struct VerifyReport {
  VerifyVerdict verdict = VerifyVerdict::UNKNOWN;
  std::string verdict_label;
  std::string summary;
  std::string path;
  std::vector<VerifyCheckItem> checks;
  int score = 0; /* higher = more confidence real */
};

const char* verdict_cstr(VerifyVerdict v);

/** Verify wallet.dat / raw dump / mkey-ckey export path. */
VerifyReport verify_wallet_file(const std::string& path);

/** Verify a $bitcoin$ hash line (hashcat -m 11300 / John). */
VerifyReport verify_bitcoin_hash_line(const std::string& line);

/** Verify stand-alone mkey/ckey text blobs (hex fields). */
VerifyReport verify_mkey_ckey_text(const std::string& text);

/** Verify an already-parsed wallet structure. */
VerifyReport verify_parsed_wallet(const WalletParseResult& w);

std::string verify_report_text(const VerifyReport& r);
