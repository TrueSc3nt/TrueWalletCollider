#pragma once
#include "WalletDat.h"
#include <string>
#include <vector>

struct ArchaeologyFinding {
  std::string flag; /* e.g. UNENCRYPTED_KEY, MULTI_MKEY, PLAINTEXT_SCRAP */
  std::string detail;
  size_t offset = 0;
  int severity = 1; /* 1=info 2=warn 3=critical */
};

struct ArchaeologyReport {
  std::vector<ArchaeologyFinding> findings;
  int unencrypted_keys = 0;
  int mkey_count = 0;
  int plaintext_scraps = 0;
  std::string summary;
};

/** Version archaeology: unencrypted key records, multiple mkeys, leftover scraps. */
ArchaeologyReport analyze_archaeology(const WalletParseResult& wallet,
                                      const uint8_t* data = nullptr, size_t len = 0);
