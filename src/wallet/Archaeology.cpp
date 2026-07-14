#include "Archaeology.h"

#include <algorithm>
#include <cstring>
#include <sstream>

ArchaeologyReport analyze_archaeology(const WalletParseResult& wallet, const uint8_t* data,
                                      size_t len) {
  ArchaeologyReport r;
  int mkeys = wallet.mkey.found ? 1 : 0;
  /* Count mkey meta tags as possible multiples */
  int mkey_tags = 0, key_tags = 0;
  for (auto& m : wallet.meta) {
    if (m.tag == "mkey") ++mkey_tags;
    if (m.tag == "key") ++key_tags;
  }
  if (mkey_tags > 1) {
    ArchaeologyFinding f;
    f.flag = "MULTI_MKEY";
    f.detail = "multiple mkey markers in file (" + std::to_string(mkey_tags) + ")";
    f.severity = 2;
    r.findings.push_back(f);
  }
  r.mkey_count = (std::max)(mkeys, mkey_tags);

  if (key_tags > 0) {
    ArchaeologyFinding f;
    f.flag = "UNENCRYPTED_KEY";
    f.detail = "legacy unencrypted 'key' records detected (" + std::to_string(key_tags) +
               ") — may contain plaintext privkeys";
    f.severity = 3;
    r.findings.push_back(f);
    r.unencrypted_keys = key_tags;
  }

  if (wallet.mkey.found && wallet.mkey.iterations > 0 && wallet.mkey.iterations < 10000) {
    ArchaeologyFinding f;
    f.flag = "LOW_ITER";
    f.detail = "nDeriveIterations=" + std::to_string(wallet.mkey.iterations) +
               " — prioritize passphrase lab (cheap KDF)";
    f.severity = 2;
    r.findings.push_back(f);
  }

  if (!wallet.magic_ok) {
    ArchaeologyFinding f;
    f.flag = "CORRUPT_OR_RAW";
    f.detail = "BDB magic mismatch — use Salvage carve";
    f.severity = 2;
    r.findings.push_back(f);
  }

  /* Plaintext scraps: look for WIF-like / 32-byte following 0x80 in raw dump */
  if (data && len > 64) {
    for (size_t i = 0; i + 37 <= len && r.plaintext_scraps < 20; ++i) {
      if (data[i] != 0x80) continue;
      /* crude: next 32 non-zero-ish + possible 0x01 compressed flag */
      int nz = 0;
      for (int j = 1; j <= 32; ++j)
        if (data[i + j]) ++nz;
      if (nz < 16) continue;
      ArchaeologyFinding f;
      f.flag = "PLAINTEXT_SCRAP";
      f.detail = "possible raw privkey-shaped blob (0x80 prefix)";
      f.offset = i;
      f.severity = 2;
      r.findings.push_back(f);
      ++r.plaintext_scraps;
      i += 32;
    }
  }

  if (wallet.ckeys.empty() && wallet.mkey.found) {
    ArchaeologyFinding f;
    f.flag = "MKEY_NO_CKEY";
    f.detail = "mkey present but no ckeys — salvage or incomplete wallet";
    f.severity = 2;
    r.findings.push_back(f);
  }

  std::ostringstream s;
  s << "Archaeology: mkeys=" << r.mkey_count << " unencrypted_key_tags=" << r.unencrypted_keys
    << " plaintext_scraps=" << r.plaintext_scraps << " findings=" << r.findings.size();
  r.summary = s.str();
  return r;
}
