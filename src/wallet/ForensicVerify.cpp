#include "ForensicVerify.h"
#include "HashcatExport.h"

#include <cctype>
#include <cstdio>
#include <fstream>
#include <sstream>

const char* verdict_cstr(VerifyVerdict v) {
  switch (v) {
    case VerifyVerdict::REAL: return "REAL";
    case VerifyVerdict::SUSPECT: return "SUSPECT";
    case VerifyVerdict::FAKE: return "FAKE";
    case VerifyVerdict::CORRUPT: return "CORRUPT";
    default: return "UNKNOWN";
  }
}

static void add_check(VerifyReport& r, const char* name, bool pass, const std::string& detail) {
  VerifyCheckItem c;
  c.name = name;
  c.pass = pass;
  c.detail = detail;
  r.checks.push_back(c);
  if (pass) r.score += 10;
  else r.score -= 5;
}

static void finalize(VerifyReport& r) {
  int pass_n = 0, fail_n = 0;
  for (auto& c : r.checks) {
    if (c.pass) ++pass_n;
    else ++fail_n;
  }
  if (r.checks.empty()) {
    r.verdict = VerifyVerdict::UNKNOWN;
  } else if (fail_n == 0 && pass_n >= 3) {
    r.verdict = VerifyVerdict::REAL;
  } else if (fail_n > pass_n && pass_n == 0) {
    r.verdict = VerifyVerdict::FAKE;
  } else if (fail_n >= 2 && r.score < 0) {
    r.verdict = VerifyVerdict::CORRUPT;
  } else if (fail_n > 0) {
    r.verdict = VerifyVerdict::SUSPECT;
  } else {
    r.verdict = VerifyVerdict::REAL;
  }
  r.verdict_label = verdict_cstr(r.verdict);
  std::ostringstream s;
  s << r.verdict_label << " — " << pass_n << " pass / " << fail_n << " fail (score " << r.score << ")";
  r.summary = s.str();
}

static bool looks_hex(const std::string& h, size_t min_len = 2) {
  if (h.size() < min_len || (h.size() % 2)) return false;
  for (char c : h) {
    if (!std::isxdigit((unsigned char)c)) return false;
  }
  return true;
}

VerifyReport verify_parsed_wallet(const WalletParseResult& w) {
  VerifyReport r;
  r.path = w.path;

  add_check(r, "file_readable", w.file_size > 0, "size=" + std::to_string(w.file_size));
  add_check(r, "bdb_magic", w.magic_ok,
            w.magic_ok ? ("magic=" + w.magic_hex) : ("magic missing — " + w.bdb_note));
  add_check(r, "mkey_present", w.mkey.found,
            w.mkey.found ? ("iters=" + std::to_string(w.mkey.iterations) + " salt_len=" +
                            std::to_string(w.mkey.salt.size()))
                         : "no structured mkey");
  if (w.mkey.found) {
    add_check(r, "mkey_enc48", w.mkey.encrypted48.size() == 48 || w.mkey.encrypted_hex.size() >= 64,
              "enc_hex_len=" + std::to_string(w.mkey.encrypted_hex.size()));
    add_check(r, "mkey_salt", w.mkey.salt.size() >= 8 || w.mkey.salt_hex.size() >= 16,
              "salt_hex=" + w.mkey.salt_hex.substr(0, 16));
    add_check(r, "mkey_iters_sane",
              w.mkey.iterations >= 1000 && w.mkey.iterations <= 5000000,
              "iterations=" + std::to_string(w.mkey.iterations));
    std::string hc = export_bitcoin_hashcat_line(w.mkey);
    add_check(r, "hashcat_export", !hc.empty(), hc.empty() ? "cannot build $bitcoin$" : hc.substr(0, 40) + "...");
  }
  add_check(r, "ckeys", !w.ckeys.empty(), "count=" + std::to_string(w.ckeys.size()));
  int addr_ok = 0;
  for (auto& c : w.ckeys)
    if (c.address_ok) ++addr_ok;
  if (!w.ckeys.empty()) {
    add_check(r, "ckey_addresses", addr_ok > 0,
              std::to_string(addr_ok) + "/" + std::to_string(w.ckeys.size()) + " address checksums OK");
    add_check(r, "ckey_blob48", w.ckeys[0].encrypted48.size() == 48 || w.ckeys[0].encrypted_hex.size() == 96,
              "first enc_hex_len=" + std::to_string(w.ckeys[0].encrypted_hex.size()));
  }

  /* Heuristic corrupt vs empty fake */
  if (w.file_size > 0 && !w.magic_ok && !w.mkey.found && w.ckeys.empty()) {
    add_check(r, "structure", false, "no BDB magic, mkey, or ckeys — corrupt or not a Core wallet");
  }

  finalize(r);
  /* Override: tiny non-wallet */
  if (w.file_size > 0 && w.file_size < 64 && !w.mkey.found) {
    r.verdict = VerifyVerdict::FAKE;
    r.verdict_label = "FAKE";
    r.summary = "FAKE — file too small / no wallet structures";
  }
  return r;
}

VerifyReport verify_wallet_file(const std::string& path) {
  WalletDatParser p;
  auto w = p.parse_file(path);
  auto r = verify_parsed_wallet(w);
  r.path = path;
  return r;
}

VerifyReport verify_bitcoin_hash_line(const std::string& line) {
  VerifyReport r;
  r.path = "($bitcoin$ line)";
  std::string s = line;
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
  add_check(r, "prefix", s.rfind("$bitcoin$", 0) == 0, s.substr(0, 32));
  if (s.rfind("$bitcoin$", 0) != 0) {
    finalize(r);
    r.verdict = VerifyVerdict::FAKE;
    r.verdict_label = "FAKE";
    r.summary = "FAKE — not a $bitcoin$ hash line";
    return r;
  }
  /* $bitcoin$LEN$HEX$SALTLEN$SALTHEX$ITERS$... */
  std::vector<std::string> parts;
  {
    std::string cur;
    for (char c : s) {
      if (c == '$') {
        parts.push_back(cur);
        cur.clear();
      } else
        cur.push_back(c);
    }
    parts.push_back(cur);
  }
  /* parts[0] empty, parts[1]=bitcoin, parts[2]=len, parts[3]=cry... */
  add_check(r, "field_count", parts.size() >= 8, "fields=" + std::to_string(parts.size()));
  if (parts.size() >= 6) {
    int cry_len = 0, salt_len = 0;
    try {
      cry_len = std::stoi(parts[2]);
      salt_len = std::stoi(parts[4]);
    } catch (...) {
    }
    add_check(r, "cry_hex", looks_hex(parts[3]) && (int)parts[3].size() == cry_len,
              "declared=" + parts[2] + " actual=" + std::to_string(parts[3].size()));
    add_check(r, "salt_hex", looks_hex(parts[5]) && (int)parts[5].size() == salt_len,
              "declared=" + parts[4] + " actual=" + std::to_string(parts[5].size()));
  }
  if (parts.size() >= 7) {
    int iters = 0;
    try {
      iters = std::stoi(parts[6]);
    } catch (...) {
    }
    add_check(r, "iters", iters >= 1000 && iters <= 5000000, "iters=" + std::to_string(iters));
  }
  finalize(r);
  return r;
}

VerifyReport verify_mkey_ckey_text(const std::string& text) {
  VerifyReport r;
  r.path = "(mkey/ckey text)";
  bool has_mkey = text.find("mkey") != std::string::npos || text.find("04mkey") != std::string::npos ||
                  text.find("encrypted") != std::string::npos;
  bool has_hex = false;
  size_t hex_run = 0;
  for (char c : text) {
    if (std::isxdigit((unsigned char)c)) {
      ++hex_run;
      if (hex_run >= 64) has_hex = true;
    } else
      hex_run = 0;
  }
  add_check(r, "mentions_key_material", has_mkey, has_mkey ? "keyword hit" : "no mkey/ckey keywords");
  add_check(r, "long_hex", has_hex, has_hex ? ">=32-byte hex run" : "no long hex");
  /* Try parse as wallet path if single line looks like a path */
  std::string path = text;
  while (!path.empty() && (path.back() == '\n' || path.back() == '\r')) path.pop_back();
  if (path.size() < 260 && (path.find(".dat") != std::string::npos || path.find('\\') != std::string::npos)) {
    std::ifstream f(path, std::ios::binary);
    if (f) return verify_wallet_file(path);
  }
  finalize(r);
  if (!has_mkey && !has_hex) {
    r.verdict = VerifyVerdict::FAKE;
    r.verdict_label = "FAKE";
    r.summary = "FAKE — no recognizable key material";
  }
  return r;
}

std::string verify_report_text(const VerifyReport& r) {
  std::ostringstream o;
  o << "=== Verify: " << r.verdict_label << " ===\n";
  o << "path: " << r.path << "\n";
  o << r.summary << "\n";
  for (auto& c : r.checks) {
    o << "  [" << (c.pass ? "OK" : "!!") << "] " << c.name << " — " << c.detail << "\n";
  }
  return o.str();
}
