#include "NativePipelines.h"
#include "ForensicTools.h"
#include "OutsideBox.h"
#include "ToolCatalog.h"
#include "WalletFormat.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

static std::string read_all(const std::string& path, size_t maxn = 64 * 1024 * 1024) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  if (s.size() > maxn) s.resize(maxn);
  return s;
}

static bool write_text(const std::string& path, const std::string& body) {
  std::ofstream o(path, std::ios::binary | std::ios::trunc);
  if (!o) return false;
  o.write(body.data(), (std::streamsize)body.size());
  return true;
}

static std::string to_lower(std::string s) {
  for (char& c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}

static void collect_files(const std::string& root, const std::string& glob_suffix,
                          std::vector<std::string>& out, int depth = 0) {
  if (depth > 8 || out.size() > 2000) return;
#ifdef _WIN32
  std::string base = root;
  if (!base.empty() && base.back() != '\\' && base.back() != '/') base += "\\";
  WIN32_FIND_DATAA fd{};
  HANDLE h = FindFirstFileA((base + "*").c_str(), &fd);
  if (h == INVALID_HANDLE_VALUE) return;
  do {
    std::string name = fd.cFileName;
    if (name == "." || name == "..") continue;
    std::string full = base + name;
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      collect_files(full, glob_suffix, out, depth + 1);
    } else {
      std::string low = to_lower(name);
      if (glob_suffix.empty() ||
          (low.size() >= glob_suffix.size() &&
           low.substr(low.size() - glob_suffix.size()) == glob_suffix))
        out.push_back(full);
      else if (glob_suffix == ".ldb" && (low.find(".ldb") != std::string::npos ||
                                         low.find(".log") != std::string::npos || low == "current" ||
                                         low == "manifest"))
        out.push_back(full);
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
#else
  (void)root;
  (void)glob_suffix;
  (void)out;
  (void)depth;
#endif
}

static bool looks_like_vault_json(const std::string& s) {
  return s.find("\"data\"") != std::string::npos && s.find("\"iv\"") != std::string::npos &&
         (s.find("\"salt\"") != std::string::npos || s.find("KeyringController") != std::string::npos);
}

PipelineReport pipeline_metamask_leveldb(const std::string& folder_or_file) {
  PipelineReport r;
  std::vector<std::string> files;
  std::ifstream probe(folder_or_file, std::ios::binary);
  if (probe) {
    files.push_back(folder_or_file);
  } else {
    collect_files(folder_or_file, ".ldb", files);
  }
  std::ostringstream extracted;
  for (auto& path : files) {
    std::string blob = read_all(path, 8 * 1024 * 1024);
    if (blob.empty()) continue;
    /* sliding crude scan for vault-like JSON substrings */
    for (size_t i = 0; i + 32 < blob.size(); ++i) {
      if (blob[i] != '{') continue;
      size_t end = blob.find('}', i);
      if (end == std::string::npos || end - i > 200000) continue;
      /* expand to larger brace region */
      size_t j = i;
      int depth = 0;
      for (; j < blob.size() && j < i + 500000; ++j) {
        if (blob[j] == '{') ++depth;
        else if (blob[j] == '}') {
          --depth;
          if (depth == 0) {
            ++j;
            break;
          }
        }
      }
      if (depth != 0) continue;
      std::string chunk = blob.substr(i, j - i);
      if (looks_like_vault_json(chunk)) {
        PipelineHit h;
        h.kind = "metamask_vault";
        h.path_or_offset = path + " @" + std::to_string(i);
        h.snippet = chunk.substr(0, (std::min)(chunk.size(), (size_t)240));
        h.score = 90;
        r.hits.push_back(h);
        extracted << "// from " << path << " offset " << i << "\n" << chunk << "\n\n";
        i = j;
      }
    }
  }
  if (!r.hits.empty()) {
    r.export_path = "metamask_vault_extract.json.txt";
    write_text(r.export_path, extracted.str());
    r.hashcat_hint =
        "Use metamask_pwn / metamask-leveldb-forensic-tools → Hashcat -m 26600 or 26620 "
        "(dynamic iters). BTCRecover also supports MetaMask extract scripts.";
    r.ok = true;
    r.summary = "Found " + std::to_string(r.hits.size()) + " vault-like JSON blob(s). Wrote " +
                r.export_path;
  } else {
    r.summary = "No vault-like JSON found. Tip: point at Chrome Extension Settings/"
                "nkbihfbeogaeaoehlefnkodbefgpgknn/ LevelDB folder.";
  }
  return r;
}

PipelineReport pipeline_exodus_seco(const std::string& folder_or_file) {
  PipelineReport r;
  std::vector<std::string> files;
  std::string low = to_lower(folder_or_file);
  if (low.find(".seco") != std::string::npos) {
    files.push_back(folder_or_file);
  } else {
    collect_files(folder_or_file, ".seco", files);
#ifdef _WIN32
    char* appdata = nullptr;
    size_t len = 0;
    if (_dupenv_s(&appdata, &len, "APPDATA") == 0 && appdata) {
      collect_files(std::string(appdata) + "\\Exodus\\exodus.wallet", ".seco", files);
      free(appdata);
    }
#endif
  }
  for (auto& p : files) {
    PipelineHit h;
    h.kind = "exodus_seco";
    h.path_or_offset = p;
    h.snippet = "Exodus seed.seco candidate";
    h.score = 80;
    r.hits.push_back(h);
  }
  if (!r.hits.empty()) {
    r.hashcat_hint =
        "python third_party/hashcat/tools/exodus2hashcat.py <seed.seco> → hashcat -m 28200";
    r.ok = true;
    r.summary = "Found " + std::to_string(r.hits.size()) + " .seco file(s). " + r.hashcat_hint;
  } else {
    r.summary = "No .seco found. Typical path: %APPDATA%\\Exodus\\exodus.wallet\\seed.seco";
  }
  return r;
}

PipelineReport pipeline_electrum_helper(const std::string& path) {
  PipelineReport r;
  std::string blob = read_all(path, 4 * 1024 * 1024);
  if (blob.empty()) {
    r.summary = "cannot read " + path;
    return r;
  }
  std::string low = to_lower(blob);
  bool looks = low.find("seed_version") != std::string::npos ||
               low.find("keystore") != std::string::npos || low.find("xpub") != std::string::npos ||
               low.find("electrum") != std::string::npos || path.find("default_wallet") != std::string::npos;
  if (looks) {
    PipelineHit h;
    h.kind = "electrum_wallet";
    h.path_or_offset = path;
    h.snippet = "Electrum-like wallet JSON/text";
    h.score = 70;
    r.hits.push_back(h);
    r.hashcat_hint =
        "Hashcat -m 16600 / 21700 / 21800 depending on Electrum version; "
        "BTCRecover --wallet with Electrum extract; Hydra CUDA Electrum modes experimental.";
    r.ok = true;
    r.summary = "Electrum-like wallet detected. " + r.hashcat_hint;
  } else {
    r.summary = "Does not look like Electrum wallet text/JSON.";
  }
  return r;
}

PipelineReport pipeline_bip39_ocr_intake(const std::string& text_file) {
  PipelineReport r;
  std::string text = read_all(text_file, 2 * 1024 * 1024);
  if (text.empty()) {
    r.summary = "empty/unreadable OCR text file";
    return r;
  }
  /* normalize to words */
  std::string cur, mnemonic;
  int words = 0;
  for (char c : text) {
    if (std::isalpha((unsigned char)c))
      cur.push_back((char)std::tolower((unsigned char)c));
    else if (!cur.empty()) {
      if (!mnemonic.empty()) mnemonic.push_back(' ');
      mnemonic += cur;
      ++words;
      cur.clear();
    }
  }
  if (!cur.empty()) {
    if (!mnemonic.empty()) mnemonic.push_back(' ');
    mnemonic += cur;
    ++words;
  }
  auto v = bip39_validate_mnemonic(mnemonic);
  PipelineHit h;
  h.kind = "ocr_mnemonic";
  h.path_or_offset = text_file;
  h.snippet = mnemonic.substr(0, (std::min)(mnemonic.size(), (size_t)200));
  h.score = v.ok ? 100 : (v.unknown_words.empty() ? 40 : 10);
  r.hits.push_back(h);
  r.ok = v.ok;
  r.summary = "OCR intake words≈" + std::to_string(words) + " — " + v.message;
  if (!v.unknown_words.empty()) {
    r.summary += " unknown:";
    for (size_t i = 0; i < v.unknown_words.size() && i < 8; ++i) r.summary += " " + v.unknown_words[i];
  }
  r.hashcat_hint =
      "If checksum OK: use BTCRecover seedrecover / seedcat / Hydra with known address or xpub. "
      "Never feed OCR garbage as entropy.";
  return r;
}

PipelineReport pipeline_mbox_seed_scavenge(const std::string& path) {
  PipelineReport r;
  auto dump = scavenge_memory_dump(path, 200);
  std::vector<std::string> wordlist;
  bip39_load_wordlist(&wordlist, nullptr);
  std::ostringstream o;
  for (auto& hit : dump.hits) {
    if (hit.kind.find("bip39") != std::string::npos || hit.score >= 50) {
      PipelineHit h;
      h.kind = hit.kind;
      h.path_or_offset = std::to_string(hit.offset);
      h.snippet = hit.text.substr(0, (std::min)(hit.text.size(), (size_t)160));
      h.score = hit.score;
      r.hits.push_back(h);
    }
  }
  /* also extract 12/24 alpha word runs and validate */
  std::string blob = read_all(path, 16 * 1024 * 1024);
  std::vector<std::string> toks;
  std::string cur;
  for (char c : blob) {
    if (std::isalpha((unsigned char)c))
      cur.push_back((char)std::tolower((unsigned char)c));
    else if (!cur.empty()) {
      toks.push_back(cur);
      cur.clear();
    }
  }
  for (size_t i = 0; i + 12 <= toks.size(); ++i) {
    for (int n : {12, 15, 18, 21, 24}) {
      if (i + (size_t)n > toks.size()) continue;
      std::string m;
      for (int k = 0; k < n; ++k) {
        if (k) m.push_back(' ');
        m += toks[i + k];
      }
      auto v = bip39_validate_mnemonic(m);
      if (v.ok) {
        PipelineHit h;
        h.kind = "bip39_checksum_ok";
        h.path_or_offset = "token@" + std::to_string(i);
        h.snippet = m;
        h.score = 100;
        r.hits.push_back(h);
      }
    }
  }
  r.ok = !r.hits.empty();
  r.summary = dump.summary + " | BIP39-valid runs: " +
              std::to_string(std::count_if(r.hits.begin(), r.hits.end(), [](const PipelineHit& h) {
                return h.kind == "bip39_checksum_ok";
              }));
  return r;
}

PipelineReport pipeline_browser_extension_walker(const std::string& profile_root) {
  PipelineReport r;
  struct Ext {
    const char* id;
    const char* name;
  };
  static const Ext exts[] = {
      {"nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"},
      {"bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"},
      {"acmacodkjbdgmoleebolmdjonilkdbch", "Rabby"},
      {"fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin"},
      {"hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet"},
      {"fhbohimaesofhdjckmhpchloaajgahoa", "Binance Chain"},
  };
  std::vector<std::string> roots;
  if (!profile_root.empty()) roots.push_back(profile_root);
#ifdef _WIN32
  char* la = nullptr;
  size_t len = 0;
  if (_dupenv_s(&la, &len, "LOCALAPPDATA") == 0 && la) {
    roots.push_back(std::string(la) + "\\Google\\Chrome\\User Data");
    roots.push_back(std::string(la) + "\\Microsoft\\Edge\\User Data");
    roots.push_back(std::string(la) + "\\BraveSoftware\\Brave-Browser\\User Data");
    free(la);
  }
#endif
  for (auto& root : roots) {
    for (auto& e : exts) {
      std::string p = root + "\\Default\\Local Extension Settings\\" + e.id;
#ifdef _WIN32
      DWORD a = GetFileAttributesA(p.c_str());
      if (a != INVALID_FILE_ATTRIBUTES) {
        PipelineHit h;
        h.kind = "extension_leveldb";
        h.path_or_offset = p;
        h.snippet = e.name;
        h.score = 85;
        r.hits.push_back(h);
      }
#endif
    }
  }
  r.ok = !r.hits.empty();
  r.summary = r.ok ? ("Found " + std::to_string(r.hits.size()) + " extension LevelDB path(s)")
                   : "No known wallet extension LevelDB folders under profile roots";
  r.hashcat_hint = "Feed MetaMask paths to MetaMask LevelDB Vault Pipe / metamask_pwn.";
  return r;
}

PipelineReport pipeline_sqlite_core_wallet(const std::string& path) {
  PipelineReport r;
  std::string blob = read_all(path, 32 * 1024 * 1024);
  if (blob.size() < 16) {
    r.summary = "unreadable";
    return r;
  }
  bool sqlite = blob.compare(0, 15, "SQLite format 3") == 0;
  bool has_mkey = blob.find("mkey") != std::string::npos;
  bool has_ckey = blob.find("ckey") != std::string::npos;
  PipelineHit h;
  h.kind = sqlite ? "sqlite_wallet" : "binary_wallet";
  h.path_or_offset = path;
  h.snippet = std::string("sqlite=") + (sqlite ? "yes" : "no") + " mkey=" + (has_mkey ? "yes" : "no") +
              " ckey=" + (has_ckey ? "yes" : "no");
  h.score = (sqlite && has_mkey) ? 90 : (has_mkey ? 60 : 20);
  r.hits.push_back(h);
  r.ok = has_mkey || sqlite;
  r.summary = h.snippet +
              ". Prefer BTCRecover/bitcoin2john for SQLite Core ≥0.21; native Extract still covers BDB.";
  r.hashcat_hint = "hashcat -m 11300 after bitcoin2john / --export-hashcat";
  return r;
}

PipelineReport pipeline_volatile_dump_scan(const std::string& path) {
  PipelineReport r;
  auto dump = scavenge_memory_dump(path, 400);
  for (auto& hit : dump.hits) {
    PipelineHit h;
    h.kind = hit.kind;
    h.path_or_offset = std::to_string(hit.offset);
    h.snippet = hit.text.substr(0, (std::min)(hit.text.size(), (size_t)120));
    h.score = hit.score;
    r.hits.push_back(h);
  }
  r.ok = !r.hits.empty();
  r.summary = dump.summary + " (import-only; no silent RAM capture)";
  return r;
}

PipelineReport pipeline_addressdb_builder_hook(const std::string& out_dir) {
  PipelineReport r;
  std::string dir = out_dir.empty() ? "data\\addressdb" : out_dir;
#ifdef _WIN32
  CreateDirectoryA("data", nullptr);
  CreateDirectoryA(dir.c_str(), nullptr);
#endif
  std::string readme = dir + "\\README_AddressDB.txt";
  std::string body =
      "TrueWalletCollider AddressDB builder hook\n"
      "Made by TrueScent — https://t.me/TrueScent\n\n"
      "Purpose: prepare inputs for BTCRecover address database (seed mode without full GPU farm).\n"
      "1. Place known owner addresses (one per line) in addresses.txt\n"
      "2. Or place block explorer CSV dumps here\n"
      "3. Use BTCRecover's create-address-database tooling from third_party/btcrecover\n"
      "4. Then seedrecover / seedcat / Hydra with the DB or bloom\n\n"
      "Honesty: blind BIP39 entropy without address/xpub is not practical.\n";
  write_text(readme, body);
  write_text(dir + "\\addresses.txt", "# one address per line\n");
  write_text(dir + "\\run_build_hint.bat",
             "@echo off\n"
             "echo See BTCRecover docs: create-address-database\n"
             "echo python ..\\..\\third_party\\btcrecover\\... (version-dependent script names)\n"
             "pause\n");
  r.ok = true;
  r.export_path = dir;
  r.summary = "AddressDB hook folder ready: " + dir;
  r.hashcat_hint = "Not a Hashcat mode — feeds seed GPU / BTCRecover.";
  return r;
}

PipelineReport pipeline_keepass_csv_bridge(const std::string& csv_path) {
  PipelineReport r;
  auto csv = import_password_manager_csv(csv_path);
  r.summary = csv.summary;
  r.ok = csv.passwords > 0;
  if (r.ok) {
    r.export_path = "csv_bridge_wordlist.txt";
    std::ostringstream o;
    for (auto& w : csv.wordlist) o << w << "\n";
    write_text(r.export_path, o.str());
    r.hashcat_hint = "Feed " + r.export_path + " to Hashcat -a 0 -m 11300 or Passphrase Lab dict.";
  }
  return r;
}

PipelineReport pipeline_orchestrate_intake(const std::string& path) {
  /* Delegate to Open Any Wallet detect/open for first-class multi-format routing. */
  auto d = open_any_wallet(path);
  PipelineReport r;
  r.ok = d.open_ok || d.family != WalletFamily::Unknown;
  r.summary = d.status_line + "\n" + d.crack_hint;
  if (!d.hash_export_path.empty()) r.export_path = d.hash_export_path;
  r.hashcat_hint = d.hashcat_mode ? ("hashcat -m " + std::to_string(d.hashcat_mode)) : d.crack_hint;
  for (auto& line : d.inventory) {
    PipelineHit h;
    h.kind = "inventory";
    h.path_or_offset = path;
    h.snippet = line;
    h.score = 50;
    r.hits.push_back(h);
  }
  if (!d.pipeline.hits.empty())
    r.hits.insert(r.hits.end(), d.pipeline.hits.begin(), d.pipeline.hits.end());
  return r;
}
