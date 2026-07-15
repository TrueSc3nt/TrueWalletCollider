#include "ToolCatalog.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#endif

#include "ToolCatalogData.inc"

static std::string module_dir() {
#ifdef _WIN32
  char module[MAX_PATH] = {};
  if (GetModuleFileNameA(nullptr, module, MAX_PATH)) {
    std::string dir = module;
    size_t slash = dir.find_last_of("\\/");
    if (slash != std::string::npos) return dir.substr(0, slash + 1);
  }
#endif
  return {};
}

static bool path_exists(const std::string& p) {
  if (p.empty()) return false;
  std::ifstream f(p, std::ios::binary);
  return (bool)f;
}

static bool dir_or_file_exists(const std::string& p) {
  if (path_exists(p)) return true;
#ifdef _WIN32
  DWORD a = GetFileAttributesA(p.c_str());
  return a != INVALID_FILE_ATTRIBUTES;
#else
  return false;
#endif
}

static std::string resolve_hint(const std::string& hint) {
  if (hint.empty()) return {};
  std::string root = module_dir();
  std::vector<std::string> cands = {hint, root + hint};
  std::string alt = hint;
  for (char& c : alt)
    if (c == '/') c = '\\';
  cands.push_back(alt);
  cands.push_back(root + alt);
  for (auto& c : cands)
    if (dir_or_file_exists(c)) return c;
  return {};
}

const char* tool_category_name(ToolCategory c) {
  switch (c) {
    case ToolCategory::Crackers: return "Crackers";
    case ToolCategory::Carvers: return "Carvers";
    case ToolCategory::SeedGPU: return "Seed GPU";
    case ToolCategory::Browser: return "Browser";
    case ToolCategory::Mobile: return "Mobile";
    case ToolCategory::Memory: return "Memory";
    case ToolCategory::DiskVSS: return "Disk/VSS";
    case ToolCategory::OCREmail: return "OCR/Email";
    case ToolCategory::Password: return "Password";
    case ToolCategory::CommercialLE: return "Commercial LE";
    case ToolCategory::OnChain: return "On-chain labeling";
    case ToolCategory::Native: return "Native / First-party";
    case ToolCategory::Research: return "Research / Quickfire";
    case ToolCategory::Imaging: return "Imaging / Acquisition";
  }
  return "?";
}

const char* tool_kind_name(ToolKind k) {
  switch (k) {
    case ToolKind::Native: return "Native";
    case ToolKind::SetupFetch: return "Setup";
    case ToolKind::Bridge: return "Bridge";
    case ToolKind::Commercial: return "Commercial";
    case ToolKind::Experimental: return "Experimental";
    case ToolKind::Idea: return "Idea";
  }
  return "?";
}

const char* tool_status_name(ToolInstallStatus s) {
  switch (s) {
    case ToolInstallStatus::Runnable: return "Runnable";
    case ToolInstallStatus::Installed: return "Installed";
    case ToolInstallStatus::Missing: return "Missing";
    case ToolInstallStatus::BridgeAvailable: return "Bridge OK";
    case ToolInstallStatus::CommercialMissing: return "Install separately";
    case ToolInstallStatus::IdeaOnly: return "Catalog/Idea";
    case ToolInstallStatus::Unknown: return "Unknown";
  }
  return "?";
}

std::vector<CatalogEntry> tool_catalog_all() {
  std::vector<CatalogEntry> out;
  tool_catalog_fill(out);
  return out;
}

static std::map<std::string, std::string> load_commercial_paths() {
  std::map<std::string, std::string> m;
  std::string cfg = commercial_config_path();
  std::ifstream f(cfg);
  if (!f) return m;
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    m[line.substr(0, eq)] = line.substr(eq + 1);
  }
  return m;
}

std::string commercial_config_path() {
  return module_dir() + "data\\commercial_paths.ini";
}

void commercial_set_user_path(const std::string& id, const std::string& path) {
  auto m = load_commercial_paths();
  m[id] = path;
  std::string cfg = commercial_config_path();
#ifdef _WIN32
  CreateDirectoryA((module_dir() + "data").c_str(), nullptr);
#endif
  std::ofstream o(cfg, std::ios::trunc);
  o << "# TrueWalletCollider commercial Integration Hub paths\n";
  o << "# Never pirate — configure licensed installs only\n";
  for (auto& kv : m) o << kv.first << "=" << kv.second << "\n";
}

static std::string detect_common_commercial(const std::string& id) {
  auto user = load_commercial_paths();
  if (user.count(id) && dir_or_file_exists(user[id])) return user[id];
#ifdef _WIN32
  std::vector<std::string> guesses;
  if (id == "cellebrite")
    guesses = {"C:\\Program Files\\Cellebrite", "C:\\Program Files (x86)\\Cellebrite"};
  else if (id == "magnet_axiom")
    guesses = {"C:\\Program Files\\Magnet Forensics\\AXIOM",
               "C:\\Program Files\\Magnet AXIOM"};
  else if (id == "magnet_graykey")
    guesses = {"C:\\Program Files\\Magnet Forensics"};
  else if (id == "belkasoft")
    guesses = {"C:\\Program Files\\Belkasoft", "C:\\Program Files\\Belkasoft Evidence Center"};
  else if (id == "msab")
    guesses = {"C:\\Program Files\\MSAB", "C:\\Program Files (x86)\\MSAB"};
  else if (id == "oxygen")
    guesses = {"C:\\Program Files\\Oxygen Forensics", "C:\\Program Files\\Oxygen Forensic Detective"};
  else if (id == "xways")
    guesses = {"C:\\Program Files\\X-Ways Forensics", "C:\\xwforensics"};
  else if (id == "encase")
    guesses = {"C:\\Program Files\\EnCase", "C:\\Program Files\\OpenText\\EnCase"};
  else if (id == "ftk")
    guesses = {"C:\\Program Files\\AccessData\\FTK", "C:\\Program Files\\Exterro\\FTK"};
  else if (id == "passware")
    guesses = {"C:\\Program Files\\Passware", "C:\\Program Files (x86)\\Passware"};
  else if (id == "elcomsoft_edpr")
    guesses = {"C:\\Program Files\\Elcomsoft\\Distributed Password Recovery",
               "C:\\Program Files\\Elcomsoft"};
  else if (id == "maltego")
    guesses = {"C:\\Program Files\\Maltego", "C:\\Program Files (x86)\\Maltego"};
  else if (id == "autopsy")
    guesses = {"C:\\Program Files\\Autopsy", "C:\\Program Files\\BasisTech\\Autopsy"};
  else if (id == "kape")
    guesses = {"C:\\KAPE", "C:\\Program Files\\KAPE"};
  else if (id == "shadowexplorer")
    guesses = {"C:\\Program Files\\ShadowExplorer", "C:\\Program Files (x86)\\ShadowExplorer"};
  for (auto& g : guesses)
    if (dir_or_file_exists(g)) return g;
#endif
  return {};
}

std::vector<CatalogEntryRuntime> tool_catalog_refresh() {
  auto base = tool_catalog_all();
  std::vector<CatalogEntryRuntime> out;
  out.reserve(base.size());
  for (auto& e : base) {
    CatalogEntryRuntime r;
    static_cast<CatalogEntry&>(r) = e;
    switch (e.kind) {
      case ToolKind::Native:
        r.status = ToolInstallStatus::Runnable;
        r.status_label = "Runnable (native)";
        r.resolved_path = "built-in";
        break;
      case ToolKind::SetupFetch:
      case ToolKind::Experimental: {
        r.resolved_path = resolve_hint(e.detect_hint);
        if (!r.resolved_path.empty()) {
          r.status = ToolInstallStatus::Installed;
          r.status_label = (e.kind == ToolKind::Experimental) ? "Installed (experimental)"
                                                              : "Installed (setup)";
        } else {
          r.status = ToolInstallStatus::Missing;
          r.status_label = "Missing — run setup_forensics.bat";
        }
        break;
      }
      case ToolKind::Bridge: {
        r.resolved_path = detect_common_commercial(e.id);
        if (r.resolved_path.empty()) r.resolved_path = resolve_hint(e.detect_hint);
        if (!r.resolved_path.empty()) {
          r.status = ToolInstallStatus::BridgeAvailable;
          r.status_label = "Bridge available";
        } else {
          r.status = ToolInstallStatus::Missing;
          r.status_label = "Not found — configure path or install";
        }
        break;
      }
      case ToolKind::Commercial: {
        r.resolved_path = detect_common_commercial(e.id);
        if (!r.resolved_path.empty()) {
          r.status = ToolInstallStatus::BridgeAvailable;
          r.status_label = "Licensed install detected";
        } else {
          r.status = ToolInstallStatus::CommercialMissing;
          r.status_label = "Install separately (never pirate)";
        }
        break;
      }
      case ToolKind::Idea:
        r.status = ToolInstallStatus::IdeaOnly;
        r.status_label = "Catalog entry / research idea";
        break;
    }
    out.push_back(std::move(r));
  }
  return out;
}

CatalogStats tool_catalog_stats(const std::vector<CatalogEntryRuntime>& rows) {
  CatalogStats s;
  s.total = (int)rows.size();
  for (auto& r : rows) {
    switch (r.kind) {
      case ToolKind::Native: ++s.native_runnable; break;
      case ToolKind::SetupFetch:
        if (r.status == ToolInstallStatus::Installed || r.status == ToolInstallStatus::Runnable)
          ++s.setup_installed;
        else
          ++s.setup_missing;
        break;
      case ToolKind::Bridge: ++s.bridge; break;
      case ToolKind::Commercial: ++s.commercial; break;
      case ToolKind::Experimental:
        ++s.experimental;
        if (r.status == ToolInstallStatus::Installed) ++s.setup_installed;
        else ++s.setup_missing;
        break;
      case ToolKind::Idea: ++s.idea; break;
    }
  }
  std::ostringstream o;
  o << "Universal Tool Bay catalog: " << s.total << " entries\n"
    << "  Native runnable: " << s.native_runnable << "\n"
    << "  Setup/Experimental installed: " << s.setup_installed
    << "  missing: " << s.setup_missing << "\n"
    << "  Bridge: " << s.bridge << "  Commercial LE/On-chain: " << s.commercial << "\n"
    << "  Research/quickfire ideas: " << s.idea << "\n"
    << "Honesty: commercial = bridge only; GPU seed tools often experimental;\n"
    << "on-chain labeling ≠ local crack. Made by TrueScent — https://t.me/TrueScent\n";
  s.summary = o.str();
  return s;
}

static std::string lower(std::string s) {
  for (char& c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}

std::vector<CatalogEntryRuntime> tool_catalog_filter(const std::vector<CatalogEntryRuntime>& rows,
                                                     const std::string& search,
                                                     ToolCategory* category_filter,
                                                     bool only_runnable) {
  std::string q = lower(search);
  std::vector<CatalogEntryRuntime> out;
  for (auto& r : rows) {
    if (category_filter && r.category != *category_filter) continue;
    if (only_runnable) {
      if (!(r.status == ToolInstallStatus::Runnable || r.status == ToolInstallStatus::Installed ||
            r.status == ToolInstallStatus::BridgeAvailable))
        continue;
    }
    if (!q.empty()) {
      std::string hay = lower(r.name + " " + r.description + " " + r.id + " " +
                              tool_category_name(r.category));
      if (hay.find(q) == std::string::npos) continue;
    }
    out.push_back(r);
  }
  return out;
}

std::vector<std::string> tool_catalog_recommend(const std::string& path_or_hint) {
  std::vector<std::string> rec;
  std::string p = lower(path_or_hint);
  auto push = [&](const char* id) { rec.push_back(id); };
  if (p.find("wallet.dat") != std::string::npos || p.find(".dat") != std::string::npos) {
    push("twc_extract");
    push("twc_verify");
    push("twc_hashcat_exp");
    push("hashcat");
    push("john");
    push("btcrecover");
    push("pywallet");
    push("twc_breaker");
  }
  if (p.find("seco") != std::string::npos || p.find("exodus") != std::string::npos) {
    push("twc_exodus_pipe");
    push("exodus2hashcat");
    push("hashcat");
  }
  if (p.find("leveldb") != std::string::npos || p.find("metamask") != std::string::npos ||
      p.find("nkbihfbeogaeaoehlefnkodbefgpgknn") != std::string::npos) {
    push("twc_metamask_pipe");
    push("twc_ext_walker");
    push("metamask_pwn");
    push("mm_leveldb");
    push("hashcat");
  }
  if (p.find("electrum") != std::string::npos) {
    push("twc_electrum_help");
    push("btcrecover");
    push("hashcat");
    push("hydra_cuda");
  }
  if (p.find(".dmp") != std::string::npos || p.find("pagefile") != std::string::npos ||
      p.find("hiber") != std::string::npos || p.find("mem") != std::string::npos) {
    push("twc_memscan");
    push("vol3");
    push("twc_outside");
  }
  if (p.find("mbox") != std::string::npos || p.find(".eml") != std::string::npos ||
      p.find("mail") != std::string::npos) {
    push("twc_mbox");
    push("qf_gmail_mbox");
  }
  if (p.find(".png") != std::string::npos || p.find(".jpg") != std::string::npos ||
      p.find("ocr") != std::string::npos || p.find("seed") != std::string::npos) {
    push("twc_ocr_intake");
    push("seed_sweep");
    push("img_seed_finder");
  }
  if (rec.empty()) {
    push("twc_extract");
    push("hashcat");
    push("btcrecover");
    push("twc_outside");
  }
  return rec;
}

std::string tool_catalog_status_report() {
  auto rows = tool_catalog_refresh();
  auto st = tool_catalog_stats(rows);
  std::ostringstream o;
  o << st.summary << "\n";
  o << "--- Key bundled detectors ---\n";
  for (auto& r : rows) {
    if (r.id == "hashcat" || r.id == "john" || r.id == "btcrecover" || r.id == "python_embed" ||
        r.id == "pywallet" || r.id == "vol3" || r.id == "metamask_pwn" || r.id == "exodus2hashcat" ||
        r.id == "ileapp" || r.id == "aleapp" || r.id == "seedcat" || r.id == "hydra_cuda" ||
        r.id == "cuda_mnemonic" || r.id == "bulk_extractor" || r.id == "photorec") {
      o << r.id << ": " << r.status_label;
      if (!r.resolved_path.empty() && r.resolved_path != "built-in") o << " @ " << r.resolved_path;
      o << "\n";
    }
  }
  o << "\n--- Commercial Integration Hub (sample) ---\n";
  for (auto& c : commercial_integration_hub()) {
    o << c.name << ": " << (c.found ? ("FOUND " + c.detected_path) : "Install separately") << "\n"
      << "  TWC covers instead: " << c.twc_covers_instead << "\n";
  }
  return o.str();
}

std::vector<CommercialBridge> commercial_integration_hub() {
  struct Def {
    const char* id;
    const char* name;
    const char* covers;
  };
  static const Def defs[] = {
      {"cellebrite", "Cellebrite", "Native extract/salvage + Hashcat/BTCRecover for Core/vaults"},
      {"magnet_axiom", "Magnet AXIOM", "Outside Box artifact hunt + aLEAPP/iLEAPP bridges"},
      {"magnet_graykey", "Magnet Graykey", "Mobile path notes; on-chain labeling is NOT crack"},
      {"belkasoft", "Belkasoft X", "Memory/dump scavenger + carving lane"},
      {"msab", "MSAB XRY", "aLEAPP/iLEAPP parse after acquisition"},
      {"oxygen", "Oxygen Forensic", "Email/OCR seed scavenger + cloud leftover guidance"},
      {"xways", "X-Ways Forensics", "Salvage/unallocated carve + PhotoRec/TSK setup"},
      {"encase", "EnCase", "Case manager + imaging bridges"},
      {"ftk", "FTK", "Case manager + imaging bridges"},
      {"passware", "Passware Kit", "Native KDF + Hashcat -m 11300 + John for Core"},
      {"elcomsoft_edpr", "Elcomsoft EDPR", "Hashcat/John/BTCRecover local farms"},
      {"chainalysis", "Chainalysis", "Optional post-unlock balance only — never substitutes labeling DB"},
      {"trm", "TRM Labs", "On-chain after unlock — not a password cracker"},
      {"elliptic", "Elliptic", "On-chain after unlock — not a password cracker"},
      {"maltego", "Maltego", "OSINT graphs after addresses exist"},
  };
  std::vector<CommercialBridge> out;
  for (auto& d : defs) {
    CommercialBridge b;
    b.id = d.id;
    b.name = d.name;
    b.twc_covers_instead = d.covers;
    b.detected_path = detect_common_commercial(d.id);
    b.found = !b.detected_path.empty();
    out.push_back(b);
  }
  return out;
}

bool commercial_try_launch(const std::string& id, std::string* err) {
  std::string path = detect_common_commercial(id);
  if (path.empty()) {
    if (err) *err = "Not installed / path not configured — install licensed copy separately";
    return false;
  }
#ifdef _WIN32
  HINSTANCE hi = ShellExecuteA(nullptr, "open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
  if ((INT_PTR)hi <= 32) {
    if (err) *err = "ShellExecute failed for " + path;
    return false;
  }
  return true;
#else
  if (err) *err = "Launch is Windows-only";
  return false;
#endif
}
