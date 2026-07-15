#include "OutsideBox.h"
#include "Passphrase.h"
#include "ForensicTools.h"
#include "CaseManager.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <filesystem>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <winhttp.h>
#endif

namespace fs = std::filesystem;

namespace {

std::string trim(std::string s) {
  while (!s.empty() && (unsigned char)s.front() <= ' ') s.erase(s.begin());
  while (!s.empty() && (unsigned char)s.back() <= ' ') s.pop_back();
  return s;
}

std::string to_lower_copy(std::string s) {
  for (char& c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}

bool looks_printable(const uint8_t* p, size_t n) {
  if (n < 4) return false;
  size_t ok = 0;
  for (size_t i = 0; i < n; ++i) {
    uint8_t c = p[i];
    if (c >= 32 && c < 127) ++ok;
    else if (c == '\t' || c == '\n' || c == '\r') ++ok;
    else return false;
  }
  return ok == n;
}

std::string hex_of(const uint8_t* p, size_t n) {
  static const char* H = "0123456789abcdef";
  std::string o;
  o.resize(n * 2);
  for (size_t i = 0; i < n; ++i) {
    o[i * 2] = H[p[i] >> 4];
    o[i * 2 + 1] = H[p[i] & 0xf];
  }
  return o;
}

bool parse_hex_bytes(const std::string& hex, std::vector<uint8_t>* out) {
  std::string h;
  for (char c : hex) {
    if (std::isxdigit((unsigned char)c)) h.push_back((char)std::tolower((unsigned char)c));
  }
  if (h.size() % 2) return false;
  out->clear();
  out->reserve(h.size() / 2);
  for (size_t i = 0; i < h.size(); i += 2) {
    unsigned v = 0;
    if (std::sscanf(h.c_str() + i, "%2x", &v) != 1) return false;
    out->push_back((uint8_t)v);
  }
  return true;
}

bool is_hex64(const std::string& s) {
  if (s.size() != 64) return false;
  for (char c : s)
    if (!std::isxdigit((unsigned char)c)) return false;
  return true;
}

std::vector<std::string> split_tokens(const std::string& text) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : text) {
    if (std::isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.') {
      cur.push_back(c);
    } else if (!cur.empty()) {
      if (cur.size() >= 2) out.push_back(cur);
      cur.clear();
    }
  }
  if (cur.size() >= 2) out.push_back(cur);
  return out;
}

uint64_t file_mtime_unix_win(const std::string& path) {
#ifdef _WIN32
  WIN32_FILE_ATTRIBUTE_DATA fad{};
  if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fad)) return 0;
  ULARGE_INTEGER ull;
  ull.LowPart = fad.ftLastWriteTime.dwLowDateTime;
  ull.HighPart = fad.ftLastWriteTime.dwHighDateTime;
  const uint64_t EPOCH_DIFF = 116444736000000000ULL;
  if (ull.QuadPart < EPOCH_DIFF) return 0;
  return (ull.QuadPart - EPOCH_DIFF) / 10000000ULL;
#else
  (void)path;
  return 0;
#endif
}

std::string run_powershell_capture(const std::string& script, DWORD timeout_ms = 120000) {
#ifdef _WIN32
  std::string cmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"" + script + "\"";
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  HANDLE rd = nullptr, wr = nullptr;
  if (!CreatePipe(&rd, &wr, &sa, 0)) return "[E] CreatePipe failed\n";
  SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOA si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = wr;
  si.hStdError = wr;
  PROCESS_INFORMATION pi{};
  std::vector<char> buf(cmd.begin(), cmd.end());
  buf.push_back(0);
  if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                      nullptr, &si, &pi)) {
    CloseHandle(rd);
    CloseHandle(wr);
    return "[E] CreateProcess failed\n";
  }
  CloseHandle(wr);
  std::string out;
  char tmp[4096];
  DWORD n = 0;
  DWORD start = GetTickCount();
  while (ReadFile(rd, tmp, sizeof(tmp) - 1, &n, nullptr) && n) {
    tmp[n] = 0;
    out += tmp;
    if (GetTickCount() - start > timeout_ms) break;
  }
  WaitForSingleObject(pi.hProcess, 5000);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(rd);
  return out;
#else
  (void)script;
  (void)timeout_ms;
  return "[!] PowerShell VSS helpers are Windows-only\n";
#endif
}

std::string run_powershell_elevated_script_file(const std::string& ps1_path) {
#ifdef _WIN32
  /* Triggers UAC elevation prompt — guided, not silent. */
  std::string args = "-NoProfile -ExecutionPolicy Bypass -File \"" + ps1_path + "\"";
  SHELLEXECUTEINFOA sei{};
  sei.cbSize = sizeof(sei);
  sei.fMask = SEE_MASK_NOCLOSEPROCESS;
  sei.lpVerb = "runas";
  sei.lpFile = "powershell.exe";
  sei.lpParameters = args.c_str();
  sei.nShow = SW_SHOW;
  if (!ShellExecuteExA(&sei)) {
    return "[E] elevation cancelled or failed (VSS copy needs admin)";
  }
  if (sei.hProcess) {
    WaitForSingleObject(sei.hProcess, 180000);
    CloseHandle(sei.hProcess);
  }
  return "[+] elevated PowerShell finished (check case folder for copies)";
#else
  (void)ps1_path;
  return "[!] elevation Windows-only";
#endif
}

bool name_looks_wallet_ghost(const std::string& name) {
  std::string n = to_lower_copy(name);
  if (n.find("wallet") == std::string::npos) return false;
  if (n.find(".dat") != std::string::npos) return true;
  if (n.find(".tmp") != std::string::npos) return true;
  if (n.find("conflict") != std::string::npos) return true;
  if (n.find("copy") != std::string::npos) return true;
  /* wallet (1).dat style */
  if (n.rfind(".dat") != std::string::npos || n.find("wallet.dat") != std::string::npos) return true;
  return n.find("wallet.dat") != std::string::npos;
}

void walk_ghosts(const fs::path& root, GhostFinderReport& r, int max_hits) {
  std::error_code ec;
  if (!fs::exists(root, ec)) return;
  fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
  fs::recursive_directory_iterator end;
  for (; it != end; it.increment(ec)) {
    if (ec) {
      ec.clear();
      continue;
    }
    ++r.dirs_walked;
    if (!it->is_regular_file(ec)) continue;
    auto name = it->path().filename().string();
    if (!name_looks_wallet_ghost(name)) continue;
    GhostFileHit h;
    h.path = it->path().string();
    h.size = (size_t)it->file_size(ec);
    std::string ln = to_lower_copy(name);
    if (ln.find("conflict") != std::string::npos)
      h.kind = "conflict";
    else if (ln.find(".tmp") != std::string::npos)
      h.kind = "tmp";
    else if (ln.find("(") != std::string::npos)
      h.kind = "numbered";
    else
      h.kind = "wallet.dat";
    h.mtime_unix = file_mtime_unix_win(h.path);
    r.hits.push_back(h);
    if ((int)r.hits.size() >= max_hits) return;
  }
}

bool bip39ish_word(const std::string& w, const std::set<std::string>& wl) {
  return wl.count(to_lower_copy(w)) > 0;
}

std::set<std::string> load_bip39_set() {
  std::set<std::string> s;
  std::vector<std::string> words;
  bip39_load_wordlist(&words, nullptr);
  for (auto& w : words) s.insert(to_lower_copy(w));
  return s;
}

DumpScavengeReport scavenge_large_file(const std::string& path, size_t max_hits, bool prefer_bip39,
                                       const char* label, std::atomic<bool>* stop,
                                       std::function<void(size_t, size_t)> progress) {
  DumpScavengeReport r;
  r.path = path;
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    r.summary = std::string("[E] cannot open ") + path;
    return r;
  }
  in.seekg(0, std::ios::end);
  r.file_size = (size_t)in.tellg();
  in.seekg(0, std::ios::beg);
  auto bip = load_bip39_set();
  const size_t CHUNK = 1 << 20;
  const size_t OVERLAP = 256;
  std::vector<uint8_t> buf(CHUNK + OVERLAP);
  size_t off = 0;
  size_t carry = 0;
  while (in && (!stop || !stop->load())) {
    in.read((char*)buf.data() + carry, (std::streamsize)(CHUNK));
    size_t got = (size_t)in.gcount() + carry;
    if (got < 8) break;
    /* ASCII strings */
    size_t i = 0;
    while (i + 6 < got && r.hits.size() < max_hits) {
      if (buf[i] < 32 || buf[i] >= 127) {
        ++i;
        continue;
      }
      size_t j = i;
      while (j < got && buf[j] >= 32 && buf[j] < 127) ++j;
      size_t len = j - i;
      if (len >= 6 && len < 200 && looks_printable(buf.data() + i, len)) {
        std::string text((char*)buf.data() + i, len);
        DumpScavengeHit h;
        h.offset = off + i - (carry > i ? 0 : 0);
        h.offset = (off >= carry ? off - carry : 0) + i;
        h.text = text;
        h.kind = "string";
        h.score = (int)std::min<size_t>(len, 40);
        auto toks = split_tokens(text);
        int bip_hits = 0;
        for (auto& t : toks)
          if (bip39ish_word(t, bip)) ++bip_hits;
        if (bip_hits >= 8) {
          h.kind = "bip39";
          h.score = 80 + bip_hits;
        } else if (prefer_bip39 && bip_hits >= 3) {
          h.kind = "bip39ish";
          h.score = 40 + bip_hits;
        } else if (to_lower_copy(text).find("pass") != std::string::npos ||
                   to_lower_copy(text).find("wallet") != std::string::npos) {
          h.kind = "passphraseish";
          h.score = 50;
        }
        if (h.score >= 20 || h.kind != "string") r.hits.push_back(std::move(h));
      }
      i = j + 1;
    }
    /* hex-looking 64-char windows at printable spans already covered; also raw entropy blobs */
    for (size_t k = 0; k + 32 <= got && r.hits.size() < max_hits; k += 16) {
      /* score high-entropy 32-byte blocks lightly */
      int nz = 0, uniq = 0;
      bool seen[256] = {};
      for (int t = 0; t < 32; ++t) {
        if (buf[k + t]) ++nz;
        if (!seen[buf[k + t]]) {
          seen[buf[k + t]] = true;
          ++uniq;
        }
      }
      if (nz >= 28 && uniq >= 20) {
        DumpScavengeHit h;
        h.offset = (off >= carry ? off - carry : 0) + k;
        h.kind = "hex32";
        h.text = hex_of(buf.data() + k, 32);
        h.score = 30 + uniq / 4;
        r.hits.push_back(std::move(h));
      }
    }
    r.scanned = off + got;
    if (progress) progress(r.scanned, r.file_size);
    if (got <= OVERLAP) break;
    std::memmove(buf.data(), buf.data() + got - OVERLAP, OVERLAP);
    carry = OVERLAP;
    off += got - OVERLAP;
    if (r.hits.size() >= max_hits) break;
  }
  std::sort(r.hits.begin(), r.hits.end(),
            [](const DumpScavengeHit& a, const DumpScavengeHit& b) { return a.score > b.score; });
  if (r.hits.size() > max_hits) r.hits.resize(max_hits);
  std::ostringstream ss;
  ss << label << ": scanned=" << r.scanned << "/" << r.file_size << " hits=" << r.hits.size();
  r.summary = ss.str();
  return r;
}

}  // namespace

std::vector<std::string> load_dict_lines(const std::string& path, size_t max_lines) {
  std::vector<std::string> out;
  std::ifstream in(path);
  if (!in) return out;
  std::string line;
  while (std::getline(in, line) && out.size() < max_lines) {
    line = trim(line);
    if (!line.empty() && line[0] != '#') out.push_back(line);
  }
  return out;
}

bool write_text_file(const std::string& path, const std::string& body) {
  std::ofstream o(path, std::ios::binary);
  if (!o) return false;
  o.write(body.data(), (std::streamsize)body.size());
  return true;
}

std::string outside_box_module_inventory() {
  return
      "Outside Box modules (authorized DFIR / owner recovery):\n"
      " 1  VSS / Shadow-copy harvester          [LANDED]\n"
      " 2  NTFS undelete / unallocated carve   [LANDED — user dump]\n"
      " 3  Cloud sync ghost finder             [LANDED]\n"
      " 4  Portable / leftover scanner         [LANDED]\n"
      " 5  Unlock-session capture kit          [LANDED — guided + import]\n"
      " 6  pagefile/hiberfil string hunt       [LANDED — import]\n"
      " 7  GPU VRAM residue                    [EXPERIMENTAL-LITE]\n"
      " 8  Passphrase-change multi-mkey        [LANDED]\n"
      " 9  Crash-dump AES candidates           [LANDED]\n"
      "10  Descriptor / PSBT scrapyard         [LANDED]\n"
      "11  Two-Body multi-wallet               [LANDED]\n"
      "12  Keyboard adjacency / fat-finger     [LANDED]\n"
      "13  Heir interview grammar              [LANDED]\n"
      "14  Password-manager CSV bridge         [LANDED]\n"
      "15  Backup stitch surgeon               [LANDED]\n"
      "16  Rebuild / re-encrypt                [LANDED — Breaker tab]\n"
      "17  ChipWhisperer / EM importer         [EXPERIMENTAL-LITE]\n"
      "18  Fault-injection candidate import    [LANDED]\n"
      "19  Fake-wallet detector++              [LANDED]\n"
      "20  Network timeline (HTTP read-only)   [LANDED]\n"
      "21  Time-Slice Crack plan               [LANDED]\n"
      "22  Keyhole mode                        [LANDED — wires to AES Partial]\n"
      "23  Seed Mirage Meter                   [LANDED]\n";
}

/* ─── 1 VSS ─── */
VssHarvestReport vss_list_shadows() {
  VssHarvestReport r;
  r.elevated_attempted = false;
  std::string ps =
      "Get-CimInstance Win32_ShadowCopy | Select-Object ID,DeviceObject,InstallDate,VolumeName | "
      "ForEach-Object { $_.ID + '|' + $_.DeviceObject + '|' + $_.InstallDate + '|' + "
      "$_.VolumeName }";
  r.script_log = run_powershell_capture(ps);
  std::istringstream iss(r.script_log);
  std::string line;
  while (std::getline(iss, line)) {
    line = trim(line);
    if (line.empty() || line[0] == '[') continue;
    auto p1 = line.find('|');
    auto p2 = line.find('|', p1 == std::string::npos ? 0 : p1 + 1);
    auto p3 = line.find('|', p2 == std::string::npos ? 0 : p2 + 1);
    if (p1 == std::string::npos) continue;
    VssShadowEntry e;
    e.id = line.substr(0, p1);
    if (p2 != std::string::npos) e.device_object = line.substr(p1 + 1, p2 - p1 - 1);
    if (p3 != std::string::npos) {
      e.create_time = line.substr(p2 + 1, p3 - p2 - 1);
      e.volume = line.substr(p3 + 1);
    }
    e.note = "Volume Shadow Copy";
    r.shadows.push_back(e);
  }
  r.ok = !r.shadows.empty();
  std::ostringstream ss;
  ss << "VSS list: " << r.shadows.size()
     << " shadow(s). Admin may be required to copy wallet.dat from DeviceObject paths.";
  if (r.shadows.empty())
    ss << " Empty — run GUI Harvest (elevated) or ensure VSS is enabled.";
  r.summary = ss.str();
  return r;
}

VssHarvestReport vss_harvest_wallets(const std::string& case_out_dir,
                                     const std::vector<std::string>& relative_wallet_paths) {
  VssHarvestReport r = vss_list_shadows();
  r.elevated_attempted = true;
  std::error_code ec;
  fs::create_directories(case_out_dir, ec);
  std::string out_vss = case_out_dir + "/vss";
  fs::create_directories(out_vss, ec);

  std::vector<std::string> rels = relative_wallet_paths;
  if (rels.empty()) {
    rels = {"Users/*/AppData/Roaming/Bitcoin/wallet.dat",
            "Users/*/AppData/Roaming/Bitcoin/wallets/*/wallet.dat"};
  }

  /* Write helper script: for each shadow DeviceObject, try Copy-Item of common paths */
  std::string ps1 = out_vss + "/harvest_vss.ps1";
  std::ostringstream script;
  script << "$ErrorActionPreference='Continue'\n";
  script << "$Out='" << out_vss << "'\n";
  script << "New-Item -ItemType Directory -Force -Path $Out | Out-Null\n";
  script << "$shadows = Get-CimInstance Win32_ShadowCopy\n";
  script << "$i=0\n";
  script << "foreach($s in $shadows){\n";
  script << "  $i++; $dev=$s.DeviceObject; if(-not $dev){continue}\n";
  script << "  $dest=Join-Path $Out ('shadow_'+$i); New-Item -ItemType Directory -Force -Path "
            "$dest | Out-Null\n";
  script << "  $cands=@(\n";
  script << "    (Join-Path $dev 'Users'),\n";
  script << "    (Join-Path $dev 'Documents and Settings')\n";
  script << "  )\n";
  script << "  foreach($root in $cands){\n";
  script << "    if(Test-Path -LiteralPath $root){\n";
  script << "      Get-ChildItem -LiteralPath $root -Recurse -Filter 'wallet.dat*' -ErrorAction "
            "SilentlyContinue | ForEach-Object {\n";
  script << "        $rel=$_.FullName.Substring($dev.Length).TrimStart('\\')\n";
  script << "        $target=Join-Path $dest ($rel -replace '[\\\\/:*?\"<>|]','_')\n";
  script << "        New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null\n";
  script << "        Copy-Item -LiteralPath $_.FullName -Destination $target -Force "
            "-ErrorAction SilentlyContinue\n";
  script << "      }\n";
  script << "    }\n";
  script << "  }\n";
  script << "}\n";
  script << "Get-ChildItem -Path $Out -Recurse -Filter 'wallet.dat*' | ForEach-Object { "
            "$_.FullName } | Out-File -Encoding utf8 (Join-Path $Out 'copied.txt')\n";
  write_text_file(ps1, script.str());

  r.script_log += run_powershell_elevated_script_file(ps1);
  /* Collect results if any already present / after elevate */
  if (fs::exists(out_vss + "/copied.txt", ec)) {
    std::ifstream in(out_vss + "/copied.txt");
    std::string line;
    while (std::getline(in, line)) {
      line = trim(line);
      if (line.empty()) continue;
      VssHarvestHit h;
      h.dest_path = line;
      h.source_path = line;
      h.copied = true;
      std::error_code e2;
      if (fs::exists(line, e2)) h.size = (size_t)fs::file_size(line, e2);
      h.message = "copied under case/vss";
      r.hits.push_back(h);
    }
  }
  /* Also try non-elevated recursive search of accessible shadow junctions is usually blocked */
  r.ok = !r.hits.empty() || !r.shadows.empty();
  std::ostringstream ss;
  ss << "VSS harvest: shadows=" << r.shadows.size() << " copies=" << r.hits.size()
     << " out=" << out_vss << " (UAC elevation prompted for copy)";
  r.summary = ss.str();
  (void)rels;
  return r;
}

/* ─── 2 Unallocated ─── */
UnallocatedCarveReport carve_unallocated_dump(const std::string& path, std::atomic<bool>* stop,
                                              std::function<void(size_t, size_t)> progress) {
  UnallocatedCarveReport r;
  r.path = path;
  r.salvage = salvage_file(path);
  r.file_size = r.salvage.file_size;
  r.scanned = r.file_size;
  if (progress) progress(r.scanned, r.file_size);
  /* Extra: BDB magic and ASCII wallet markers */
  std::ifstream in(path, std::ios::binary);
  if (in) {
    const size_t CHUNK = 1 << 20;
    std::vector<uint8_t> buf(CHUNK);
    size_t off = 0;
    while (in && (!stop || !stop->load()) && r.extra.size() < 200) {
      in.read((char*)buf.data(), (std::streamsize)CHUNK);
      size_t got = (size_t)in.gcount();
      if (!got) break;
      for (size_t i = 0; i + 4 <= got; ++i) {
        /* Berkeley DB magic little-endian 0x00053162 */
        if (buf[i] == 0x62 && buf[i + 1] == 0x31 && buf[i + 2] == 0x05 && buf[i + 3] == 0x00) {
          UnallocatedCarveHit h;
          h.offset = off + i;
          h.kind = "wallet_magic";
          h.score = 70;
          h.preview = "BDB magic";
          r.extra.push_back(h);
        }
      }
      off += got;
      r.scanned = off;
      if (progress) progress(off, r.file_size ? r.file_size : off);
    }
  }
  std::ostringstream ss;
  ss << "Unallocated carve: mkeys=" << r.salvage.mkey_candidates
     << " ckeys=" << r.salvage.ckey_candidates << " magic_hits=" << r.extra.size()
     << " (best-effort on user-supplied dump; not full NTFS undelete)";
  r.summary = ss.str();
  return r;
}

/* ─── 3 Cloud ghosts ─── */
GhostFinderReport cloud_sync_ghost_find(const std::vector<std::string>& roots, int max_hits) {
  GhostFinderReport r;
  for (const auto& root : roots) {
    if ((int)r.hits.size() >= max_hits) break;
    walk_ghosts(fs::path(root), r, max_hits);
  }
  std::ostringstream ss;
  ss << "Cloud/ghost scan: roots=" << roots.size() << " hits=" << r.hits.size()
     << " (wallet.dat*, (1), .tmp, conflict copies)";
  r.summary = ss.str();
  return r;
}

/* ─── 4 Portable ─── */
PortableScanReport portable_leftover_scan(bool scan_usb_letters) {
  PortableScanReport r;
  std::vector<std::string> cands;
#ifdef _WIN32
  char profile[MAX_PATH] = {};
  if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, profile))) {
    std::string p = profile;
    cands.push_back(p + "\\AppData\\Roaming\\Bitcoin\\wallet.dat");
    cands.push_back(p + "\\AppData\\Roaming\\Bitcoin\\wallets");
    cands.push_back(p + "\\AppData\\Roaming\\Electrum\\wallets");
    cands.push_back(p + "\\Documents\\Bitcoin\\wallet.dat");
    cands.push_back(p + "\\Desktop");
  }
  if (scan_usb_letters) {
    DWORD masks = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
      if (!(masks & (1u << i))) continue;
      char root[] = "A:\\";
      root[0] = (char)('A' + i);
      UINT t = GetDriveTypeA(root);
      if (t == DRIVE_REMOVABLE || t == DRIVE_FIXED) {
        cands.push_back(std::string(root) + "Bitcoin\\wallet.dat");
        cands.push_back(std::string(root) + "wallet.dat");
      }
    }
  }
#else
  (void)scan_usb_letters;
  cands.push_back("./wallet.dat");
#endif

  WalletDatParser parser;
  for (const auto& c : cands) {
    std::error_code ec;
    if (fs::is_directory(c, ec)) {
      try {
        for (auto& e : fs::recursive_directory_iterator(
                 c, fs::directory_options::skip_permission_denied, ec)) {
          if (!e.is_regular_file(ec)) continue;
          auto nm = to_lower_copy(e.path().filename().string());
          if (nm != "wallet.dat" && nm.find("wallet.dat") == std::string::npos) continue;
          PortableScanHit h;
          h.path = e.path().string();
          h.size = (size_t)e.file_size(ec);
          h.source = "profile";
          auto pr = parser.parse_file(h.path);
          h.parseable = pr.mkey.found || !pr.ckeys.empty();
          h.iterations = pr.mkey.iterations;
          h.ckeys = (int)pr.ckeys.size();
          r.hits.push_back(h);
        }
      } catch (...) {
      }
      continue;
    }
    if (!fs::exists(c, ec)) continue;
    PortableScanHit h;
    h.path = c;
    h.size = (size_t)fs::file_size(c, ec);
    h.source = (c.size() >= 2 && c[1] == ':' && c[0] != 'C' && c[0] != 'c') ? "usb" : "common";
    auto pr = parser.parse_file(c);
    h.parseable = pr.mkey.found || !pr.ckeys.empty();
    h.iterations = pr.mkey.iterations;
    h.ckeys = (int)pr.ckeys.size();
    r.hits.push_back(h);
  }
  std::ostringstream ss;
  ss << "Portable/leftover: " << r.hits.size() << " path(s) under common Core/USB locations";
  r.summary = ss.str();
  return r;
}

UnlockSessionChecklist unlock_session_kit_guidance() {
  UnlockSessionChecklist c;
  c.tip_import_only = true;
  c.guidance_markdown =
      "## Unlock-session capture kit (import-centric)\n"
      "Authorized DFIR only. TrueWalletCollider does **not** silently read live RAM.\n\n"
      "1. Prefer a voluntary **process dump** of `bitcoin-qt.exe` / `bitcoind.exe` while the "
      "wallet is **unlocked** (Task Manager → Details → Create dump file).\n"
      "2. Or use Sysinternals **procdump** (you run it): `procdump -ma <pid> unlock.dmp`.\n"
      "3. Optional: full RAM capture with your org's approved tool → import here.\n"
      "4. Import the dump into **Memory Import** → Unlock scavenge / AES candidates.\n"
      "5. Disable hibernation only if YOUR policy allows: `powercfg /hibernate off` "
      "(admin) — do not alter evidence disks without authority.\n";
  return c;
}

DumpScavengeReport scavenge_memory_dump(const std::string& path, size_t max_hits,
                                        std::atomic<bool>* stop,
                                        std::function<void(size_t, size_t)> progress) {
  return scavenge_large_file(path, max_hits, true, "RAM/process dump scavenge", stop, progress);
}

DumpScavengeReport hunt_pagefile_hiberfil(const std::string& path, size_t max_hits,
                                          std::atomic<bool>* stop,
                                          std::function<void(size_t, size_t)> progress) {
  return scavenge_large_file(path, max_hits, true, "pagefile/hiberfil hunt", stop, progress);
}

DumpScavengeReport scavenge_vram_dump_experimental(const std::string& path, size_t max_hits,
                                                   std::atomic<bool>* stop,
                                                   std::function<void(size_t, size_t)> progress) {
  auto r = scavenge_large_file(path, max_hits, false, "VRAM residue (experimental)", stop, progress);
  r.summary += " — experimental: GPU VRAM captures are opportunistic; expect noise.";
  return r;
}

/* ─── 8 multi-mkey ─── */
std::vector<MasterKeyInfo> extract_all_mkeys(const uint8_t* data, size_t len) {
  std::vector<MasterKeyInfo> out;
  auto sal = salvage_carve(data, len, "multi-mkey");
  out = sal.mkeys;
  if (out.empty()) {
    WalletDatParser p;
    auto w = p.parse_bytes(data, len, "multi-mkey");
    if (w.mkey.found) out.push_back(w.mkey);
  }
  return out;
}

bool attack_all_mkeys_shared_dict(const WalletParseResult& wallet,
                                  const std::vector<MasterKeyInfo>& mkeys,
                                  const std::vector<std::string>& dict,
                                  MultiMkeyAttackProgress& prog, const std::string& found_file) {
  prog.running = true;
  prog.stop = false;
  prog.hit = false;
  prog.tried = 0;
  prog.total = dict.size() * (std::max)((size_t)1, mkeys.size());
  prog.message = "multi-mkey shared dict attack…";
  for (size_t mi = 0; mi < mkeys.size() && !prog.stop.load(); ++mi) {
    WalletParseResult w = wallet;
    w.mkey = mkeys[mi];
    for (const auto& pass : dict) {
      if (prog.stop.load()) break;
      auto dv = dual_verify_passphrase(w.mkey, w, pass, found_file);
      prog.tried.fetch_add(1);
      if (dv.ok) {
        prog.hit = true;
        prog.hit_mkey_index = (int)mi;
        prog.found_pass = pass;
        prog.dual = dv;
        prog.message = "HIT mkey#" + std::to_string(mi) + " pass=" + pass;
        prog.running = false;
        return true;
      }
    }
  }
  prog.message = "no hit across " + std::to_string(mkeys.size()) + " mkey(s)";
  prog.running = false;
  return false;
}

/* ─── 9 crash dump AES ─── */
CrashDumpAesReport extract_aes_candidates_from_dump(const std::string& path,
                                                    const WalletParseResult& wallet,
                                                    size_t max_cands, bool dual_verify,
                                                    std::atomic<bool>* stop) {
  CrashDumpAesReport r;
  r.path = path;
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    r.summary = "[E] cannot open dump";
    return r;
  }
  in.seekg(0, std::ios::end);
  size_t sz = (size_t)in.tellg();
  in.seekg(0);
  /* Cap read for huge dumps — first 64MB + last 16MB heuristic + middle sample */
  const size_t CAP = 64 * 1024 * 1024;
  std::vector<std::pair<size_t, size_t>> ranges;
  ranges.push_back({0, (std::min)(sz, CAP)});
  if (sz > CAP + 16 * 1024 * 1024)
    ranges.push_back({sz - 16 * 1024 * 1024, 16 * 1024 * 1024});

  std::set<std::string> seen;
  for (auto& rg : ranges) {
    if (stop && stop->load()) break;
    std::vector<uint8_t> buf(rg.second);
    in.seekg((std::streamoff)rg.first);
    in.read((char*)buf.data(), (std::streamsize)buf.size());
    size_t got = (size_t)in.gcount();
    for (size_t i = 0; i + 32 <= got && r.candidates.size() < max_cands; i += 4) {
      int uniq = 0;
      bool seenb[256] = {};
      int nz = 0;
      for (int t = 0; t < 32; ++t) {
        if (buf[i + t]) ++nz;
        if (!seenb[buf[i + t]]) {
          seenb[buf[i + t]] = true;
          ++uniq;
        }
      }
      if (nz < 24 || uniq < 16) continue;
      std::string hx = hex_of(buf.data() + i, 32);
      if (seen.count(hx)) continue;
      seen.insert(hx);
      AesCandidate c;
      c.offset = rg.first + i;
      c.hex32 = hx;
      c.score = uniq;
      r.candidates.push_back(c);
    }
  }
  std::sort(r.candidates.begin(), r.candidates.end(),
            [](const AesCandidate& a, const AesCandidate& b) { return a.score > b.score; });
  if (r.candidates.size() > max_cands) r.candidates.resize(max_cands);

  if (dual_verify && wallet.mkey.found) {
    for (auto& c : r.candidates) {
      if (stop && stop->load()) break;
      std::vector<uint8_t> key;
      if (!parse_hex_bytes(c.hex32, &key) || key.size() != 32) continue;
      c.dual = dual_verify_master(key.data(), wallet);
      c.verified = c.dual.ok;
      if (c.verified) ++r.verified_ok;
    }
  }
  std::ostringstream ss;
  ss << "Crash-dump AES: cands=" << r.candidates.size() << " dual_ok=" << r.verified_ok;
  r.summary = ss.str();
  return r;
}

/* ─── 10 descriptor / PSBT ─── */
DescriptorScrapReport carve_descriptor_psbt_scrapyard(const uint8_t* data, size_t len,
                                                      size_t max_hits) {
  DescriptorScrapReport r;
  auto try_push = [&](size_t off, const std::string& kind, const std::string& text) {
    if (r.hits.size() >= max_hits) return;
    DescriptorScrapHit h;
    h.offset = off;
    h.kind = kind;
    h.text = text.size() > 240 ? text.substr(0, 240) + "…" : text;
    r.hits.push_back(h);
  };
  /* PSBT magic "psbt" 0x70 0x73 0x62 0x74 */
  for (size_t i = 0; i + 4 <= len; ++i) {
    if (data[i] == 'p' && data[i + 1] == 's' && data[i + 2] == 'b' && data[i + 3] == 't') {
      size_t j = i;
      while (j < len && j < i + 512 && data[j] >= 32 && data[j] < 127) ++j;
      try_push(i, "psbt", std::string((char*)data + i, j - i));
    }
  }
  /* ASCII scan for descriptors / xpub */
  size_t i = 0;
  while (i < len && r.hits.size() < max_hits) {
    if (data[i] < 32 || data[i] >= 127) {
      ++i;
      continue;
    }
    size_t j = i;
    while (j < len && data[j] >= 32 && data[j] < 127) ++j;
    if (j - i >= 20) {
      std::string s((char*)data + i, j - i);
      std::string sl = to_lower_copy(s);
      if (sl.find("wpkh(") != std::string::npos || sl.find("wsh(") != std::string::npos ||
          sl.find("sh(") != std::string::npos || sl.find("tr(") != std::string::npos ||
          sl.find("multi(") != std::string::npos || sl.find("sortedmulti(") != std::string::npos) {
        try_push(i, "descriptor", s);
      } else if (s.find("xpub") != std::string::npos || s.find("ypub") != std::string::npos ||
                 s.find("zpub") != std::string::npos) {
        try_push(i, "xpub", s);
      } else if (s.find("xprv") != std::string::npos) {
        try_push(i, "xprv", s);
      }
    }
    i = j + 1;
  }
  std::ostringstream ss;
  ss << "Descriptor/PSBT scrapyard: hits=" << r.hits.size();
  r.summary = ss.str();
  return r;
}

DescriptorScrapReport carve_descriptor_psbt_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    DescriptorScrapReport r;
    r.summary = "[E] open failed";
    return r;
  }
  in.seekg(0, std::ios::end);
  size_t sz = (size_t)in.tellg();
  in.seekg(0);
  if (sz > 64 * 1024 * 1024) sz = 64 * 1024 * 1024;
  std::vector<uint8_t> buf(sz);
  in.read((char*)buf.data(), (std::streamsize)sz);
  return carve_descriptor_psbt_scrapyard(buf.data(), (size_t)in.gcount());
}

/* ─── 11 Two-Body ─── */
std::vector<TwoBodyWallet> twobody_load_case_folder(const std::string& folder) {
  std::vector<TwoBodyWallet> out;
  WalletDatParser p;
  std::error_code ec;
  if (!fs::exists(folder, ec)) return out;
  for (auto& e : fs::recursive_directory_iterator(folder, fs::directory_options::skip_permission_denied, ec)) {
    if (!e.is_regular_file(ec)) continue;
    auto nm = to_lower_copy(e.path().filename().string());
    if (nm.find(".dat") == std::string::npos && nm.find("wallet") == std::string::npos) continue;
    TwoBodyWallet w;
    w.path = e.path().string();
    w.parsed = p.parse_file(w.path);
    w.ok = w.parsed.mkey.found;
    out.push_back(w);
  }
  return out;
}

bool twobody_shared_passphrase_attack(const std::vector<TwoBodyWallet>& wallets,
                                      const std::vector<std::string>& dict, TwoBodyProgress& prog,
                                      const std::string& found_file) {
  prog.running = true;
  prog.hit = false;
  prog.stop = false;
  size_t targets = 0;
  for (auto& w : wallets)
    if (w.ok) ++targets;
  prog.total = dict.size() * (std::max)(targets, (size_t)1);
  prog.tried = 0;
  for (size_t wi = 0; wi < wallets.size() && !prog.stop.load(); ++wi) {
    if (!wallets[wi].ok) continue;
    for (const auto& pass : dict) {
      if (prog.stop.load()) break;
      auto dv = dual_verify_passphrase(wallets[wi].parsed.mkey, wallets[wi].parsed, pass, found_file);
      prog.tried.fetch_add(1);
      if (dv.ok) {
        prog.hit = true;
        prog.hit_wallet_index = (int)wi;
        prog.found_pass = pass;
        prog.dual = dv;
        prog.message = "Two-Body HIT " + wallets[wi].path;
        prog.running = false;
        return true;
      }
    }
  }
  prog.message = "Two-Body: no shared passphrase hit";
  prog.running = false;
  return false;
}

/* ─── 12 keyboard adjacency ─── */
static const char* QWERTY_ROW[] = {"`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"};
static const char* QWERTY_SHIFT[] = {"~!@#$%^&*()_+", "QWERTYUIOP{}|", "ASDFGHJKL:\"", "ZXCVBNM<>?"};

static std::vector<char> neighbors_of(char ch) {
  std::vector<char> n;
  char lc = (char)std::tolower((unsigned char)ch);
  for (int row = 0; row < 4; ++row) {
    std::string r = QWERTY_ROW[row];
    std::string rs = QWERTY_SHIFT[row];
    auto pos = r.find(lc);
    if (pos == std::string::npos) {
      pos = rs.find(ch);
      if (pos == std::string::npos) continue;
      r = rs;
    }
    for (int d = -1; d <= 1; ++d) {
      if (d == 0) continue;
      int p = (int)pos + d;
      if (p >= 0 && p < (int)r.size()) n.push_back(r[p]);
    }
    if (row > 0) {
      std::string up = QWERTY_ROW[row - 1];
      if (pos < up.size()) n.push_back(up[pos]);
    }
    if (row < 3) {
      std::string dn = QWERTY_ROW[row + 1];
      if (pos < dn.size()) n.push_back(dn[pos]);
    }
  }
  return n;
}

std::vector<std::string> keyboard_adjacency_mutants(const std::string& almost, size_t max_out) {
  std::vector<std::string> out;
  auto push = [&](const std::string& s) {
    if (out.size() >= max_out) return;
    if (std::find(out.begin(), out.end(), s) == out.end()) out.push_back(s);
  };
  push(almost);
  for (size_t i = 0; i < almost.size() && out.size() < max_out; ++i) {
    auto ns = neighbors_of(almost[i]);
    for (char c : ns) {
      std::string m = almost;
      m[i] = c;
      push(m);
    }
  }
  /* transposition fat-finger */
  for (size_t i = 0; i + 1 < almost.size() && out.size() < max_out; ++i) {
    std::string m = almost;
    std::swap(m[i], m[i + 1]);
    push(m);
  }
  /* delete / duplicate one char */
  for (size_t i = 0; i < almost.size() && out.size() < max_out; ++i) {
    std::string m = almost;
    m.erase(i, 1);
    push(m);
    m = almost;
    m.insert(m.begin() + (std::ptrdiff_t)i, almost[i]);
    push(m);
  }
  return out;
}

std::vector<std::string> fat_finger_masks(const std::string& almost, size_t max_out) {
  auto m = keyboard_adjacency_mutants(almost, max_out);
  /* also case flip ends */
  if (!almost.empty() && m.size() < max_out) {
    std::string a = almost;
    a[0] = (char)std::toupper((unsigned char)a[0]);
    m.push_back(a);
  }
  return m;
}

/* ─── 13 heir interview ─── */
std::vector<std::string> heir_interview_to_candidates(const HeirInterview& h, size_t max_out,
                                                     CandidateGenStats* stats) {
  RecallTokens tok;
  tok.keyboard_walks = h.keyboard_walks;
  tok.case_variants = h.case_variants;
  tok.leet = h.leet;
  tok.append_years = h.append_years;
  tok.separators = {"", " ", "-", "_", ".", "!"};
  auto add_field = [&](const std::string& field) {
    for (auto& t : split_tokens(field)) tok.known_words.push_back(t);
  };
  add_field(h.person_names);
  add_field(h.places);
  add_field(h.pets);
  add_field(h.dates);
  add_field(h.hobbies);
  add_field(h.free_story);
  for (auto& t : split_tokens(h.dates)) {
    if (t.size() == 4 && std::isdigit((unsigned char)t[0])) tok.years.push_back(t);
  }
  /* structured story phrases */
  std::vector<std::string> story_bits = split_tokens(h.free_story);
  for (size_t i = 0; i + 1 < story_bits.size() && tok.known_words.size() < 40; ++i)
    tok.known_words.push_back(story_bits[i] + story_bits[i + 1]);

  return generate_recall_candidates(tok, max_out, stats);
}

/* ─── 14 CSV bridge ─── */
CsvBridgeReport import_password_manager_csv(const std::string& path, size_t max_words) {
  CsvBridgeReport r;
  std::ifstream in(path);
  if (!in) {
    r.summary = "[E] cannot open CSV";
    return r;
  }
  std::string header;
  std::getline(in, header);
  std::string hl = to_lower_copy(header);
  if (hl.find("password") != std::string::npos && hl.find("url") != std::string::npos &&
      hl.find("username") != std::string::npos)
    r.detected_format = "chrome";
  else if (hl.find("login_password") != std::string::npos ||
           (hl.find("password") != std::string::npos && hl.find("name") != std::string::npos))
    r.detected_format = "bitwarden";
  else if (hl.find("password") != std::string::npos && hl.find("title") != std::string::npos)
    r.detected_format = "keepass";
  else
    r.detected_format = "generic";

  auto parse_csv_line = [](const std::string& line) {
    std::vector<std::string> cols;
    std::string cur;
    bool q = false;
    for (size_t i = 0; i < line.size(); ++i) {
      char c = line[i];
      if (c == '"') {
        if (q && i + 1 < line.size() && line[i + 1] == '"') {
          cur.push_back('"');
          ++i;
        } else
          q = !q;
      } else if (c == ',' && !q) {
        cols.push_back(cur);
        cur.clear();
      } else
        cur.push_back(c);
    }
    cols.push_back(cur);
    return cols;
  };

  auto cols_h = parse_csv_line(header);
  int idx_pass = -1, idx_user = -1, idx_name = -1;
  for (int i = 0; i < (int)cols_h.size(); ++i) {
    std::string c = to_lower_copy(trim(cols_h[i]));
    if (c == "password" || c == "login_password") idx_pass = i;
    if (c == "username" || c == "login_username") idx_user = i;
    if (c == "name" || c == "title" || c == "account" || c == "url") idx_name = i;
  }
  if (idx_pass < 0) {
    /* fallback: last column */
    idx_pass = (int)cols_h.size() - 1;
  }

  std::set<std::string> uniq;
  std::string line;
  while (std::getline(in, line) && uniq.size() < max_words) {
    if (trim(line).empty()) continue;
    ++r.rows;
    auto cols = parse_csv_line(line);
    auto take = [&](int idx) {
      if (idx < 0 || idx >= (int)cols.size()) return std::string();
      return trim(cols[idx]);
    };
    std::string pw = take(idx_pass);
    std::string user = take(idx_user);
    std::string name = take(idx_name);
    if (!pw.empty()) {
      uniq.insert(pw);
      ++r.passwords;
      /* also tokens from password */
      for (auto& t : split_tokens(pw))
        if (t.size() >= 3) uniq.insert(t);
    }
    if (!user.empty()) {
      uniq.insert(user);
      ++r.usernames;
    }
    if (!name.empty())
      for (auto& t : split_tokens(name))
        if (t.size() >= 3) uniq.insert(t);
  }
  r.wordlist.assign(uniq.begin(), uniq.end());
  std::ostringstream ss;
  ss << "CSV bridge (" << r.detected_format << "): rows=" << r.rows << " wordlist=" << r.wordlist.size();
  r.summary = ss.str();
  return r;
}

/* ─── 15 stitch ─── */
StitchReport backup_stitch_try(const WalletParseResult& wallet_a_mkey_source,
                               const WalletParseResult& wallet_b_ckey_source,
                               const std::string& passphrase, const std::string& found_file) {
  StitchReport r;
  if (!wallet_a_mkey_source.mkey.found) {
    r.summary = "[E] wallet A has no mkey";
    return r;
  }
  WalletParseResult stitch = wallet_b_ckey_source;
  stitch.mkey = wallet_a_mkey_source.mkey;
  stitch.path = "stitch:" + wallet_a_mkey_source.path + "+" + wallet_b_ckey_source.path;
  r.dual = dual_verify_passphrase(stitch.mkey, stitch, passphrase, found_file);
  r.ok = r.dual.ok;
  if (r.ok) {
    r.master_hex = r.dual.master_hex;
    std::vector<uint8_t> key;
    if (parse_hex_bytes(r.master_hex, &key) && key.size() == 32)
      r.decrypt = decrypt_all_ckeys(key.data(), stitch, found_file);
  }
  std::ostringstream ss;
  ss << "Backup stitch: mkey@" << wallet_a_mkey_source.path << " + ckeys@"
     << wallet_b_ckey_source.path << " → " << (r.ok ? "OK" : "fail");
  r.summary = ss.str();
  return r;
}

/* ─── 17 EM / ChipWhisperer ─── */
EmTraceImportReport import_chipwhisperer_csv(const std::string& path, size_t max_cands) {
  EmTraceImportReport r;
  r.experimental = true;
  std::ifstream in(path);
  if (!in) {
    r.summary = "[E] open failed";
    return r;
  }
  std::string line;
  while (std::getline(in, line) && r.candidates < (int)max_cands) {
    line = trim(line);
    if (line.empty() || line[0] == '#') continue;
    /* take first hex-looking field or raw password */
    std::string field = line;
    auto comma = line.find(',');
    if (comma != std::string::npos) field = trim(line.substr(0, comma));
    /* strip quotes */
    if (field.size() >= 2 && field.front() == '"' && field.back() == '"')
      field = field.substr(1, field.size() - 2);
    if (is_hex64(field))
      r.hex_keys.push_back(to_lower_copy(field));
    else if (!field.empty())
      r.passphrase_guesses.push_back(field);
    ++r.candidates;
  }
  std::ostringstream ss;
  ss << "ChipWhisperer/EM CSV (experimental): keys=" << r.hex_keys.size()
     << " passes=" << r.passphrase_guesses.size();
  r.summary = ss.str();
  return r;
}

EmTraceImportReport import_em_trace_bin(const std::string& path, size_t max_cands) {
  EmTraceImportReport r;
  r.experimental = true;
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    r.summary = "[E] open failed";
    return r;
  }
  std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  /* Interpret as ranked 32-byte blocks */
  for (size_t i = 0; i + 32 <= buf.size() && r.hex_keys.size() < max_cands; i += 32) {
    r.hex_keys.push_back(hex_of(buf.data() + i, 32));
    ++r.candidates;
  }
  r.summary = "EM bin (experimental): " + std::to_string(r.hex_keys.size()) + " x 32-byte blocks";
  return r;
}

/* ─── 18 FI ─── */
FiCandidateReport import_fault_injection_candidates(const std::string& paste_or_file,
                                                    const WalletParseResult& wallet,
                                                    bool dual_verify) {
  FiCandidateReport r;
  std::string body = paste_or_file;
  std::ifstream in(paste_or_file, std::ios::binary);
  if (in) {
    std::ostringstream ss;
    ss << in.rdbuf();
    body = ss.str();
  }
  std::istringstream iss(body);
  std::string line;
  while (std::getline(iss, line)) {
    line = trim(line);
    if (line.empty()) continue;
    std::string hx;
    for (char c : line)
      if (std::isxdigit((unsigned char)c)) hx.push_back((char)std::tolower((unsigned char)c));
    if (hx.size() == 64) r.hex_keys.push_back(hx);
  }
  if (dual_verify && wallet.mkey.found) {
    for (auto& hx : r.hex_keys) {
      AesCandidate c;
      c.hex32 = hx;
      std::vector<uint8_t> key;
      if (!parse_hex_bytes(hx, &key) || key.size() != 32) continue;
      c.dual = dual_verify_master(key.data(), wallet);
      c.verified = c.dual.ok;
      if (c.verified) ++r.ok_count;
      r.verified.push_back(c);
    }
  }
  r.summary = "FI candidates: " + std::to_string(r.hex_keys.size()) + " dual_ok=" + std::to_string(r.ok_count);
  return r;
}

/* ─── 19 fake++ ─── */
FakeWalletPlusReport fake_wallet_detector_plus(const WalletParseResult& w, const uint8_t* raw,
                                               size_t len) {
  FakeWalletPlusReport r;
  r.base = verify_parsed_wallet(w);
  r.extras.push_back("base_verdict=" + r.base.verdict_label);

  if (raw && len) {
    auto hx = hex_dump_entropy(raw, (std::min)(len, (size_t)65536));
    r.entropy_score = hx.shannon_entropy;
    if (hx.shannon_entropy < 3.0)
      r.extras.push_back("LOW_ENTROPY_TEMPLATE_RISK");
    else if (hx.shannon_entropy > 7.5)
      r.extras.push_back("HIGH_ENTROPY_BLOB_OK");
  }

  double cons = 0;
  int checks = 0;
  auto add = [&](bool ok, const char* msg) {
    ++checks;
    if (ok) cons += 1;
    else r.extras.push_back(msg);
  };
  add(w.magic_ok, "MAGIC_FAIL");
  add(w.mkey.found, "NO_MKEY");
  add(!w.ckeys.empty(), "NO_CKEY");
  if (w.mkey.found) {
    add(w.mkey.iterations >= 1000, "SUSPECT_ITERS");
    add(w.mkey.salt.size() >= 8, "SALT_SHORT");
    add(w.mkey.encrypted48.size() == 48, "MKEY48_BAD");
  }
  int addr_ok = 0;
  for (auto& c : w.ckeys)
    if (c.address_ok) ++addr_ok;
  if (!w.ckeys.empty()) add(addr_ok > 0, "NO_VALID_ADDRESS");
  r.consistency_score = checks ? (cons / checks) : 0;

  r.overall = 0.35 * (r.base.score / 100.0) + 0.4 * r.consistency_score +
              0.25 * (std::min)(1.0, r.entropy_score / 8.0);
  if (r.base.verdict == VerifyVerdict::FAKE) r.overall *= 0.3;
  if (r.base.verdict == VerifyVerdict::CORRUPT) r.overall *= 0.5;

  std::ostringstream ss;
  ss << "Fake-wallet detector++: overall=" << r.overall << " entropy=" << r.entropy_score
     << " consistency=" << r.consistency_score << " base=" << r.base.verdict_label;
  r.summary = ss.str();
  return r;
}

FakeWalletPlusReport fake_wallet_detector_plus_file(const std::string& path) {
  WalletDatParser p;
  auto w = p.parse_file(path);
  std::ifstream in(path, std::ios::binary);
  std::vector<uint8_t> raw;
  if (in) {
    in.seekg(0, std::ios::end);
    size_t sz = (size_t)in.tellg();
    in.seekg(0);
    if (sz > 8 * 1024 * 1024) sz = 8 * 1024 * 1024;
    raw.resize(sz);
    in.read((char*)raw.data(), (std::streamsize)sz);
    raw.resize((size_t)in.gcount());
  }
  return fake_wallet_detector_plus(w, raw.empty() ? nullptr : raw.data(), raw.size());
}

/* ─── 20 network timeline ─── */
#ifdef _WIN32
static std::string http_get_win(const std::wstring& host, const std::wstring& path) {
  std::string out;
  HINTERNET ses = WinHttpOpen(L"TrueWalletCollider/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!ses) return out;
  HINTERNET con = WinHttpConnect(ses, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (!con) {
    WinHttpCloseHandle(ses);
    return out;
  }
  HINTERNET req =
      WinHttpOpenRequest(con, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                         WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!req) {
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return out;
  }
  if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
      WinHttpReceiveResponse(req, nullptr)) {
    char buf[4096];
    DWORD rd = 0;
    while (WinHttpReadData(req, buf, sizeof(buf), &rd) && rd) out.append(buf, buf + rd);
  }
  WinHttpCloseHandle(req);
  WinHttpCloseHandle(con);
  WinHttpCloseHandle(ses);
  return out;
}
#endif

NetworkTimelineReport network_timeline_for_addresses(const std::vector<std::string>& addrs,
                                                     bool enable_http) {
  NetworkTimelineReport r;
  if (!enable_http) {
    r.summary = "HTTP disabled — enable read-only network for balance/first-seen.";
    for (auto& a : addrs) {
      NetworkTimelineEvent e;
      e.address = a;
      e.kind = "skipped";
      e.value = "http_off";
      r.events.push_back(e);
    }
    return r;
  }
#ifdef _WIN32
  for (auto& a : addrs) {
    if (a.empty()) continue;
    std::wstring path = L"/rawaddr/" + std::wstring(a.begin(), a.end()) + L"?limit=5";
    std::string json = http_get_win(L"blockchain.info", path);
    r.http_ok = r.http_ok || !json.empty();
    NetworkTimelineEvent bal;
    bal.address = a;
    bal.kind = "balance_json";
    bal.raw_snippet = json.size() > 400 ? json.substr(0, 400) + "…" : json;
    /* crude field extract */
    auto grab = [&](const char* key) -> std::string {
      std::string k = std::string("\"") + key + "\":";
      auto p = json.find(k);
      if (p == std::string::npos) return {};
      p += k.size();
      while (p < json.size() && (json[p] == ' ')) ++p;
      size_t e = p;
      while (e < json.size() && json[e] != ',' && json[e] != '}') ++e;
      return trim(json.substr(p, e - p));
    };
    bal.value = grab("final_balance");
    r.events.push_back(bal);
    NetworkTimelineEvent ntx;
    ntx.address = a;
    ntx.kind = "n_tx";
    ntx.value = grab("n_tx");
    r.events.push_back(ntx);
    NetworkTimelineEvent fs;
    fs.address = a;
    fs.kind = "first_seen_hint";
    fs.value = grab("total_received");
    fs.raw_snippet = "total_received as activity proxy (blockchain.info read-only)";
    r.events.push_back(fs);
  }
#else
  r.summary = "Network timeline requires Windows WinHTTP in this build.";
  (void)addrs;
#endif
  std::ostringstream ss;
  ss << "Network timeline: events=" << r.events.size() << " http_ok=" << (r.http_ok ? 1 : 0);
  r.summary = ss.str();
  return r;
}

/* ─── 21 Time-Slice ─── */
TimeSlicePlan timeslice_crack_plan(const std::string& folder_or_case) {
  TimeSlicePlan plan;
  WalletDatParser p;
  std::error_code ec;
  if (!fs::exists(folder_or_case, ec)) {
    plan.summary = "[E] path missing";
    return plan;
  }
  for (auto& e : fs::recursive_directory_iterator(
           folder_or_case, fs::directory_options::skip_permission_denied, ec)) {
    if (!e.is_regular_file(ec)) continue;
    auto nm = to_lower_copy(e.path().filename().string());
    if (nm.find("wallet") == std::string::npos && nm.find(".dat") == std::string::npos) continue;
    TimeSlicePlanItem it;
    it.path = e.path().string();
    it.mtime_unix = file_mtime_unix_win(it.path);
    auto w = p.parse_file(it.path);
    it.iterations = w.mkey.found ? w.mkey.iterations : 250000;
    /* Higher priority = newer file and fewer iterations */
    double age_bonus = (double)it.mtime_unix / 1e10;
    double iter_score = 1.0 / std::log10((double)(std::max)(it.iterations, 10u) + 10.0);
    it.priority = age_bonus * 0.35 + iter_score * 0.65;
    std::ostringstream reason;
    reason << "mtime=" << it.mtime_unix << " iters=" << it.iterations;
    it.reason = reason.str();
    plan.items.push_back(it);
  }
  std::sort(plan.items.begin(), plan.items.end(),
            [](const TimeSlicePlanItem& a, const TimeSlicePlanItem& b) {
              return a.priority > b.priority;
            });
  std::ostringstream ss;
  ss << "Time-Slice plan: " << plan.items.size()
     << " wallet(s) ordered by file age × KDF iters (cheap+recent first)";
  plan.summary = ss.str();
  return plan;
}

/* ─── 22 Keyhole ─── */
KeyholePlan keyhole_build_plan(const KeyholeSpec& spec) {
  KeyholePlan p;
  std::vector<uint8_t> prefix, suffix;
  parse_hex_bytes(spec.known_prefix_hex, &prefix);
  parse_hex_bytes(spec.known_suffix_hex, &suffix);
  bool known[32] = {};
  for (size_t i = 0; i < prefix.size() && i < 32; ++i) known[i] = true;
  for (size_t i = 0; i < suffix.size() && i < 32; ++i) known[31 - i] = true;
  for (size_t i = 0; i < spec.known_byte_indices.size(); ++i) {
    int idx = spec.known_byte_indices[i];
    if (idx >= 0 && idx < 32) known[idx] = true;
  }
  uint64_t freeb = 0;
  for (int i = 0; i < 32; ++i)
    if (!known[i]) ++freeb;
  p.free_bytes = freeb;
  p.space_log2 = 8.0 * (double)freeb;
  /* CUDA MODE_PARTIAL wants a contiguous leading prefix */
  p.partial_prefix_for_cuda = spec.known_prefix_hex;
  p.ok = !spec.known_prefix_hex.empty() || !spec.known_byte_indices.empty() ||
         !spec.known_suffix_hex.empty();
  std::ostringstream g;
  g << "Keyhole: free_bytes=" << freeb << " space~2^" << p.space_log2
    << ". Contiguous leading prefix → AES Partial / CUDA MODE_PARTIAL. "
       "Sparse known bytes → CPU constrained search (experimental) or export candidates.";
  if (freeb == 0) g << " All 32 bytes known — use Try Key / dual-verify directly.";
  p.guidance = g.str();
  return p;
}

/* ─── 23 Seed Mirage ─── */
SeedMirageReport seed_mirage_meter(const std::vector<std::string>& carved_mnemonics,
                                   const WalletParseResult& wallet) {
  SeedMirageReport r;
  std::set<std::string> addrs;
  for (auto& c : wallet.ckeys)
    if (!c.address.empty()) addrs.insert(c.address);

  for (auto& m : carved_mnemonics) {
    SeedMirageScore s;
    s.mnemonic = m;
    auto v = bip39_validate_mnemonic(m);
    s.bip39_checksum = v.checksum_ok;
    s.word_count = v.word_count;
    s.score = 0;
    if (v.checksum_ok) s.score += 50;
    s.score += (std::min)(v.word_count, 24);
    /* Experimental overlap: shared substrings with addresses (not HD derivation) */
    int overlap = 0;
    std::string ml = to_lower_copy(m);
    for (auto& a : addrs) {
      if (a.size() >= 6 && ml.find(to_lower_copy(a.substr(0, 6))) != std::string::npos) ++overlap;
    }
    s.address_overlap = addrs.empty() ? 0 : (double)overlap / (double)addrs.size();
    s.score += s.address_overlap * 20;
    s.note = v.message;
    if (!addrs.empty())
      s.note += " | experimental address-substring overlap (not BIP32 proof)";
    else
      s.note += " | no addresses in wallet to compare";
    r.ranked.push_back(s);
  }
  std::sort(r.ranked.begin(), r.ranked.end(),
            [](const SeedMirageScore& a, const SeedMirageScore& b) { return a.score > b.score; });
  r.summary = "Seed Mirage: ranked " + std::to_string(r.ranked.size()) +
              " mnemonic(s). Classic Core wallet.dat usually stores no BIP39.";
  return r;
}
