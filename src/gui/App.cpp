#include "App.h"
#include "Theme.h"

#include "../crack/CrackEngine.h"
#include "../wallet/Passphrase.h"
#include "../wallet/WalletDat.h"
#include "../wallet/DualVerify.h"
#include "../wallet/HashcatExport.h"
#include "../wallet/PassphraseLab.h"
#include "../wallet/Salvage.h"
#include "../wallet/Archaeology.h"
#include "../wallet/Experiment.h"

#define GLAD_GL_IMPLEMENTATION
#include <glad/gl.h>
#ifndef GLFW_INCLUDE_NONE
#define GLFW_INCLUDE_NONE
#endif
#include <GLFW/glfw3.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#endif

TargetCipher crack_make_target(const std::vector<uint8_t>& blob48);

struct ScannedWallet {
  std::string path;
  uint32_t iterations = UINT32_MAX;
  size_t file_size = 0;
  bool mkey_found = false;
  int ckey_count = 0;
};

struct AppState {
  WalletParseResult wallet;
  bool has_wallet = false;
  char target_address[128] = {};
  char try_key[80] = {};
  char passphrase[256] = {};
  char wif_check[128] = {};
  char seq_start[80] = {};
  char found_path[260] = "FOUND_WALLET.txt";
  char out_path[260] = "key_found.txt";
  char mem_budget[32] = "auto";

  int device = 0;
  int blocks = 0;
  int threads = 0;
  int streams = 4;
  int mode = 0; /* 0=r 1=q 2=rs 3=partial */
  int mixed_span = 256;
  bool light_theme = false;
  bool include_mkey = true;
  bool include_ckeys = true;
  int selected_ckey = -1;

  /* Extract / folder scan */
  char scan_folder[512] = {};
  bool folder_scan_mode = false;
  std::vector<ScannedWallet> scanned_wallets;
  int selected_scan = -1;
  ArchaeologyReport archaeology;
  std::vector<uint8_t> wallet_raw;

  /* Salvage */
  SalvageReport salvage;
  bool has_salvage = false;
  char salvage_import_path[512] = {};
  int selected_salvage_ckey = -1;

  /* Passphrase Lab */
  RecallTokens recall;
  char dict_path[512] = {};
  char mask_pattern[128] = {};
  char single_pass[256] = {};
  char recall_word_buf[64] = {};
  char recall_prefix_buf[32] = {};
  char recall_suffix_buf[32] = {};
  std::vector<std::string> candidates;
  CandidateGenStats candidate_stats;
  PassphraseCrackProgress pp_progress;
  std::thread pp_thread;
  double measured_hps = 0;

  /* AES Partial */
  char partial_prefix[128] = {};
  char cold_boot_keys[4096] = {};

  /* Hashcat Bridge */
  char hashcat_export_path[260] = "wallet_hash.txt";
  char hashcat_wordlist[512] = {};
  std::string hashcat_exe_cached;

  /* Results */
  DualVerifyResult last_dual;
  bool has_last_dual = false;
  MultiCkeyDecryptResult multi_decrypt;
  bool has_multi_decrypt = false;
  char recovered_master_hex[68] = {};

  bool wipe_found_on_erase = false;

  std::vector<std::string> devices;
  std::vector<std::string> console;
  std::mutex console_mu;

  CrackEngine cracker;
  std::string last_hit_text;
  std::string passphrase_result;
  std::string wif_result;

  double drop_pulse = 0;

  void log(const std::string& line) {
    std::lock_guard<std::mutex> lock(console_mu);
    console.push_back(line);
    if (console.size() > 2000) console.erase(console.begin(), console.begin() + 500);
  }
};

static void glfw_error(int code, const char* desc) {
  std::fprintf(stderr, "GLFW %d: %s\n", code, desc);
}

#ifdef _WIN32
static std::string open_file_dialog(const char* filter = "Wallet DAT\0*.dat\0All\0*.*\0") {
  char file[MAX_PATH] = {};
  OPENFILENAMEA ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.lpstrFile = file;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrFilter = filter;
  ofn.nFilterIndex = 1;
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
  if (GetOpenFileNameA(&ofn)) return file;
  return {};
}

static std::string save_file_dialog(const char* filter, const char* defext) {
  char file[MAX_PATH] = {};
  OPENFILENAMEA ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.lpstrFile = file;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrFilter = filter;
  ofn.nFilterIndex = 1;
  ofn.lpstrDefExt = defext;
  ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
  if (GetSaveFileNameA(&ofn)) return file;
  return {};
}

static std::string browse_folder_dialog() {
  char path[MAX_PATH] = {};
  BROWSEINFOA bi{};
  bi.lpszTitle = "Select folder to scan for wallet.dat";
  bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
  LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
  if (!pidl) return {};
  if (!SHGetPathFromIDListA(pidl, path)) {
    CoTaskMemFree(pidl);
    return {};
  }
  CoTaskMemFree(pidl);
  return path;
}

static void set_clipboard(const std::string& s) {
  if (!OpenClipboard(nullptr)) return;
  EmptyClipboard();
  HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, s.size() + 1);
  if (h) {
    memcpy(GlobalLock(h), s.c_str(), s.size() + 1);
    GlobalUnlock(h);
    SetClipboardData(CF_TEXT, h);
  }
  CloseClipboard();
}

static bool secure_erase_file(const std::string& path) {
  std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
  if (!f) return false;
  f.seekg(0, std::ios::end);
  auto sz = f.tellg();
  if (sz <= 0) return false;
  std::vector<char> zeros((size_t)sz, '\0');
  f.seekp(0);
  f.write(zeros.data(), zeros.size());
  f.flush();
  f.close();
  return true;
}
#else
static std::string open_file_dialog(const char* = nullptr) { return {}; }
static std::string save_file_dialog(const char*, const char*) { return {}; }
static std::string browse_folder_dialog() { return {}; }
static void set_clipboard(const std::string&) {}
static bool secure_erase_file(const std::string&) { return false; }
#endif

static std::vector<uint8_t> read_file_bytes(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
}

static bool hex_to_master32(const char* hex, uint8_t out[32]) {
  std::vector<uint8_t> b;
  for (int i = 0; hex[i] && hex[i + 1]; i += 2) {
    auto nib = [](char c) {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int a = nib(hex[i]), d = nib(hex[i + 1]);
    if (a < 0 || d < 0) return false;
    b.push_back((uint8_t)((a << 4) | d));
  }
  if (b.size() != 32) return false;
  memcpy(out, b.data(), 32);
  return true;
}

static void load_wallet_path(AppState& app, const std::string& path) {
  if (path.empty()) return;
  WalletDatParser parser;
  app.wallet = parser.parse_file(path);
  app.has_wallet = true;
  app.wallet_raw = read_file_bytes(path);
  app.archaeology = analyze_archaeology(app.wallet, app.wallet_raw.data(), app.wallet_raw.size());
  app.selected_ckey = app.wallet.ckeys.empty() ? -1 : 0;
  for (auto& line : app.wallet.log) app.log(line);
  for (auto& w : app.wallet.warnings) app.log("[warn] " + w);
  for (auto& f : app.archaeology.findings)
    app.log("[arch] " + f.flag + ": " + f.detail);
  app.log("[+] ready — " + std::to_string(app.wallet.ckeys.size()) + " ckeys");
  if (app.target_address[0]) {
    for (size_t i = 0; i < app.wallet.ckeys.size(); ++i) {
      if (app.wallet.ckeys[i].address == app.target_address) {
        app.log("*** TARGET MATCH ckey #" + std::to_string(i) + " ***");
        app.selected_ckey = (int)i;
      }
    }
  }
}

#ifdef _WIN32
static void scan_folder_wallets(AppState& app) {
  app.scanned_wallets.clear();
  std::string base = app.scan_folder;
  if (base.empty()) return;
  if (base.back() != '\\' && base.back() != '/') base += "\\";
  std::string pattern = base + "*.dat";
  WIN32_FIND_DATAA fd{};
  HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
  if (h == INVALID_HANDLE_VALUE) {
    app.log("[!] folder scan: no *.dat in " + base);
    return;
  }
  WalletDatParser parser;
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    std::string full = base + fd.cFileName;
    auto w = parser.parse_file(full);
    ScannedWallet sw;
    sw.path = full;
    sw.file_size = w.file_size;
    sw.mkey_found = w.mkey.found;
    sw.ckey_count = w.ckey_count();
    sw.iterations = w.mkey.found ? w.mkey.iterations : UINT32_MAX;
    app.scanned_wallets.push_back(sw);
  } while (FindNextFileA(h, &fd));
  FindClose(h);
  std::sort(app.scanned_wallets.begin(), app.scanned_wallets.end(),
            [](const ScannedWallet& a, const ScannedWallet& b) {
              if (a.iterations != b.iterations) return a.iterations < b.iterations;
              return a.file_size < b.file_size;
            });
  app.log("[+] folder scan: " + std::to_string(app.scanned_wallets.size()) +
          " wallet.dat (sorted low-iter first)");
}
#endif

static void load_poc_wallet(AppState& app) {
  app.wallet = WalletParseResult{};
  app.wallet.path = "(PoC bundled)";
  app.wallet.magic_ok = true;
  app.wallet.bdb_note = "demo — crackBTCwallet PoC ckey";
  CKeyInfo ck;
  const char* enc =
      "2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155";
  const char* pub =
      "0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5";
  auto hex = [](const char* h, std::vector<uint8_t>& o) {
    o.clear();
    for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
      auto nib = [](char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
      };
      o.push_back((uint8_t)((nib(h[i]) << 4) | nib(h[i + 1])));
    }
  };
  hex(enc, ck.encrypted48);
  ck.encrypted_hex = enc;
  hex(pub, ck.pubkey);
  ck.pubkey_hex = pub;
  ck.address = "(PoC — see selftest WIFs)";
  ck.address_ok = true;
  app.wallet.ckeys.push_back(ck);
  app.has_wallet = true;
  app.wallet_raw.clear();
  app.archaeology = analyze_archaeology(app.wallet, nullptr, 0);
  app.selected_ckey = 0;
  app.log("[+] loaded bundled PoC ckey + pubkey");
}

static std::vector<CrackTarget> build_targets(AppState& app) {
  std::vector<CrackTarget> out;
  if (app.include_mkey && app.wallet.mkey.found && app.wallet.mkey.encrypted48.size() == 48) {
    CrackTarget t;
    t.wallet.enc48 = app.wallet.mkey.encrypted48;
    t.wallet.enc_hex = app.wallet.mkey.encrypted_hex;
    t.wallet.is_mkey = true;
    t.cipher = crack_make_target(t.wallet.enc48);
    out.push_back(t);
  }
  if (app.include_ckeys) {
    for (auto& ck : app.wallet.ckeys) {
      if (ck.encrypted48.size() != 48) continue;
      CrackTarget t;
      t.wallet.enc48 = ck.encrypted48;
      t.wallet.enc_hex = ck.encrypted_hex;
      t.wallet.pubkey = ck.pubkey;
      t.wallet.pubkey_hex = ck.pubkey_hex;
      t.wallet.is_mkey = false;
      t.cipher = crack_make_target(t.wallet.enc48);
      out.push_back(t);
    }
  }
  return out;
}

static void draw_brand_bar(AppState& app) {
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.78f, 0.62f, 0.28f, 1.f));
  ImGui::TextUnformatted("TrueWalletCollider");
  ImGui::PopStyleColor();
  ImGui::SameLine();
  ImGui::TextColored(ImVec4(0.55f, 0.52f, 0.45f, 0.95f), "  // Recovery Lab");
  ImGui::SameLine(ImGui::GetWindowWidth() - 280);
  if (ImGui::SmallButton(app.light_theme ? "Noir" : "Light")) {
    app.light_theme = !app.light_theme;
    ApplyTrueScentTheme(app.light_theme);
  }
  ImGui::SameLine();
  ImGui::TextDisabled("wallet.dat + CUDA + passphrase lab");
  ImGui::Separator();
}

static void draw_archaeology_flags(AppState& app) {
  if (!app.has_wallet) return;
  ImGui::TextWrapped("%s", app.archaeology.summary.c_str());
  if (ImGui::BeginTable("arch", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                        ImVec2(0, 120))) {
    ImGui::TableSetupColumn("Flag");
    ImGui::TableSetupColumn("Severity");
    ImGui::TableSetupColumn("Detail");
    ImGui::TableHeadersRow();
    for (auto& f : app.archaeology.findings) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImVec4 col = f.severity >= 3 ? ImVec4(1.f, 0.45f, 0.35f, 1.f)
                  : f.severity >= 2 ? ImVec4(0.95f, 0.75f, 0.25f, 1.f)
                                    : ImVec4(0.55f, 0.92f, 0.55f, 1.f);
      ImGui::TextColored(col, "%s", f.flag.c_str());
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("%d", f.severity);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextWrapped("%s", f.detail.c_str());
    }
    ImGui::EndTable();
  }
  ImGui::Text("mkeys=%d unencrypted_keys=%d plaintext_scraps=%d", app.archaeology.mkey_count,
              app.archaeology.unencrypted_keys, app.archaeology.plaintext_scraps);
}

static void draw_mkey_panel(AppState& app) {
  if (!app.has_wallet || !app.wallet.mkey.found) {
    ImGui::TextDisabled("No master key parsed.");
    return;
  }
  auto& m = app.wallet.mkey;
  ImGui::Text("Offset: %zu", m.file_offset);
  ImGui::TextWrapped("encrypted48:\n%s", m.encrypted_hex.c_str());
  if (ImGui::Button("Copy enc")) set_clipboard(m.encrypted_hex);
  ImGui::SameLine();
  if (ImGui::Button("Copy salt")) set_clipboard(m.salt_hex);
  ImGui::SameLine();
  if (ImGui::Button("Copy target_mkey")) set_clipboard(m.target_mkey_hex);
  ImGui::Text("salt: %s", m.salt_hex.c_str());
  ImGui::Text("iv:   %s", m.iv_hex.c_str());
  ImGui::Text("ct:   %s", m.ct_hex.c_str());
  ImGui::Text("method: %u | iterations: %u", m.method, m.iterations);
  ImGui::TextWrapped("target_mkey: %s", m.target_mkey_hex.c_str());
}

static void draw_ckeys_panel(AppState& app) {
  if (!app.has_wallet) {
    ImGui::TextDisabled("Load a wallet first.");
    return;
  }
  ImGui::BeginChild("ckey_list", ImVec2(260, 0), true);
  for (int i = 0; i < (int)app.wallet.ckeys.size(); ++i) {
    char label[128];
    std::snprintf(label, sizeof(label), "#%d %s", i,
                  app.wallet.ckeys[i].address.empty() ? "(no addr)"
                                                      : app.wallet.ckeys[i].address.c_str());
    if (ImGui::Selectable(label, app.selected_ckey == i)) app.selected_ckey = i;
  }
  ImGui::EndChild();
  ImGui::SameLine();
  ImGui::BeginChild("ckey_detail", ImVec2(0, 0), true);
  if (app.selected_ckey >= 0 && app.selected_ckey < (int)app.wallet.ckeys.size()) {
    auto& c = app.wallet.ckeys[app.selected_ckey];
    ImGui::Text("Offset: %zu", c.file_offset);
    ImGui::TextWrapped("Address: %s", c.address.c_str());
    ImGui::TextWrapped("encrypted:\n%s", c.encrypted_hex.c_str());
    ImGui::TextWrapped("pubkey:\n%s", c.pubkey_hex.c_str());
    if (ImGui::Button("Copy enc")) set_clipboard(c.encrypted_hex);
    ImGui::SameLine();
    if (ImGui::Button("Copy pub")) set_clipboard(c.pubkey_hex);
    ImGui::SameLine();
    if (ImGui::Button("Copy address")) set_clipboard(c.address);
  }
  ImGui::EndChild();
}

static void draw_meta_panel(AppState& app) {
  if (!app.has_wallet) return;
  if (ImGui::BeginTable("meta", 3,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                        ImVec2(0, 160))) {
    ImGui::TableSetupColumn("Tag");
    ImGui::TableSetupColumn("Offset");
    ImGui::TableSetupColumn("Note");
    ImGui::TableHeadersRow();
    for (auto& m : app.wallet.meta) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextUnformatted(m.tag.c_str());
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("%zu", m.offset);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextWrapped("%s", m.note.c_str());
    }
    ImGui::EndTable();
  }
}

static void draw_extract_tab(AppState& app) {
  if (!app.has_wallet) {
    ImGui::TextWrapped(
        "Drop wallet.dat here or Open File. Extract tab folds overview, mkey, ckeys, metadata, "
        "and archaeology flags.");
    if (ImGui::Button("Open wallet.dat", ImVec2(180, 36))) {
      auto p = open_file_dialog();
      if (!p.empty()) load_wallet_path(app, p);
    }
    ImGui::SameLine();
    if (ImGui::Button("Load PoC targets", ImVec2(160, 36))) load_poc_wallet(app);
    ImGui::Separator();
    ImGui::Checkbox("Folder scan mode", &app.folder_scan_mode);
    if (app.folder_scan_mode) {
      ImGui::InputText("Scan folder", app.scan_folder, sizeof(app.scan_folder));
      ImGui::SameLine();
      if (ImGui::Button("Browse")) {
        auto f = browse_folder_dialog();
        if (!f.empty()) std::snprintf(app.scan_folder, sizeof(app.scan_folder), "%s", f.c_str());
      }
#ifdef _WIN32
      if (ImGui::Button("Scan *.dat (low iter first)")) scan_folder_wallets(app);
#endif
      if (!app.scanned_wallets.empty() && ImGui::BeginTable("scan", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 140))) {
        ImGui::TableSetupColumn("Path");
        ImGui::TableSetupColumn("Iters");
        ImGui::TableSetupColumn("CKeys");
        ImGui::TableSetupColumn("Size");
        ImGui::TableHeadersRow();
        for (int i = 0; i < (int)app.scanned_wallets.size(); ++i) {
          auto& sw = app.scanned_wallets[i];
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          bool sel = (app.selected_scan == i);
          if (ImGui::Selectable(sw.path.c_str(), sel, ImGuiSelectableFlags_SpanAllColumns))
            app.selected_scan = i;
          ImGui::TableSetColumnIndex(1);
          ImGui::Text("%u", sw.iterations == UINT32_MAX ? 0 : sw.iterations);
          ImGui::TableSetColumnIndex(2);
          ImGui::Text("%d", sw.ckey_count);
          ImGui::TableSetColumnIndex(3);
          ImGui::Text("%zu", sw.file_size);
        }
        ImGui::EndTable();
        if (app.selected_scan >= 0 && ImGui::Button("Load selected wallet"))
          load_wallet_path(app, app.scanned_wallets[app.selected_scan].path);
      }
    }
    return;
  }

  ImGui::Text("File: %s", app.wallet.path.c_str());
  ImGui::Text("Size: %zu | Magic: %s", app.wallet.file_size, app.wallet.magic_ok ? "OK" : "BAD");
  ImGui::TextWrapped("%s", app.wallet.bdb_note.c_str());
  ImGui::InputText("Target address", app.target_address, sizeof(app.target_address));
  if (ImGui::Button("Re-open")) {
    auto p = open_file_dialog();
    if (!p.empty()) load_wallet_path(app, p);
  }
  ImGui::SameLine();
  if (ImGui::Button("Export TXT")) {
    auto p = save_file_dialog("Text\0*.txt\0", "txt");
    if (!p.empty()) {
      std::ofstream o(p);
      o << WalletDatParser::export_txt(app.wallet);
      app.log("[+] exported TXT " + p);
    }
  }
  ImGui::SameLine();
  if (ImGui::Button("Export JSON")) {
    auto p = save_file_dialog("JSON\0*.json\0", "json");
    if (!p.empty()) {
      std::ofstream o(p);
      o << WalletDatParser::export_json(app.wallet);
      app.log("[+] exported JSON " + p);
    }
  }
  ImGui::SameLine();
  if (ImGui::Button("Export ckeys")) {
    WalletDatParser::write_ckeys_file(app.wallet, "ckeys_export.txt");
    WalletDatParser::write_mkeys_file(app.wallet, "mkeys_export.txt");
    app.log("[+] wrote ckeys_export.txt / mkeys_export.txt");
  }

  if (ImGui::CollapsingHeader("Archaeology flags", ImGuiTreeNodeFlags_DefaultOpen))
    draw_archaeology_flags(app);
  if (ImGui::CollapsingHeader("Master key", ImGuiTreeNodeFlags_DefaultOpen)) draw_mkey_panel(app);
  if (ImGui::CollapsingHeader("CKeys")) draw_ckeys_panel(app);
  if (ImGui::CollapsingHeader("Metadata")) draw_meta_panel(app);
}

static void draw_salvage_tab(AppState& app) {
  ImGui::TextWrapped(
      "Salvage carves mkey/ckey/pubkey blobs from damaged BDB or raw dumps. "
      "Import pane: point at user-provided forensic images or partial wallet fragments.");
  ImGui::InputText("Import path", app.salvage_import_path, sizeof(app.salvage_import_path));
  ImGui::SameLine();
  if (ImGui::Button("Browse file")) {
    auto p = open_file_dialog("All\0*.*\0");
    if (!p.empty()) std::snprintf(app.salvage_import_path, sizeof(app.salvage_import_path), "%s", p.c_str());
  }
  if (ImGui::Button("salvage_file")) {
    app.salvage = salvage_file(app.salvage_import_path);
    app.has_salvage = true;
    app.selected_salvage_ckey = app.salvage.ckeys_ranked.empty() ? -1 : 0;
    for (auto& n : app.salvage.notes) app.log("[salvage] " + n);
    app.log("[+] salvage_file done — " + std::to_string(app.salvage.ckey_candidates) + " ckey candidates");
  }
  ImGui::SameLine();
  if (ImGui::Button("salvage_carve (raw bytes)")) {
    auto raw = read_file_bytes(app.salvage_import_path);
    app.salvage = salvage_carve(raw.data(), raw.size(), app.salvage_import_path);
    app.has_salvage = true;
    app.selected_salvage_ckey = app.salvage.ckeys_ranked.empty() ? -1 : 0;
    for (auto& n : app.salvage.notes) app.log("[salvage] " + n);
    app.log("[+] salvage_carve done");
  }
  if (!app.has_salvage) return;

  ImGui::Separator();
  ImGui::Text("path=%s size=%zu magic=%s mkey_cand=%d ckey_cand=%d", app.salvage.path.c_str(),
              app.salvage.file_size, app.salvage.magic_ok ? "OK" : "no", app.salvage.mkey_candidates,
              app.salvage.ckey_candidates);
  ImGui::TextUnformatted("Heatmap (offset intensity):");
  ImGui::BeginChild("heatmap", ImVec2(0, 100), true, ImGuiWindowFlags_HorizontalScrollbar);
  ImGui::TextUnformatted(app.salvage.heatmap_ascii.c_str());
  ImGui::EndChild();

  if (ImGui::BeginTable("salv_ckeys", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 160))) {
    ImGui::TableSetupColumn("Rank");
    ImGui::TableSetupColumn("Score");
    ImGui::TableSetupColumn("Note / address");
    ImGui::TableHeadersRow();
    for (int i = 0; i < (int)app.salvage.ckeys_ranked.size(); ++i) {
      auto& sc = app.salvage.ckeys_ranked[i];
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      if (ImGui::Selectable(std::to_string(i).c_str(), app.selected_salvage_ckey == i))
        app.selected_salvage_ckey = i;
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("%d", sc.score);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextWrapped("%s | %s", sc.rank_note.c_str(), sc.ckey.address.c_str());
    }
    ImGui::EndTable();
  }
  if (ImGui::Button("Export salvage TXT")) {
    auto p = save_file_dialog("Text\0*.txt\0", "txt");
    if (!p.empty()) {
      std::ofstream o(p);
      o << salvage_export_txt(app.salvage);
      app.log("[+] salvage TXT " + p);
    }
  }
  ImGui::SameLine();
  if (ImGui::Button("Export salvage JSON")) {
    auto p = save_file_dialog("JSON\0*.json\0", "json");
    if (!p.empty()) {
      std::ofstream o(p);
      o << salvage_export_json(app.salvage);
      app.log("[+] salvage JSON " + p);
    }
  }
}

static void draw_passphrase_lab_tab(AppState& app) {
  if (!app.has_wallet || !app.wallet.mkey.found) {
    ImGui::TextDisabled("Load a wallet with structured mkey first.");
    return;
  }
  ImGui::Text("Iterations: %u | method: %u", app.wallet.mkey.iterations, app.wallet.mkey.method);

  ImGui::InputText("Single passphrase", app.single_pass, sizeof(app.single_pass), ImGuiInputTextFlags_Password);
  if (ImGui::Button("Try single (dual_verify)")) {
    app.last_dual = dual_verify_passphrase(app.wallet.mkey, app.wallet, app.single_pass, app.found_path);
    app.has_last_dual = true;
    app.log(app.last_dual.ok ? "[+] passphrase FOUND" : "[!] passphrase miss");
    if (app.last_dual.ok && !app.last_dual.master_hex.empty())
      std::snprintf(app.recovered_master_hex, sizeof(app.recovered_master_hex), "%s",
                    app.last_dual.master_hex.c_str());
  }

  ImGui::Separator();
  ImGui::InputText("Dictionary file", app.dict_path, sizeof(app.dict_path));
  ImGui::SameLine();
  if (ImGui::Button("Pick dict")) {
    auto p = open_file_dialog("Text\0*.txt\0All\0*.*\0");
    if (!p.empty()) std::snprintf(app.dict_path, sizeof(app.dict_path), "%s", p.c_str());
  }
  ImGui::InputText("Simple mask", app.mask_pattern, sizeof(app.mask_pattern));
  ImGui::TextDisabled("Mask: ?d digit, ?l lower, ?u upper, ?s symbol — e.g. Pass?d?d?d");

  if (ImGui::TreeNode("Recall token interview")) {
    ImGui::InputText("Add word", app.recall_word_buf, sizeof(app.recall_word_buf));
    ImGui::SameLine();
    if (ImGui::Button("Add") && app.recall_word_buf[0]) {
      app.recall.known_words.push_back(app.recall_word_buf);
      app.recall_word_buf[0] = 0;
    }
    for (int i = 0; i < (int)app.recall.known_words.size(); ++i) {
      ImGui::BulletText("%s", app.recall.known_words[i].c_str());
      ImGui::SameLine();
      ImGui::PushID(i);
      if (ImGui::SmallButton("X")) app.recall.known_words.erase(app.recall.known_words.begin() + i--);
      ImGui::PopID();
    }
    ImGui::Checkbox("keyboard walks", &app.recall.keyboard_walks);
    ImGui::SameLine();
    ImGui::Checkbox("case variants", &app.recall.case_variants);
    ImGui::SameLine();
    ImGui::Checkbox("leet", &app.recall.leet);
    ImGui::Checkbox("append years", &app.recall.append_years);
    ImGui::InputText("Prefix", app.recall_prefix_buf, sizeof(app.recall_prefix_buf));
    ImGui::SameLine();
    if (ImGui::Button("Add prefix") && app.recall_prefix_buf[0]) {
      app.recall.prefixes.push_back(app.recall_prefix_buf);
      app.recall_prefix_buf[0] = 0;
    }
    ImGui::InputText("Suffix", app.recall_suffix_buf, sizeof(app.recall_suffix_buf));
    ImGui::SameLine();
    if (ImGui::Button("Add suffix") && app.recall_suffix_buf[0]) {
      app.recall.suffixes.push_back(app.recall_suffix_buf);
      app.recall_suffix_buf[0] = 0;
    }
    if (app.recall.separators.empty()) app.recall.separators = {"", " ", "-", "_", "."};
    if (app.recall.years.empty())
      for (int y = 2010; y <= 2026; ++y) app.recall.years.push_back(std::to_string(y));
    ImGui::TreePop();
  }

  if (ImGui::Button("Generate candidates")) {
    app.candidates.clear();
    if (app.dict_path[0]) {
      std::ifstream df(app.dict_path);
      std::string line;
      while (std::getline(df, line) && app.candidates.size() < 500000) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (!line.empty()) app.candidates.push_back(line);
      }
    }
    if (app.mask_pattern[0]) {
      auto m = expand_simple_mask(app.mask_pattern, 100000);
      app.candidates.insert(app.candidates.end(), m.begin(), m.end());
    }
    if (!app.recall.known_words.empty()) {
      auto r = generate_recall_candidates(app.recall, 200000, &app.candidate_stats);
      app.candidates.insert(app.candidates.end(), r.begin(), r.end());
    }
    if (app.single_pass[0]) app.candidates.insert(app.candidates.begin(), app.single_pass);
    std::sort(app.candidates.begin(), app.candidates.end());
    app.candidates.erase(std::unique(app.candidates.begin(), app.candidates.end()), app.candidates.end());
    app.candidate_stats.count = app.candidates.size();
    app.log("[+] candidates: " + std::to_string(app.candidates.size()));
  }
  ImGui::SameLine();
  if (ImGui::Button("Measure H/s")) {
    app.measured_hps = measure_kdf_hps(app.wallet.mkey, 3);
    app.log("[+] measured ~" + std::to_string((int)app.measured_hps) + " H/s");
  }
  if (app.candidates.size())
    ImGui::Text("Candidates: %zu | H/s: %.1f | %s", app.candidates.size(), app.measured_hps,
                format_passphrase_eta(app.wallet.mkey.iterations, app.candidates.size(), app.measured_hps).c_str());

  bool pp_running = app.pp_progress.running.load();
  if (!pp_running) {
    if (ImGui::Button("Run batch dual_verify_passphrase", ImVec2(-1, 32)) && !app.candidates.empty()) {
      if (app.pp_thread.joinable()) app.pp_thread.join();
      auto cands = app.candidates;
      app.pp_thread = std::thread([&app, cands]() {
        run_passphrase_batch(app.wallet, cands, app.pp_progress, app.found_path);
      });
    }
  } else {
    if (ImGui::Button("Stop batch")) app.pp_progress.stop = true;
  }
  if (pp_running || app.pp_progress.tried.load()) {
    float pct = app.pp_progress.total ? (float)app.pp_progress.tried.load() / (float)app.pp_progress.total : 0.f;
    ImGui::ProgressBar(pct, ImVec2(-1, 0));
    ImGui::Text("%llu / %llu @ %.1f H/s — %s", (unsigned long long)app.pp_progress.tried.load(),
                (unsigned long long)app.pp_progress.total.load(), app.pp_progress.rate_hps,
                app.pp_progress.message.c_str());
    if (app.pp_progress.hit.load()) {
      app.last_dual = app.pp_progress.dual;
      app.has_last_dual = true;
      if (!app.last_dual.master_hex.empty())
        std::snprintf(app.recovered_master_hex, sizeof(app.recovered_master_hex), "%s",
                      app.last_dual.master_hex.c_str());
    }
  }
}

static void draw_aes_partial_tab(AppState& app) {
  ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.25f, 1.f),
                     "Research notice: full 256-bit AES brute is infeasible.");
  ImGui::TextWrapped(
      "GPU search earns its keep only on constrained spaces: known hex prefix (cold-boot / "
      "partial key material), sequential windows, or targeted random spans. Use Passphrase Lab "
      "or Hashcat Bridge for wallet passwords.");
  ImGui::Separator();
  ImGui::InputText("Hex prefix (even len, 1..31 bytes)", app.partial_prefix, sizeof(app.partial_prefix));
  ImGui::TextDisabled("MODE_PARTIAL: GPU walks unknown suffix bytes only.");

  if (ImGui::Button("Start PARTIAL CUDA") && app.has_wallet) {
    auto targets = build_targets(app);
    if (targets.empty()) {
      app.log("[E] no targets for partial search");
    } else {
      CrackConfig cfg;
      cfg.device = app.device;
      cfg.blocks = app.blocks;
      cfg.threads = app.threads;
      cfg.streams = (std::max)(1, app.streams);
      cfg.mem = app.mem_budget;
      cfg.mode = MODE_PARTIAL;
      cfg.partial_prefix_hex = app.partial_prefix;
      cfg.found_file = app.found_path;
      cfg.out_file = app.out_path;
      app.cracker.set_config(cfg);
      app.cracker.set_targets(std::move(targets));
      if (app.cracker.start()) app.log("[+] MODE_PARTIAL CUDA started");
      else app.log("[E] " + app.cracker.status().last_message);
    }
  }

  ImGui::Separator();
  ImGui::TextUnformatted("Cold-boot / RAM dump candidates (one 64-hex key per line):");
  ImGui::InputTextMultiline("##cold", app.cold_boot_keys, sizeof(app.cold_boot_keys), ImVec2(-1, 120));
  if (ImGui::Button("Try all cold-boot keys (host)")) {
    auto targets = build_targets(app);
    if (targets.empty()) {
      app.log("[!] no targets — load wallet first");
    } else {
      CrackConfig cfg;
      cfg.found_file = app.found_path;
      cfg.out_file = app.out_path;
      app.cracker.set_config(cfg);
      app.cracker.set_targets(targets);
      std::istringstream iss(app.cold_boot_keys);
      std::string line;
      int tried = 0;
      while (std::getline(iss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
          line.pop_back();
        size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        line = line.substr(start);
        if (line.size() != 64) continue;
        std::string msg;
        if (app.cracker.try_key(line, &msg)) {
          app.log(msg);
          app.last_hit_text = msg;
          break;
        }
        ++tried;
      }
      app.log("[+] cold-boot try_key done (" + std::to_string(tried) + " keys)");
    }
  }
}

static void draw_hashcat_bridge_tab(AppState& app) {
  if (!app.has_wallet || !app.wallet.mkey.found) {
    ImGui::TextDisabled("Load wallet with mkey to export $bitcoin$ hash.");
    return;
  }
  std::string line = export_bitcoin_hashcat_line_extended(app.wallet);
  ImGui::TextWrapped("Hashcat mode -m 11300 (Bitcoin Core wallet.dat)");
  ImGui::BeginChild("hcline", ImVec2(-1, 60), true);
  ImGui::TextWrapped("%s", line.c_str());
  ImGui::EndChild();
  if (ImGui::Button("Copy $bitcoin$ line")) set_clipboard(line);

  ImGui::InputText("Export path", app.hashcat_export_path, sizeof(app.hashcat_export_path));
  if (ImGui::Button("Write hash file")) {
    if (write_hashcat_file(app.wallet, app.hashcat_export_path, true))
      app.log("[+] wrote " + std::string(app.hashcat_export_path));
    else
      app.log("[E] hash export failed");
  }
  if (app.hashcat_exe_cached.empty()) app.hashcat_exe_cached = find_hashcat_exe();
  ImGui::Text("hashcat: %s",
              app.hashcat_exe_cached.empty() ? "(not found — run setup_forensics.bat or add PATH)"
                                             : app.hashcat_exe_cached.c_str());
  if (ImGui::Button("Rescan hashcat")) {
    app.hashcat_exe_cached = find_hashcat_exe();
    app.log(app.hashcat_exe_cached.empty() ? "[!] hashcat still missing"
                                           : "[+] hashcat: " + app.hashcat_exe_cached);
  }
  ImGui::InputText("Wordlist (optional)", app.hashcat_wordlist, sizeof(app.hashcat_wordlist));
  if (ImGui::Button("Spawn hashcat -m 11300")) {
    app.hashcat_exe_cached = find_hashcat_exe();
    auto r = spawn_hashcat_attack(app.hashcat_export_path, app.hashcat_wordlist, app.hashcat_exe_cached);
    app.log(r.message);
  }
  ImGui::Separator();
  ImGui::TextWrapped(
      "Manual: hashcat -m 11300 -a 0 wallet_hash.txt wordlist.txt\n"
      "Bundled path after setup: third_party\\hashcat\\hashcat.exe\n"
      "John the Ripper: bitcoin2john wallet.dat > hash.txt");
}

static void draw_results_tab(AppState& app) {
  ImGui::Text("FOUND_WALLET path: %s", app.found_path);
  if (ImGui::Button("Open FOUND file location")) {
#ifdef _WIN32
    ShellExecuteA(nullptr, "open", app.found_path, nullptr, nullptr, SW_SHOWNORMAL);
#endif
  }
  ImGui::Separator();
  if (app.has_last_dual) {
    ImGui::TextColored(app.last_dual.ok ? ImVec4(0.55f, 0.92f, 0.55f, 1.f) : ImVec4(0.9f, 0.5f, 0.4f, 1.f),
                       "Last dual verify: %s", app.last_dual.ok ? "OK" : "FAIL");
    ImGui::TextWrapped("%s", app.last_dual.message.c_str());
    ImGui::Text("pkcs_mkey=%d pkcs_ckey=%d pubkey_match=%d", app.last_dual.pkcs_mkey,
                app.last_dual.pkcs_ckey, app.last_dual.pubkey_match);
    if (!app.last_dual.master_hex.empty())
      ImGui::Text("master: %s", app.last_dual.master_hex.c_str());
  } else {
    ImGui::TextDisabled("No dual verify result yet.");
  }

  ImGui::Separator();
  ImGui::InputText("Recovered master (64 hex)", app.recovered_master_hex, sizeof(app.recovered_master_hex));
  if (ImGui::Button("decrypt_all_ckeys") && app.has_wallet) {
    uint8_t master[32];
    if (hex_to_master32(app.recovered_master_hex, master)) {
      app.multi_decrypt = decrypt_all_ckeys(master, app.wallet, app.found_path);
      app.has_multi_decrypt = true;
      app.log(app.multi_decrypt.report);
    } else {
      app.log("[E] invalid master hex");
    }
  }
  if (app.has_multi_decrypt) {
    ImGui::TextWrapped("%s", app.multi_decrypt.report.c_str());
    ImGui::Text("decrypted=%d failed=%d pubkey_ok=%d", app.multi_decrypt.decrypted,
                app.multi_decrypt.failed, app.multi_decrypt.pubkey_ok);
  }

  ImGui::Separator();
  ImGui::TextUnformatted("Secure-erase checklist (authorized recovery only):");
  ImGui::BulletText("Export keys to offline media; verify WIF on air-gapped machine.");
  ImGui::BulletText("Delete local copies of wallet.dat fragments and FOUND_WALLET dumps.");
  ImGui::BulletText("Clear console log before closing if sensitive.");
  ImGui::Checkbox("Wipe FOUND + hit log with zero overwrite", &app.wipe_found_on_erase);
  if (ImGui::Button("Run secure erase")) {
    bool ok1 = app.wipe_found_on_erase ? secure_erase_file(app.found_path) : true;
    bool ok2 = app.wipe_found_on_erase ? secure_erase_file(app.out_path) : true;
    app.log(ok1 && ok2 ? "[+] secure erase done" : "[!] erase partial/failed");
  }
}

static void draw_tools_tab(AppState& app) {
  ImGui::TextUnformatted("Quick passphrase (method 0)");
  ImGui::InputText("Passphrase", app.passphrase, sizeof(app.passphrase), ImGuiInputTextFlags_Password);
  if (ImGui::Button("Try passphrase on mkey")) {
    if (!app.has_wallet || !app.wallet.mkey.found) {
      app.passphrase_result = "load wallet with structured mkey first";
    } else {
      auto r = try_wallet_passphrase(app.wallet.mkey, app.passphrase);
      app.passphrase_result = r.message;
      if (r.ok) {
        app.passphrase_result += "\nkey=" + r.derived_key_hex + "\nmkey_plain=" + r.decrypted_mkey_hex;
        app.log("[+] passphrase OK — master key decrypted");
      } else {
        app.log("[!] " + r.message);
      }
    }
  }
  ImGui::TextWrapped("%s", app.passphrase_result.c_str());

  ImGui::Separator();
  ImGui::TextUnformatted("Verify WIF");
  ImGui::InputText("WIF", app.wif_check, sizeof(app.wif_check));
  if (ImGui::Button("Verify")) {
    std::string detail;
    bool ok = verify_wif(app.wif_check, &detail);
    app.wif_result = ok ? detail : ("FAIL — " + detail);
  }
  ImGui::TextWrapped("%s", app.wif_result.c_str());

  ImGui::Separator();
  if (ImGui::Button("Experiment: dual_fp")) {
    std::string log;
    experiment_dual_fp(&log, 5000);
    app.log(log);
  }
  ImGui::SameLine();
  if (ImGui::Button("Experiment: passphrase")) {
    std::string log;
    experiment_passphrase_selftest(&log);
    app.log(log);
  }
  ImGui::SameLine();
  if (ImGui::Button("Experiment: secp")) {
    std::string log;
    run_experiment("secp", &log);
    app.log(log);
  }
}

static void draw_crack_panel(AppState& app) {
  if (app.devices.empty()) app.devices = CrackEngine::list_devices();

  ImGui::Text("CUDA device");
  if (ImGui::BeginCombo("##dev",
                        app.devices.empty() ? "(no devices)"
                                            : app.devices[(std::min)(app.device, (int)app.devices.size() - 1)]
                                                  .c_str())) {
    for (int i = 0; i < (int)app.devices.size(); ++i) {
      bool sel = (app.device == i);
      if (ImGui::Selectable(app.devices[i].c_str(), sel)) app.device = i;
    }
    ImGui::EndCombo();
  }

  ImGui::Checkbox("Include mkey", &app.include_mkey);
  ImGui::SameLine();
  ImGui::Checkbox("Include ckeys", &app.include_ckeys);

  ImGui::RadioButton("Random (-r)", &app.mode, 0);
  ImGui::SameLine();
  ImGui::RadioButton("Sequential (-q)", &app.mode, 1);
  ImGui::SameLine();
  ImGui::RadioButton("Mixed (-rs)", &app.mode, 2);

  ImGui::InputInt("Blocks (0=auto)", &app.blocks);
  ImGui::SameLine();
  ImGui::InputInt("Threads (0=auto)", &app.threads);
  ImGui::InputInt("Streams", &app.streams);
  ImGui::SameLine();
  ImGui::InputInt("Mixed span", &app.mixed_span);
  ImGui::InputText("-M VRAM", app.mem_budget, sizeof(app.mem_budget));
  ImGui::InputText("Seq start (-s)", app.seq_start, sizeof(app.seq_start));
  ImGui::InputText("FOUND file", app.found_path, sizeof(app.found_path));
  ImGui::InputText("Hit log", app.out_path, sizeof(app.out_path));

  ImGui::InputText("Try AES key (64 hex)", app.try_key, sizeof(app.try_key));
  if (ImGui::Button("Try key (host)")) {
    auto targets = build_targets(app);
    if (targets.empty()) {
      app.log("[!] no targets from wallet — load wallet or PoC");
    } else {
      CrackConfig cfg;
      cfg.found_file = app.found_path;
      cfg.out_file = app.out_path;
      app.cracker.set_config(cfg);
      app.cracker.set_targets(targets);
      std::string msg;
      if (app.cracker.try_key(app.try_key, &msg)) {
        app.last_hit_text = msg;
        app.log(msg);
      } else {
        app.log(msg);
      }
    }
  }
  ImGui::SameLine();
  if (ImGui::Button("Selftest")) {
    std::string log;
    int rc = CrackEngine::run_selftest(app.device, app.found_path, &log);
    app.log(log);
    app.log(rc == 0 ? "[+] selftest OK" : "[E] selftest failed");
  }

  bool running = app.cracker.is_running();
  if (!running) {
    if (ImGui::Button("START CUDA SEARCH", ImVec2(220, 40))) {
      auto targets = build_targets(app);
      if (targets.empty()) {
        app.log("[E] no targets — parse wallet or Load PoC");
      } else {
        CrackConfig cfg;
        cfg.device = app.device;
        cfg.blocks = app.blocks;
        cfg.threads = app.threads;
        cfg.streams = (std::max)(1, app.streams);
        cfg.mem = app.mem_budget;
        cfg.mode = app.mode == 1 ? MODE_SEQUENTIAL : app.mode == 2 ? MODE_MIXED : MODE_RANDOM;
        cfg.mixed_span = (uint32_t)app.mixed_span;
        cfg.seq_start = app.seq_start;
        cfg.found_file = app.found_path;
        cfg.out_file = app.out_path;
        app.cracker.set_config(cfg);
        app.cracker.set_targets(std::move(targets));
        if (app.cracker.start())
          app.log("[+] CUDA search started");
        else
          app.log("[E] failed to start: " + app.cracker.status().last_message);
      }
    }
  } else {
    if (ImGui::Button("STOP", ImVec2(120, 40))) {
      app.cracker.stop();
      app.log("[!] stop requested");
    }
  }

  auto& st = app.cracker.status();
  ImGui::Separator();
  ImGui::Text("Status: %s", running ? "RUNNING" : "idle");
  ImGui::Text("Device: %s", st.device_name.c_str());
  ImGui::Text("Grid: %d x %d | keys/launch: %llu", st.blocks, st.threads,
              (unsigned long long)st.keys_per_launch);
  ImGui::Text("Keys: %llu | launches: %llu", (unsigned long long)st.keys_total.load(),
              (unsigned long long)st.launches.load());
  ImGui::TextColored(ImVec4(0.55f, 0.92f, 0.55f, 1.f), "Speed: %s | Peak: %s",
                     CrackEngine::format_rate(st.rate.load()).c_str(),
                     CrackEngine::format_rate(st.peak_rate.load()).c_str());
  {
    std::lock_guard<std::mutex> lock(st.mu);
    ImGui::TextWrapped("%s", st.last_message.c_str());
    if (st.hit.load()) {
      ImGui::Separator();
      ImGui::TextColored(ImVec4(0.78f, 0.62f, 0.28f, 1.f), "HIT");
      ImGui::Text("AES key: %s", st.hit_key_hex.c_str());
      ImGui::TextWrapped("%s", st.hit_result.message.c_str());
      ImGui::Text("WIF_u: %s", st.hit_result.wif_uncompressed.c_str());
      ImGui::Text("WIF_c: %s", st.hit_result.wif_compressed.c_str());
      if (ImGui::Button("Copy WIF compressed")) set_clipboard(st.hit_result.wif_compressed);
    }
  }
}

static void draw_console(AppState& app) {
  if (ImGui::Button("Clear")) {
    std::lock_guard<std::mutex> lock(app.console_mu);
    app.console.clear();
  }
  ImGui::SameLine();
  if (ImGui::Button("Copy all")) {
    std::lock_guard<std::mutex> lock(app.console_mu);
    std::string all;
    for (auto& l : app.console) {
      all += l;
      all += "\n";
    }
    set_clipboard(all);
  }
  ImGui::BeginChild("log", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
  {
    std::lock_guard<std::mutex> lock(app.console_mu);
    for (auto& l : app.console) ImGui::TextUnformatted(l.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8) ImGui::SetScrollHereY(1.f);
  }
  ImGui::EndChild();
}

static void draw_lab_docs_tab(AppState& app) {
  ImGui::TextColored(ImVec4(0.78f, 0.62f, 0.28f, 1.f), "TrueWalletCollider // Recovery Lab");
  ImGui::TextWrapped("%s", experiment_help().c_str());
  ImGui::Separator();
  ImGui::TextUnformatted("Workflow");
  ImGui::BulletText("Extract: parse wallet.dat, archaeology flags, folder scan (low iter first).");
  ImGui::BulletText("Passphrase Lab: KDF candidates + dual_verify_passphrase batch.");
  ImGui::BulletText("Salvage: damaged BDB carve for orphan ckeys/mkeys.");
  ImGui::BulletText("AES Partial: prefix-constrained GPU only — not full 2^256 brute.");
  ImGui::BulletText("Hashcat Bridge: export $bitcoin$ -m 11300 for external wordlists.");
  ImGui::BulletText("Results: multi-ckey decrypt after master recovery.");
  ImGui::Separator();
  ImGui::TextUnformatted("Hibernation / RAM forensic guidance");
  ImGui::TextWrapped(
      "Cold-boot AES candidates belong in AES Partial tab. Only analyze hibernation files, "
      "pagefile, or RAM dumps from systems you own or are explicitly authorized to recover. "
      "Unauthorized forensic imaging is illegal.");
  ImGui::Separator();
  ImGui::TextUnformatted("Secure erase checklist");
  ImGui::BulletText("Move recovered keys offline; verify on air-gapped host.");
  ImGui::BulletText("Zero-fill FOUND_WALLET and local scratch copies when done.");
  ImGui::BulletText("See Results tab for wipe controls.");
  if (ImGui::Button("Run dual_fp experiment")) {
    std::string log;
    run_experiment("dual_fp", &log);
    app.log(log);
  }
}

int RunGuiApp() {
  glfwSetErrorCallback(glfw_error);
  if (!glfwInit()) return 1;

  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
  GLFWwindow* window =
      glfwCreateWindow(1440, 900, "TrueWalletCollider — Recovery Lab", nullptr, nullptr);
  if (!window) {
    glfwTerminate();
    return 1;
  }
  glfwMakeContextCurrent(window);
  glfwSwapInterval(1);
  if (!gladLoadGL(glfwGetProcAddress)) {
    std::fprintf(stderr, "Failed to load OpenGL via GLAD\n");
    return 1;
  }

#ifdef _WIN32
  glfwSetDropCallback(window, [](GLFWwindow* w, int count, const char** paths) {
    auto* app = reinterpret_cast<AppState*>(glfwGetWindowUserPointer(w));
    if (!app || count <= 0) return;
    for (int i = 0; i < count; ++i) {
      std::string p = paths[i];
      if (p.size() >= 4) {
        auto lower = p;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return (char)std::tolower(c); });
        if (lower.size() >= 4 && lower.substr(lower.size() - 4) == ".dat") {
          load_wallet_path(*app, p);
          app->drop_pulse = 1.0;
          break;
        }
      }
    }
  });
#endif

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io.IniFilename = "truewalletcollider_imgui.ini";
  ApplyTrueScentTheme(false);
  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init("#version 330");

  AppState app;
  glfwSetWindowUserPointer(window, &app);
  app.devices = CrackEngine::list_devices();
  app.log("TrueWalletCollider Recovery Lab ready — drop wallet.dat or Extract tab");
  if (!app.devices.empty())
    app.log("CUDA: " + app.devices[0]);
  else
    app.log("[!] no CUDA devices visible");

  while (!glfwWindowShouldClose(window)) {
    glfwPollEvents();
    if (app.pp_thread.joinable() && !app.pp_progress.running.load()) app.pp_thread.join();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("TrueWalletColliderMain", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    draw_brand_bar(app);

    if (app.drop_pulse > 0) {
      ImGui::TextColored(ImVec4(0.55f, 0.92f, 0.55f, (float)app.drop_pulse), "wallet dropped");
      app.drop_pulse -= io.DeltaTime * 0.6;
    }

    ImGui::Columns(2, "maincols", true);
    ImGui::SetColumnWidth(0, vp->WorkSize.x * 0.58f);

    if (ImGui::BeginTabBar("lefttabs")) {
      if (ImGui::BeginTabItem("Extract")) {
        draw_extract_tab(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Salvage")) {
        draw_salvage_tab(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Passphrase Lab")) {
        draw_passphrase_lab_tab(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("AES Partial")) {
        draw_aes_partial_tab(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Hashcat Bridge")) {
        draw_hashcat_bridge_tab(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Results")) {
        draw_results_tab(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Tools")) {
        draw_tools_tab(app);
        ImGui::EndTabItem();
      }
      ImGui::EndTabBar();
    }

    ImGui::NextColumn();
    if (ImGui::BeginTabBar("righttabs")) {
      if (ImGui::BeginTabItem("CUDA Crack")) {
        draw_crack_panel(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Console")) {
        draw_console(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Lab Docs")) {
        draw_lab_docs_tab(app);
        ImGui::EndTabItem();
      }
      ImGui::EndTabBar();
    }
    ImGui::Columns(1);
    ImGui::End();

    ImGui::Render();
    int dw, dh;
    glfwGetFramebufferSize(window, &dw, &dh);
    glViewport(0, 0, dw, dh);
    glClearColor(0.05f, 0.05f, 0.06f, 1.f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(window);
  }

  app.cracker.stop();
  if (app.pp_progress.running.load()) app.pp_progress.stop = true;
  if (app.pp_thread.joinable()) app.pp_thread.join();
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();
  glfwDestroyWindow(window);
  glfwTerminate();
  return 0;
}
