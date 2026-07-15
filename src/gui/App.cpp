#include "App.h"
#include "Theme.h"
#include "ClipboardWin32.h"

#include "../crack/CrackEngine.h"
#include "../wallet/Passphrase.h"
#include "../wallet/WalletDat.h"
#include "../wallet/DualVerify.h"
#include "../wallet/HashcatExport.h"
#include "../wallet/PassphraseLab.h"
#include "../wallet/Salvage.h"
#include "../wallet/Archaeology.h"
#include "../wallet/Experiment.h"
#include "../wallet/ForensicVerify.h"
#include "../wallet/CaseManager.h"
#include "../wallet/ForensicTools.h"
#include "../wallet/ToolBridge.h"
#include "../wallet/CpuSimd.h"
#include "../wallet/BreakerRebuild.h"
#include "../wallet/OutsideBox.h"
#include "../wallet/ToolCatalog.h"
#include "../wallet/NativePipelines.h"
#include "../wallet/WalletFormat.h"
#include "../wallet/TrueReweave.h"
#include "../wallet/DerivationPaths.h"

#define GLAD_GL_IMPLEMENTATION
#include <glad/gl.h>
#ifndef GLFW_INCLUDE_NONE
#define GLFW_INCLUDE_NONE
#endif
#include <GLFW/glfw3.h>
#ifdef _WIN32
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>
#endif

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
  int selected_plain_key = -1;

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
  ProcessStreamer hashcat_stream;
  ToolDetectStatus tools_status;

  /* Verify */
  VerifyReport verify_report;
  bool has_verify = false;
  char verify_input[1024] = {};

  /* Case management */
  char case_title[128] = {};
  char case_operator[64] = "operator";
  char case_note[1024] = {};
  char case_id_buf[128] = {};
  CaseRecord current_case;
  bool has_case = false;
  std::vector<std::string> case_ids;
  char case_zip_path[260] = "case_export.zip";

  /* BTCRecover Lab */
  char btc_wallet[512] = {};
  char btc_tokenlist[512] = {};
  char btc_passwordlist[512] = {};
  char btc_extra[256] = {};
  char btc_mnemonic[512] = {};
  bool btc_bip39 = false;
  bool btc_electrum = false;
  bool btc_typos = false;
  bool btc_seedrecover = false;
  int btc_typo_max = 1;
  ProcessStreamer btc_stream;

  /* Forensic tools pane */
  char bip39_mnemonic[1024] = {};
  char brain_pass[256] = {};
  char base58_hex[512] = {};
  char bech32_hrp[32] = "bc";
  char bech32_prog_hex[128] = {};
  int bech32_witver = 0;
  char hexdump_path[512] = {};
  char diff_path_a[512] = {};
  char diff_path_b[512] = {};
  char strings_path[512] = {};
  char balance_addr[128] = {};
  bool balance_http = false;
  char triage_folder[512] = {};
  std::string tools_panel_out;
  std::vector<TriageWalletRow> triage_rows;
  std::vector<StringsHit> strings_hits;

  /* Breaker & Rebuild Lab */
  OrchestratorOptions orch_opt;
  OrchestratorReport orch_report;
  bool has_orch = false;
  CarveReport carve_report;
  bool has_carve = false;
  char rebuild_new_pass[256] = {};
  char rebuild_out_prefix[260] = "rebuild_export";
  int rebuild_iters = 50000;
  RebuildPackage rebuild_pkg;
  bool has_rebuild = false;
  char orch_dict[512] = {};
  char orch_tokenlist[512] = {};
  bool about_open = false;

  /* One-click Full Breaker — unlock then rematerialize under new passphrase */
  char breaker_unlock_pass[256] = "adam";
  char breaker_new_pass[256] = "adam";
  bool breaker_new_same_as_unlock = true;
  bool breaker_try_dict = true;
  bool breaker_queue_hashcat = true;
  char breaker_out_prefix[260] = "breaker_oneclick";
  std::string breaker_progress;
  bool breaker_busy = false;
  std::thread breaker_thread;

  /* Open Any Wallet / multi-format */
  DetectedWallet detected;
  bool has_detected = false;
  char user_coin_tag[64] = {};

  /* TrueReweave */
  TrueReweaveInventory reweave_inv;
  bool has_reweave_inv = false;
  TrueReweaveResult reweave_result;
  bool has_reweave = false;
  char reweave_new_pass[256] = {};
  char reweave_out_prefix[260] = "truereweave_export";
  int reweave_iters = 50000;

  /* Results */
  DualVerifyResult last_dual;
  bool has_last_dual = false;
  MultiCkeyDecryptResult multi_decrypt;
  bool has_multi_decrypt = false;
  char recovered_master_hex[68] = {};

  /* Outside Box — maximalist DFIR modules */
  char ob_case_dir[512] = "cases/outside_box";
  char ob_ghost_root[512] = {};
  char ob_dump_path[512] = {};
  char ob_unalloc_path[512] = {};
  char ob_dict_path[512] = {};
  char ob_csv_path[512] = {};
  char ob_almost_pass[256] = {};
  char ob_stitch_b[512] = {};
  char ob_em_path[512] = {};
  char ob_fi_paste[4096] = {};
  char ob_keyhole_prefix[128] = {};
  char ob_keyhole_suffix[128] = {};
  char ob_twobody_folder[512] = {};
  char ob_timeslice_folder[512] = {};
  char ob_heir_names[256] = {};
  char ob_heir_places[256] = {};
  char ob_heir_pets[128] = {};
  char ob_heir_dates[128] = {};
  char ob_heir_hobbies[128] = {};
  char ob_heir_story[1024] = {};
  char ob_mirage_mnem[1024] = {};
  bool ob_scan_usb = true;
  bool ob_net_http = false;
  bool ob_dual_verify_cands = true;
  std::string ob_panel_out;
  VssHarvestReport ob_vss;
  GhostFinderReport ob_ghosts;
  PortableScanReport ob_portable;
  UnallocatedCarveReport ob_unalloc;
  DumpScavengeReport ob_dump_scavenge;
  DescriptorScrapReport ob_desc;
  CrashDumpAesReport ob_crash_aes;
  CsvBridgeReport ob_csv;
  EmTraceImportReport ob_em;
  FiCandidateReport ob_fi;
  FakeWalletPlusReport ob_fake_plus;
  NetworkTimelineReport ob_net;
  TimeSlicePlan ob_timeslice;
  KeyholePlan ob_keyhole;
  SeedMirageReport ob_mirage;
  StitchReport ob_stitch;
  std::vector<MasterKeyInfo> ob_mkeys;
  std::vector<TwoBodyWallet> ob_twobody;
  TwoBodyProgress ob_twobody_prog;
  MultiMkeyAttackProgress ob_mm_prog;
  std::thread ob_attack_thread;
  std::vector<std::string> ob_mutants;
  UnlockSessionChecklist ob_unlock = unlock_session_kit_guidance();

  /* Universal Tool Bay / Catalog */
  std::vector<CatalogEntryRuntime> catalog_rows;
  CatalogStats catalog_stats;
  char catalog_search[128] = {};
  int catalog_cat_filter = 0; /* 0=all, then enum+1 */
  bool catalog_only_runnable = false;
  int catalog_selected = -1;
  char catalog_intake_path[512] = {};
  char catalog_pipe_out[512] = {};
  std::string catalog_detail;
  std::string catalog_orch_out;
  char commercial_path_edit[512] = {};
  std::vector<CommercialBridge> commercial_hub;

  bool wipe_found_on_erase = false;
  bool quit_requested = false;
  GLFWwindow* window = nullptr;

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

static void join_thread_timeout(std::thread& t, int timeout_ms) {
  if (!t.joinable()) return;
#ifdef _WIN32
  HANDLE h = (HANDLE)t.native_handle();
  if (WaitForSingleObject(h, (DWORD)(timeout_ms < 0 ? 0 : timeout_ms)) == WAIT_OBJECT_0)
    t.join();
  else
    t.detach();
#else
  (void)timeout_ms;
  t.join();
#endif
}

static void request_app_quit(AppState& app) {
  app.quit_requested = true;
  if (app.window) glfwSetWindowShouldClose(app.window, GLFW_TRUE);
}

/** Stop crack engines, kill Hashcat/John/BTCRecover children, join workers with timeout. */
static void shutdown_app_workers(AppState& app) {
  app.cracker.request_stop();
  app.pp_progress.stop = true;
  app.ob_mm_prog.stop = true;
  app.ob_twobody_prog.stop = true;
  app.hashcat_stream.stop();
  app.btc_stream.stop();
  app.cracker.join_timeout(2000);
  join_thread_timeout(app.pp_thread, 2000);
  join_thread_timeout(app.ob_attack_thread, 2000);
  join_thread_timeout(app.breaker_thread, 2000);
}

#ifdef _WIN32
static void set_clipboard(const std::string& s) { clipboard_win32_set_utf8(s.c_str()); }

/** Paste clipboard into buf; strips trailing CR/LF. Returns true if non-empty paste applied. */
static bool paste_clipboard_into(char* buf, size_t buf_size) {
  if (!buf || buf_size == 0) return false;
  const char* clip = clipboard_win32_get_utf8();
  if (!clip || !clip[0]) return false;
  std::strncpy(buf, clip, buf_size - 1);
  buf[buf_size - 1] = '\0';
  size_t n = std::strlen(buf);
  while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
    buf[--n] = '\0';
  return true;
}

/** InputText + Paste button (Ctrl+V should also work via Platform clipboard handlers). */
static bool InputTextWithPaste(const char* label, char* buf, size_t buf_size,
                               ImGuiInputTextFlags flags = 0) {
  ImGui::PushID(label);
  bool changed = ImGui::InputText("##it", buf, buf_size, flags);
  ImGui::SameLine();
  if (ImGui::SmallButton("Paste")) {
    if (paste_clipboard_into(buf, buf_size)) changed = true;
  }
  ImGui::SameLine(0, ImGui::GetStyle().ItemInnerSpacing.x);
  ImGui::TextUnformatted(label);
  ImGui::PopID();
  return changed;
}
#else
static void set_clipboard(const std::string&) {}
static bool paste_clipboard_into(char*, size_t) { return false; }
static bool InputTextWithPaste(const char* label, char* buf, size_t buf_size,
                               ImGuiInputTextFlags flags = 0) {
  return ImGui::InputText(label, buf, buf_size, flags);
}
#endif

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
  app.detected = open_any_wallet(path);
  app.has_detected = true;
  for (auto& line : app.detected.log) app.log(line);
  for (auto& w : app.detected.warnings) app.log("[warn] " + w);
  app.log(app.detected.status_line);

  if (app.detected.is_core_family) {
    app.wallet = app.detected.core;
    app.has_wallet = true;
    app.wallet_raw = read_file_bytes(path);
    if (!app.detected.coin_display.empty())
      app.wallet.coin_label = app.detected.coin_display;
    if (app.user_coin_tag[0]) app.wallet.coin_label = app.user_coin_tag;
    app.archaeology = analyze_archaeology(app.wallet, app.wallet_raw.data(), app.wallet_raw.size());
    app.selected_ckey = app.wallet.ckeys.empty() ? -1 : 0;
    app.selected_plain_key = app.wallet.plain_keys.empty() ? -1 : 0;
    for (auto& f : app.archaeology.findings)
      app.log("[arch] " + f.flag + ": " + f.detail);
    app.log("[+] Core-family ready — " + std::to_string(app.wallet.ckeys.size()) + " ckeys | " +
            std::to_string(app.wallet.plain_keys.size()) + " plain keys | " +
            app.wallet.coin_label + " | " + app.wallet.storage_kind);
    if (app.target_address[0]) {
      for (size_t i = 0; i < app.wallet.ckeys.size(); ++i) {
        if (app.wallet.ckeys[i].address == app.target_address) {
          app.log("*** TARGET MATCH ckey #" + std::to_string(i) + " ***");
          app.selected_ckey = (int)i;
        }
      }
    }
  } else {
    /* Non-Core: keep inventory in detected; optional empty Core parse clear */
    app.has_wallet = false;
    app.wallet = WalletParseResult{};
    app.wallet.path = path;
    app.wallet_raw = read_file_bytes(path);
    app.log("[+] Non-Core wallet routed — hash/crack path: " + app.detected.crack_hint);
    if (!app.detected.hash_export_path.empty())
      app.log("[+] hash export: " + app.detected.hash_export_path +
              (app.detected.hashcat_mode ? (" (-m " + std::to_string(app.detected.hashcat_mode) + ")")
                                         : ""));
  }
  app.reweave_inv = truereweave_inventory(app.wallet, &app.detected);
  app.has_reweave_inv = true;
}

static void breaker_plog(AppState& app, const std::string& line) {
  app.breaker_progress += line;
  if (app.breaker_progress.size() > 0 && app.breaker_progress.back() != '\n')
    app.breaker_progress += '\n';
  app.log(line);
}

/** One-click: load → inventory → try unlock → decrypt/TrueReweave OR queue crack with cand. */
static void run_full_breaker_pipeline(AppState& app, const std::string& path) {
  app.breaker_progress.clear();
  if (path.empty()) {
    breaker_plog(app, "[E] no wallet path");
    return;
  }
  if (app.breaker_new_same_as_unlock)
    std::strncpy(app.breaker_new_pass, app.breaker_unlock_pass, sizeof(app.breaker_new_pass) - 1);

  const std::string unlock = app.breaker_unlock_pass;
  const std::string new_pass = app.breaker_new_pass[0] ? app.breaker_new_pass : unlock;

  breaker_plog(app, "=== Full Breaker start ===");
  breaker_plog(app, "[1] Open Any Wallet: " + path);
  load_wallet_path(app, path);

  if (app.has_reweave_inv) {
    breaker_plog(app, "[2] Inventory: " + app.reweave_inv.summary);
    for (size_t i = 0; i < app.reweave_inv.records.size() && i < 12; ++i)
      breaker_plog(app, "    · " + app.reweave_inv.records[i]);
  }

  if (app.has_detected && !app.detected.hash_export_path.empty()) {
    breaker_plog(app, std::string("[2b] Hash export: ") + app.detected.hash_export_path +
                          (app.detected.hashcat_mode
                               ? (std::string(" (-m ") + std::to_string(app.detected.hashcat_mode) + ")")
                               : std::string()));
  }

  if (!app.has_wallet || !app.wallet.mkey.found) {
    breaker_plog(app,
                 "[!] No Core mkey — cannot unlock with passphrase here. Extract/hash path ready; "
                 "wrong format or unencrypted/plain inventory only. Honesty: no magic unlock.");
    if (app.has_detected && !app.detected.hash_line.empty()) {
      breaker_plog(app, "[…] Queuing crack hint: " + app.detected.crack_hint);
      if (app.breaker_queue_hashcat && !app.detected.hash_export_path.empty()) {
        std::ofstream wl("breaker_first_cand.txt", std::ios::binary);
        wl << unlock << "\n";
        wl.close();
        auto r = spawn_hashcat_streamed(app.detected.hash_export_path, "breaker_first_cand.txt",
                                        app.hashcat_exe_cached, &app.hashcat_stream);
        breaker_plog(app, std::string("[…] Hashcat: ") + (r.launched ? "trying…" : "not launched") +
                              " — " + r.message);
      }
    }
    breaker_plog(app, "=== Full Breaker done (no Core unlock) ===");
    return;
  }

  breaker_plog(app, std::string("[3] Trying unlock passphrase (single try)") +
                        (unlock.empty() ? std::string(" — EMPTY")
                                        : (std::string(": \"") + unlock + "\"")));
  app.last_dual = dual_verify_passphrase(app.wallet.mkey, app.wallet, unlock, app.found_path);
  app.has_last_dual = true;

  if (app.last_dual.ok && !app.last_dual.master_hex.empty()) {
    breaker_plog(app, "[+] Unlock OK — master recovered");
    std::strncpy(app.recovered_master_hex, app.last_dual.master_hex.c_str(),
                 sizeof(app.recovered_master_hex) - 1);
    uint8_t master[32];
    if (!hex_to_master32(app.recovered_master_hex, master)) {
      breaker_plog(app, "[E] master hex decode failed");
      return;
    }

    breaker_plog(app, "[4] Decrypt all ckeys → WIF");
    app.multi_decrypt = decrypt_all_ckeys(master, app.wallet, app.found_path);
    app.has_multi_decrypt = true;
    breaker_plog(app, app.multi_decrypt.report);

    breaker_plog(app, std::string("[5] TrueReweave rematerialize under NEW passphrase") +
                          (new_pass.empty() ? " (export-only)" : ""));
    std::strncpy(app.reweave_new_pass, new_pass.c_str(), sizeof(app.reweave_new_pass) - 1);
    std::strncpy(app.rebuild_new_pass, new_pass.c_str(), sizeof(app.rebuild_new_pass) - 1);
    app.reweave_result =
        truereweave_rematerialize(master, app.wallet, new_pass, (uint32_t)app.reweave_iters);
    app.has_reweave = true;
    if (breaker_write_package(app.reweave_result.package, app.breaker_out_prefix))
      breaker_plog(app, "[+] Wrote " + std::string(app.breaker_out_prefix) + ".{json,txt}");
    breaker_plog(app, app.reweave_result.message);
    if (!app.reweave_result.package.txt_bundle.empty()) {
      breaker_plog(app, "--- WIFs / export ---");
      breaker_plog(app, app.reweave_result.package.txt_bundle);
    }
    breaker_plog(app, "=== Full Breaker SUCCESS ===");
    return;
  }

  breaker_plog(app, "[!] Unlock miss — wrong passphrase cannot magic-unlock. Continuing extract + crack.");
  breaker_plog(app, app.last_dual.message);

  /* Prefer unlock as first native/hashcat candidate */
  std::vector<std::string> cands;
  if (!unlock.empty()) cands.push_back(unlock);
  if (app.breaker_try_dict && !app.candidates.empty()) {
    for (auto& c : app.candidates) {
      if (c != unlock) cands.push_back(c);
    }
  } else if (app.breaker_try_dict && app.dict_path[0]) {
    std::ifstream df(app.dict_path);
    std::string line;
    while (std::getline(df, line) && (int)cands.size() < app.orch_opt.max_native_tries) {
      while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
      if (!line.empty() && line != unlock) cands.push_back(line);
    }
  }

  write_hashcat_file(app.wallet, app.hashcat_export_path, true);
  breaker_plog(app, "[4] Exported $bitcoin$ → " + std::string(app.hashcat_export_path));

  {
    std::ofstream wl("breaker_first_cand.txt", std::ios::binary);
    for (auto& c : cands) wl << c << "\n";
    if (cands.empty()) wl << "\n";
    wl.close();
  }

  app.orch_opt.dict_path = app.orch_dict[0] ? app.orch_dict : "breaker_first_cand.txt";
  app.orch_opt.tokenlist = app.orch_tokenlist;
  app.orch_opt.hash_export_path = app.hashcat_export_path;
  app.orch_opt.passphrase_candidates = cands;
  app.orch_opt.do_verify = true;
  app.orch_opt.do_carve = true;
  app.orch_opt.do_native_kdf = true;
  app.orch_opt.do_hashcat = app.breaker_queue_hashcat;
  app.orch_opt.use_cpu = true;

  breaker_plog(app, std::string("[5] trying… native KDF") +
                        (app.breaker_queue_hashcat ? " + Hashcat queue" : "") + " (" +
                        std::to_string(cands.size()) + " candidates, first=\"" + unlock + "\")");

  app.orch_report =
      breaker_orchestrate(app.wallet, app.wallet_raw, app.orch_opt, &app.hashcat_stream, &app.btc_stream);
  app.has_orch = true;
  breaker_plog(app, app.orch_report.log);

  if (app.orch_report.success && !app.orch_report.master_hex.empty()) {
    std::strncpy(app.recovered_master_hex, app.orch_report.master_hex.c_str(),
                 sizeof(app.recovered_master_hex) - 1);
    uint8_t master[32];
    if (hex_to_master32(app.recovered_master_hex, master)) {
      breaker_plog(app, "[+] Crack hit — rematerializing with new passphrase");
      app.multi_decrypt = decrypt_all_ckeys(master, app.wallet, app.found_path);
      app.has_multi_decrypt = true;
      app.reweave_result =
          truereweave_rematerialize(master, app.wallet, new_pass, (uint32_t)app.reweave_iters);
      app.has_reweave = true;
      breaker_write_package(app.reweave_result.package, app.breaker_out_prefix);
      breaker_plog(app, app.reweave_result.message);
    }
  } else {
    breaker_plog(app,
                 "Honesty: passphrase wrong / not in list — wallet loaded + hash exported; crackers "
                 "may still be running.");
  }
  breaker_plog(app, "=== Full Breaker done ===");
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
  app.selected_plain_key = -1;
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
  if (ImGui::BeginMainMenuBar()) {
    if (ImGui::BeginMenu("File")) {
      if (ImGui::MenuItem("Exit", "Alt+F4")) request_app_quit(app);
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Edit")) {
      ImGui::TextDisabled("Ctrl+C / Ctrl+X / Ctrl+V / Ctrl+A in text fields");
#ifdef _WIN32
      if (ImGui::MenuItem("Paste into focused field", "Ctrl+V")) {
        /* Force-refresh clipboard through our Win32 path; ImGui InputText handles Ctrl+V when focused. */
        (void)clipboard_win32_get_utf8();
      }
      if (ImGui::MenuItem("Clipboard self-test")) {
        std::string detail;
        bool ok = clipboard_win32_selftest(&detail);
        app.log(std::string(ok ? "[+] " : "[E] ") + detail);
      }
#endif
      ImGui::EndMenu();
    }
    ImGui::EndMainMenuBar();
  }
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.78f, 0.62f, 0.28f, 1.f));
  ImGui::TextUnformatted("TrueWalletCollider");
  ImGui::PopStyleColor();
  ImGui::SameLine();
  ImGui::TextColored(ImVec4(0.55f, 0.52f, 0.45f, 0.95f), "  // Forensic Suite");
  ImGui::SameLine();
  ImGui::TextDisabled("  Made by TrueScent");
  const auto& cpu = cpu_simd_detect();
  ImGui::SameLine(ImGui::GetWindowWidth() - 520);
  ImGui::TextColored(ImVec4(0.45f, 0.75f, 0.9f, 1.f), "%s", cpu.status_line.c_str());
  ImGui::SameLine();
  if (ImGui::SmallButton(app.light_theme ? "Noir" : "Light")) {
    app.light_theme = !app.light_theme;
    ApplyTrueScentTheme(app.light_theme);
  }
  ImGui::SameLine();
  if (ImGui::SmallButton("About")) app.about_open = true;
  ImGui::SameLine();
  if (ImGui::SmallButton("Exit")) request_app_quit(app);
  ImGui::Separator();
  ImGui::TextColored(ImVec4(0.9f, 0.55f, 0.35f, 1.f),
                     "AUTHORIZED USE ONLY — owner recovery / DFIR under authority");
  ImGui::SameLine(ImGui::GetWindowWidth() - 200);
  if (ImGui::SmallButton("t.me/TrueScent")) {
#ifdef _WIN32
    ShellExecuteA(nullptr, "open", "https://t.me/TrueScent", nullptr, nullptr, SW_SHOWNORMAL);
#endif
  }
  ImGui::Separator();
}

static void draw_about_modal(AppState& app) {
  if (!app.about_open) return;
  ImGui::OpenPopup("About TrueWalletCollider");
  if (ImGui::BeginPopupModal("About TrueWalletCollider", &app.about_open,
                             ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::TextColored(ImVec4(0.78f, 0.62f, 0.28f, 1.f), "TrueWalletCollider");
    ImGui::Text("Forensic Suite / Recovery Lab");
    ImGui::Text("Made by TrueScent");
    ImGui::Separator();
    ImGui::TextWrapped(
        "Authorized wallet owners, businesses, and DFIR under clear legal authority only. "
        "Unauthorized access is illegal. Classic Bitcoin Core wallet.dat typically has no BIP39 "
        "seed — Breaker Lab will say so honestly.");
    ImGui::Separator();
    ImGui::Text("Telegram: https://t.me/TrueScent");
    if (ImGui::Button("Open Telegram")) {
#ifdef _WIN32
      ShellExecuteA(nullptr, "open", "https://t.me/TrueScent", nullptr, nullptr, SW_SHOWNORMAL);
#endif
    }
    ImGui::SameLine();
    if (ImGui::Button("Close")) {
      app.about_open = false;
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }
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

static void draw_plain_keys_panel(AppState& app) {
  if (!app.has_wallet) {
    ImGui::TextDisabled("Load a wallet first.");
    return;
  }
  if (app.wallet.plain_keys.empty()) {
    ImGui::TextDisabled(
        "No plaintext UNENCRYPTED_KEY material (encrypted ckeys are listed under CKeys).");
    return;
  }
  ImGui::TextColored(ImVec4(1.f, 0.55f, 0.35f, 1.f),
                     "%d unencrypted private key(s) — owner recovery display",
                     (int)app.wallet.plain_keys.size());
  ImGui::BeginChild("plain_list", ImVec2(260, 0), true);
  for (int i = 0; i < (int)app.wallet.plain_keys.size(); ++i) {
    char label[160];
    auto& k = app.wallet.plain_keys[i];
    if (!k.address.empty())
      std::snprintf(label, sizeof(label), "#%d %s", i, k.address.c_str());
    else
      std::snprintf(label, sizeof(label), "#%d %.12s…", i, k.priv_hex.c_str());
    if (ImGui::Selectable(label, app.selected_plain_key == i)) app.selected_plain_key = i;
  }
  ImGui::EndChild();
  ImGui::SameLine();
  ImGui::BeginChild("plain_detail", ImVec2(0, 0), true);
  if (app.selected_plain_key >= 0 &&
      app.selected_plain_key < (int)app.wallet.plain_keys.size()) {
    auto& k = app.wallet.plain_keys[app.selected_plain_key];
    ImGui::Text("Offset: %zu | source: %s", k.file_offset, k.source.c_str());
    ImGui::TextWrapped("Address: %s", k.address.c_str());
    ImGui::TextWrapped("priv_hex:\n%s", k.priv_hex.c_str());
    ImGui::TextWrapped("WIF_u: %s", k.wif_uncompressed.c_str());
    ImGui::TextWrapped("WIF_c: %s", k.wif_compressed.c_str());
    ImGui::TextWrapped("pubkey:\n%s", k.pubkey_hex.c_str());
    if (ImGui::Button("Copy priv hex")) set_clipboard(k.priv_hex);
    ImGui::SameLine();
    if (ImGui::Button("Copy WIF_c")) set_clipboard(k.wif_compressed);
    ImGui::SameLine();
    if (ImGui::Button("Copy WIF_u")) set_clipboard(k.wif_uncompressed);
    ImGui::SameLine();
    if (ImGui::Button("Copy address")) set_clipboard(k.address);
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
  ImGui::TextColored(ImVec4(0.55f, 0.85f, 0.95f, 1.f), "Open Any Wallet — multi-format (SHIPPED)");
  ImGui::TextWrapped(
      "Drop any wallet file/folder here or Open. Auto-detects Core wallet.dat (BTC/BCH/LTC/DOGE + "
      "forks, BDB+SQLite), Ethereum keystore, Electrum, Exodus .seco, MetaMask/Phantom LevelDB, "
      "Blockchain.com / MultiBit / Wasabi.");
  if (app.has_detected) {
    ImGui::TextColored(ImVec4(0.45f, 0.95f, 0.55f, 1.f), "%s", app.detected.status_line.c_str());
    ImGui::TextWrapped("Coin: %s | Mode hint: %s", app.detected.coin_display.c_str(),
                       app.detected.crack_hint.c_str());
  }

  if (!app.has_wallet && !app.has_detected) {
    if (ImGui::Button("Open Any Wallet", ImVec2(180, 36))) {
      auto p = open_file_dialog(
          "All wallets\0*.dat;*.json;*.seco;*.wallet;*.*\0Core DAT\0*.dat\0JSON\0*.json\0"
          "Exodus SECO\0*.seco\0All\0*.*\0");
      if (!p.empty()) load_wallet_path(app, p);
    }
    ImGui::SameLine();
    if (ImGui::Button("Load PoC targets", ImVec2(160, 36))) load_poc_wallet(app);
    ImGui::InputText("Optional coin tag (BCH/LTC/DOGE…)", app.user_coin_tag,
                     sizeof(app.user_coin_tag));
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
      if (!app.scanned_wallets.empty() &&
          ImGui::BeginTable("scan", 4,
                            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                            ImVec2(0, 140))) {
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

  /* Non-Core detected wallet panel */
  if (app.has_detected && !app.detected.is_core_family) {
    ImGui::Separator();
    ImGui::Text("File: %s", app.detected.path.c_str());
    ImGui::TextWrapped("%s", app.detected.label.c_str());
    if (app.detected.hashcat_mode)
      ImGui::Text("Hashcat mode: %d", app.detected.hashcat_mode);
    if (!app.detected.hash_line.empty()) {
      ImGui::TextWrapped("Hash: %s", app.detected.hash_line.substr(0, 120).c_str());
      if (ImGui::Button("Copy hash line")) set_clipboard(app.detected.hash_line);
    }
    if (!app.detected.hash_export_path.empty())
      ImGui::Text("Export: %s", app.detected.hash_export_path.c_str());
    if (ImGui::Button("Spawn Hashcat for detected mode")) {
      auto sp = spawn_hashcat_for_detected(app.detected, app.hashcat_wordlist);
      app.log(sp.message);
    }
    ImGui::SameLine();
    if (ImGui::Button("Re-open Any Wallet")) {
      auto p = open_file_dialog(
          "All wallets\0*.dat;*.json;*.seco;*.wallet;*.*\0All\0*.*\0");
      if (!p.empty()) load_wallet_path(app, p);
    }
    if (ImGui::CollapsingHeader("Derivation path hints", ImGuiTreeNodeFlags_DefaultOpen)) {
      for (auto& h : app.detected.derivation_hints) ImGui::BulletText("%s", h.c_str());
    }
    if (ImGui::CollapsingHeader("Inventory", ImGuiTreeNodeFlags_DefaultOpen)) {
      for (auto& line : app.detected.inventory) ImGui::TextWrapped("%s", line.c_str());
    }
    return;
  }

  ImGui::Text("File: %s", app.wallet.path.c_str());
  ImGui::Text("Size: %zu | Magic: %s | Storage: %s | Coin: %s", app.wallet.file_size,
              app.wallet.magic_ok ? "OK" : "BAD", app.wallet.storage_kind.c_str(),
              app.wallet.coin_label.c_str());
  ImGui::TextWrapped("%s", app.wallet.bdb_note.c_str());
  ImGui::InputText("Target address", app.target_address, sizeof(app.target_address));
  ImGui::InputText("Coin tag override", app.user_coin_tag, sizeof(app.user_coin_tag));
  if (ImGui::Button("Apply coin tag") && app.user_coin_tag[0]) {
    app.wallet.coin_label = app.user_coin_tag;
    if (app.has_detected) app.detected.coin_display = app.user_coin_tag;
  }
  if (ImGui::Button("Re-open Any Wallet")) {
    auto p = open_file_dialog(
        "All wallets\0*.dat;*.json;*.seco;*.wallet;*.*\0Core DAT\0*.dat\0All\0*.*\0");
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
  ImGui::SameLine();
  if (ImGui::Button("Export $bitcoin$")) {
    if (write_hashcat_file(app.wallet, app.hashcat_export_path, true))
      app.log("[+] wrote " + std::string(app.hashcat_export_path));
    else
      app.log("[E] no mkey/salt for hashcat export");
  }

  if (ImGui::CollapsingHeader("Derivation path hints", ImGuiTreeNodeFlags_DefaultOpen)) {
    auto hints = app.has_detected ? app.detected.derivation_hints
                                  : derivation_hints_for_coin(app.wallet.coin_label);
    for (auto& h : hints) ImGui::BulletText("%s", h.c_str());
  }
  if (ImGui::CollapsingHeader("Archaeology flags", ImGuiTreeNodeFlags_DefaultOpen))
    draw_archaeology_flags(app);
  {
    ImGuiTreeNodeFlags pk_flags =
        app.wallet.plain_keys.empty() ? 0 : ImGuiTreeNodeFlags_DefaultOpen;
    if (ImGui::CollapsingHeader("Unencrypted keys", pk_flags)) draw_plain_keys_panel(app);
  }
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

  InputTextWithPaste("Single passphrase", app.single_pass, sizeof(app.single_pass));
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
  if (ImGui::SmallButton("Paste##dict")) paste_clipboard_into(app.dict_path, sizeof(app.dict_path));
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
  InputTextWithPaste("Hex prefix (even len, 1..31 bytes)", app.partial_prefix,
                     sizeof(app.partial_prefix));
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
  ImGui::TextWrapped(
      "AUTHORIZED USE ONLY — exports $bitcoin$ for Hashcat -m 11300 / John. "
      "Run setup_forensics.bat to bundle hashcat.exe under third_party\\hashcat\\.");
  ImGui::Separator();
  app.tools_status = detect_forensics_tools();
  ImGui::TextWrapped("%s", app.tools_status.status_text.c_str());
  if (ImGui::Button("Rescan tools")) {
    app.tools_status = detect_forensics_tools();
    app.hashcat_exe_cached = app.tools_status.hashcat;
    app.log("[+] rescanned forensic tools");
  }

  if (!app.has_wallet || !app.wallet.mkey.found) {
    ImGui::TextDisabled("Load wallet with mkey to export $bitcoin$ hash.");
  } else {
    std::string line = export_bitcoin_hashcat_line_extended(app.wallet);
    ImGui::TextWrapped("Hashcat mode -m 11300 (Bitcoin Core wallet.dat)");
    ImGui::BeginChild("hcline", ImVec2(-1, 60), true);
    ImGui::TextWrapped("%s", line.c_str());
    ImGui::EndChild();
    if (ImGui::Button("Copy $bitcoin$ line")) set_clipboard(line);
    InputTextWithPaste("Export path", app.hashcat_export_path, sizeof(app.hashcat_export_path));
    if (ImGui::Button("Write hash file")) {
      if (write_hashcat_file(app.wallet, app.hashcat_export_path, true))
        app.log("[+] wrote " + std::string(app.hashcat_export_path));
      else
        app.log("[E] hash export failed");
    }
  }

  if (app.hashcat_exe_cached.empty()) app.hashcat_exe_cached = find_hashcat_exe();
  ImGui::Text("hashcat: %s",
              app.hashcat_exe_cached.empty() ? "(not found — run setup_forensics.bat)"
                                             : app.hashcat_exe_cached.c_str());
  InputTextWithPaste("Wordlist (optional)", app.hashcat_wordlist, sizeof(app.hashcat_wordlist));
  if (ImGui::Button("Browse wordlist")) {
    auto p = open_file_dialog("Text\0*.txt\0All\0*.*\0");
    if (!p.empty()) {
      strncpy(app.hashcat_wordlist, p.c_str(), sizeof(app.hashcat_wordlist) - 1);
    }
  }
  ImGui::SameLine();
  if (ImGui::Button("Spawn hashcat (new console)")) {
    app.hashcat_exe_cached = find_hashcat_exe();
    auto r = spawn_hashcat_attack(app.hashcat_export_path, app.hashcat_wordlist, app.hashcat_exe_cached);
    app.log(r.message);
  }
  ImGui::SameLine();
  if (ImGui::Button("Spawn + stream output")) {
    app.hashcat_exe_cached = find_hashcat_exe();
    auto r = spawn_hashcat_streamed(app.hashcat_export_path, app.hashcat_wordlist,
                                    app.hashcat_exe_cached, &app.hashcat_stream);
    app.log(r.message);
  }
  if (app.hashcat_stream.running()) {
    ImGui::SameLine();
    if (ImGui::Button("Stop stream")) app.hashcat_stream.stop();
  }
  ImGui::BeginChild("hcstream", ImVec2(-1, 140), true);
  ImGui::TextUnformatted(app.hashcat_stream.snapshot().c_str());
  ImGui::EndChild();

  ImGui::Separator();
  ImGui::TextUnformatted("John the Ripper");
  if (ImGui::Button("Spawn john --format=bitcoin")) {
    ProcessStreamer* unused = nullptr;
    auto r = spawn_john_bitcoin(app.hashcat_export_path, unused);
    app.log(r.message);
  }
  ImGui::SameLine();
  if (ImGui::Button("John + stream")) {
    auto r = spawn_john_bitcoin(app.hashcat_export_path, &app.hashcat_stream);
    app.log(r.message);
  }
  ImGui::TextWrapped(
      "Manual: hashcat -m 11300 -a 0 wallet_hash.txt wordlist.txt\n"
      "Bundled: third_party\\hashcat\\hashcat.exe after setup_forensics.bat");
}

static void draw_verify_tab(AppState& app) {
  ImGui::TextColored(ImVec4(0.9f, 0.55f, 0.35f, 1.f), "AUTHORIZED USE ONLY");
  ImGui::TextWrapped(
      "Classify evidence as REAL / SUSPECT / FAKE / CORRUPT — wallet.dat, $bitcoin$ lines, "
      "or pasted mkey/ckey text.");
  ImGui::InputText("Path or $bitcoin$ / paste", app.verify_input, sizeof(app.verify_input));
  if (ImGui::Button("Browse wallet.dat")) {
    auto p = open_file_dialog();
    if (!p.empty()) strncpy(app.verify_input, p.c_str(), sizeof(app.verify_input) - 1);
  }
  ImGui::SameLine();
  if (ImGui::Button("Verify loaded wallet") && app.has_wallet) {
    app.verify_report = verify_parsed_wallet(app.wallet);
    app.has_verify = true;
    app.log(app.verify_report.summary);
  }
  ImGui::SameLine();
  if (ImGui::Button("Run verify")) {
    std::string s = app.verify_input;
    if (s.rfind("$bitcoin$", 0) == 0)
      app.verify_report = verify_bitcoin_hash_line(s);
    else if (!s.empty()) {
      std::ifstream f(s, std::ios::binary);
      if (f)
        app.verify_report = verify_wallet_file(s);
      else
        app.verify_report = verify_mkey_ckey_text(s);
    } else if (app.has_wallet) {
      app.verify_report = verify_parsed_wallet(app.wallet);
    }
    app.has_verify = true;
    app.log(app.verify_report.summary);
  }
  if (!app.has_verify) {
    ImGui::TextDisabled("No verify report yet.");
    return;
  }
  ImVec4 col = ImVec4(0.7f, 0.7f, 0.7f, 1.f);
  if (app.verify_report.verdict == VerifyVerdict::REAL) col = ImVec4(0.45f, 0.9f, 0.5f, 1.f);
  else if (app.verify_report.verdict == VerifyVerdict::SUSPECT) col = ImVec4(0.95f, 0.75f, 0.25f, 1.f);
  else if (app.verify_report.verdict == VerifyVerdict::FAKE) col = ImVec4(0.95f, 0.4f, 0.35f, 1.f);
  else if (app.verify_report.verdict == VerifyVerdict::CORRUPT) col = ImVec4(0.95f, 0.55f, 0.2f, 1.f);
  ImGui::TextColored(col, "Verdict: %s", app.verify_report.verdict_label.c_str());
  ImGui::TextWrapped("%s", app.verify_report.summary.c_str());
  if (ImGui::BeginTable("vchk", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                        ImVec2(0, 280))) {
    ImGui::TableSetupColumn("Check");
    ImGui::TableSetupColumn("Pass");
    ImGui::TableSetupColumn("Detail");
    ImGui::TableHeadersRow();
    for (auto& c : app.verify_report.checks) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextUnformatted(c.name.c_str());
      ImGui::TableSetColumnIndex(1);
      ImGui::TextColored(c.pass ? ImVec4(0.45f, 0.9f, 0.5f, 1.f) : ImVec4(0.95f, 0.4f, 0.35f, 1.f),
                         "%s", c.pass ? "OK" : "FAIL");
      ImGui::TableSetColumnIndex(2);
      ImGui::TextWrapped("%s", c.detail.c_str());
    }
    ImGui::EndTable();
  }
  if (ImGui::Button("Copy report")) set_clipboard(verify_report_text(app.verify_report));
}

static void draw_case_tab(AppState& app) {
  ImGui::TextColored(ImVec4(0.9f, 0.55f, 0.35f, 1.f), "AUTHORIZED USE ONLY — case / evidence hygiene");
  ImGui::TextWrapped("Cases live under cases/<id>/ with notes, artifacts, and zip export.");
  ImGui::InputText("Title", app.case_title, sizeof(app.case_title));
  ImGui::InputText("Operator", app.case_operator, sizeof(app.case_operator));
  if (ImGui::Button("Create case")) {
    std::string ev = app.has_wallet ? app.wallet.path : "";
    app.current_case = case_create(app.case_title, app.case_operator, ev);
    app.has_case = true;
    strncpy(app.case_id_buf, app.current_case.id.c_str(), sizeof(app.case_id_buf) - 1);
    app.case_ids = case_list_ids();
    app.log("[+] case " + app.current_case.id);
  }
  ImGui::SameLine();
  if (ImGui::Button("Refresh list")) app.case_ids = case_list_ids();
  if (ImGui::BeginCombo("Open case", app.case_id_buf[0] ? app.case_id_buf : "(select)")) {
    for (auto& id : app.case_ids) {
      if (ImGui::Selectable(id.c_str(), id == app.case_id_buf)) {
        strncpy(app.case_id_buf, id.c_str(), sizeof(app.case_id_buf) - 1);
        app.current_case = case_load(id);
        app.has_case = true;
      }
    }
    ImGui::EndCombo();
  }
  ImGui::InputTextMultiline("Note", app.case_note, sizeof(app.case_note), ImVec2(-1, 80));
  if (ImGui::Button("Append note") && app.case_id_buf[0]) {
    if (case_append_note(app.case_id_buf, app.case_operator, app.case_note)) {
      app.current_case = case_load(app.case_id_buf);
      app.case_note[0] = 0;
      app.log("[+] note appended");
    }
  }
  ImGui::SameLine();
  if (ImGui::Button("Add loaded wallet as artifact") && app.has_wallet && app.case_id_buf[0]) {
    if (case_add_artifact(app.case_id_buf, app.wallet.path)) {
      app.current_case = case_load(app.case_id_buf);
      app.log("[+] artifact copied");
    }
  }
  ImGui::InputText("Zip export path", app.case_zip_path, sizeof(app.case_zip_path));
  if (ImGui::Button("Export evidence zip") && app.case_id_buf[0]) {
    std::string msg;
    if (case_export_zip(app.case_id_buf, app.case_zip_path, &msg))
      app.log("[+] " + msg);
    else
      app.log("[E] " + msg);
  }
  if (app.has_case) {
    ImGui::Separator();
    ImGui::BeginChild("caseview", ImVec2(0, 0), true);
    ImGui::TextUnformatted(case_summary_text(app.current_case).c_str());
    ImGui::EndChild();
  }
}

static void draw_btcrecover_lab_tab(AppState& app) {
  ImGui::TextColored(ImVec4(0.9f, 0.55f, 0.35f, 1.f), "AUTHORIZED USE ONLY — BTCRecover Lab");
  ImGui::TextWrapped(
      "GUI front-end for bundled BTCRecover + embeddable Python "
      "(third_party\\btcrecover + third_party\\python after setup_forensics.bat).");
  auto det = detect_forensics_tools();
  ImGui::TextWrapped("Python: %s", det.python.empty() ? "MISSING" : det.python.c_str());
  ImGui::TextWrapped("BTCRecover: %s", det.btcrecover.empty() ? "MISSING" : det.btcrecover.c_str());
  if (ImGui::Button("Show --help (stream)")) {
    BtcRecoverOptions opt;
    opt.extra_args = "--help";
    auto r = spawn_btcrecover(opt, &app.btc_stream);
    app.log(r.message);
  }
  ImGui::InputText("wallet.dat", app.btc_wallet, sizeof(app.btc_wallet));
  ImGui::SameLine();
  if (ImGui::Button("Browse##btcwal")) {
    auto p = open_file_dialog();
    if (!p.empty()) strncpy(app.btc_wallet, p.c_str(), sizeof(app.btc_wallet) - 1);
  }
  ImGui::InputText("tokenlist", app.btc_tokenlist, sizeof(app.btc_tokenlist));
  ImGui::SameLine();
  if (ImGui::Button("Browse##btctok")) {
    auto p = open_file_dialog("Text\0*.txt\0All\0*.*\0");
    if (!p.empty()) strncpy(app.btc_tokenlist, p.c_str(), sizeof(app.btc_tokenlist) - 1);
  }
  ImGui::InputText("passwordlist", app.btc_passwordlist, sizeof(app.btc_passwordlist));
  ImGui::Checkbox("BIP39 mode", &app.btc_bip39);
  ImGui::SameLine();
  ImGui::Checkbox("Electrum", &app.btc_electrum);
  ImGui::SameLine();
  ImGui::Checkbox("seedrecover.py", &app.btc_seedrecover);
  ImGui::Checkbox("Typos", &app.btc_typos);
  ImGui::SameLine();
  ImGui::InputInt("typo max", &app.btc_typo_max);
  ImGui::InputText("mnemonic (optional)", app.btc_mnemonic, sizeof(app.btc_mnemonic));
  ImGui::InputText("Extra CLI args", app.btc_extra, sizeof(app.btc_extra));
  if (ImGui::Button("Build cmdline (copy)")) {
    BtcRecoverOptions opt;
    opt.wallet_dat = app.btc_wallet;
    opt.tokenlist = app.btc_tokenlist;
    opt.passwordlist = app.btc_passwordlist;
    opt.bip39_mode = app.btc_bip39;
    opt.electrum_mode = app.btc_electrum;
    opt.typos = app.btc_typos;
    opt.typo_max = app.btc_typo_max;
    opt.extra_args = app.btc_extra;
    opt.bip39_mnemonic = app.btc_mnemonic;
    opt.seedrecover = app.btc_seedrecover;
    std::string cmd = build_btcrecover_cmdline(opt);
    set_clipboard(cmd);
    app.log(cmd.empty() ? "[E] incomplete — run setup_forensics.bat" : "[+] cmdline copied");
  }
  ImGui::SameLine();
  if (ImGui::Button("Launch + stream")) {
    BtcRecoverOptions opt;
    opt.wallet_dat = app.btc_wallet;
    opt.tokenlist = app.btc_tokenlist;
    opt.passwordlist = app.btc_passwordlist;
    opt.bip39_mode = app.btc_bip39;
    opt.electrum_mode = app.btc_electrum;
    opt.typos = app.btc_typos;
    opt.typo_max = app.btc_typo_max;
    opt.extra_args = app.btc_extra;
    opt.bip39_mnemonic = app.btc_mnemonic;
    opt.seedrecover = app.btc_seedrecover;
    auto r = spawn_btcrecover(opt, &app.btc_stream);
    app.log(r.message);
  }
  ImGui::SameLine();
  if (ImGui::Button("Stop") && app.btc_stream.running()) app.btc_stream.stop();
  ImGui::BeginChild("btcstream", ImVec2(0, 0), true);
  ImGui::TextUnformatted(app.btc_stream.snapshot().c_str());
  ImGui::EndChild();
}

static void draw_breaker_rebuild_tab(AppState& app) {
  ImGui::TextColored(ImVec4(0.78f, 0.62f, 0.28f, 1.f), "TrueScent Wallet Breaker / Rebuild Lab");
  ImGui::TextDisabled("Made by TrueScent — authorized owner rematerialization only");
  ImGui::TextWrapped(
      "Break = orchestrate verify + carve + native CPU KDF (+ AVX workers) + Hashcat/John/BTCRecover. "
      "Rebuild = decrypt keys, optional re-encrypt mkey under YOUR passphrase, export WIF/JSON. "
      "Does NOT invent BIP39 seeds for classic Core wallets that never stored one.");
  ImGui::TextColored(ImVec4(0.45f, 0.75f, 0.9f, 1.f), "%s", cpu_simd_detect().status_line.c_str());
  ImGui::Separator();

  ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.35f, 1.f), "One-click Full Breaker");
  ImGui::TextWrapped(
      "Open wallet.dat → auto Extract/Open Any Wallet → inventory → try Unlock passphrase → "
      "on success decrypt all + TrueReweave with New passphrase. On fail: extract + queue crack "
      "(that password first). Wrong passphrase cannot magic-unlock.");
  InputTextWithPaste("Unlock passphrase (try first)", app.breaker_unlock_pass,
                     sizeof(app.breaker_unlock_pass));
  ImGui::Checkbox("New passphrase = unlock", &app.breaker_new_same_as_unlock);
  if (app.breaker_new_same_as_unlock) {
    std::strncpy(app.breaker_new_pass, app.breaker_unlock_pass, sizeof(app.breaker_new_pass) - 1);
    ImGui::BeginDisabled();
    InputTextWithPaste("New passphrase for rebuilt wallet", app.breaker_new_pass,
                       sizeof(app.breaker_new_pass));
    ImGui::EndDisabled();
  } else {
    InputTextWithPaste("New passphrase for rebuilt wallet", app.breaker_new_pass,
                       sizeof(app.breaker_new_pass));
  }
  ImGui::Checkbox("On miss: also try dict/candidates", &app.breaker_try_dict);
  ImGui::SameLine();
  ImGui::Checkbox("Queue Hashcat", &app.breaker_queue_hashcat);
  InputTextWithPaste("Export prefix", app.breaker_out_prefix, sizeof(app.breaker_out_prefix));

  if (ImGui::Button("Open wallet.dat & Run Full Breaker", ImVec2(-1, 44))) {
    if (app.breaker_busy) {
      app.log("[!] Breaker already running");
    } else {
      auto p = open_file_dialog(
          "Wallet\0*.dat;*.json;*.wallet;*.seco;*.keys\0DAT\0*.dat\0JSON\0*.json\0All\0*.*\0");
      if (!p.empty()) {
        app.breaker_busy = true;
        run_full_breaker_pipeline(app, p);
        app.breaker_busy = false;
      }
    }
  }
  if (app.breaker_busy) ImGui::TextColored(ImVec4(0.9f, 0.7f, 0.3f, 1.f), "trying…");
  ImGui::BeginChild("breaker_oneclick_log", ImVec2(0, 140), true);
  ImGui::TextUnformatted(app.breaker_progress.empty() ? "(progress log — each step appears here)"
                                                      : app.breaker_progress.c_str());
  ImGui::EndChild();
  if (app.has_reweave && !app.reweave_result.package.txt_bundle.empty()) {
    if (ImGui::Button("Copy TrueReweave export"))
      set_clipboard(app.reweave_result.package.txt_bundle);
  }
  ImGui::Separator();

  if (ImGui::BeginTabBar("breaker_inner")) {
    if (ImGui::BeginTabItem("1 · Break")) {
      ImGui::Checkbox("Verify REAL/FAKE", &app.orch_opt.do_verify);
      ImGui::SameLine();
      ImGui::Checkbox("Carve", &app.orch_opt.do_carve);
      ImGui::SameLine();
      ImGui::Checkbox("Native KDF (CPU)", &app.orch_opt.do_native_kdf);
      ImGui::Checkbox("Hashcat -m 11300", &app.orch_opt.do_hashcat);
      ImGui::SameLine();
      ImGui::Checkbox("John bitcoin", &app.orch_opt.do_john);
      ImGui::SameLine();
      ImGui::Checkbox("BTCRecover", &app.orch_opt.do_btcrecover);
      ImGui::Checkbox("CUDA partial hint", &app.orch_opt.do_cuda_partial);
      ImGui::SameLine();
      ImGui::Checkbox("Use CPU", &app.orch_opt.use_cpu);
      ImGui::SameLine();
      ImGui::Checkbox("Use GPU", &app.orch_opt.use_gpu);
      InputTextWithPaste("Dictionary / passwordlist", app.orch_dict, sizeof(app.orch_dict));
      ImGui::SameLine();
      if (ImGui::Button("Browse##orchd")) {
        auto p = open_file_dialog("Text\0*.txt\0All\0*.*\0");
        if (!p.empty()) strncpy(app.orch_dict, p.c_str(), sizeof(app.orch_dict) - 1);
      }
      InputTextWithPaste("BTCRecover tokenlist", app.orch_tokenlist, sizeof(app.orch_tokenlist));
      InputTextWithPaste("Partial AES prefix", app.partial_prefix, sizeof(app.partial_prefix));
      ImGui::InputInt("Max native tries", &app.orch_opt.max_native_tries);
      if (ImGui::Button("RUN ORCHESTRATOR", ImVec2(220, 36))) {
        if (!app.has_wallet) {
          app.log("[E] load wallet first");
        } else {
          app.orch_opt.dict_path = app.orch_dict;
          app.orch_opt.tokenlist = app.orch_tokenlist;
          app.orch_opt.partial_prefix_hex = app.partial_prefix;
          if (!app.candidates.empty())
            app.orch_opt.passphrase_candidates = app.candidates;
          else if (app.single_pass[0])
            app.orch_opt.passphrase_candidates = {app.single_pass};
          app.orch_report =
              breaker_orchestrate(app.wallet, app.wallet_raw, app.orch_opt, &app.hashcat_stream,
                                  &app.btc_stream);
          app.has_orch = true;
          app.log(app.orch_report.log);
          if (app.orch_report.success) {
            strncpy(app.recovered_master_hex, app.orch_report.master_hex.c_str(),
                    sizeof(app.recovered_master_hex) - 1);
            app.has_last_dual = app.orch_report.has_dual;
            app.last_dual = app.orch_report.dual;
          }
        }
      }
      if (app.has_orch) {
        ImGui::BeginChild("orchlog", ImVec2(0, 0), true);
        ImGui::TextUnformatted(app.orch_report.log.c_str());
        for (auto& s : app.orch_report.steps) {
          ImGui::BulletText("%s: %s", s.name.c_str(), s.detail.c_str());
        }
        ImGui::EndChild();
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("2 · Carve")) {
      if (ImGui::Button("Carve mkey/ckey + mnemonic scraps")) {
        app.carve_report =
            breaker_carve(app.wallet_raw.empty() ? nullptr : app.wallet_raw.data(),
                          app.wallet_raw.size(), app.has_wallet ? &app.wallet : nullptr);
        app.has_carve = true;
        app.log(app.carve_report.summary);
      }
      if (app.has_carve) {
        ImGui::TextWrapped("%s", app.carve_report.summary.c_str());
        if (app.carve_report.classic_core_has_no_bip39 && app.carve_report.mnemonics.empty()) {
          ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.25f, 1.f),
                             "BIP39 seed: NOT PRESENT (normal for classic Bitcoin Core wallet.dat)");
        }
        ImGui::Text("mkeys=%zu ckeys=%zu mnemonics=%zu", app.carve_report.mkeys.size(),
                    app.carve_report.ckeys.size(), app.carve_report.mnemonics.size());
        for (auto& m : app.carve_report.mnemonics) {
          ImGui::Separator();
          ImGui::Text("off=%zu words=%d bip39=%s", m.offset, m.word_count,
                      m.bip39_checksum_ok ? "OK" : "no");
          ImGui::TextWrapped("%s", m.note.c_str());
          ImGui::TextWrapped("%s", m.text.c_str());
        }
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("3 · Rebuild")) {
      ImGui::TextWrapped(
          "After master recovery: decrypt all keys, optionally re-encrypt mkey under a new "
          "passphrase you choose, export WIF/hex/JSON. Not a scam fake-balance wallet.");
      InputTextWithPaste("Recovered master (64 hex)", app.recovered_master_hex,
                         sizeof(app.recovered_master_hex));
      InputTextWithPaste("New passphrase (replace password)", app.rebuild_new_pass,
                         sizeof(app.rebuild_new_pass));
      ImGui::InputInt("New KDF iterations", &app.rebuild_iters);
      InputTextWithPaste("Export prefix", app.rebuild_out_prefix, sizeof(app.rebuild_out_prefix));
      if (ImGui::Button("Rebuild package") && app.has_wallet) {
        uint8_t master[32];
        if (!hex_to_master32(app.recovered_master_hex, master)) {
          app.log("[E] invalid master hex");
        } else {
          app.rebuild_pkg = breaker_rebuild(master, app.wallet, app.rebuild_new_pass,
                                            (uint32_t)app.rebuild_iters, true);
          app.has_rebuild = true;
          if (breaker_write_package(app.rebuild_pkg, app.rebuild_out_prefix))
            app.log("[+] wrote " + std::string(app.rebuild_out_prefix) + ".{json,txt}");
          app.log(app.rebuild_pkg.message);
        }
      }
      if (app.has_rebuild) {
        ImGui::TextWrapped("%s", app.rebuild_pkg.message.c_str());
        ImGui::TextWrapped("%s", app.rebuild_pkg.new_passphrase_note.c_str());
        if (ImGui::Button("Copy JSON")) set_clipboard(app.rebuild_pkg.json_bundle);
        ImGui::SameLine();
        if (ImGui::Button("Copy TXT")) set_clipboard(app.rebuild_pkg.txt_bundle);
        ImGui::BeginChild("reb", ImVec2(0, 0), true);
        ImGui::TextUnformatted(app.rebuild_pkg.txt_bundle.c_str());
        ImGui::EndChild();
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("4 · TrueReweave")) {
      ImGui::TextColored(ImVec4(0.95f, 0.55f, 0.35f, 1.f), "TrueReweave");
      ImGui::TextWrapped("%s", truereweave_panel_banner().c_str());
      ImGui::Separator();
      if (ImGui::Button("Inventory every record")) {
        app.reweave_inv =
            truereweave_inventory(app.wallet, app.has_detected ? &app.detected : nullptr);
        app.has_reweave_inv = true;
        app.log("[+] TrueReweave inventory: " + app.reweave_inv.summary);
      }
      if (app.has_reweave_inv) {
        ImGui::TextWrapped("%s", app.reweave_inv.honesty.c_str());
        ImGui::BeginChild("reweave_inv", ImVec2(0, 160), true);
        for (auto& line : app.reweave_inv.records) ImGui::TextWrapped("%s", line.c_str());
        ImGui::EndChild();
      }
      ImGui::Separator();
      InputTextWithPaste("Recovered master (64 hex)##rw", app.recovered_master_hex,
                         sizeof(app.recovered_master_hex));
      InputTextWithPaste("New passphrase##rw", app.reweave_new_pass, sizeof(app.reweave_new_pass));
      ImGui::InputInt("New KDF iterations##rw", &app.reweave_iters);
      InputTextWithPaste("Export prefix##rw", app.reweave_out_prefix, sizeof(app.reweave_out_prefix));
      ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.f),
                         "BIP39 rewrite inside Core wallet.dat: FORBIDDEN");
      if (ImGui::Button("Rematerialize (WIF / new passphrase)") && app.has_wallet) {
        uint8_t master[32];
        if (!hex_to_master32(app.recovered_master_hex, master)) {
          app.log("[E] invalid master hex");
        } else {
          app.reweave_result = truereweave_rematerialize(master, app.wallet, app.reweave_new_pass,
                                                         (uint32_t)app.reweave_iters);
          app.has_reweave = true;
          if (breaker_write_package(app.reweave_result.package, app.reweave_out_prefix))
            app.log("[+] TrueReweave wrote " + std::string(app.reweave_out_prefix) + ".{json,txt}");
          app.log(app.reweave_result.message);
        }
      }
      if (app.has_reweave) {
        ImGui::TextWrapped("%s", app.reweave_result.message.c_str());
        ImGui::BeginChild("reweave_out", ImVec2(0, 0), true);
        ImGui::TextUnformatted(app.reweave_result.package.txt_bundle.c_str());
        ImGui::EndChild();
      }
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }
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
  ImGui::TextColored(ImVec4(0.9f, 0.55f, 0.35f, 1.f), "AUTHORIZED USE ONLY");
  if (ImGui::BeginTabBar("tools_inner")) {
    if (ImGui::BeginTabItem("Pass/WIF")) {
      ImGui::TextUnformatted("Quick passphrase (method 0)");
      InputTextWithPaste("Passphrase", app.passphrase, sizeof(app.passphrase));
      if (ImGui::Button("Try passphrase on mkey")) {
        if (!app.has_wallet || !app.wallet.mkey.found) {
          app.passphrase_result = "load wallet with structured mkey first";
        } else {
          auto r = try_wallet_passphrase(app.wallet.mkey, app.passphrase);
          app.passphrase_result = r.message;
          if (r.ok) {
            app.passphrase_result +=
                "\nkey=" + r.derived_key_hex + "\nmkey_plain=" + r.decrypted_mkey_hex;
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
      if (ImGui::Button("Verify WIF")) {
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
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("BIP39")) {
      ImGui::InputTextMultiline("Mnemonic", app.bip39_mnemonic, sizeof(app.bip39_mnemonic),
                               ImVec2(-1, 80));
      if (ImGui::Button("Validate BIP39 checksum")) {
        auto r = bip39_validate_mnemonic(app.bip39_mnemonic);
        app.tools_panel_out = r.message;
        if (!r.unknown_words.empty()) {
          app.tools_panel_out += "\nunknown:";
          for (auto& w : r.unknown_words) app.tools_panel_out += " " + w;
        }
        app.log("[bip39] " + r.message);
      }
      ImGui::TextWrapped("%s", app.tools_panel_out.c_str());
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Brainwallet")) {
      ImGui::InputText("Passphrase → SHA256 → WIF", app.brain_pass, sizeof(app.brain_pass));
      if (ImGui::Button("Derive")) {
        auto r = brainwallet_sha256_to_wif(app.brain_pass);
        app.tools_panel_out = r.message + "\npriv=" + r.priv_hex + "\nWIF_u=" + r.wif_uncompressed +
                              "\nWIF_c=" + r.wif_compressed;
      }
      ImGui::TextWrapped("%s", app.tools_panel_out.c_str());
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Base58/Bech32")) {
      ImGui::InputText("Hex payload", app.base58_hex, sizeof(app.base58_hex));
      if (ImGui::Button("Base58 encode")) {
        app.tools_panel_out = base58_encode_hex(app.base58_hex);
        if (app.tools_panel_out.empty()) app.tools_panel_out = "(encode failed)";
      }
      ImGui::Separator();
      ImGui::InputText("HRP", app.bech32_hrp, sizeof(app.bech32_hrp));
      ImGui::InputInt("witver", &app.bech32_witver);
      ImGui::InputText("witness program hex", app.bech32_prog_hex, sizeof(app.bech32_prog_hex));
      if (ImGui::Button("Bech32 encode")) {
        std::vector<uint8_t> prog;
        std::string h = app.bech32_prog_hex;
        for (size_t i = 0; i + 1 < h.size(); i += 2) {
          auto nib = [](char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
          };
          int a = nib(h[i]), b = nib(h[i + 1]);
          if (a < 0 || b < 0) {
            prog.clear();
            break;
          }
          prog.push_back((uint8_t)((a << 4) | b));
        }
        app.tools_panel_out =
            bech32_encode(app.bech32_hrp, app.bech32_witver, prog.data(), prog.size());
        if (app.tools_panel_out.empty()) app.tools_panel_out = "(bech32 failed)";
      }
      ImGui::TextWrapped("%s", app.tools_panel_out.c_str());
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Hex/Entropy")) {
      ImGui::InputText("File", app.hexdump_path, sizeof(app.hexdump_path));
      ImGui::SameLine();
      if (ImGui::Button("Browse##hex")) {
        auto p = open_file_dialog("All\0*.*\0");
        if (!p.empty()) strncpy(app.hexdump_path, p.c_str(), sizeof(app.hexdump_path) - 1);
      }
      if (ImGui::Button("Dump + entropy")) {
        auto r = hex_dump_file(app.hexdump_path);
        app.tools_panel_out = r.summary + "\n" + r.hex_dump;
      }
      ImGui::SameLine();
      if (ImGui::Button("Dump loaded wallet") && !app.wallet_raw.empty()) {
        auto r = hex_dump_entropy(app.wallet_raw.data(), app.wallet_raw.size());
        app.tools_panel_out = r.summary + "\n" + r.hex_dump;
      }
      ImGui::BeginChild("hexout", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
      ImGui::TextUnformatted(app.tools_panel_out.c_str());
      ImGui::EndChild();
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Diff")) {
      ImGui::InputText("Wallet A", app.diff_path_a, sizeof(app.diff_path_a));
      ImGui::SameLine();
      if (ImGui::Button("Browse##da")) {
        auto p = open_file_dialog();
        if (!p.empty()) strncpy(app.diff_path_a, p.c_str(), sizeof(app.diff_path_a) - 1);
      }
      ImGui::InputText("Wallet B", app.diff_path_b, sizeof(app.diff_path_b));
      ImGui::SameLine();
      if (ImGui::Button("Browse##db")) {
        auto p = open_file_dialog();
        if (!p.empty()) strncpy(app.diff_path_b, p.c_str(), sizeof(app.diff_path_b) - 1);
      }
      if (ImGui::Button("Diff wallet.dat")) {
        auto r = wallet_dat_diff(app.diff_path_a, app.diff_path_b);
        app.tools_panel_out = r.report;
      }
      ImGui::TextWrapped("%s", app.tools_panel_out.c_str());
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Strings")) {
      ImGui::InputText("Dump file", app.strings_path, sizeof(app.strings_path));
      ImGui::SameLine();
      if (ImGui::Button("Browse##str")) {
        auto p = open_file_dialog("All\0*.*\0");
        if (!p.empty()) strncpy(app.strings_path, p.c_str(), sizeof(app.strings_path) - 1);
      }
      if (ImGui::Button("Scavenge strings")) {
        app.strings_hits = strings_scavenge_file(app.strings_path);
        app.tools_panel_out = "hits=" + std::to_string(app.strings_hits.size());
      }
      ImGui::SameLine();
      if (ImGui::Button("Scavenge loaded") && !app.wallet_raw.empty()) {
        app.strings_hits = strings_scavenge(app.wallet_raw.data(), app.wallet_raw.size());
        app.tools_panel_out = "hits=" + std::to_string(app.strings_hits.size());
      }
      ImGui::BeginChild("strout", ImVec2(0, 0), true);
      for (auto& h : app.strings_hits)
        ImGui::Text("%08zx  %s", h.offset, h.text.c_str());
      ImGui::EndChild();
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Balance")) {
      ImGui::Checkbox("Enable read-only HTTP (blockchain.info)", &app.balance_http);
      ImGui::InputText("Address", app.balance_addr, sizeof(app.balance_addr));
      if (app.has_wallet && app.selected_ckey >= 0 &&
          app.selected_ckey < (int)app.wallet.ckeys.size()) {
        if (ImGui::Button("Use selected ckey address")) {
          strncpy(app.balance_addr, app.wallet.ckeys[app.selected_ckey].address.c_str(),
                  sizeof(app.balance_addr) - 1);
        }
      }
      if (ImGui::Button("Lookup")) {
        auto r = address_balance_lookup(app.balance_addr, app.balance_http);
        app.tools_panel_out = r.message + "\n" + r.raw_json;
      }
      ImGui::BeginChild("balout", ImVec2(0, 0), true);
      ImGui::TextWrapped("%s", app.tools_panel_out.c_str());
      ImGui::EndChild();
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Triage")) {
      ImGui::TextWrapped("Multi-wallet folder triage sorted by iterations (low first).");
      ImGui::InputText("Folder", app.triage_folder, sizeof(app.triage_folder));
      ImGui::SameLine();
      if (ImGui::Button("Browse##tri")) {
        auto p = browse_folder_dialog();
        if (!p.empty()) strncpy(app.triage_folder, p.c_str(), sizeof(app.triage_folder) - 1);
      }
      if (ImGui::Button("Triage *.dat")) {
        app.triage_rows = multi_wallet_triage(app.triage_folder);
        app.log("[+] triage " + std::to_string(app.triage_rows.size()) + " wallets");
      }
      if (ImGui::BeginTable("tri", 5,
                            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                            ImVec2(0, 0))) {
        ImGui::TableSetupColumn("Path");
        ImGui::TableSetupColumn("Iters");
        ImGui::TableSetupColumn("CKeys");
        ImGui::TableSetupColumn("Size");
        ImGui::TableSetupColumn("Note");
        ImGui::TableHeadersRow();
        for (auto& row : app.triage_rows) {
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          if (ImGui::Selectable(row.path.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
            load_wallet_path(app, row.path);
          ImGui::TableSetColumnIndex(1);
          ImGui::Text("%u", row.iterations);
          ImGui::TableSetColumnIndex(2);
          ImGui::Text("%d", row.ckeys);
          ImGui::TableSetColumnIndex(3);
          ImGui::Text("%zu", row.size);
          ImGui::TableSetColumnIndex(4);
          ImGui::TextUnformatted(row.note.c_str());
        }
        ImGui::EndTable();
      }
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }
}

static void draw_outside_box_tab(AppState& app) {
  ImGui::TextColored(ImVec4(0.78f, 0.62f, 0.28f, 1.f), "Outside Box — Forensic Maximalist");
  ImGui::TextDisabled("Made by TrueScent · https://t.me/TrueScent — authorized DFIR / owner recovery only");
  ImGui::TextWrapped(
      "Live memory & VSS are guided capture + import / elevated PowerShell copies — no silent RAM "
      "stealers. Partial modules labeled Experimental.");
  if (ImGui::Button("Show module inventory")) {
    app.ob_panel_out = outside_box_module_inventory();
    app.log("[+] Outside Box inventory");
  }
  ImGui::SameLine();
  ImGui::InputText("Case/output", app.ob_case_dir, sizeof(app.ob_case_dir));
  ImGui::Separator();

  if (ImGui::BeginTabBar("ob_inner")) {
    /* Disk */
    if (ImGui::BeginTabItem("Disk")) {
      ImGui::TextUnformatted("1 · VSS / Shadow-copy harvester");
      if (ImGui::Button("List VSS shadows")) {
        app.ob_vss = vss_list_shadows();
        app.ob_panel_out = app.ob_vss.summary + "\n" + app.ob_vss.script_log;
        app.log(app.ob_vss.summary);
      }
      ImGui::SameLine();
      if (ImGui::Button("Harvest wallet.dat (UAC)")) {
        app.ob_vss = vss_harvest_wallets(app.ob_case_dir, {});
        app.ob_panel_out = app.ob_vss.summary + "\n" + app.ob_vss.script_log;
        for (auto& h : app.ob_vss.hits) app.log("[VSS] " + h.dest_path);
        app.log(app.ob_vss.summary);
      }
      ImGui::Text("Shadows: %zu  Copies: %zu", app.ob_vss.shadows.size(), app.ob_vss.hits.size());

      ImGui::Separator();
      ImGui::TextUnformatted("2 · NTFS undelete / unallocated carve (user dump)");
      ImGui::InputText("Unallocated/image dump", app.ob_unalloc_path, sizeof(app.ob_unalloc_path));
      ImGui::SameLine();
      if (ImGui::Button("Browse##unalloc")) {
        auto p = open_file_dialog("All\0*.*\0");
        if (!p.empty()) strncpy(app.ob_unalloc_path, p.c_str(), sizeof(app.ob_unalloc_path) - 1);
      }
      if (ImGui::Button("Carve unallocated")) {
        app.ob_unalloc = carve_unallocated_dump(app.ob_unalloc_path);
        app.ob_panel_out = app.ob_unalloc.summary;
        app.log(app.ob_unalloc.summary);
      }

      ImGui::Separator();
      ImGui::TextUnformatted("3 · Cloud sync ghost finder");
      ImGui::InputText("Root (Dropbox/OneDrive/Desktop)", app.ob_ghost_root, sizeof(app.ob_ghost_root));
      ImGui::SameLine();
      if (ImGui::Button("Browse##ghost")) {
        auto f = browse_folder_dialog();
        if (!f.empty()) strncpy(app.ob_ghost_root, f.c_str(), sizeof(app.ob_ghost_root) - 1);
      }
      if (ImGui::Button("Find ghosts")) {
        std::vector<std::string> roots;
        if (app.ob_ghost_root[0]) roots.push_back(app.ob_ghost_root);
        app.ob_ghosts = cloud_sync_ghost_find(roots);
        std::ostringstream ss;
        ss << app.ob_ghosts.summary << "\n";
        for (auto& h : app.ob_ghosts.hits)
          ss << h.kind << "  " << h.size << "  " << h.path << "\n";
        app.ob_panel_out = ss.str();
        app.log(app.ob_ghosts.summary);
      }

      ImGui::Separator();
      ImGui::TextUnformatted("4 · Portable / leftover scanner");
      ImGui::Checkbox("Scan USB / drive letters", &app.ob_scan_usb);
      if (ImGui::Button("Scan common paths")) {
        app.ob_portable = portable_leftover_scan(app.ob_scan_usb);
        std::ostringstream ss;
        ss << app.ob_portable.summary << "\n";
        for (auto& h : app.ob_portable.hits)
          ss << h.source << " ckeys=" << h.ckeys << " iter=" << h.iterations << " " << h.path << "\n";
        app.ob_panel_out = ss.str();
        app.log(app.ob_portable.summary);
      }
      ImGui::EndTabItem();
    }

    /* Memory */
    if (ImGui::BeginTabItem("Memory")) {
      ImGui::TextUnformatted("5 · Unlock-session capture kit");
      ImGui::TextWrapped("%s", app.ob_unlock.guidance_markdown.c_str());
      ImGui::InputText("Dump path (RAM / process / pagefile / hiberfil / VRAM)", app.ob_dump_path,
                       sizeof(app.ob_dump_path));
      ImGui::SameLine();
      if (ImGui::Button("Browse##dump")) {
        auto p = open_file_dialog("Dump\0*.dmp;*.bin;*.raw;*.sys\0All\0*.*\0");
        if (!p.empty()) strncpy(app.ob_dump_path, p.c_str(), sizeof(app.ob_dump_path) - 1);
      }
      if (ImGui::Button("Scavenge unlock dump")) {
        app.ob_dump_scavenge = scavenge_memory_dump(app.ob_dump_path);
        app.ob_panel_out = app.ob_dump_scavenge.summary;
        app.log(app.ob_dump_scavenge.summary);
      }
      ImGui::SameLine();
      if (ImGui::Button("6 · pagefile/hiberfil hunt")) {
        app.ob_dump_scavenge = hunt_pagefile_hiberfil(app.ob_dump_path);
        app.ob_panel_out = app.ob_dump_scavenge.summary;
        app.log(app.ob_dump_scavenge.summary);
      }
      ImGui::SameLine();
      if (ImGui::Button("7 · VRAM (experimental)")) {
        app.ob_dump_scavenge = scavenge_vram_dump_experimental(app.ob_dump_path);
        app.ob_panel_out = app.ob_dump_scavenge.summary + " [EXPERIMENTAL]";
        app.log(app.ob_dump_scavenge.summary);
      }
      if (!app.ob_dump_scavenge.hits.empty() && ImGui::BeginTable("dumphits", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY, ImVec2(0, 160))) {
        ImGui::TableSetupColumn("off");
        ImGui::TableSetupColumn("kind");
        ImGui::TableSetupColumn("text");
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < (std::min)(app.ob_dump_scavenge.hits.size(), (size_t)80); ++i) {
          auto& h = app.ob_dump_scavenge.hits[i];
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          ImGui::Text("%zu", h.offset);
          ImGui::TableSetColumnIndex(1);
          ImGui::TextUnformatted(h.kind.c_str());
          ImGui::TableSetColumnIndex(2);
          if (h.text.size() > 80) {
            std::string preview = h.text.substr(0, 80) + "…";
            ImGui::TextUnformatted(preview.c_str());
          } else {
            ImGui::TextUnformatted(h.text.c_str());
          }
        }
        ImGui::EndTable();
      }

      ImGui::Separator();
      ImGui::TextUnformatted("9 · Crash-dump partial AES → dual-verify");
      ImGui::Checkbox("Dual-verify candidates against loaded wallet", &app.ob_dual_verify_cands);
      if (ImGui::Button("Extract AES candidates from dump")) {
        if (!app.has_wallet) app.log("[E] load wallet first for dual-verify");
        app.ob_crash_aes = extract_aes_candidates_from_dump(app.ob_dump_path, app.wallet, 256,
                                                           app.ob_dual_verify_cands);
        app.ob_panel_out = app.ob_crash_aes.summary;
        app.log(app.ob_crash_aes.summary);
        if (app.ob_crash_aes.verified_ok > 0) {
          for (auto& c : app.ob_crash_aes.candidates)
            if (c.verified) {
              strncpy(app.recovered_master_hex, c.dual.master_hex.c_str(),
                      sizeof(app.recovered_master_hex) - 1);
              app.last_dual = c.dual;
              app.has_last_dual = true;
              break;
            }
        }
      }
      ImGui::EndTabItem();
    }

    /* Structural */
    if (ImGui::BeginTabItem("Structural")) {
      ImGui::TextUnformatted("8 · Passphrase-change archaeology (multi-mkey)");
      if (ImGui::Button("Extract all mkeys from loaded wallet raw")) {
        if (app.wallet_raw.empty())
          app.log("[E] load wallet (raw buffer empty)");
        else {
          app.ob_mkeys = extract_all_mkeys(app.wallet_raw.data(), app.wallet_raw.size());
          app.log("[+] mkeys found: " + std::to_string(app.ob_mkeys.size()));
          app.ob_panel_out = "mkeys=" + std::to_string(app.ob_mkeys.size());
        }
      }
      ImGui::InputText("Shared dict", app.ob_dict_path, sizeof(app.ob_dict_path));
      ImGui::SameLine();
      if (ImGui::Button("Browse##obdict")) {
        auto p = open_file_dialog("Text\0*.txt\0All\0*.*\0");
        if (!p.empty()) strncpy(app.ob_dict_path, p.c_str(), sizeof(app.ob_dict_path) - 1);
      }
      if (ImGui::Button("Attack all mkeys (shared dict)")) {
        if (app.ob_attack_thread.joinable()) app.ob_attack_thread.join();
        auto dict = load_dict_lines(app.ob_dict_path);
        if (dict.empty() && !app.candidates.empty()) dict = app.candidates;
        auto mkeys = app.ob_mkeys;
        if (mkeys.empty() && app.has_wallet && app.wallet.mkey.found) mkeys.push_back(app.wallet.mkey);
        app.ob_attack_thread = std::thread([&, dict, mkeys]() {
          attack_all_mkeys_shared_dict(app.wallet, mkeys, dict, app.ob_mm_prog, app.found_path);
          app.log(app.ob_mm_prog.message);
        });
      }
      if (app.ob_mm_prog.running.load()) {
        ImGui::Text("multi-mkey… %llu / %llu", (unsigned long long)app.ob_mm_prog.tried.load(),
                    (unsigned long long)app.ob_mm_prog.total.load());
        if (ImGui::Button("Stop multi-mkey")) app.ob_mm_prog.stop = true;
      }

      ImGui::Separator();
      ImGui::TextUnformatted("10 · Descriptor / PSBT scrapyard");
      if (ImGui::Button("Carve descriptors/PSBT/xpub from loaded raw")) {
        if (app.wallet_raw.empty()) {
          auto p = open_file_dialog("All\0*.*\0");
          if (!p.empty()) app.ob_desc = carve_descriptor_psbt_file(p);
        } else
          app.ob_desc = carve_descriptor_psbt_scrapyard(app.wallet_raw.data(), app.wallet_raw.size());
        app.ob_panel_out = app.ob_desc.summary;
        app.log(app.ob_desc.summary);
      }

      ImGui::Separator();
      ImGui::TextUnformatted("11 · Two-Body multi-wallet correlation");
      ImGui::InputText("Case folder of wallets", app.ob_twobody_folder, sizeof(app.ob_twobody_folder));
      ImGui::SameLine();
      if (ImGui::Button("Browse##tb")) {
        auto f = browse_folder_dialog();
        if (!f.empty()) strncpy(app.ob_twobody_folder, f.c_str(), sizeof(app.ob_twobody_folder) - 1);
      }
      if (ImGui::Button("Load Two-Body set")) {
        app.ob_twobody = twobody_load_case_folder(app.ob_twobody_folder);
        app.log("[+] Two-Body wallets: " + std::to_string(app.ob_twobody.size()));
      }
      ImGui::SameLine();
      if (ImGui::Button("Shared-passphrase attack")) {
        if (app.ob_attack_thread.joinable()) app.ob_attack_thread.join();
        auto dict = load_dict_lines(app.ob_dict_path);
        if (dict.empty()) dict = app.candidates;
        auto wallets = app.ob_twobody;
        app.ob_attack_thread = std::thread([&, dict, wallets]() {
          twobody_shared_passphrase_attack(wallets, dict, app.ob_twobody_prog, app.found_path);
          app.log(app.ob_twobody_prog.message);
        });
      }

      ImGui::Separator();
      ImGui::TextUnformatted("12 · Keyboard adjacency / fat-finger");
      ImGui::InputText("Almost-password", app.ob_almost_pass, sizeof(app.ob_almost_pass));
      if (ImGui::Button("Generate adjacency mutants")) {
        app.ob_mutants = fat_finger_masks(app.ob_almost_pass, 8000);
        app.candidates = app.ob_mutants;
        app.log("[+] fat-finger mutants: " + std::to_string(app.ob_mutants.size()));
        app.ob_panel_out = "mutants=" + std::to_string(app.ob_mutants.size()) + " (loaded into Passphrase Lab candidates)";
      }

      ImGui::Separator();
      ImGui::TextUnformatted("13 · Heir interview grammar");
      ImGui::InputText("Names", app.ob_heir_names, sizeof(app.ob_heir_names));
      ImGui::InputText("Places", app.ob_heir_places, sizeof(app.ob_heir_places));
      ImGui::InputText("Pets", app.ob_heir_pets, sizeof(app.ob_heir_pets));
      ImGui::InputText("Dates/years", app.ob_heir_dates, sizeof(app.ob_heir_dates));
      ImGui::InputText("Hobbies", app.ob_heir_hobbies, sizeof(app.ob_heir_hobbies));
      ImGui::InputTextMultiline("Free story", app.ob_heir_story, sizeof(app.ob_heir_story), ImVec2(-1, 60));
      if (ImGui::Button("Story → candidates")) {
        HeirInterview h;
        h.person_names = app.ob_heir_names;
        h.places = app.ob_heir_places;
        h.pets = app.ob_heir_pets;
        h.dates = app.ob_heir_dates;
        h.hobbies = app.ob_heir_hobbies;
        h.free_story = app.ob_heir_story;
        CandidateGenStats st;
        app.candidates = heir_interview_to_candidates(h, 20000, &st);
        app.candidate_stats = st;
        app.log("[+] heir candidates: " + std::to_string(app.candidates.size()) + " — " + st.summary);
      }

      ImGui::Separator();
      ImGui::TextUnformatted("14 · Password-manager CSV bridge");
      ImGui::InputText("Chrome/Bitwarden/KeePass CSV", app.ob_csv_path, sizeof(app.ob_csv_path));
      ImGui::SameLine();
      if (ImGui::Button("Browse##csv")) {
        auto p = open_file_dialog("CSV\0*.csv\0All\0*.*\0");
        if (!p.empty()) strncpy(app.ob_csv_path, p.c_str(), sizeof(app.ob_csv_path) - 1);
      }
      if (ImGui::Button("Import CSV → wordlist")) {
        app.ob_csv = import_password_manager_csv(app.ob_csv_path);
        app.candidates = app.ob_csv.wordlist;
        app.ob_panel_out = app.ob_csv.summary;
        app.log(app.ob_csv.summary);
        std::string out = std::string(app.ob_case_dir) + "/csv_wordlist.txt";
        std::ostringstream body;
        for (auto& w : app.ob_csv.wordlist) body << w << "\n";
        write_text_file(out, body.str());
        app.log("[+] wrote " + out);
      }

      ImGui::Separator();
      ImGui::TextUnformatted("15 · Backup stitch surgeon (mkey A + ckeys B)");
      ImGui::TextDisabled("Wallet A = currently loaded (mkey source). Browse B for ckeys.");
      ImGui::InputText("Wallet B path", app.ob_stitch_b, sizeof(app.ob_stitch_b));
      ImGui::SameLine();
      if (ImGui::Button("Browse##stitchb")) {
        auto p = open_file_dialog();
        if (!p.empty()) strncpy(app.ob_stitch_b, p.c_str(), sizeof(app.ob_stitch_b) - 1);
      }
      ImGui::InputText("Passphrase to try##stitch", app.single_pass, sizeof(app.single_pass));
      if (ImGui::Button("Stitch + dual-verify")) {
        if (!app.has_wallet) {
          app.log("[E] load wallet A first");
        } else {
          WalletDatParser p;
          auto b = p.parse_file(app.ob_stitch_b);
          app.ob_stitch = backup_stitch_try(app.wallet, b, app.single_pass, app.found_path);
          app.ob_panel_out = app.ob_stitch.summary;
          app.log(app.ob_stitch.summary);
          if (app.ob_stitch.ok) {
            app.last_dual = app.ob_stitch.dual;
            app.has_last_dual = true;
            strncpy(app.recovered_master_hex, app.ob_stitch.master_hex.c_str(),
                    sizeof(app.recovered_master_hex) - 1);
          }
        }
      }
      ImGui::TextWrapped("16 · Rebuild/re-encrypt → see Breaker & Rebuild tab (LANDED).");
      ImGui::EndTabItem();
    }

    /* Lab exotic */
    if (ImGui::BeginTabItem("Lab Exotic")) {
      ImGui::TextUnformatted("17 · ChipWhisperer / EM trace importer [EXPERIMENTAL]");
      ImGui::InputText("CSV or bin path", app.ob_em_path, sizeof(app.ob_em_path));
      ImGui::SameLine();
      if (ImGui::Button("Browse##em")) {
        auto p = open_file_dialog("All\0*.*\0");
        if (!p.empty()) strncpy(app.ob_em_path, p.c_str(), sizeof(app.ob_em_path) - 1);
      }
      if (ImGui::Button("Import EM CSV")) {
        app.ob_em = import_chipwhisperer_csv(app.ob_em_path);
        app.ob_panel_out = app.ob_em.summary;
        if (!app.ob_em.passphrase_guesses.empty()) app.candidates = app.ob_em.passphrase_guesses;
        app.log(app.ob_em.summary);
      }
      ImGui::SameLine();
      if (ImGui::Button("Import EM bin blocks")) {
        app.ob_em = import_em_trace_bin(app.ob_em_path);
        app.ob_panel_out = app.ob_em.summary;
        app.log(app.ob_em.summary);
      }
      if (!app.ob_em.hex_keys.empty() && ImGui::Button("Feed EM keys to host try_key")) {
        auto targets = build_targets(app);
        CrackConfig cfg;
        cfg.found_file = app.found_path;
        cfg.out_file = app.out_path;
        app.cracker.set_config(cfg);
        app.cracker.set_targets(targets);
        for (auto& hx : app.ob_em.hex_keys) {
          std::string msg;
          if (app.cracker.try_key(hx, &msg)) {
            app.log(msg);
            break;
          }
        }
      }

      ImGui::Separator();
      ImGui::TextUnformatted("18 · Fault-injection candidate importer");
      ImGui::InputTextMultiline("Paste 64-hex keys (or path)", app.ob_fi_paste, sizeof(app.ob_fi_paste),
                                ImVec2(-1, 80));
      if (ImGui::Button("Import FI + dual-verify")) {
        app.ob_fi = import_fault_injection_candidates(app.ob_fi_paste, app.wallet, true);
        app.ob_panel_out = app.ob_fi.summary;
        app.log(app.ob_fi.summary);
        if (app.ob_fi.ok_count > 0) {
          for (auto& c : app.ob_fi.verified)
            if (c.verified) {
              app.last_dual = c.dual;
              app.has_last_dual = true;
              strncpy(app.recovered_master_hex, c.dual.master_hex.c_str(),
                      sizeof(app.recovered_master_hex) - 1);
              break;
            }
        }
      }

      ImGui::Separator();
      ImGui::TextUnformatted("19 · Fake-wallet detector++");
      if (ImGui::Button("Score loaded wallet")) {
        app.ob_fake_plus = fake_wallet_detector_plus(
            app.wallet, app.wallet_raw.empty() ? nullptr : app.wallet_raw.data(),
            app.wallet_raw.size());
        app.ob_panel_out = app.ob_fake_plus.summary + "\n" + verify_report_text(app.ob_fake_plus.base);
        for (auto& e : app.ob_fake_plus.extras) app.ob_panel_out += "\n- " + e;
        app.log(app.ob_fake_plus.summary);
      }

      ImGui::Separator();
      ImGui::TextUnformatted("20 · Network timeline (read-only HTTP)");
      ImGui::Checkbox("Enable HTTP (blockchain.info)", &app.ob_net_http);
      if (ImGui::Button("Timeline for wallet addresses")) {
        std::vector<std::string> addrs;
        for (auto& c : app.wallet.ckeys)
          if (!c.address.empty()) addrs.push_back(c.address);
        app.ob_net = network_timeline_for_addresses(addrs, app.ob_net_http);
        std::ostringstream ss;
        ss << app.ob_net.summary << "\n";
        for (auto& e : app.ob_net.events)
          ss << e.address << " " << e.kind << "=" << e.value << "\n";
        app.ob_panel_out = ss.str();
        app.log(app.ob_net.summary);
      }

      ImGui::Separator();
      ImGui::TextUnformatted("21 · Time-Slice Crack plan");
      ImGui::InputText("Folder/case", app.ob_timeslice_folder, sizeof(app.ob_timeslice_folder));
      ImGui::SameLine();
      if (ImGui::Button("Browse##ts")) {
        auto f = browse_folder_dialog();
        if (!f.empty()) strncpy(app.ob_timeslice_folder, f.c_str(), sizeof(app.ob_timeslice_folder) - 1);
      }
      if (ImGui::Button("Build Time-Slice plan")) {
        app.ob_timeslice = timeslice_crack_plan(app.ob_timeslice_folder[0] ? app.ob_timeslice_folder
                                                                            : app.ob_case_dir);
        std::ostringstream ss;
        ss << app.ob_timeslice.summary << "\n";
        for (auto& it : app.ob_timeslice.items)
          ss << it.priority << "  " << it.reason << "  " << it.path << "\n";
        app.ob_panel_out = ss.str();
        app.log(app.ob_timeslice.summary);
      }

      ImGui::Separator();
      ImGui::TextUnformatted("22 · Keyhole mode (known AES bytes)");
      ImGui::InputText("Known prefix hex", app.ob_keyhole_prefix, sizeof(app.ob_keyhole_prefix));
      ImGui::InputText("Known suffix hex", app.ob_keyhole_suffix, sizeof(app.ob_keyhole_suffix));
      if (ImGui::Button("Build Keyhole plan → AES Partial")) {
        KeyholeSpec spec;
        spec.known_prefix_hex = app.ob_keyhole_prefix;
        spec.known_suffix_hex = app.ob_keyhole_suffix;
        app.ob_keyhole = keyhole_build_plan(spec);
        if (!app.ob_keyhole.partial_prefix_for_cuda.empty())
          strncpy(app.partial_prefix, app.ob_keyhole.partial_prefix_for_cuda.c_str(),
                  sizeof(app.partial_prefix) - 1);
        app.ob_panel_out = app.ob_keyhole.guidance;
        app.log(app.ob_keyhole.guidance);
      }

      ImGui::Separator();
      ImGui::TextUnformatted("23 · Seed Mirage Meter");
      ImGui::InputTextMultiline("Carved mnemonics (one per line)", app.ob_mirage_mnem,
                                sizeof(app.ob_mirage_mnem), ImVec2(-1, 60));
      if (ImGui::Button("Score Seed Mirage")) {
        std::vector<std::string> ms;
        std::istringstream iss(app.ob_mirage_mnem);
        std::string line;
        while (std::getline(iss, line)) {
          while (!line.empty() && (unsigned char)line.back() <= ' ') line.pop_back();
          while (!line.empty() && (unsigned char)line.front() <= ' ') line.erase(line.begin());
          if (!line.empty()) ms.push_back(line);
        }
        /* also from breaker carve */
        if (ms.empty() && app.has_carve)
          for (auto& m : app.carve_report.mnemonics) ms.push_back(m.text);
        app.ob_mirage = seed_mirage_meter(ms, app.wallet);
        std::ostringstream ss;
        ss << app.ob_mirage.summary << "\n";
        for (auto& s : app.ob_mirage.ranked)
          ss << s.score << " bip39=" << (s.bip39_checksum ? 1 : 0) << " " << s.mnemonic << "\n";
        app.ob_panel_out = ss.str();
        app.log(app.ob_mirage.summary);
      }
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }

  ImGui::Separator();
  ImGui::BeginChild("ob_out", ImVec2(0, 0), true);
  ImGui::TextUnformatted(app.ob_panel_out.c_str());
  ImGui::EndChild();
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

static void catalog_refresh(AppState& app) {
  app.catalog_rows = tool_catalog_refresh();
  app.catalog_stats = tool_catalog_stats(app.catalog_rows);
  app.commercial_hub = commercial_integration_hub();
}

static void draw_tool_bay_tab(AppState& app) {
  ImGui::TextColored(ImVec4(0.78f, 0.62f, 0.28f, 1.f), "Universal Tool Bay — DFIR Catalog");
  ImGui::TextWrapped(
      "Every tool from the Huge DFIR research dump has a GUI entry. Native = runnable here. "
      "Setup = setup_forensics.bat. Commercial = licensed bridge only (never pirate). "
      "On-chain labeling ≠ crack. Made by TrueScent — https://t.me/TrueScent");
  if (ImGui::Button("Refresh status")) {
    catalog_refresh(app);
    app.tools_status = detect_forensics_tools();
  }
  ImGui::SameLine();
  ImGui::Text("Entries: %d | Native: %d | Setup OK/miss: %d/%d | Ideas: %d", app.catalog_stats.total,
              app.catalog_stats.native_runnable, app.catalog_stats.setup_installed,
              app.catalog_stats.setup_missing, app.catalog_stats.idea);

  if (ImGui::BeginTabBar("toolbay_inner")) {
    if (ImGui::BeginTabItem("Catalog")) {
      ImGui::InputText("Search", app.catalog_search, sizeof(app.catalog_search));
      ImGui::Checkbox("Only runnable/installed", &app.catalog_only_runnable);
      const char* cats[] = {"All",
                            "Crackers",
                            "Carvers",
                            "Seed GPU",
                            "Browser",
                            "Mobile",
                            "Memory",
                            "Disk/VSS",
                            "OCR/Email",
                            "Password",
                            "Commercial LE",
                            "On-chain labeling",
                            "Native / First-party",
                            "Research / Quickfire",
                            "Imaging / Acquisition"};
      ImGui::Combo("Category", &app.catalog_cat_filter, cats, IM_ARRAYSIZE(cats));
      ToolCategory cat_val = ToolCategory::Crackers;
      ToolCategory* cat_ptr = nullptr;
      if (app.catalog_cat_filter > 0) {
        cat_val = static_cast<ToolCategory>(app.catalog_cat_filter - 1);
        cat_ptr = &cat_val;
      }
      auto filtered = tool_catalog_filter(app.catalog_rows, app.catalog_search, cat_ptr,
                                          app.catalog_only_runnable);
      ImGui::Text("Showing %d / %d", (int)filtered.size(), (int)app.catalog_rows.size());
      ImGui::BeginChild("catlist", ImVec2(0, 280), true);
      for (int i = 0; i < (int)filtered.size(); ++i) {
        auto& e = filtered[i];
        bool sel = (app.catalog_selected >= 0 && app.catalog_selected < (int)app.catalog_rows.size() &&
                    app.catalog_rows[app.catalog_selected].id == e.id);
        char label[256];
        std::snprintf(label, sizeof(label), "[%s] %s — %s", tool_kind_name(e.kind), e.name.c_str(),
                      e.status_label.c_str());
        if (ImGui::Selectable(label, sel)) {
          for (int j = 0; j < (int)app.catalog_rows.size(); ++j)
            if (app.catalog_rows[j].id == e.id) {
              app.catalog_selected = j;
              break;
            }
          app.catalog_detail = e.description + "\n\nStatus: " + e.status_label +
                               "\nCategory: " + std::string(tool_category_name(e.category)) +
                               "\nDocs: " + e.docs_url + "\nPath: " + e.resolved_path +
                               "\nNotes: " + e.notes;
        }
      }
      ImGui::EndChild();
      ImGui::BeginChild("catdetail", ImVec2(0, 120), true);
      ImGui::TextWrapped("%s", app.catalog_detail.c_str());
      ImGui::EndChild();
      if (app.catalog_selected >= 0 && app.catalog_selected < (int)app.catalog_rows.size()) {
        auto& e = app.catalog_rows[app.catalog_selected];
        if (e.kind == ToolKind::Native && ImGui::Button("Open related native tab hint")) {
          app.log("[Tool Bay] Native action: " + e.native_action + " — use matching GUI tab / Pipelines");
        }
        if ((e.kind == ToolKind::SetupFetch || e.kind == ToolKind::Experimental) &&
            ImGui::Button("Setup hint")) {
          app.log("[Tool Bay] Run setup_forensics.bat (section key: " +
                  (e.setup_key.empty() ? e.id : e.setup_key) + ")");
          app.log("Missing tools download into third_party/. GUI shows Installed/Missing.");
        }
        if ((e.kind == ToolKind::Bridge || e.kind == ToolKind::Commercial) &&
            ImGui::Button("Try launch / open path")) {
          std::string err;
          if (commercial_try_launch(e.id, &err))
            app.log("[+] launched " + e.id);
          else
            app.log("[!] " + err);
        }
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Pipelines")) {
      ImGui::TextWrapped("First-party native intake pipelines (authorized DFIR only).");
      ImGui::InputText("Path / folder", app.catalog_pipe_out, sizeof(app.catalog_pipe_out));
      ImGui::SameLine();
      if (ImGui::Button("Browse##pipe")) {
        auto p = open_file_dialog("All\0*.*\0");
        if (!p.empty()) {
          strncpy(app.catalog_pipe_out, p.c_str(), sizeof(app.catalog_pipe_out) - 1);
        }
      }
      auto run_pipe = [&](const char* name, PipelineReport (*fn)(const std::string&)) {
        auto rep = fn(app.catalog_pipe_out);
        app.catalog_orch_out = std::string("[") + name + "]\n" + rep.summary;
        if (!rep.hashcat_hint.empty()) app.catalog_orch_out += "\n" + rep.hashcat_hint;
        for (size_t i = 0; i < rep.hits.size() && i < 12; ++i)
          app.catalog_orch_out +=
              "\n* " + rep.hits[i].kind + " " + rep.hits[i].path_or_offset + " | " + rep.hits[i].snippet;
        app.log(app.catalog_orch_out);
      };
      if (ImGui::Button("MetaMask LevelDB")) run_pipe("metamask", pipeline_metamask_leveldb);
      ImGui::SameLine();
      if (ImGui::Button("Exodus SECO")) run_pipe("exodus", pipeline_exodus_seco);
      ImGui::SameLine();
      if (ImGui::Button("Electrum")) run_pipe("electrum", pipeline_electrum_helper);
      if (ImGui::Button("OCR BIP39 intake")) run_pipe("ocr", pipeline_bip39_ocr_intake);
      ImGui::SameLine();
      if (ImGui::Button("Mbox seed scavenge")) run_pipe("mbox", pipeline_mbox_seed_scavenge);
      ImGui::SameLine();
      if (ImGui::Button("Dump scan")) run_pipe("dump", pipeline_volatile_dump_scan);
      if (ImGui::Button("SQLite Core heuristic")) run_pipe("sqlite", pipeline_sqlite_core_wallet);
      ImGui::SameLine();
      if (ImGui::Button("KeePass/CSV bridge")) run_pipe("csv", pipeline_keepass_csv_bridge);
      ImGui::SameLine();
      if (ImGui::Button("Extension walker")) {
        auto rep = pipeline_browser_extension_walker(app.catalog_pipe_out);
        app.catalog_orch_out = rep.summary;
        for (auto& h : rep.hits) app.catalog_orch_out += "\n* " + h.snippet + " @ " + h.path_or_offset;
        app.log(app.catalog_orch_out);
      }
      if (ImGui::Button("AddressDB builder hook")) {
        auto rep = pipeline_addressdb_builder_hook("data\\addressdb");
        app.catalog_orch_out = rep.summary;
        app.log(app.catalog_orch_out);
      }
      ImGui::Separator();
      ImGui::InputText("Orchestrate input", app.catalog_intake_path, sizeof(app.catalog_intake_path));
      if (ImGui::Button("Recommend + cheap scan chain")) {
        auto rep = pipeline_orchestrate_intake(app.catalog_intake_path);
        app.catalog_orch_out = rep.summary;
        app.log(app.catalog_orch_out);
      }
      ImGui::BeginChild("pipeout", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
      ImGui::TextUnformatted(app.catalog_orch_out.c_str());
      ImGui::EndChild();
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Integration Hub")) {
      ImGui::TextWrapped(
          "Commercial LE / on-chain tools are bridges only. Configure licensed install paths in "
          "data/commercial_paths.ini. Never pirate. Chainalysis/TRM/Elliptic/Maltego label funds after "
          "keys/addresses exist — they do not crack wallet.dat.");
      for (auto& c : app.commercial_hub) {
        ImGui::Separator();
        ImGui::Text("%s — %s", c.name.c_str(), c.found ? "DETECTED" : "Install separately");
        if (c.found) ImGui::TextWrapped("%s", c.detected_path.c_str());
        ImGui::TextWrapped("TWC covers instead: %s", c.twc_covers_instead.c_str());
        if (c.found && ImGui::Button(("Open##" + c.id).c_str())) {
          std::string err;
          commercial_try_launch(c.id, &err);
        }
      }
      ImGui::Separator();
      ImGui::InputText("Manual path (id=path after Set)", app.commercial_path_edit,
                       sizeof(app.commercial_path_edit));
      if (ImGui::Button("Set path for selected catalog commercial id")) {
        if (app.catalog_selected >= 0 && app.catalog_selected < (int)app.catalog_rows.size()) {
          commercial_set_user_path(app.catalog_rows[app.catalog_selected].id, app.commercial_path_edit);
          catalog_refresh(app);
          app.log("[+] saved commercial path for " + app.catalog_rows[app.catalog_selected].id);
        } else {
          app.log("[!] select a Commercial catalog row first");
        }
      }
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }
}

static void draw_lab_docs_tab(AppState& app) {
  ImGui::TextColored(ImVec4(0.78f, 0.62f, 0.28f, 1.f), "TrueWalletCollider // Forensic Suite");
  ImGui::TextWrapped("%s", experiment_help().c_str());
  ImGui::Separator();
  ImGui::TextUnformatted("Workflow");
  ImGui::BulletText("Open Any Wallet / Extract: auto-detect Core (BTC/BCH/LTC/DOGE), ETH, Electrum, Exodus, MetaMask…");
  ImGui::BulletText("Salvage / Passphrase Lab / AES Partial / dual-verify (Core Recovery Lab).");
  ImGui::BulletText("TrueReweave (Breaker tab 4): inventory + rematerialize — NO fake BIP39-in-Core rewrite.");
  ImGui::BulletText("Outside Box: VSS, ghosts, leftovers, memory import, multi-mkey, Two-Body, CSV, Keyhole, Time-Slice, …");
  ImGui::BulletText("Tool Bay: full DFIR catalog + native pipelines wired into Open/Detect.");
  ImGui::BulletText("Verify: REAL/SUSPECT/FAKE/CORRUPT checklist (CLI --verify / --verify-plus).");
  ImGui::BulletText("Case: notes + evidence zip under cases/.");
  ImGui::BulletText("BTCRecover Lab + Hashcat Bridge: multi-mode (11300/15600/…/28200) after setup_forensics.bat.");
  ImGui::Separator();
  ImGui::TextUnformatted("Supported formats (SHIPPED)");
  ImGui::TextWrapped("%s", supported_formats_shipped().c_str());
  ImGui::Separator();
  ImGui::TextUnformatted("Derivation path hints");
  ImGui::TextWrapped("%s", derivation_paths_markdown().c_str());
  ImGui::Separator();
  ImGui::TextUnformatted("Honesty");
  ImGui::BulletText("Commercial crackers are bridges — not embedded free.");
  ImGui::BulletText("Some GPU seed tools are experimental (clone/build).");
  ImGui::BulletText("On-chain labeling ≠ local passphrase/AES crack.");
  ImGui::BulletText("FORBIDDEN: inject BIP39 into classic Core wallet.dat (never stored there).");
  ImGui::Separator();
  ImGui::TextUnformatted("Hibernation / RAM forensic guidance");
  ImGui::TextWrapped(
      "Use Outside Box → Memory (unlock kit / pagefile / hiberfil / VRAM import). Cold-boot AES keys "
      "also belong in AES Partial. Only analyze dumps from systems you own or are authorized to recover. "
      "No silent live RAM capture. Unauthorized forensic imaging is illegal.");
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
#ifdef _WIN32
  /* Prevent Windows Restart Manager from auto-relaunching after a prior crash/abort. */
  UnregisterApplicationRestart();
#endif
  glfwSetErrorCallback(glfw_error);
  if (!glfwInit()) return 1;

  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
  GLFWwindow* window =
      glfwCreateWindow(1440, 900, "TrueWalletCollider — Forensic Suite", nullptr, nullptr);
  if (!window) {
    glfwTerminate();
    return 1;
  }
  glfwMakeContextCurrent(window);
  glfwSwapInterval(1);
  if (!gladLoadGL(glfwGetProcAddress)) {
    std::fprintf(stderr, "Failed to load OpenGL via GLAD\n");
    glfwDestroyWindow(window);
    glfwTerminate();
    return 1;
  }

#ifdef _WIN32
  glfwSetDropCallback(window, [](GLFWwindow* w, int count, const char** paths) {
    auto* app = reinterpret_cast<AppState*>(glfwGetWindowUserPointer(w));
    if (!app || count <= 0) return;
    for (int i = 0; i < count; ++i) {
      std::string p = paths[i];
      if (p.empty()) continue;
      load_wallet_path(*app, p);
      app->drop_pulse = 1.0;
      break;
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
#ifdef _WIN32
  /* Root cause of prior paste failure:
   * 1) OpenClipboard(NULL) + EmptyClipboard → SetClipboardData fails (no owner HWND).
   * 2) Get buffer resized to len-1 then wrote len bytes (overrun / corrupt UTF-8).
   * 3) No OpenClipboard retries (Win10/11 Clipboard History often holds the lock).
   * 4) GLFW backend used NULL window; we still override with Win32 + reinstall each frame. */
  clipboard_win32_set_owner(glfwGetWin32Window(window));
  clipboard_win32_install_imgui_handlers();
#endif

  AppState app;
  app.window = window;
  glfwSetWindowUserPointer(window, &app);
  glfwSetWindowCloseCallback(window, [](GLFWwindow* w) {
    auto* a = reinterpret_cast<AppState*>(glfwGetWindowUserPointer(w));
    if (a) a->quit_requested = true;
    glfwSetWindowShouldClose(w, GLFW_TRUE);
  });
  app.devices = CrackEngine::list_devices();
  app.log("TrueWalletCollider Forensic Suite ready — Made by TrueScent");
  app.log(cpu_simd_detect().status_line);
  app.log("Bundles: run setup_forensics.bat for Hashcat + BTCRecover + John + Python");
  app.log("Telegram: https://t.me/TrueScent — authorized use only");
#ifdef _WIN32
  {
    std::string clip_detail;
    bool clip_ok = clipboard_win32_selftest(&clip_detail);
    app.log(std::string(clip_ok ? "[+] " : "[E] ") + clip_detail);
    if (clip_ok) app.log("Clipboard: Ctrl+V + Paste buttons use Win32 CF_UNICODETEXT (HWND owner)");
  }
#else
  app.log("Clipboard: use OS defaults");
#endif
  app.case_ids = case_list_ids();
  app.tools_status = detect_forensics_tools();
  app.hashcat_exe_cached = app.tools_status.hashcat;
  catalog_refresh(app);
  app.log(app.catalog_stats.summary);
  app.orch_opt.do_verify = true;
  app.orch_opt.do_carve = true;
  app.orch_opt.do_native_kdf = true;
  app.orch_opt.use_cpu = true;
  app.orch_opt.use_gpu = true;
  if (!app.devices.empty())
    app.log("CUDA: " + app.devices[0]);
  else
    app.log("[!] no CUDA devices visible");

  while (!glfwWindowShouldClose(window) && !app.quit_requested) {
    glfwPollEvents();
    if (app.quit_requested) break;
    if (app.pp_thread.joinable() && !app.pp_progress.running.load()) app.pp_thread.join();
    if (app.ob_attack_thread.joinable() && !app.ob_mm_prog.running.load() &&
        !app.ob_twobody_prog.running.load())
      app.ob_attack_thread.join();
    if (app.breaker_thread.joinable() && !app.breaker_busy) app.breaker_thread.join();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
#ifdef _WIN32
    /* Re-install after GLFW NewFrame so our Win32 handlers always win. */
    clipboard_win32_install_imgui_handlers();
#endif
    ImGui::NewFrame();

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("TrueWalletColliderMain", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    draw_brand_bar(app);
    draw_about_modal(app);

      ImGui::TextColored(app.drop_pulse > 0 ? ImVec4(0.55f, 0.92f, 0.55f, (float)app.drop_pulse)
                                           : ImVec4(0.6f, 0.6f, 0.6f, 1.f),
                         app.drop_pulse > 0 ? "wallet dropped — auto-detected"
                                            : "drop any wallet format");
      if (app.drop_pulse > 0) app.drop_pulse -= io.DeltaTime * 0.6;

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
      if (ImGui::BeginTabItem("Breaker & Rebuild")) {
        draw_breaker_rebuild_tab(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Outside Box")) {
        draw_outside_box_tab(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Verify")) {
        draw_verify_tab(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Case")) {
        draw_case_tab(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("BTCRecover Lab")) {
        draw_btcrecover_lab_tab(app);
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
      if (ImGui::BeginTabItem("Tool Bay")) {
        draw_tool_bay_tab(app);
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

  /* Clean exit: stop engines, kill child tools, join with timeout — never hang. */
  shutdown_app_workers(app);
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();
  glfwDestroyWindow(window);
  app.window = nullptr;
  glfwTerminate();
#ifdef _WIN32
  /* Guarantee process stays dead (no CUDA teardown hang / joinable-thread abort restart). */
  ExitProcess(0);
#endif
  return 0;
}
