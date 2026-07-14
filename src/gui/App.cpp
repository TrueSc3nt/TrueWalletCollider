#include "App.h"
#include "Theme.h"

#include "../crack/CrackEngine.h"
#include "../wallet/Passphrase.h"
#include "../wallet/WalletDat.h"

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
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
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
#endif

TargetCipher crack_make_target(const std::vector<uint8_t>& blob48);

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
  int mode = 0; /* 0=r 1=q 2=rs */
  int mixed_span = 256;
  bool light_theme = false;
  bool include_mkey = true;
  bool include_ckeys = true;
  int selected_ckey = -1;

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
static std::string open_file_dialog() {
  char file[MAX_PATH] = {};
  OPENFILENAMEA ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.lpstrFile = file;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrFilter = "Wallet DAT\0*.dat\0All\0*.*\0";
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
#else
static std::string open_file_dialog() { return {}; }
static std::string save_file_dialog(const char*, const char*) { return {}; }
static void set_clipboard(const std::string&) {}
#endif

static void load_wallet_path(AppState& app, const std::string& path) {
  if (path.empty()) return;
  WalletDatParser parser;
  app.wallet = parser.parse_file(path);
  app.has_wallet = true;
  app.selected_ckey = app.wallet.ckeys.empty() ? -1 : 0;
  for (auto& line : app.wallet.log) app.log(line);
  for (auto& w : app.wallet.warnings) app.log("[warn] " + w);
  app.log("[+] ready — " + std::to_string(app.wallet.ckeys.size()) + " ckeys");

  /* address match popup-style log */
  if (app.target_address[0]) {
    for (size_t i = 0; i < app.wallet.ckeys.size(); ++i) {
      if (app.wallet.ckeys[i].address == app.target_address) {
        app.log("*** TARGET MATCH ckey #" + std::to_string(i) + " ***");
        app.selected_ckey = (int)i;
      }
    }
  }
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
  ImGui::TextColored(ImVec4(0.55f, 0.92f, 0.55f, 0.9f), "  // TrueScent lab");
  ImGui::SameLine(ImGui::GetWindowWidth() - 280);
  if (ImGui::SmallButton(app.light_theme ? "Noir" : "Light")) {
    app.light_theme = !app.light_theme;
    ApplyTrueScentTheme(app.light_theme);
  }
  ImGui::SameLine();
  ImGui::TextDisabled("wallet.dat + CUDA mkey/ckey");
  ImGui::Separator();
}

static void draw_overview(AppState& app) {
  if (!app.has_wallet) {
    ImGui::TextWrapped(
        "Drop a Bitcoin Core wallet.dat here, or Open File. "
        "Extracts mkey, ckeys, pubkeys, addresses, salts, KDF metadata, and structural tags.");
    ImGui::Dummy(ImVec2(0, 8));
    if (ImGui::Button("Open wallet.dat", ImVec2(180, 36))) {
      auto p = open_file_dialog();
      if (!p.empty()) load_wallet_path(app, p);
    }
    ImGui::SameLine();
    if (ImGui::Button("Load PoC targets", ImVec2(160, 36))) {
      /* synthetic wallet from TrueMkeyCollider PoC */
      app.wallet = WalletParseResult{};
      app.wallet.path = "(PoC bundled)";
      app.wallet.file_size = 0;
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
      app.selected_ckey = 0;
      app.log("[+] loaded bundled PoC ckey + pubkey");
    }
    return;
  }

  ImGui::Text("File: %s", app.wallet.path.c_str());
  ImGui::Text("Size: %zu bytes | Magic: %s (%s)", app.wallet.file_size,
              app.wallet.magic_ok ? "OK" : "mismatch", app.wallet.magic_hex.c_str());
  ImGui::TextWrapped("%s", app.wallet.bdb_note.c_str());
  ImGui::Separator();
  ImGui::Text("Master key: %s", app.wallet.mkey.found ? "FOUND" : "none");
  if (app.wallet.mkey.found) {
    ImGui::Text("  method=%u  iterations=%u", app.wallet.mkey.method, app.wallet.mkey.iterations);
    ImGui::Text("  salt: %s", app.wallet.mkey.salt_hex.c_str());
  }
  ImGui::Text("CKeys: %d", app.wallet.ckey_count());
  ImGui::Text("Meta tags: %zu", app.wallet.meta.size());

  ImGui::Separator();
  ImGui::InputText("Target address", app.target_address, sizeof(app.target_address));
  if (ImGui::Button("Scan for target")) {
    bool found = false;
    for (size_t i = 0; i < app.wallet.ckeys.size(); ++i) {
      if (app.wallet.ckeys[i].address == app.target_address) {
        app.log("MATCH #" + std::to_string(i) + " " + app.wallet.ckeys[i].address);
        app.selected_ckey = (int)i;
        found = true;
      }
    }
    if (!found) app.log("No ckey address matched target");
  }
  ImGui::SameLine();
  if (ImGui::Button("Re-open…")) {
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
  if (ImGui::Button("Export ckeys.txt")) {
    WalletDatParser::write_ckeys_file(app.wallet, "ckeys_export.txt");
    WalletDatParser::write_mkeys_file(app.wallet, "mkeys_export.txt");
    app.log("[+] wrote ckeys_export.txt / mkeys_export.txt");
  }
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
  ImGui::BeginChild("ckey_list", ImVec2(280, 0), true);
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
    ImGui::Text("SHA256:    %s", c.sha256_hex.c_str());
    ImGui::Text("RIPEMD160: %s", c.ripemd160_hex.c_str());
    ImGui::Text("Raw addr:  %s", c.address_raw_hex.c_str());
    if (ImGui::Button("Copy enc")) set_clipboard(c.encrypted_hex);
    ImGui::SameLine();
    if (ImGui::Button("Copy pub")) set_clipboard(c.pubkey_hex);
    ImGui::SameLine();
    if (ImGui::Button("Copy address")) set_clipboard(c.address);
    ImGui::SameLine();
    if (ImGui::Button("Copy line (ckeys format)"))
      set_clipboard(c.encrypted_hex + (c.pubkey_hex.empty() ? "" : " " + c.pubkey_hex));
  }
  ImGui::EndChild();
}

static void draw_meta_panel(AppState& app) {
  if (!app.has_wallet) return;
  if (ImGui::BeginTable("meta", 3,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                        ImVec2(0, 0))) {
    ImGui::TableSetupColumn("Tag");
    ImGui::TableSetupColumn("Offset");
    ImGui::TableSetupColumn("Note / preview");
    ImGui::TableHeadersRow();
    for (auto& m : app.wallet.meta) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextUnformatted(m.tag.c_str());
      ImGui::TableSetColumnIndex(1);
      ImGui::Text("%zu", m.offset);
      ImGui::TableSetColumnIndex(2);
      ImGui::TextWrapped("%s | %s", m.note.c_str(), m.preview_hex.c_str());
    }
    ImGui::EndTable();
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
      /* allow PoC if empty */
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

static void draw_tools_panel(AppState& app) {
  ImGui::TextUnformatted("Passphrase attempt (Bitcoin Core method 0)");
  ImGui::InputText("Passphrase", app.passphrase, sizeof(app.passphrase),
                   ImGuiInputTextFlags_Password);
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

int RunGuiApp() {
  glfwSetErrorCallback(glfw_error);
  if (!glfwInit()) return 1;

  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
  GLFWwindow* window =
      glfwCreateWindow(1440, 900, "TrueWalletCollider — TrueScent lab", nullptr, nullptr);
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
  app.log("TrueWalletCollider ready — drop wallet.dat or Open File");
  if (!app.devices.empty())
    app.log("CUDA: " + app.devices[0]);
  else
    app.log("[!] no CUDA devices visible");

  while (!glfwWindowShouldClose(window)) {
    glfwPollEvents();
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
      ImGui::TextColored(ImVec4(0.55f, 0.92f, 0.55f, (float)app.drop_pulse),
                         "wallet dropped");
      app.drop_pulse -= io.DeltaTime * 0.6;
    }

    ImGui::Columns(2, "maincols", true);
    ImGui::SetColumnWidth(0, vp->WorkSize.x * 0.58f);

    if (ImGui::BeginTabBar("lefttabs")) {
      if (ImGui::BeginTabItem("Overview")) {
        draw_overview(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Master Key")) {
        draw_mkey_panel(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("CKeys")) {
        draw_ckeys_panel(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Metadata")) {
        draw_meta_panel(app);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Tools")) {
        draw_tools_panel(app);
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
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();
  glfwDestroyWindow(window);
  glfwTerminate();
  return 0;
}
