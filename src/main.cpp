#include "gui/App.h"
#include "gui/ClipboardWin32.h"
#include "crack/CrackEngine.h"
#include "wallet/WalletDat.h"
#include "wallet/Passphrase.h"
#include "wallet/HashcatExport.h"
#include "wallet/Experiment.h"
#include "wallet/Salvage.h"
#include "wallet/ForensicVerify.h"
#include "wallet/ToolBridge.h"
#include "wallet/OutsideBox.h"
#include "wallet/ToolCatalog.h"
#include "wallet/NativePipelines.h"
#include "wallet/WalletFormat.h"
#include "wallet/TrueReweave.h"
#include "crypto/crypto_wallet.h"
#include "crypto/secp256k1_lite.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void usage() {
  std::printf(
      "TrueWalletCollider — Forensic Suite / Recovery Lab\n"
      "(authorized owner recovery / DFIR / cryptanalysis R&D only)\n"
      "Made by TrueScent — https://t.me/TrueScent\n\n"
      "  TrueWalletCollider.exe [flags]     launch Forensic Suite GUI\n"
      "  --selftest                         GPU+host PoC AES/WIF pipeline\n"
      "  --parse FILE                       parse wallet.dat → TXT/JSON exports\n"
      "  --verify FILE|$bitcoin$LINE        REAL/SUSPECT/FAKE/CORRUPT checklist\n"
      "  --verify-plus FILE                 fake-wallet detector++ (entropy+consistency)\n"
      "  --export-hashcat FILE              print $bitcoin$ line (hashcat -m 11300)\n"
      "  --salvage FILE                     carve mkey/ckey from damaged dump\n"
      "  --outside-box                      list Outside Box module inventory\n"
      "  --vss-list                         list Volume Shadow Copies (PowerShell)\n"
      "  --portable-scan                    scan common/USB wallet.dat leftovers\n"
      "  --ghost-scan DIR                   cloud sync wallet.dat* ghost finder\n"
      "  --scavenge-dump FILE               RAM/process/pagefile string scavenge\n"
      "  --timeslice DIR                    Time-Slice crack plan by age×iters\n"
      "  --csv-bridge FILE                  password-manager CSV → wordlist stdout\n"
      "  --keyhole PREFIX_HEX               Keyhole plan (wires to AES Partial)\n"
      "  --experiment NAME                  research harness (help|dual_fp|passphrase|secp|hashcat_fmt|force_rebuild)\n"
      "  --tools-status                     full DFIR catalog + bundle detectors\n"
      "  --catalog-count                    print Universal Tool Bay entry count\n"
      "  --pipeline NAME PATH               native intake (metamask|exodus|mbox|ocr|dump|ext|sqlite|orch|electrum)\n"
      "  --detect FILE                      Open Any Wallet format detect (status line)\n"
      "  --open-any FILE                    detect + extract hash + inventory\n"
      "  --formats                          list SHIPPED multi-format Open/Detect support\n"
      "  --clipboard-selftest               Win32 clipboard Set/Get round-trip (UTF-8)\n"
      "  --partial-help                     document AES partial-key GPU mode\n\n"
      "Honest scope: multi-format Open Any Wallet + passphrase/KDF + dual-verify + salvage + Outside Box.\n"
      "There is NO magic bypass of wallet.dat AES/mkey without the passphrase.\n"
      "TrueReweave rematerializes keys AFTER unlock — FORBIDDEN to fake BIP39 rewrite inside Core wallet.dat.\n"
      "Force Rebuild Experimental = NEW BIP39 keys only (does not unlock original encrypted ckeys).\n"
      "Raw full AES-256 search of unknown keys is research/partial-key only (2^256).\n"
      "Commercial tools = Integration Hub bridges only (never pirate).\n"
      "Optional bundles: run setup_forensics.bat → third_party\\...\n");
}

int RunHeadlessCli(int argc, char** argv) {
  (void)argc;
  (void)argv;
  return 0;
}

int main(int argc, char** argv) {
  if (argc >= 2) {
    std::string a = argv[1];
    if (a == "-h" || a == "--help") {
      usage();
      return 0;
    }
    if (a == "--outside-box") {
      std::fputs(outside_box_module_inventory().c_str(), stdout);
      return 0;
    }
    if (a == "--vss-list") {
      auto r = vss_list_shadows();
      std::fputs(r.summary.c_str(), stdout);
      std::fputc('\n', stdout);
      for (auto& s : r.shadows)
        std::printf("%s | %s | %s\n", s.id.c_str(), s.device_object.c_str(), s.create_time.c_str());
      return r.ok ? 0 : 2;
    }
    if (a == "--portable-scan") {
      auto r = portable_leftover_scan(true);
      std::puts(r.summary.c_str());
      for (auto& h : r.hits)
        std::printf("%s\t%u\t%d\t%s\n", h.source.c_str(), h.iterations, h.ckeys, h.path.c_str());
      return r.hits.empty() ? 2 : 0;
    }
    if (a == "--ghost-scan" && argc >= 3) {
      auto r = cloud_sync_ghost_find({argv[2]});
      std::puts(r.summary.c_str());
      for (auto& h : r.hits)
        std::printf("%s\t%zu\t%s\n", h.kind.c_str(), h.size, h.path.c_str());
      return r.hits.empty() ? 2 : 0;
    }
    if (a == "--scavenge-dump" && argc >= 3) {
      auto r = scavenge_memory_dump(argv[2]);
      std::puts(r.summary.c_str());
      for (size_t i = 0; i < r.hits.size() && i < 50; ++i)
        std::printf("%zu\t%s\t%s\n", r.hits[i].offset, r.hits[i].kind.c_str(),
                    r.hits[i].text.c_str());
      return r.hits.empty() ? 2 : 0;
    }
    if (a == "--timeslice" && argc >= 3) {
      auto r = timeslice_crack_plan(argv[2]);
      std::puts(r.summary.c_str());
      for (auto& it : r.items)
        std::printf("%.6f\t%u\t%s\t%s\n", it.priority, it.iterations, it.reason.c_str(),
                    it.path.c_str());
      return r.items.empty() ? 2 : 0;
    }
    if (a == "--csv-bridge" && argc >= 3) {
      auto r = import_password_manager_csv(argv[2]);
      std::puts(r.summary.c_str());
      for (auto& w : r.wordlist) std::puts(w.c_str());
      return r.wordlist.empty() ? 2 : 0;
    }
    if (a == "--keyhole" && argc >= 3) {
      KeyholeSpec spec;
      spec.known_prefix_hex = argv[2];
      if (argc >= 4) spec.known_suffix_hex = argv[3];
      auto p = keyhole_build_plan(spec);
      std::puts(p.guidance.c_str());
      if (!p.partial_prefix_for_cuda.empty())
        std::printf("partial_prefix=%s\n", p.partial_prefix_for_cuda.c_str());
      return p.ok ? 0 : 2;
    }
    if (a == "--verify-plus" && argc >= 3) {
      auto r = fake_wallet_detector_plus_file(argv[2]);
      std::puts(r.summary.c_str());
      std::fputs(verify_report_text(r.base).c_str(), stdout);
      return r.base.verdict == VerifyVerdict::REAL      ? 0
             : r.base.verdict == VerifyVerdict::SUSPECT ? 1
             : r.base.verdict == VerifyVerdict::CORRUPT ? 2
                                                       : 3;
    }
    if (a == "--formats") {
      std::fputs(supported_formats_shipped().c_str(), stdout);
      return 0;
    }
    if (a == "--detect" && argc >= 3) {
      auto d = detect_wallet_file(argv[2]);
      std::puts(d.status_line.c_str());
      std::printf("family=%s coin=%s mode=%d\n", wallet_family_cstr(d.family),
                  coin_hint_cstr(d.coin), d.hashcat_mode);
      return d.family == WalletFamily::Unknown ? 2 : 0;
    }
    if (a == "--open-any" && argc >= 3) {
      auto d = open_any_wallet(argv[2]);
      std::puts(d.status_line.c_str());
      std::printf("label=%s coin=%s open_ok=%d mode=%d\n", d.label.c_str(), d.coin_display.c_str(),
                  (int)d.open_ok, d.hashcat_mode);
      if (!d.hash_line.empty()) std::printf("hash=%s\n", d.hash_line.c_str());
      if (!d.hash_export_path.empty()) std::printf("export=%s\n", d.hash_export_path.c_str());
      std::puts(d.crack_hint.c_str());
      for (auto& line : d.inventory) std::printf("inv: %s\n", line.c_str());
      for (auto& h : d.derivation_hints) std::printf("path: %s\n", h.c_str());
      return d.open_ok || d.family != WalletFamily::Unknown ? 0 : 2;
    }
    if (a == "--clipboard-selftest") {
#ifdef _WIN32
      std::string detail;
      bool ok = clipboard_win32_selftest(&detail);
      std::puts(detail.c_str());
      return ok ? 0 : 2;
#else
      std::puts("clipboard selftest is Win32-only");
      return 2;
#endif
    }
    if (a == "--partial-help") {
      std::printf(
          "AES Partial-Key / Keyhole mode (where GPU AES earns its keep)\n"
          "  Known prefix of N bytes → search space 256^(32-N).\n"
          "  GUI: Outside Box → Keyhole, or AES Partial → hex prefix.\n"
          "  CLI: --keyhole HEXPREFIX [HEXSUFFIX]\n"
          "  Does NOT claim a break of unknown full AES-256 master keys.\n");
      return 0;
    }
    if (a == "--tools-status") {
      auto s = detect_forensics_tools();
      std::fputs(s.status_text.c_str(), stdout);
      std::fputc('\n', stdout);
      std::fputs(tool_catalog_status_report().c_str(), stdout);
      auto rows = tool_catalog_refresh();
      auto st = tool_catalog_stats(rows);
      return (s.hashcat.empty() && s.btcrecover.empty() && st.native_runnable == 0) ? 2 : 0;
    }
    if (a == "--catalog-count") {
      auto rows = tool_catalog_refresh();
      auto st = tool_catalog_stats(rows);
      std::printf("CATALOG_ENTRIES=%d\n", st.total);
      std::printf("NATIVE_RUNNABLE=%d\n", st.native_runnable);
      std::printf("SETUP_INSTALLED=%d\n", st.setup_installed);
      std::printf("SETUP_MISSING=%d\n", st.setup_missing);
      std::printf("BRIDGE=%d\n", st.bridge);
      std::printf("COMMERCIAL=%d\n", st.commercial);
      std::printf("EXPERIMENTAL=%d\n", st.experimental);
      std::printf("IDEA=%d\n", st.idea);
      std::fputs(st.summary.c_str(), stdout);
      return 0;
    }
    if (a == "--pipeline" && argc >= 4) {
      std::string name = argv[2];
      std::string path = argv[3];
      PipelineReport rep;
      if (name == "metamask")
        rep = pipeline_metamask_leveldb(path);
      else if (name == "exodus")
        rep = pipeline_exodus_seco(path);
      else if (name == "mbox")
        rep = pipeline_mbox_seed_scavenge(path);
      else if (name == "ocr")
        rep = pipeline_bip39_ocr_intake(path);
      else if (name == "dump")
        rep = pipeline_volatile_dump_scan(path);
      else if (name == "ext")
        rep = pipeline_browser_extension_walker(path);
      else if (name == "sqlite")
        rep = pipeline_sqlite_core_wallet(path);
      else if (name == "electrum")
        rep = pipeline_electrum_helper(path);
      else if (name == "orch")
        rep = pipeline_orchestrate_intake(path);
      else {
        std::fprintf(stderr, "unknown pipeline (metamask|exodus|electrum|mbox|ocr|dump|ext|sqlite|orch)\n");
        return 2;
      }
      std::puts(rep.summary.c_str());
      if (!rep.hashcat_hint.empty()) std::puts(rep.hashcat_hint.c_str());
      return rep.ok ? 0 : 2;
    }
    if (a == "--verify" && argc >= 3) {
      std::string arg = argv[2];
      VerifyReport r;
      if (arg.rfind("$bitcoin$", 0) == 0)
        r = verify_bitcoin_hash_line(arg);
      else {
        std::ifstream f(arg, std::ios::binary);
        if (f) {
          r = verify_wallet_file(arg);
        } else {
          std::string joined = arg;
          for (int i = 3; i < argc; ++i) {
            joined += " ";
            joined += argv[i];
          }
          if (joined.rfind("$bitcoin$", 0) == 0)
            r = verify_bitcoin_hash_line(joined);
          else
            r = verify_mkey_ckey_text(joined);
        }
      }
      std::fputs(verify_report_text(r).c_str(), stdout);
      return r.verdict == VerifyVerdict::REAL      ? 0
             : r.verdict == VerifyVerdict::SUSPECT ? 1
             : r.verdict == VerifyVerdict::CORRUPT ? 2
                                                   : 3;
    }
    if (a == "--experiment") {
      std::string name = argc >= 3 ? argv[2] : "help";
      std::string log;
      int rc = run_experiment(name, &log);
      std::fputs(log.c_str(), stdout);
      return rc;
    }
    if (a == "--selftest") {
      int device = 0;
      std::string found = "FOUND_WALLET.txt";
      for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == "-d" && i + 1 < argc) device = std::atoi(argv[++i]);
        if (std::string(argv[i]) == "--found" && i + 1 < argc) found = argv[++i];
      }
      std::string log;
      int rc = CrackEngine::run_selftest(device, found, &log);
      std::fputs(log.c_str(), stdout);
      std::string elog;
      int erc = run_experiment("passphrase", &elog);
      std::fputs(elog.c_str(), stdout);
      std::string slog;
      int src = run_experiment("secp", &slog);
      std::fputs(slog.c_str(), stdout);
      return rc | erc | src;
    }
    if (a == "--parse" && argc >= 3) {
      WalletDatParser p;
      auto r = p.parse_file(argv[2]);
      std::puts(WalletDatParser::export_txt(r).c_str());
      std::string out = std::string(argv[2]) + ".twc.txt";
      std::ofstream of(out);
      if (of) {
        of << WalletDatParser::export_txt(r);
        std::printf("[+] wrote %s\n", out.c_str());
      }
      std::string oj = std::string(argv[2]) + ".twc.json";
      std::ofstream jf(oj);
      if (jf) {
        jf << WalletDatParser::export_json(r);
        std::printf("[+] wrote %s\n", oj.c_str());
      }
      WalletDatParser::write_ckeys_file(r, "ckeys_export.txt");
      WalletDatParser::write_mkeys_file(r, "mkeys_export.txt");
      if (r.mkey.found && !r.mkey.salt_hex.empty()) {
        std::string hc = export_bitcoin_hashcat_line(r.mkey);
        if (!hc.empty()) {
          std::printf("[+] hashcat -m 11300:\n%s\n", hc.c_str());
          std::ofstream hf("wallet_hashcat.txt");
          if (hf) hf << hc << "\n";
        }
      }
      return r.ckeys.empty() && !r.mkey.found && r.plain_keys.empty() ? 2 : 0;
    }
    if (a == "--export-hashcat" && argc >= 3) {
      WalletDatParser p;
      auto r = p.parse_file(argv[2]);
      std::string line = export_bitcoin_hashcat_line_extended(r);
      if (line.empty()) {
        std::fprintf(stderr, "[E] no mkey/salt for hashcat export\n");
        return 2;
      }
      std::puts(line.c_str());
      return 0;
    }
    if (a == "--salvage" && argc >= 3) {
      auto rep = salvage_file(argv[2]);
      std::puts(salvage_export_txt(rep).c_str());
      salvage_write_report(rep, std::string(argv[2]) + ".salvage.txt",
                           std::string(argv[2]) + ".salvage.json");
      return rep.ckey_candidates == 0 && rep.mkey_candidates == 0 ? 2 : 0;
    }
    if (a == "--no-gui") {
      usage();
      return 0;
    }
  }

  return RunGuiApp();
}
