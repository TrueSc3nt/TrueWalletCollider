#include "gui/App.h"
#include "crack/CrackEngine.h"
#include "wallet/WalletDat.h"
#include "wallet/Passphrase.h"
#include "wallet/HashcatExport.h"
#include "wallet/Experiment.h"
#include "wallet/Salvage.h"
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
      "TrueWalletCollider — Recovery Lab (authorized owner recovery / cryptanalysis R&D)\n\n"
      "  TrueWalletCollider.exe [flags]     launch Recovery Lab GUI\n"
      "  --selftest                         GPU+host PoC AES/WIF pipeline\n"
      "  --parse FILE                       parse wallet.dat → TXT/JSON exports\n"
      "  --export-hashcat FILE              print $bitcoin$ line (hashcat -m 11300)\n"
      "  --salvage FILE                     carve mkey/ckey from damaged dump\n"
      "  --experiment NAME                  research harness (help|dual_fp|passphrase|secp|hashcat_fmt)\n"
      "  --partial-help                     document AES partial-key GPU mode\n\n"
      "Honest scope: passphrase/KDF + dual-verify + salvage + partial AES key.\n"
      "Raw full AES-256 search of unknown keys is research/partial-key only (2^256).\n");
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
    if (a == "--partial-help") {
      std::printf(
          "AES Partial-Key mode (where GPU AES earns its keep)\n"
          "  Known prefix of N bytes → search space 256^(32-N).\n"
          "  GUI: Recovery Lab → AES Partial → enter hex prefix (e.g. 56375875).\n"
          "  CLI (TrueMkeyCollider): --partial HEXPREFIX  (MODE_PARTIAL)\n"
          "  Does NOT claim a break of unknown full AES-256 master keys.\n");
      return 0;
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
      return r.ckeys.empty() && !r.mkey.found ? 2 : 0;
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
