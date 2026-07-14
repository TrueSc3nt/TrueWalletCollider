#include "gui/App.h"
#include "crack/CrackEngine.h"
#include "wallet/WalletDat.h"
#include "wallet/Passphrase.h"
#include "crypto/crypto_wallet.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void usage() {
  std::printf(
      "TrueWalletCollider — Bitcoin wallet.dat analyzer + CUDA mkey/ckey cracker\n\n"
      "  TrueWalletCollider.exe              launch GUI\n"
      "  TrueWalletCollider.exe --selftest   GPU+host PoC pipeline\n"
      "  TrueWalletCollider.exe --parse FILE parse wallet.dat → console/export\n"
      "  TrueWalletCollider.exe --cli ...    headless CUDA crack (TrueMkeyCollider flags)\n"
      "\nGUI: drag-drop wallet.dat, export TXT/JSON, CUDA crack panel.\n"
      "CUDA core: embedded TrueMkeyCollider (AES-256 search + auto WIF).\n");
}

int RunHeadlessCli(int argc, char** argv) {
  /* Minimal: --selftest and --parse handled in main; --cli spawns style args */
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
      return rc;
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
      return r.ckeys.empty() && !r.mkey.found ? 2 : 0;
    }
    if (a == "--no-gui") {
      usage();
      return 0;
    }
  }

  /* Default: GUI */
  return RunGuiApp();
}
