#include "HashcatExport.h"

#include <cstdio>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

std::string export_bitcoin_hashcat_line(const MasterKeyInfo& mkey) {
  if (!mkey.found || mkey.encrypted_hex.size() < 64 || mkey.salt_hex.size() < 16)
    return {};
  /* bitcoin2john: last two AES blocks (64 hex) of encrypted master */
  std::string cry = mkey.encrypted_hex.size() >= 64
                        ? mkey.encrypted_hex.substr(mkey.encrypted_hex.size() - 64)
                        : mkey.encrypted_hex;
  std::string salt = mkey.salt_hex.substr(0, 16);
  uint32_t iters = mkey.iterations ? mkey.iterations : 25000;
  std::ostringstream o;
  o << "$bitcoin$" << cry.size() << "$" << cry << "$" << salt.size() << "$" << salt << "$"
    << iters << "$2$00$2$00";
  return o.str();
}

std::string export_bitcoin_hashcat_line_extended(const WalletParseResult& wallet) {
  std::string base = export_bitcoin_hashcat_line(wallet.mkey);
  if (base.empty()) return {};
  /* Prefer short form for hashcat -m 11300; extended when ckey+pub present (John). */
  if (wallet.ckeys.empty() || wallet.ckeys[0].encrypted_hex.size() != 96 ||
      wallet.ckeys[0].pubkey_hex.empty())
    return base;
  /* Replace trailing $2$00$2$00 with ckey/pub payloads (John-compatible long form). */
  if (base.size() >= 10 && base.substr(base.size() - 10) == "$2$00$2$00") {
    std::ostringstream o;
    o << base.substr(0, base.size() - 10);
    o << "$96$" << wallet.ckeys[0].encrypted_hex << "$"
      << wallet.ckeys[0].pubkey_hex.size() << "$" << wallet.ckeys[0].pubkey_hex;
    return o.str();
  }
  return base;
}

bool write_hashcat_file(const WalletParseResult& wallet, const std::string& path,
                        bool extended) {
  std::string line =
      extended ? export_bitcoin_hashcat_line_extended(wallet) : export_bitcoin_hashcat_line(wallet.mkey);
  if (line.empty()) return false;
  std::ofstream out(path);
  if (!out) return false;
  out << line << "\n";
  return true;
}

std::string find_hashcat_exe() {
#ifdef _WIN32
  char buf[MAX_PATH];
  DWORD n = SearchPathA(nullptr, "hashcat.exe", nullptr, MAX_PATH, buf, nullptr);
  if (n > 0 && n < MAX_PATH) return buf;
  n = SearchPathA(nullptr, "hashcat", nullptr, MAX_PATH, buf, nullptr);
  if (n > 0 && n < MAX_PATH) return buf;
#else
  FILE* p = popen("command -v hashcat 2>/dev/null", "r");
  if (p) {
    char line[512] = {};
    if (fgets(line, sizeof(line), p)) {
      std::string s = line;
      while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
      pclose(p);
      return s;
    }
    pclose(p);
  }
#endif
  return {};
}

HashcatSpawnResult spawn_hashcat_attack(const std::string& hash_file,
                                        const std::string& wordlist,
                                        const std::string& hashcat_exe) {
  HashcatSpawnResult r;
  std::string exe = hashcat_exe.empty() ? find_hashcat_exe() : hashcat_exe;
  if (exe.empty()) {
    r.message =
        "hashcat.exe not on PATH — export hash file and run manually:\n"
        "  hashcat -m 11300 -a 0 <hashfile> <wordlist>";
    return r;
  }
  std::ostringstream cmd;
  cmd << "\"" << exe << "\" -m 11300 -a 0 \"" << hash_file << "\"";
  if (!wordlist.empty()) cmd << " \"" << wordlist << "\"";
  r.cmdline = cmd.str();
#ifdef _WIN32
  STARTUPINFOA si{};
  PROCESS_INFORMATION pi{};
  si.cb = sizeof(si);
  std::string mutable_cmd = r.cmdline;
  if (CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE,
                     nullptr, nullptr, &si, &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    r.launched = true;
    r.message = "spawned hashcat (new console): " + r.cmdline;
  } else {
    r.message = "CreateProcess failed for: " + r.cmdline;
  }
#else
  r.message = "Run manually: " + r.cmdline;
#endif
  return r;
}
