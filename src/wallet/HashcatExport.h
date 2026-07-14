#pragma once
#include "WalletDat.h"
#include <string>

/** bitcoin2john / Hashcat -m 11300 line (short form). */
std::string export_bitcoin_hashcat_line(const MasterKeyInfo& mkey);

/** Extended form with first ckey + pubkey when available (John dual-check). */
std::string export_bitcoin_hashcat_line_extended(const WalletParseResult& wallet);

bool write_hashcat_file(const WalletParseResult& wallet, const std::string& path,
                        bool extended = true);

/** Detect hashcat.exe on PATH; returns empty if not found. */
std::string find_hashcat_exe();

/** Optional: spawn hashcat -m 11300 on exported hash (authorized recovery). */
struct HashcatSpawnResult {
  bool launched = false;
  std::string cmdline;
  std::string message;
};
HashcatSpawnResult spawn_hashcat_attack(const std::string& hash_file,
                                        const std::string& wordlist,
                                        const std::string& hashcat_exe = "");
