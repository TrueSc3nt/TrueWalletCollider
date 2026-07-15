#pragma once
/**
 * Derivation path hints (walletsrecovery.org style) for rematerialize / HD recovery.
 * Not a cracker — owner recovery reference table shipped in-app.
 */
#include <string>
#include <vector>

struct DerivationPathHint {
  const char* coin;
  const char* bip;
  const char* path;
  const char* note;
};

inline const DerivationPathHint* derivation_path_table(size_t* count) {
  static const DerivationPathHint kRows[] = {
      {"BTC", "BIP44", "m/44'/0'/0'/0/0", "Legacy P2PKH"},
      {"BTC", "BIP49", "m/49'/0'/0'/0/0", "Nested SegWit P2SH-P2WPKH"},
      {"BTC", "BIP84", "m/84'/0'/0'/0/0", "Native SegWit P2WPKH"},
      {"BTC", "BIP86", "m/86'/0'/0'/0/0", "Taproot P2TR"},
      {"BCH", "BIP44", "m/44'/145'/0'/0/0", "Bitcoin Cash cashaddr / legacy"},
      {"LTC", "BIP44", "m/44'/2'/0'/0/0", "Litecoin legacy"},
      {"LTC", "BIP84", "m/84'/2'/0'/0/0", "Litecoin native SegWit"},
      {"DOGE", "BIP44", "m/44'/3'/0'/0/0", "Dogecoin"},
      {"ETH", "BIP44", "m/44'/60'/0'/0/0", "Ethereum account 0"},
      {"SOL", "BIP44", "m/44'/501'/0'/0'", "Solana (Phantom-style)"},
      {"ATOM", "BIP44", "m/44'/118'/0'/0/0", "Cosmos"},
      {"XRP", "BIP44", "m/44'/144'/0'/0/0", "XRP"},
  };
  if (count) *count = sizeof(kRows) / sizeof(kRows[0]);
  return kRows;
}

inline std::vector<std::string> derivation_hints_for_coin(const std::string& coin_or_family) {
  size_t n = 0;
  const auto* rows = derivation_path_table(&n);
  std::string key = coin_or_family;
  for (char& c : key)
    if (c >= 'a' && c <= 'z') c = (char)(c - 32);
  std::vector<std::string> out;
  auto push_match = [&](const char* needle) {
    for (size_t i = 0; i < n; ++i) {
      if (std::string(rows[i].coin) != needle) continue;
      out.push_back(std::string(rows[i].bip) + " " + rows[i].path + " — " + rows[i].note);
    }
  };
  if (key.find("BTC") != std::string::npos || key.find("BITCOIN") != std::string::npos ||
      key == "CORE" || key.find("CORE FORK") != std::string::npos)
    push_match("BTC");
  if (key.find("BCH") != std::string::npos || key.find("CASH") != std::string::npos)
    push_match("BCH");
  if (key.find("LTC") != std::string::npos || key.find("LITE") != std::string::npos)
    push_match("LTC");
  if (key.find("DOGE") != std::string::npos)
    push_match("DOGE");
  if (key.find("ETH") != std::string::npos || key.find("ETHEREUM") != std::string::npos)
    push_match("ETH");
  if (key.find("SOL") != std::string::npos || key.find("PHANTOM") != std::string::npos)
    push_match("SOL");
  if (out.empty()) {
    push_match("BTC");
    push_match("ETH");
    push_match("SOL");
  }
  return out;
}

inline std::string derivation_paths_markdown() {
  size_t n = 0;
  const auto* rows = derivation_path_table(&n);
  std::string s = "| Coin | BIP | Path | Note |\n|------|-----|------|------|\n";
  for (size_t i = 0; i < n; ++i) {
    s += "| ";
    s += rows[i].coin;
    s += " | ";
    s += rows[i].bip;
    s += " | `";
    s += rows[i].path;
    s += "` | ";
    s += rows[i].note;
    s += " |\n";
  }
  return s;
}
