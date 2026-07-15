#include "WalletFormat.h"
#include "DerivationPaths.h"
#include "HashcatExport.h"
#include "ToolBridge.h"
#include "ToolCatalog.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

std::string to_lower(std::string s) {
  for (char& c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}

std::string read_file(const std::string& path, size_t maxn = 64 * 1024 * 1024) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  if (s.size() > maxn) s.resize(maxn);
  return s;
}

bool write_text(const std::string& path, const std::string& body) {
  std::ofstream o(path, std::ios::binary | std::ios::trunc);
  if (!o) return false;
  o.write(body.data(), (std::streamsize)body.size());
  return (bool)o;
}

bool starts_with(const std::string& s, const char* pfx) {
  size_t n = std::strlen(pfx);
  return s.size() >= n && s.compare(0, n, pfx) == 0;
}

std::string json_string_field(const std::string& j, const char* key) {
  std::string needle = std::string("\"") + key + "\"";
  size_t p = j.find(needle);
  if (p == std::string::npos) return {};
  p = j.find(':', p + needle.size());
  if (p == std::string::npos) return {};
  ++p;
  while (p < j.size() && (j[p] == ' ' || j[p] == '\t' || j[p] == '\n' || j[p] == '\r')) ++p;
  if (p >= j.size() || j[p] != '"') return {};
  ++p;
  std::string out;
  for (; p < j.size(); ++p) {
    if (j[p] == '\\' && p + 1 < j.size()) {
      out.push_back(j[p + 1]);
      ++p;
      continue;
    }
    if (j[p] == '"') break;
    out.push_back(j[p]);
  }
  return out;
}

int json_int_field(const std::string& j, const char* key, int def = 0) {
  std::string needle = std::string("\"") + key + "\"";
  size_t p = j.find(needle);
  if (p == std::string::npos) return def;
  p = j.find(':', p + needle.size());
  if (p == std::string::npos) return def;
  ++p;
  while (p < j.size() && !std::isdigit((unsigned char)j[p]) && j[p] != '-') ++p;
  if (p >= j.size()) return def;
  return std::atoi(j.c_str() + p);
}

bool looks_eth_keystore(const std::string& j) {
  std::string low = to_lower(j);
  bool has_crypto = low.find("\"crypto\"") != std::string::npos ||
                    low.find("\"crypto\"") != std::string::npos ||
                    low.find("\"ciphertext\"") != std::string::npos;
  bool has_kdf = low.find("\"kdf\"") != std::string::npos ||
                 low.find("scrypt") != std::string::npos || low.find("pbkdf2") != std::string::npos;
  bool has_mac = low.find("\"mac\"") != std::string::npos;
  return has_crypto && has_kdf && has_mac && j.find('{') != std::string::npos;
}

bool looks_electrum(const std::string& j, const std::string& path) {
  std::string low = to_lower(j);
  std::string pl = to_lower(path);
  return low.find("seed_version") != std::string::npos ||
         low.find("\"wallet_type\"") != std::string::npos ||
         (low.find("keystore") != std::string::npos && low.find("xpub") != std::string::npos) ||
         low.find("electrum") != std::string::npos || pl.find("default_wallet") != std::string::npos ||
         pl.find("electrum") != std::string::npos;
}

bool looks_blockchain_com(const std::string& j) {
  std::string low = to_lower(j);
  return low.find("pbkdf2_iterations") != std::string::npos &&
         (low.find("payload") != std::string::npos || low.find("blockchain") != std::string::npos);
}

bool looks_wasabi(const std::string& j) {
  std::string low = to_lower(j);
  return low.find("encryptedsecret") != std::string::npos ||
         (low.find("wasabi") != std::string::npos && low.find("bitcoin") != std::string::npos) ||
         (low.find("masterfingerprint") != std::string::npos &&
          low.find("extpub") != std::string::npos);
}

bool looks_multibit(const std::string& blob, const std::string& path) {
  std::string pl = to_lower(path);
  if (pl.find(".wallet") != std::string::npos && pl.find("multibit") != std::string::npos)
    return true;
  if (pl.size() >= 7 && pl.substr(pl.size() - 7) == ".wallet") {
    /* MultiBit Classic often starts with specific protobuf / encrypted markers */
    if (blob.size() >= 8 && (unsigned char)blob[0] == 0x0a) return true;
  }
  return pl.find("multibit") != std::string::npos;
}

bool is_sqlite(const std::string& blob) {
  return blob.size() >= 15 && blob.compare(0, 15, "SQLite format 3") == 0;
}

bool is_bdb_magic(const std::string& blob) {
  if (blob.size() < 20) return false;
  static const unsigned char kMagic[8] = {0x62, 0x31, 0x05, 0x00, 0x09, 0x00, 0x00, 0x00};
  return std::memcmp(blob.data() + 12, kMagic, 8) == 0;
}

bool has_core_key_markers(const std::string& blob) {
  return blob.find("mkey") != std::string::npos || blob.find("ckey") != std::string::npos ||
         blob.find("keymeta") != std::string::npos || blob.find("walletdescriptor") != std::string::npos;
}

std::string extract_eth_hash(const std::string& j, int* mode_out) {
  std::string ciphertext = json_string_field(j, "ciphertext");
  std::string mac = json_string_field(j, "mac");
  std::string salt = json_string_field(j, "salt");
  std::string kdf = to_lower(json_string_field(j, "kdf"));
  if (ciphertext.empty() || mac.empty() || salt.empty()) {
    /* nested crypto block — search entire file still works for flat string find */
  }
  if (ciphertext.empty()) ciphertext = json_string_field(j, "CipherText");
  if (kdf.empty()) {
    if (j.find("scrypt") != std::string::npos) kdf = "scrypt";
    else if (j.find("pbkdf2") != std::string::npos) kdf = "pbkdf2";
  }
  if (ciphertext.empty() || mac.empty() || salt.empty()) return {};

  if (kdf.find("scrypt") != std::string::npos) {
    int n = json_int_field(j, "n", 262144);
    int r = json_int_field(j, "r", 8);
    int p = json_int_field(j, "p", 1);
    if (mode_out) *mode_out = 15700;
    std::ostringstream o;
    o << "$ethereum$s*" << n << "*" << r << "*" << p << "*" << salt << "*" << mac << "*"
      << ciphertext;
    return o.str();
  }
  /* pbkdf2 */
  int c = json_int_field(j, "c", 262144);
  if (c <= 0) c = 262144;
  if (mode_out) *mode_out = 15600;
  std::ostringstream o;
  o << "$ethereum$p*" << c << "*" << salt << "*" << mac << "*" << ciphertext;
  return o.str();
}

std::string extract_electrum_hash(const std::string& j, int* mode_out) {
  /* Prefer modern salt-types 4/5 (21700/21800) when ciphertext-like hex present. */
  std::string seed = json_string_field(j, "seed");
  std::string xprv = json_string_field(j, "xprv");
  std::string enc = seed.empty() ? xprv : seed;
  bool use_enc = j.find("\"use_encryption\": true") != std::string::npos ||
                 j.find("\"use_encryption\":true") != std::string::npos;
  int seed_version = json_int_field(j, "seed_version", 0);

  int mode = 16600;
  if (seed_version >= 17 || j.find("\"type\": \"bip32\"") != std::string::npos)
    mode = use_enc ? 21800 : 21700;
  if (mode_out) *mode_out = mode;

  if (!enc.empty() && enc.size() >= 16) {
    std::ostringstream o;
    if (mode == 16600)
      o << "$electrum$1*" << enc;
    else if (mode == 21700)
      o << "$electrum$4*" << enc;
    else
      o << "$electrum$5*" << enc;
    return o.str();
  }
  return {};
}

std::string extract_metamask_hash(const std::string& vault_json, int* mode_out) {
  std::string data = json_string_field(vault_json, "data");
  std::string iv = json_string_field(vault_json, "iv");
  std::string salt = json_string_field(vault_json, "salt");
  if (data.empty() || iv.empty() || salt.empty()) return {};
  int iters = json_int_field(vault_json, "iterations", 10000);
  /* 26620 = dynamic PBKDF2 iters; 26600 = fixed classic */
  if (iters != 10000 && iters > 0) {
    if (mode_out) *mode_out = 26620;
    std::ostringstream o;
    o << "$metamask-short$*" << salt << "*" << iters << "*" << iv << "*" << data;
    return o.str();
  }
  if (mode_out) *mode_out = 26600;
  std::ostringstream o;
  o << "$metamask$*" << salt << "*" << iv << "*" << data;
  return o.str();
}

void fill_derivation(DetectedWallet& d) {
  d.derivation_hints = derivation_hints_for_coin(d.coin_display.empty() ? d.label : d.coin_display);
}

void inventory_core(DetectedWallet& d) {
  d.inventory.push_back("path: " + d.path);
  d.inventory.push_back("family: " + d.label);
  d.inventory.push_back("coin: " + d.coin_display);
  d.inventory.push_back(std::string("storage: ") +
                        (d.family == WalletFamily::BitcoinCoreSqlite ? "SQLite" : "BDB"));
  d.inventory.push_back("mkey: " + std::string(d.core.mkey.found ? "yes" : "no") +
                        (d.core.mkey.found ? (" iters=" + std::to_string(d.core.mkey.iterations))
                                           : ""));
  d.inventory.push_back("ckeys: " + std::to_string(d.core.ckey_count()));
  d.inventory.push_back("meta_hits: " + std::to_string(d.core.meta.size()));
  d.inventory.push_back(
      "FORBIDDEN: do not inject / rewrite BIP39 mnemonic into Core wallet.dat "
      "(classic Core never stored BIP39). Use TrueReweave rematerialize → WIF/JSON export.");
}

}  // namespace

const char* wallet_family_cstr(WalletFamily f) {
  switch (f) {
    case WalletFamily::BitcoinCoreBdb: return "BitcoinCoreBdb";
    case WalletFamily::BitcoinCoreSqlite: return "BitcoinCoreSqlite";
    case WalletFamily::EthereumKeystore: return "EthereumKeystore";
    case WalletFamily::Electrum: return "Electrum";
    case WalletFamily::ExodusSeco: return "ExodusSeco";
    case WalletFamily::MetaMaskVault: return "MetaMaskVault";
    case WalletFamily::PhantomVault: return "PhantomVault";
    case WalletFamily::AtomicWallet: return "AtomicWallet";
    case WalletFamily::BlockchainCom: return "BlockchainCom";
    case WalletFamily::MultiBit: return "MultiBit";
    case WalletFamily::Wasabi: return "Wasabi";
    case WalletFamily::GenericJson: return "GenericJson";
    default: return "Unknown";
  }
}

const char* coin_hint_cstr(CoinHint c) {
  switch (c) {
    case CoinHint::Bitcoin: return "Bitcoin";
    case CoinHint::BitcoinCash: return "Bitcoin Cash";
    case CoinHint::Litecoin: return "Litecoin";
    case CoinHint::Dogecoin: return "Dogecoin";
    case CoinHint::Ethereum: return "Ethereum";
    case CoinHint::Solana: return "Solana";
    case CoinHint::CoreFork: return "Core fork";
    default: return "Unknown";
  }
}

CoinHint infer_coin_from_path(const std::string& path) {
  std::string pl = to_lower(path);
  if (pl.find("bitcoincash") != std::string::npos || pl.find("\\bch\\") != std::string::npos ||
      pl.find("/bch/") != std::string::npos || pl.find("bitcoin cash") != std::string::npos)
    return CoinHint::BitcoinCash;
  if (pl.find("litecoin") != std::string::npos || pl.find("\\ltc\\") != std::string::npos)
    return CoinHint::Litecoin;
  if (pl.find("dogecoin") != std::string::npos || pl.find("\\doge\\") != std::string::npos)
    return CoinHint::Dogecoin;
  if (pl.find("ethereum") != std::string::npos || pl.find("keystore") != std::string::npos ||
      pl.find("\\eth\\") != std::string::npos)
    return CoinHint::Ethereum;
  if (pl.find("phantom") != std::string::npos || pl.find("solana") != std::string::npos)
    return CoinHint::Solana;
  if (pl.find("bitcoin") != std::string::npos || pl.find("\\btc\\") != std::string::npos)
    return CoinHint::Bitcoin;
  /* dateless Core dat often BTC; unknown path → Core fork label when markers present */
  if (pl.find("wallet.dat") != std::string::npos) return CoinHint::Bitcoin;
  return CoinHint::Unknown;
}

DetectedWallet detect_wallet_file(const std::string& path) {
  DetectedWallet d;
  d.path = path;
  std::string blob = read_file(path, 8 * 1024 * 1024);
  if (blob.empty()) {
    /* may be a directory (LevelDB) */
#ifdef _WIN32
    DWORD a = GetFileAttributesA(path.c_str());
    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) {
      std::string pl = to_lower(path);
      if (pl.find("nkbihfbeogaeaoehlefnkodbefgpgknn") != std::string::npos ||
          pl.find("metamask") != std::string::npos) {
        d.family = WalletFamily::MetaMaskVault;
        d.label = "MetaMask LevelDB vault";
        d.status_line = "Detected: MetaMask LevelDB";
        d.coin = CoinHint::Ethereum;
        d.coin_display = "Ethereum";
        d.hashcat_mode = 26620;
        return d;
      }
      if (pl.find("bfnaelmomeimhlpmgjnjophhpkkoljpa") != std::string::npos ||
          pl.find("phantom") != std::string::npos) {
        d.family = WalletFamily::PhantomVault;
        d.label = "Phantom LevelDB vault";
        d.status_line = "Detected: Phantom LevelDB";
        d.coin = CoinHint::Solana;
        d.coin_display = "Solana";
        return d;
      }
      if (pl.find("atomic") != std::string::npos) {
        d.family = WalletFamily::AtomicWallet;
        d.label = "Atomic Wallet LevelDB";
        d.status_line = "Detected: Atomic Wallet";
        return d;
      }
    }
#endif
    d.warnings.push_back("cannot read path");
    d.status_line = "Detected: Unknown (unreadable)";
    return d;
  }

  std::string pl = to_lower(path);
  CoinHint path_coin = infer_coin_from_path(path);

  /* Exodus */
  if (pl.find(".seco") != std::string::npos || starts_with(blob, "SECO") ||
      (blob.size() > 4 && blob[0] == 'S' && blob[1] == 'E' && blob[2] == 'C' && blob[3] == 'O')) {
    d.family = WalletFamily::ExodusSeco;
    d.label = "Exodus seed.seco";
    d.status_line = "Detected: Exodus seed.seco";
    d.hashcat_mode = 28200;
    d.coin_display = "Multi-asset (Exodus)";
    return d;
  }

  /* ETH keystore JSON */
  if ((pl.find("utc--") != std::string::npos || pl.find("keystore") != std::string::npos ||
       blob.find("\"ciphertext\"") != std::string::npos) &&
      looks_eth_keystore(blob)) {
    d.family = WalletFamily::EthereumKeystore;
    d.label = "Ethereum UTC keystore";
    d.status_line = "Detected: Ethereum Keystore";
    d.coin = CoinHint::Ethereum;
    d.coin_display = "Ethereum";
    d.hashcat_mode = 15700; /* refined on open */
    return d;
  }

  /* Electrum */
  if (looks_electrum(blob, path)) {
    d.family = WalletFamily::Electrum;
    d.label = "Electrum family wallet";
    d.status_line = "Detected: Electrum";
    d.coin = path_coin != CoinHint::Unknown ? path_coin : CoinHint::Bitcoin;
    d.coin_display = coin_hint_cstr(d.coin);
    d.hashcat_mode = 21800;
    return d;
  }

  /* Blockchain.com */
  if (looks_blockchain_com(blob) || pl.find("blockchain.com") != std::string::npos ||
      (pl.find("wallet.aes.json") != std::string::npos)) {
    d.family = WalletFamily::BlockchainCom;
    d.label = "Blockchain.com wallet JSON";
    d.status_line = "Detected: Blockchain.com";
    d.coin_display = "Bitcoin";
    return d;
  }

  /* Wasabi */
  if (looks_wasabi(blob) || pl.find("wasabi") != std::string::npos) {
    d.family = WalletFamily::Wasabi;
    d.label = "Wasabi Wallet JSON";
    d.status_line = "Detected: Wasabi";
    d.coin = CoinHint::Bitcoin;
    d.coin_display = "Bitcoin";
    return d;
  }

  /* MultiBit */
  if (looks_multibit(blob, path)) {
    d.family = WalletFamily::MultiBit;
    d.label = "MultiBit wallet";
    d.status_line = "Detected: MultiBit";
    d.coin = CoinHint::Bitcoin;
    d.coin_display = "Bitcoin";
    return d;
  }

  /* Core BDB / SQLite wallet.dat (and forks) */
  bool sqlite = is_sqlite(blob);
  bool bdb = is_bdb_magic(blob);
  bool markers = has_core_key_markers(blob);
  if (sqlite || bdb || markers || pl.find("wallet.dat") != std::string::npos ||
      (pl.size() >= 4 && pl.substr(pl.size() - 4) == ".dat")) {
    d.is_core_family = true;
    d.family = sqlite ? WalletFamily::BitcoinCoreSqlite : WalletFamily::BitcoinCoreBdb;
    d.coin = path_coin;
    if (d.coin == CoinHint::Unknown && markers) d.coin = CoinHint::CoreFork;
    if (d.coin == CoinHint::Unknown) d.coin = CoinHint::Bitcoin;
    d.coin_display = coin_hint_cstr(d.coin);
    if (d.coin == CoinHint::Bitcoin)
      d.label = sqlite ? "Bitcoin Core SQLite" : "Bitcoin Core BDB";
    else if (d.coin == CoinHint::BitcoinCash)
      d.label = sqlite ? "Bitcoin Cash Core SQLite" : "Bitcoin Cash Core BDB";
    else if (d.coin == CoinHint::Litecoin)
      d.label = sqlite ? "Litecoin Core SQLite" : "Litecoin Core BDB";
    else if (d.coin == CoinHint::Dogecoin)
      d.label = sqlite ? "Dogecoin Core SQLite" : "Dogecoin Core BDB";
    else
      d.label = sqlite ? "Core fork SQLite wallet.dat" : "Core fork BDB wallet.dat";
    d.status_line = "Detected: " + d.label;
    d.hashcat_mode = 11300;
    return d;
  }

  /* Generic JSON vault-ish */
  if (blob.find('{') != std::string::npos &&
      (blob.find("\"data\"") != std::string::npos && blob.find("\"iv\"") != std::string::npos)) {
    d.family = WalletFamily::MetaMaskVault;
    d.label = "Browser vault JSON (MetaMask-style)";
    d.status_line = "Detected: MetaMask-style vault JSON";
    d.hashcat_mode = 26600;
    d.coin = CoinHint::Ethereum;
    d.coin_display = "Ethereum";
    return d;
  }

  d.family = WalletFamily::Unknown;
  d.label = "Unknown / unrecognized";
  d.status_line = "Detected: Unknown";
  d.warnings.push_back("format not recognized — try Tool Bay orchestrator");
  return d;
}

DetectedWallet open_any_wallet(const std::string& path) {
  DetectedWallet d = detect_wallet_file(path);
  d.family_name = wallet_family_cstr(d.family);
  d.log.push_back(d.status_line);
  fill_derivation(d);

  switch (d.family) {
    case WalletFamily::BitcoinCoreBdb:
    case WalletFamily::BitcoinCoreSqlite: {
      WalletDatParser parser;
      d.core = parser.parse_file(path);
      d.is_core_family = true;
      d.open_ok = d.core.mkey.found || !d.core.ckeys.empty() || d.core.magic_ok ||
                  !d.core.log.empty();
      /* annotate storage in parse note */
      if (d.family == WalletFamily::BitcoinCoreSqlite)
        d.core.bdb_note = d.label + " — same crypto as BTC ($bitcoin$ / Hashcat 11300)";
      else if (d.core.bdb_note.find("magic OK") != std::string::npos)
        d.core.bdb_note = d.label + " — " + d.core.bdb_note;
      else
        d.core.bdb_note = d.label + " — " + d.core.bdb_note;
      d.core.log.insert(d.core.log.begin(), d.status_line);
      if (d.core.mkey.found && !d.core.mkey.salt_hex.empty()) {
        d.hash_line = export_bitcoin_hashcat_line_extended(d.core);
        d.hashcat_mode = 11300;
        d.hash_export_path = "wallet_hash_11300.txt";
        write_text(d.hash_export_path, d.hash_line + "\n");
        d.john_hint = "john --format=bitcoin " + d.hash_export_path;
        d.crack_hint = "Hashcat -m 11300 | John bitcoin | Passphrase Lab | Breaker Lab — coin label "
                       "does not change KDF (BTC/BCH/LTC/DOGE Core forks share wallet crypto).";
        d.log.push_back("[+] wrote " + d.hash_export_path);
      }
      inventory_core(d);
      for (auto& L : d.core.log) d.log.push_back(L);
      break;
    }
    case WalletFamily::EthereumKeystore: {
      std::string j = read_file(path);
      int mode = 15600;
      d.hash_line = extract_eth_hash(j, &mode);
      d.hashcat_mode = mode;
      d.hash_export_path = mode == 15700 ? "eth_hash_15700.txt" : "eth_hash_15600.txt";
      if (!d.hash_line.empty()) {
        write_text(d.hash_export_path, d.hash_line + "\n");
        d.open_ok = true;
        d.crack_hint = "Hashcat -m " + std::to_string(mode) + " (ETH keystore). Pre-sale → 16300.";
        d.log.push_back("[+] ETH hash export → " + d.hash_export_path);
      } else {
        d.warnings.push_back("keystore JSON found but hash fields incomplete");
        d.crack_hint = "Validate UTC JSON; Hashcat 15600/15700/16300; BTCRecover ethereum.";
      }
      d.inventory.push_back("path: " + path);
      d.inventory.push_back("format: Ethereum UTC keystore");
      d.inventory.push_back("hashcat_mode: " + std::to_string(d.hashcat_mode));
      d.pipeline = PipelineReport{};
      d.pipeline.ok = d.open_ok;
      d.pipeline.summary = d.status_line;
      d.pipeline.hashcat_hint = d.crack_hint;
      d.pipeline.export_path = d.hash_export_path;
      break;
    }
    case WalletFamily::Electrum: {
      d.pipeline = pipeline_electrum_helper(path);
      std::string j = read_file(path);
      int mode = 16600;
      d.hash_line = extract_electrum_hash(j, &mode);
      d.hashcat_mode = mode;
      d.hash_export_path = "electrum_hash.txt";
      if (!d.hash_line.empty()) {
        write_text(d.hash_export_path, d.hash_line + "\n");
        d.open_ok = true;
        d.log.push_back("[+] Electrum hash candidate → " + d.hash_export_path + " mode " +
                        std::to_string(mode));
      } else {
        /* still first-class: write wallet copy hint + mode tips */
        write_text("electrum_wallet_intake.txt", j.substr(0, (std::min)(j.size(), (size_t)256000)));
        d.hash_export_path = "electrum_wallet_intake.txt";
        d.open_ok = d.pipeline.ok;
        d.log.push_back("[+] Electrum intake copy → electrum_wallet_intake.txt (use "
                        "electrum2john / BTCRecover extract for exact mode)");
      }
      d.crack_hint = "Hashcat -m 16600 / 21700 / 21800; BTCRecover --wallet Electrum; John "
                     "electrum.";
      d.inventory.push_back("path: " + path);
      d.inventory.push_back("format: Electrum family");
      d.inventory.push_back("suggested_mode: " + std::to_string(d.hashcat_mode));
      break;
    }
    case WalletFamily::ExodusSeco: {
      d.pipeline = pipeline_exodus_seco(path);
      d.hashcat_mode = 28200;
      d.open_ok = d.pipeline.ok;
      d.crack_hint =
          "python third_party/hashcat/tools/exodus2hashcat.py \"" + path +
          "\" > exodus_hash.txt && hashcat -m 28200 exodus_hash.txt wordlist.txt";
      /* Try bundled python + exodus2hashcat if present */
#ifdef _WIN32
      std::string py = "third_party\\python\\python.exe";
      std::string script = "third_party\\hashcat\\tools\\exodus2hashcat.py";
      std::ifstream a(py), b(script);
      if (a && b) {
        std::string cmd = "\"" + py + "\" \"" + script + "\" \"" + path + "\" > exodus_hash_28200.txt 2>nul";
        int rc = std::system(cmd.c_str());
        (void)rc;
        std::string hash = read_file("exodus_hash_28200.txt", 4096);
        if (!hash.empty() && hash.find("$") != std::string::npos) {
          d.hash_line = hash;
          while (!d.hash_line.empty() &&
                 (d.hash_line.back() == '\n' || d.hash_line.back() == '\r'))
            d.hash_line.pop_back();
          d.hash_export_path = "exodus_hash_28200.txt";
          d.log.push_back("[+] exodus2hashcat → exodus_hash_28200.txt");
        }
      }
#endif
      d.inventory.push_back("path: " + path);
      d.inventory.push_back("format: Exodus seed.seco");
      d.inventory.push_back("hashcat_mode: 28200");
      break;
    }
    case WalletFamily::MetaMaskVault: {
      d.pipeline = pipeline_metamask_leveldb(path);
      d.hashcat_mode = 26620;
      d.open_ok = d.pipeline.ok;
      /* Prefer first vault blob for hash export */
      std::string vault_src = read_file(d.pipeline.export_path.empty() ? path : d.pipeline.export_path,
                                        2 * 1024 * 1024);
      if (vault_src.empty()) vault_src = read_file(path, 2 * 1024 * 1024);
      int mode = 26600;
      /* find first { ... } vault */
      size_t brace = vault_src.find('{');
      if (brace != std::string::npos) {
        int depth = 0;
        size_t j = brace;
        for (; j < vault_src.size(); ++j) {
          if (vault_src[j] == '{') ++depth;
          else if (vault_src[j] == '}') {
            --depth;
            if (depth == 0) {
              ++j;
              break;
            }
          }
        }
        std::string chunk = vault_src.substr(brace, j - brace);
        d.hash_line = extract_metamask_hash(chunk, &mode);
        d.hashcat_mode = mode;
        if (!d.hash_line.empty()) {
          d.hash_export_path = "metamask_hash_" + std::to_string(mode) + ".txt";
          write_text(d.hash_export_path, d.hash_line + "\n");
          d.log.push_back("[+] MetaMask hash → " + d.hash_export_path);
          d.open_ok = true;
        }
      }
      d.crack_hint = "Hashcat -m 26600 / 26620; third_party/metamask_pwn; BTCRecover MetaMask.";
      d.inventory.push_back("path: " + path);
      d.inventory.push_back("format: MetaMask LevelDB / vault");
      d.inventory.push_back("hits: " + std::to_string(d.pipeline.hits.size()));
      break;
    }
    case WalletFamily::PhantomVault: {
      d.pipeline = pipeline_metamask_leveldb(path); /* same LevelDB vault scan */
      d.open_ok = d.pipeline.ok || true;
      d.crack_hint =
          "Phantom LevelDB — use Tool Bay Phantom pipeline / MMKV research; SOL path m/44'/501'.";
      write_text("phantom_intake_note.txt",
                 "Detected Phantom LevelDB.\n" + d.pipeline.summary + "\n" + d.crack_hint + "\n");
      d.hash_export_path = "phantom_intake_note.txt";
      d.inventory.push_back("path: " + path);
      d.inventory.push_back("format: Phantom");
      d.coin = CoinHint::Solana;
      d.coin_display = "Solana";
      fill_derivation(d);
      break;
    }
    case WalletFamily::AtomicWallet: {
      d.pipeline = pipeline_metamask_leveldb(path);
      d.open_ok = true;
      d.crack_hint = "Atomic Wallet LevelDB — see Tool Bay Atomic entries; export vault scraps.";
      d.inventory.push_back("Atomic wallet path: " + path);
      break;
    }
    case WalletFamily::BlockchainCom: {
      std::string j = read_file(path);
      write_text("blockchain_com_intake.json", j.substr(0, (std::min)(j.size(), (size_t)512000)));
      d.hash_export_path = "blockchain_com_intake.json";
      d.open_ok = true;
      d.hashcat_mode = 12700; /* Blockchain.com My Wallet — if applicable */
      d.crack_hint = "Blockchain.com JSON intake — Hashcat -m 12700 / BTCRecover blockchain.com extract.";
      d.inventory.push_back("Blockchain.com wallet JSON copied to blockchain_com_intake.json");
      break;
    }
    case WalletFamily::MultiBit: {
      d.open_ok = true;
      d.crack_hint = "MultiBit — Hashcat -m 22500 (MultiBit HD) / BTCRecover multibit; copy wallet retained.";
      d.hashcat_mode = 22500;
      d.inventory.push_back("MultiBit path: " + path);
      break;
    }
    case WalletFamily::Wasabi: {
      std::string j = read_file(path);
      write_text("wasabi_intake.json", j.substr(0, (std::min)(j.size(), (size_t)512000)));
      d.hash_export_path = "wasabi_intake.json";
      d.open_ok = true;
      d.crack_hint = "Wasabi JSON intake — encrypted secret field; BTCRecover / research modes.";
      d.inventory.push_back("Wasabi wallet copied to wasabi_intake.json");
      break;
    }
    default: {
      /* Avoid recurse with pipeline_orchestrate_intake (which calls open_any_wallet). */
      auto rec = tool_catalog_recommend(path);
      std::ostringstream o;
      o << "Unrecognized — Tool Bay tips:";
      for (auto& id : rec) o << " " << id;
      d.crack_hint = o.str();
      d.log.push_back(d.crack_hint);
      /* Cheap probes */
      auto mm = pipeline_metamask_leveldb(path);
      if (mm.ok) {
        d.pipeline = mm;
        d.family = WalletFamily::MetaMaskVault;
        d.label = "MetaMask-like (probe)";
        d.status_line = "Detected: MetaMask-like vault";
        d.open_ok = true;
        d.hashcat_mode = 26620;
        d.crack_hint = mm.hashcat_hint;
      }
      break;
    }
  }

  if (d.derivation_hints.empty()) fill_derivation(d);
  d.log.push_back("[*] " + d.crack_hint);
  return d;
}

std::string write_detected_hash_file(const DetectedWallet& d, const std::string& out_path) {
  std::string path = out_path.empty() ? d.hash_export_path : out_path;
  if (path.empty()) path = "open_any_wallet_hash.txt";
  if (!d.hash_line.empty()) {
    write_text(path, d.hash_line + "\n");
    return path;
  }
  if (!d.hash_export_path.empty()) return d.hash_export_path;
  return {};
}

MultiHashcatSpawn spawn_hashcat_for_detected(const DetectedWallet& d, const std::string& wordlist) {
  MultiHashcatSpawn r;
  if (d.hashcat_mode <= 0) {
    r.message = "no Hashcat mode for this format — see crack_hint: " + d.crack_hint;
    return r;
  }
  std::string hashfile = d.hash_export_path;
  if (hashfile.empty() || d.hash_line.empty()) {
    if (!d.hash_line.empty()) {
      hashfile = "open_any_mode_" + std::to_string(d.hashcat_mode) + ".txt";
      write_text(hashfile, d.hash_line + "\n");
    } else {
      r.message = "no hash line exported yet — Open Any Wallet first";
      return r;
    }
  }
  std::string exe = find_hashcat_exe();
  if (exe.empty()) {
    r.message = "hashcat not found. Manual:\n  hashcat -m " + std::to_string(d.hashcat_mode) +
                " -a 0 \"" + hashfile + "\" <wordlist>";
    return r;
  }
  std::ostringstream cmd;
  cmd << "\"" << exe << "\" -m " << d.hashcat_mode << " -a 0 \"" << hashfile << "\"";
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
    r.message = "spawned: " + r.cmdline;
  } else {
    r.message = "CreateProcess failed: " + r.cmdline;
  }
#else
  r.message = "Run: " + r.cmdline;
#endif
  return r;
}

std::string supported_formats_shipped() {
  return
      "Supported formats (SHIPPED — Open Any Wallet / Detect):\n"
      "  • Bitcoin Core wallet.dat — BDB + SQLite (Hashcat 11300 / $bitcoin$)\n"
      "  • Bitcoin Cash / Litecoin / Dogecoin / other Core forks — same wallet.dat crypto\n"
      "  • Ethereum UTC keystore JSON — Hashcat 15600 / 15700 (/ 16300 pre-sale)\n"
      "  • Electrum family — Hashcat 16600 / 21700 / 21800 + BTCRecover\n"
      "  • Exodus seed.seco — Hashcat 28200 (exodus2hashcat)\n"
      "  • MetaMask LevelDB vault — Hashcat 26600 / 26620\n"
      "  • Phantom / Atomic LevelDB — intake + Tool Bay pipelines\n"
      "  • Blockchain.com wallet JSON — intake + Hashcat 12700 bridge\n"
      "  • MultiBit — Hashcat 22500 bridge\n"
      "  • Wasabi Wallet JSON — intake\n"
      "Derivation hints: BTC BIP44/49/84/86, ETH 60', SOL 501' (walletsrecovery.org style).\n"
      "TrueReweave: inventory + rematerialize with new passphrase / WIF — FORBIDDEN to fake "
      "BIP39 rewrite inside Core wallet.dat.\n";
}
