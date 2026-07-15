#pragma once
/**
 * Open Any Wallet — multi-format detect + hash extract + crack routing.
 * SHIPPED: Core-family wallet.dat (BTC/BCH/LTC/DOGE + forks), ETH UTC keystore,
 * Electrum, Exodus seed.seco, MetaMask/Phantom LevelDB, Blockchain.com / MultiBit / Wasabi intake.
 */
#include "WalletDat.h"
#include "NativePipelines.h"
#include <string>
#include <vector>

enum class WalletFamily {
  Unknown = 0,
  BitcoinCoreBdb,
  BitcoinCoreSqlite,
  EthereumKeystore,
  Electrum,
  ExodusSeco,
  MetaMaskVault,
  PhantomVault,
  AtomicWallet,
  BlockchainCom,
  MultiBit,
  Wasabi,
  GenericJson,
};

enum class CoinHint {
  Unknown = 0,
  Bitcoin,
  BitcoinCash,
  Litecoin,
  Dogecoin,
  Ethereum,
  Solana,
  CoreFork,
};

struct DetectedWallet {
  WalletFamily family = WalletFamily::Unknown;
  CoinHint coin = CoinHint::Unknown;
  std::string family_name;     /* short enum name */
  std::string label;           /* human: "Bitcoin Core SQLite" */
  std::string status_line;     /* "Detected: …" */
  std::string path;
  std::string coin_display;    /* "Bitcoin" / "Litecoin" / "Core fork" */
  bool is_core_family = false;
  int hashcat_mode = 0;
  std::string hash_line;
  std::string hash_export_path;
  std::string john_hint;
  std::string crack_hint;
  std::vector<std::string> derivation_hints;
  std::vector<std::string> inventory; /* TrueReweave record inventory */
  std::vector<std::string> log;
  std::vector<std::string> warnings;
  WalletParseResult core;
  PipelineReport pipeline;
  bool open_ok = false;
};

const char* wallet_family_cstr(WalletFamily f);
const char* coin_hint_cstr(CoinHint c);

/** Path / content heuristics → coin label (BTC/BCH/LTC/DOGE/Core fork). */
CoinHint infer_coin_from_path(const std::string& path);

/** Fast detect without full parse. */
DetectedWallet detect_wallet_file(const std::string& path);

/**
 * Open Any Wallet: detect → parse/extract → write hash export → fill inventory + derivation hints.
 * Routes Core wallets through WalletDatParser; others through native extractors.
 */
DetectedWallet open_any_wallet(const std::string& path);

/** Write hash line to path (or default). Returns path written. */
std::string write_detected_hash_file(const DetectedWallet& d, const std::string& out_path = "");

/** Spawn Hashcat for detected mode (11300/15600/15700/…); wordlist optional. */
struct MultiHashcatSpawn {
  bool launched = false;
  std::string cmdline;
  std::string message;
};
MultiHashcatSpawn spawn_hashcat_for_detected(const DetectedWallet& d, const std::string& wordlist);

/** Human-readable supported formats list (CLI / README / Lab Docs). */
std::string supported_formats_shipped();
