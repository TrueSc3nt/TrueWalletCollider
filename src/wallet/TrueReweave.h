#pragma once
/**
 * TrueReweave — inventory every record + rematerialize under a new passphrase.
 * FORBIDDEN: fake “replace BIP39 mnemonic inside Core wallet.dat”.
 * Classic Core stores keypool/ckeys/mkey — not BIP39 seeds.
 */
#include "WalletDat.h"
#include "BreakerRebuild.h"
#include "WalletFormat.h"
#include <string>
#include <vector>

struct TrueReweaveInventory {
  std::string title;
  std::vector<std::string> records;
  std::string honesty;
  std::string summary;
};

/** Inventory every recoverable record from a Core parse or multi-format open. */
TrueReweaveInventory truereweave_inventory(const WalletParseResult& wallet,
                                          const DetectedWallet* multi = nullptr);

/** Rematerialize after unlock: new passphrase + WIF/descriptor-style export.
 *  Explicitly refuses BIP39 injection into Core wallet.dat. */
struct TrueReweaveResult {
  bool ok = false;
  bool bip39_rewrite_forbidden = true;
  std::string message;
  RebuildPackage package;
  TrueReweaveInventory inventory;
};

TrueReweaveResult truereweave_rematerialize(const uint8_t master32[32],
                                            const WalletParseResult& wallet,
                                            const std::string& new_passphrase,
                                            uint32_t new_iterations = 50000);

std::string truereweave_panel_banner();
