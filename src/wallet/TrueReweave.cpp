#include "TrueReweave.h"
#include "DerivationPaths.h"

#include <sstream>

std::string truereweave_panel_banner() {
  return "TrueReweave — Inventory & Rematerialize\n"
         "Made by TrueScent · https://t.me/TrueScent\n"
         "FORBIDDEN: Do NOT replace / inject a BIP39 mnemonic into classic Core wallet.dat.\n"
         "Core stores mkey + ckeys (and descriptors) — not BIP39 seeds.\n"
         "After unlock: rematerialize with YOUR new passphrase → WIF / JSON / research mkey export.";
}

TrueReweaveInventory truereweave_inventory(const WalletParseResult& wallet,
                                           const DetectedWallet* multi) {
  TrueReweaveInventory inv;
  inv.title = "TrueReweave inventory";
  inv.honesty =
      "Classic Bitcoin Core / Core-fork wallet.dat typically stores NO BIP39 mnemonic. "
      "Any mnemonic-shaped scraps carved from disk are external residues — not Core key material "
      "to rewrite in-place. Rematerialize = decrypt keys + export; optional new-passphrase mkey.";
  if (multi) {
    inv.records.push_back("detected: " + multi->status_line);
    inv.records.push_back("coin: " + multi->coin_display);
    for (auto& line : multi->inventory) inv.records.push_back(line);
    for (auto& h : multi->derivation_hints) inv.records.push_back("derivation: " + h);
  } else {
    inv.records.push_back("path: " + wallet.path);
    inv.records.push_back("size: " + std::to_string(wallet.file_size));
    inv.records.push_back(wallet.bdb_note);
  }
  inv.records.push_back(std::string("mkey_present: ") + (wallet.mkey.found ? "yes" : "no"));
  if (wallet.mkey.found) {
    inv.records.push_back("mkey_iterations: " + std::to_string(wallet.mkey.iterations));
    inv.records.push_back("mkey_method: " + std::to_string(wallet.mkey.method));
    inv.records.push_back("mkey_salt: " + wallet.mkey.salt_hex);
  }
  inv.records.push_back("ckey_count: " + std::to_string(wallet.ckey_count()));
  for (size_t i = 0; i < wallet.ckeys.size(); ++i) {
    const auto& c = wallet.ckeys[i];
    inv.records.push_back("ckey[" + std::to_string(i) + "] addr=" +
                          (c.address.empty() ? "(none)" : c.address) +
                          " enc_len=" + std::to_string(c.encrypted_hex.size() / 2) +
                          " pub=" + (c.pubkey_hex.empty() ? "no" : "yes"));
  }
  for (const auto& m : wallet.meta)
    inv.records.push_back("meta[" + m.tag + "] @" + std::to_string(m.offset) + " " + m.note);
  for (const auto& w : wallet.warnings) inv.records.push_back("warn: " + w);

  std::ostringstream s;
  s << "records=" << inv.records.size() << " ckeys=" << wallet.ckey_count()
    << " mkey=" << (wallet.mkey.found ? "yes" : "no");
  inv.summary = s.str();
  return inv;
}

TrueReweaveResult truereweave_rematerialize(const uint8_t master32[32],
                                            const WalletParseResult& wallet,
                                            const std::string& new_passphrase,
                                            uint32_t new_iterations) {
  TrueReweaveResult r;
  r.bip39_rewrite_forbidden = true;
  r.inventory = truereweave_inventory(wallet, nullptr);
  r.package = breaker_rebuild(master32, wallet, new_passphrase, new_iterations, true);

  /* Explicit honesty stamp into export bundles */
  std::string forbid =
      "\n--- TrueReweave honesty ---\n"
      "BIP39-in-Core-wallet.dat rewrite: FORBIDDEN / NOT SUPPORTED.\n"
      "This package rematerializes decrypted private keys (WIF/hex) and optionally a research "
      "mkey under your new passphrase. It does not fabricate a BIP39 seed into wallet.dat.\n";
  r.package.txt_bundle += forbid;
  r.package.json_bundle =
      std::string("{\n  \"truereweave\": true,\n  \"bip39_core_rewrite\": \"FORBIDDEN\",\n") +
      "  \"inner\": " + r.package.json_bundle + "\n}\n";
  r.package.new_passphrase_note +=
      " | TrueReweave: BIP39 injection into Core wallet.dat is explicitly forbidden.";
  r.ok = r.package.ok;
  r.message = r.ok ? ("TrueReweave OK — " + std::to_string(r.package.keys.size()) +
                      " keys; BIP39-in-Core rewrite FORBIDDEN (not attempted)")
                   : ("TrueReweave failed: " + r.package.message);
  return r;
}
