#include "BreakerRebuild.h"
#include "Passphrase.h"
#include "Salvage.h"
#include "ForensicTools.h"
#include "HashcatExport.h"
#include "CpuSimd.h"
#include "../crypto/crypto_wallet.h"
#include "../crypto/secp256k1_lite.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {
static std::string to_hex(const uint8_t* p, size_t n) {
  static const char* H = "0123456789abcdef";
  std::string s(n * 2, '0');
  for (size_t i = 0; i < n; ++i) {
    s[i * 2] = H[p[i] >> 4];
    s[i * 2 + 1] = H[p[i] & 0xf];
  }
  return s;
}
static bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out) {
  out.clear();
  if (hex.size() % 2) return false;
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    auto nib = [](char c) {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int a = nib(hex[i]), b = nib(hex[i + 1]);
    if (a < 0 || b < 0) return false;
    out.push_back((uint8_t)((a << 4) | b));
  }
  return true;
}

static bool looks_like_mnemonic_window(const std::string& s) {
  int spaces = 0;
  for (char c : s)
    if (c == ' ') ++spaces;
  return spaces >= 11 && spaces <= 23;
}
}  // namespace

CarveReport breaker_carve(const uint8_t* data, size_t len, const WalletParseResult* parsed_opt) {
  CarveReport r;
  r.classic_core_has_no_bip39 = true;

  if (parsed_opt) {
    if (parsed_opt->mkey.found) r.mkeys.push_back(parsed_opt->mkey);
    r.ckeys = parsed_opt->ckeys;
  }
  if (data && len) {
    auto salv = salvage_carve(data, len, "(carve)");
    for (auto& m : salv.mkeys) {
      bool dup = false;
      for (auto& e : r.mkeys)
        if (e.encrypted_hex == m.encrypted_hex) {
          dup = true;
          break;
        }
      if (!dup) r.mkeys.push_back(m);
    }
    for (auto& c : salv.ckeys_ranked) {
      bool dup = false;
      for (auto& e : r.ckeys)
        if (e.encrypted_hex == c.ckey.encrypted_hex) {
          dup = true;
          break;
        }
      if (!dup) r.ckeys.push_back(c.ckey);
    }

    auto hits = strings_scavenge(data, len, 20, 800);
    for (auto& h : hits) {
      if (!looks_like_mnemonic_window(h.text)) continue;
      MnemonicCarveHit mh;
      mh.offset = h.offset;
      mh.text = h.text;
      auto bip = bip39_validate_mnemonic(h.text);
      mh.word_count = bip.word_count;
      mh.bip39_checksum_ok = bip.checksum_ok;
      if (bip.ok) {
        mh.note = "BIP39 checksum OK â€” likely seed scrap (NOT typical Core wallet.dat storage)";
        r.classic_core_has_no_bip39 = false;
      } else if (bip.word_count == 12 || bip.word_count == 24) {
        mh.note = "mnemonic-shaped string; BIP39 checksum FAIL or unknown words";
      } else {
        mh.note = "space-separated words; may be Electrum/other â€” not validated as BIP39";
      }
      r.mnemonics.push_back(mh);
      if (r.mnemonics.size() >= 32) break;
    }
  }

  std::ostringstream s;
  s << "Carve: mkeys=" << r.mkeys.size() << " ckeys=" << r.ckeys.size()
    << " mnemonic_candidates=" << r.mnemonics.size() << "\n";
  if (r.classic_core_has_no_bip39 && r.mnemonics.empty()) {
    s << "Honesty: classic Bitcoin Core wallet.dat typically stores NO BIP39 mnemonic â€” "
         "none found in this sample.\n";
  } else if (!r.mnemonics.empty()) {
    s << "Found mnemonic-looking scrap(s) â€” may be from descriptors/import/user scrap, "
         "not Core's native key storage.\n";
  }
  r.summary = s.str();
  return r;
}

OrchestratorReport breaker_orchestrate(const WalletParseResult& wallet,
                                       const std::vector<uint8_t>& raw,
                                       const OrchestratorOptions& opt,
                                       ProcessStreamer* hashcat_stream,
                                       ProcessStreamer* btc_stream) {
  OrchestratorReport rep;
  auto& cpu = cpu_simd_detect();
  std::ostringstream log;
  log << "=== TrueScent Breaker Orchestrator ===\n";
  log << cpu.status_line << "\n";
  log << "CPU path=" << (opt.use_cpu ? "on" : "off") << " GPU path=" << (opt.use_gpu ? "on" : "off")
      << "\n";

  auto push = [&](BreakStrategy st, const char* name, bool ran, bool hit, const std::string& d) {
    OrchestratorStepResult s;
    s.strategy = st;
    s.name = name;
    s.ran = ran;
    s.hit = hit;
    s.detail = d;
    rep.steps.push_back(s);
    log << "[" << (hit ? "HIT" : ran ? "ok" : "skip") << "] " << name << " â€” " << d << "\n";
  };

  if (opt.do_verify) {
    rep.verify = verify_parsed_wallet(wallet);
    push(BreakStrategy::Verify, "Verify", true, rep.verify.verdict == VerifyVerdict::REAL,
         rep.verify.summary);
  }

  if (opt.do_carve) {
    rep.carve = breaker_carve(raw.empty() ? nullptr : raw.data(), raw.size(), &wallet);
    push(BreakStrategy::Carve, "Carve", true, !rep.carve.mnemonics.empty() && !rep.carve.classic_core_has_no_bip39,
         rep.carve.summary);
  }

  if (opt.do_native_kdf && opt.use_cpu && wallet.mkey.found) {
    std::vector<std::string> cands = opt.passphrase_candidates;
    if (!opt.dict_path.empty()) {
      std::ifstream f(opt.dict_path);
      std::string line;
      while (std::getline(f, line) && (int)cands.size() < opt.max_native_tries) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (!line.empty()) cands.push_back(line);
      }
    }
    std::atomic<bool> found{false};
    std::string hit_pass, hit_master;
    std::mutex mu;
    int workers = (std::max)(1, cpu.recommended_workers);
    std::atomic<size_t> next{0};
    auto worker = [&]() {
      for (;;) {
        if (found.load()) return;
        size_t i = next.fetch_add(1);
        if (i >= cands.size()) return;
        auto r = try_wallet_passphrase(wallet.mkey, cands[i]);
        if (r.ok) {
          DualVerifyResult dv;
          uint8_t master[32];
          std::vector<uint8_t> mb;
          if (hex_to_bytes(r.decrypted_mkey_hex, mb) && mb.size() == 32) {
            memcpy(master, mb.data(), 32);
            dv = dual_verify_master(master, wallet, -1);
            if (dv.ok || wallet.ckeys.empty()) {
              std::lock_guard<std::mutex> lock(mu);
              if (!found.exchange(true)) {
                hit_pass = cands[i];
                hit_master = r.decrypted_mkey_hex;
                rep.dual = dv;
                rep.has_dual = true;
              }
            }
          }
        }
      }
    };
    std::vector<std::thread> th;
    for (int w = 0; w < workers; ++w) th.emplace_back(worker);
    for (auto& t : th) t.join();
    if (found.load()) {
      rep.success = true;
      rep.master_hex = hit_master;
      rep.recovered_passphrase = hit_pass;
      push(BreakStrategy::NativeKdf, "NativeKDF+dual", true, true,
           "passphrase recovered via CPU KDF (" + cpu.label + ")");
    } else {
      push(BreakStrategy::NativeKdf, "NativeKDF+dual", true, false,
           "tried " + std::to_string(cands.size()) + " candidates, no hit");
    }
  } else if (opt.do_native_kdf) {
    push(BreakStrategy::NativeKdf, "NativeKDF+dual", false, false, "skipped (CPU off or no mkey)");
  }

  if (opt.do_hashcat && !rep.success) {
    write_hashcat_file(wallet, opt.hash_export_path, true);
    auto r = spawn_hashcat_streamed(opt.hash_export_path, opt.dict_path, find_hashcat_exe(),
                                    hashcat_stream);
    push(BreakStrategy::Hashcat11300, "Hashcat-m11300", r.launched, false, r.message);
  }

  if (opt.do_john && !rep.success) {
    write_hashcat_file(wallet, opt.hash_export_path, true);
    auto r = spawn_john_bitcoin(opt.hash_export_path, hashcat_stream);
    push(BreakStrategy::JohnBitcoin, "John-bitcoin", r.launched, false, r.message);
  }

  if (opt.do_btcrecover && !rep.success) {
    BtcRecoverOptions bo;
    bo.wallet_dat = wallet.path;
    bo.tokenlist = opt.tokenlist;
    bo.passwordlist = opt.dict_path;
    bo.typos = !opt.tokenlist.empty();
    auto r = spawn_btcrecover(bo, btc_stream);
    push(BreakStrategy::BtcRecover, "BTCRecover", r.launched, false, r.message);
  }

  if (opt.do_cuda_partial && opt.use_gpu && !opt.partial_prefix_hex.empty()) {
    push(BreakStrategy::CudaPartial, "CUDA-partial", true, false,
         "prefix=" + opt.partial_prefix_hex + " â€” launch AES Partial / CUDA Crack in GUI with this prefix");
  }

  if (rep.success)
    log << "RESULT: SUCCESS master=" << rep.master_hex << "\n";
  else
    log << "RESULT: no native hit â€” external crackers may still be running\n";
  rep.log = log.str();
  return rep;
}

RebuildPackage breaker_rebuild(const uint8_t master32[32], const WalletParseResult& wallet,
                               const std::string& new_passphrase, uint32_t new_iterations,
                               bool craft_research_mkey) {
  RebuildPackage pkg;
  pkg.master_hex = to_hex(master32, 32);
  pkg.new_iterations = new_iterations ? new_iterations : 50000;

  auto dec = decrypt_all_ckeys(master32, wallet, "");
  for (size_t i = 0; i < wallet.ckeys.size() && i < dec.hits.size(); ++i) {
    if (!dec.hits[i].ok) continue;
    RebuildKeyExport e;
    e.address = wallet.ckeys[i].address;
    e.pubkey_hex = wallet.ckeys[i].pubkey_hex;
    e.priv_hex = dec.hits[i].privkey_hex;
    e.wif_uncompressed = dec.hits[i].wif_uncompressed;
    e.wif_compressed = dec.hits[i].wif_compressed;
    pkg.keys.push_back(e);
  }

  if (craft_research_mkey && !new_passphrase.empty()) {
    uint8_t salt[8];
    for (int i = 0; i < 8; ++i) salt[i] = (uint8_t)(0xA5 ^ i ^ (pkg.new_iterations & 0xff));
    if (wallet.mkey.salt.size() >= 8) memcpy(salt, wallet.mkey.salt.data(), 8);
    uint8_t enc48[48];
    if (craft_encrypted_mkey48(new_passphrase, salt, pkg.new_iterations, master32, enc48)) {
      pkg.new_mkey_enc_hex = to_hex(enc48, 48);
      pkg.new_salt_hex = to_hex(salt, 8);
      pkg.new_passphrase_note =
          "Research mkey re-encrypted under user-chosen passphrase (same master key; ckeys still "
          "valid under this master). Not a fake-balance wallet.";
    }
  } else if (new_passphrase.empty()) {
    pkg.new_passphrase_note = "No new passphrase â€” export-only rematerialization.";
  }

  pkg.research_ckey_note =
      "ckey blobs are unchanged when master key is kept; Core import of raw research mkey is "
      "experimental. Prefer WIF/JSON offline import on owner-controlled software.";

  std::ostringstream json;
  json << "{\n  \"product\": \"TrueScent Wallet Breaker / Rebuild Lab\",\n";
  json << "  \"authorized_use_only\": true,\n";
  json << "  \"master_hex\": \"" << pkg.master_hex << "\",\n";
  json << "  \"new_mkey_enc_hex\": \"" << pkg.new_mkey_enc_hex << "\",\n";
  json << "  \"new_salt_hex\": \"" << pkg.new_salt_hex << "\",\n";
  json << "  \"new_iterations\": " << pkg.new_iterations << ",\n";
  json << "  \"keys\": [\n";
  for (size_t i = 0; i < pkg.keys.size(); ++i) {
    auto& k = pkg.keys[i];
    json << "    {\"address\":\"" << k.address << "\",\"priv_hex\":\"" << k.priv_hex
         << "\",\"wif_c\":\"" << k.wif_compressed << "\",\"wif_u\":\"" << k.wif_uncompressed
         << "\",\"pubkey\":\"" << k.pubkey_hex << "\"}";
    if (i + 1 < pkg.keys.size()) json << ",";
    json << "\n";
  }
  json << "  ]\n}\n";
  pkg.json_bundle = json.str();

  std::ostringstream txt;
  txt << "TrueScent Rebuild Lab - AUTHORIZED USE ONLY\n";
  txt << "Made by TrueScent - https://t.me/TrueScent\n";
  txt << "master: " << pkg.master_hex << "\n";
  txt << pkg.new_passphrase_note << "\n";
  if (!pkg.new_mkey_enc_hex.empty()) {
    txt << "new_mkey_enc: " << pkg.new_mkey_enc_hex << "\n";
    txt << "new_salt: " << pkg.new_salt_hex << " iters=" << pkg.new_iterations << "\n";
  }
  txt << pkg.research_ckey_note << "\n";
  for (auto& k : pkg.keys) {
    txt << "addr=" << k.address << "\n  priv=" << k.priv_hex << "\n  WIF_c=" << k.wif_compressed
        << "\n  WIF_u=" << k.wif_uncompressed << "\n";
  }
  pkg.txt_bundle = txt.str();

  pkg.ok = !pkg.keys.empty() || !pkg.master_hex.empty();
  pkg.message = pkg.ok ? ("OK - " + std::to_string(pkg.keys.size()) + " keys rematerialized")
                       : "no keys decrypted";
  return pkg;
}

bool breaker_write_package(const RebuildPackage& pkg, const std::string& out_prefix) {
  std::ofstream j(out_prefix + ".json");
  std::ofstream t(out_prefix + ".txt");
  if (!j || !t) return false;
  j << pkg.json_bundle;
  t << pkg.txt_bundle;
  return true;
}

std::string force_rebuild_warning_banner() {
  return "WARNING - Force Rebuild (Experimental) does NOT decrypt original encrypted ckeys.\n"
         "Original funds stay locked without the correct passphrase / recovered master key.\n"
         "This creates NEW keys from YOUR new BIP39 seed. There is NO magic bypass of wallet.dat AES/mkey.\n"
         "Only real paths: correct passphrase, crack candidates, partial AES, or UNENCRYPTED_KEY salvage.";
}

namespace {
static const uint8_t SECP_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

static int cmp_be32(const uint8_t a[32], const uint8_t b[32]) {
  for (int i = 0; i < 32; ++i) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

static bool is_zero32(const uint8_t a[32]) {
  for (int i = 0; i < 32; ++i)
    if (a[i]) return false;
  return true;
}

static bool add_mod_n(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
  unsigned carry = 0;
  for (int i = 31; i >= 0; --i) {
    unsigned sum = (unsigned)a[i] + (unsigned)b[i] + carry;
    out[i] = (uint8_t)(sum & 0xff);
    carry = sum >> 8;
  }
  if (carry || cmp_be32(out, SECP_N) >= 0) {
    int borrow = 0;
    for (int i = 31; i >= 0; --i) {
      int v = (int)out[i] - (int)SECP_N[i] - borrow;
      if (v < 0) {
        v += 256;
        borrow = 1;
      } else
        borrow = 0;
      out[i] = (uint8_t)v;
    }
  }
  return cmp_be32(out, SECP_N) < 0 && !is_zero32(out);
}

static void ser32(uint32_t i, uint8_t out[4]) {
  out[0] = (uint8_t)(i >> 24);
  out[1] = (uint8_t)(i >> 16);
  out[2] = (uint8_t)(i >> 8);
  out[3] = (uint8_t)i;
}

struct Bip32Node {
  uint8_t priv[32]{};
  uint8_t chain[32]{};
  uint8_t pubkey[33]{};
  bool ok = false;
};

static bool bip32_from_seed(const uint8_t seed64[64], Bip32Node* n) {
  static const char* key = "Bitcoin seed";
  uint8_t I[64];
  hmac_sha512(reinterpret_cast<const uint8_t*>(key), 12, seed64, 64, I);
  memcpy(n->priv, I, 32);
  memcpy(n->chain, I + 32, 32);
  if (cmp_be32(n->priv, SECP_N) >= 0 || is_zero32(n->priv)) return false;
  size_t plen = 0;
  if (!secp256k1_priv_to_pub(n->priv, n->pubkey, &plen, true) || plen != 33) return false;
  n->ok = true;
  return true;
}

static bool bip32_ckd_priv(const Bip32Node& parent, uint32_t index, bool hardened, Bip32Node* child) {
  uint8_t data[37];
  if (hardened) {
    data[0] = 0;
    memcpy(data + 1, parent.priv, 32);
    ser32(index | 0x80000000u, data + 33);
  } else {
    memcpy(data, parent.pubkey, 33);
    ser32(index, data + 33);
  }
  uint8_t I[64];
  hmac_sha512(parent.chain, 32, data, 37, I);
  if (cmp_be32(I, SECP_N) >= 0) return false;
  if (!add_mod_n(I, parent.priv, child->priv)) return false;
  memcpy(child->chain, I + 32, 32);
  size_t plen = 0;
  if (!secp256k1_priv_to_pub(child->priv, child->pubkey, &plen, true) || plen != 33) return false;
  child->ok = true;
  return true;
}

static std::string bip32_base58check(const uint8_t* data78) {
  uint8_t chk[32];
  double_sha256(data78, 78, chk);
  std::vector<uint8_t> all(data78, data78 + 78);
  all.insert(all.end(), chk, chk + 4);
  return base58_encode(all.data(), all.size());
}

static std::string make_xprv(const Bip32Node& n) {
  uint8_t payload[78];
  payload[0] = 0x04;
  payload[1] = 0x88;
  payload[2] = 0xAD;
  payload[3] = 0xE4;
  payload[4] = 0;
  memset(payload + 5, 0, 8);
  memcpy(payload + 13, n.chain, 32);
  payload[45] = 0;
  memcpy(payload + 46, n.priv, 32);
  return bip32_base58check(payload);
}

static std::string make_xpub(const Bip32Node& n) {
  uint8_t payload[78];
  payload[0] = 0x04;
  payload[1] = 0x88;
  payload[2] = 0xB2;
  payload[3] = 0x1E;
  payload[4] = 0;
  memset(payload + 5, 0, 8);
  memcpy(payload + 13, n.chain, 32);
  memcpy(payload + 45, n.pubkey, 33);
  return bip32_base58check(payload);
}

static bool priv_to_export(const uint8_t priv[32], RebuildKeyExport* e) {
  size_t plen = 0;
  uint8_t pub[65];
  if (!secp256k1_priv_to_pub(priv, pub, &plen, true) || plen < 33) return false;
  e->priv_hex = to_hex(priv, 32);
  e->pubkey_hex = to_hex(pub, 33);
  e->wif_compressed = privkey_to_wif(priv, true);
  e->wif_uncompressed = privkey_to_wif(priv, false);
  e->address = pubkey_to_p2pkh(pub, 33);
  return !e->wif_compressed.empty();
}

static bool ensure_dir(const std::string& dir) {
#ifdef _WIN32
  return CreateDirectoryA(dir.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
#else
  return mkdir(dir.c_str(), 0755) == 0 || errno == EEXIST;
#endif
}

static std::string side_path_for(const std::string& original) {
  if (original.empty()) return "wallet.dat.reweave_new";
  return original + ".reweave_new";
}
}  // namespace

ForceRebuildResult force_rebuild_experimental(const WalletParseResult& wallet,
                                              const std::vector<uint8_t>& raw,
                                              const ForceRebuildOptions& opt) {
  ForceRebuildResult r;
  r.decrypts_original_ckeys = false;
  r.warning_banner = force_rebuild_warning_banner();

  /* 1) Always rip apart */
  r.carve = breaker_carve(raw.empty() ? nullptr : raw.data(), raw.size(), &wallet);
  {
    std::ostringstream inv;
    inv << "ForceRebuild inventory: path=" << wallet.path << " size=" << wallet.file_size
        << " mkey=" << (wallet.mkey.found ? "yes" : "no") << " ckeys=" << wallet.ckey_count()
        << " plain_keys=" << wallet.plain_key_count() << " carve_mkeys=" << r.carve.mkeys.size()
        << " carve_ckeys=" << r.carve.ckeys.size()
        << " mnemonic_scraps=" << r.carve.mnemonics.size();
    r.inventory_summary = inv.str();
  }

  /* Salvage UNENCRYPTED_KEY material (real recovery) */
  for (const auto& pk : wallet.plain_keys) {
    RebuildKeyExport e;
    e.address = pk.address;
    e.pubkey_hex = pk.pubkey_hex;
    e.priv_hex = pk.priv_hex;
    e.wif_compressed = pk.wif_compressed;
    e.wif_uncompressed = pk.wif_uncompressed;
    if (e.priv_hex.empty() && pk.priv32.size() == 32) e.priv_hex = to_hex(pk.priv32.data(), 32);
    r.salvaged_plain.push_back(e);
  }

  /* 2) NEW BIP39 seed */
  std::string mnemonic = opt.new_mnemonic;
  std::string err;
  if (mnemonic.empty()) {
    if (!bip39_generate_mnemonic(12, &mnemonic, &err)) {
      r.message = "BIP39 generate failed: " + err;
      return r;
    }
  } else {
    auto v = bip39_validate_mnemonic(mnemonic);
    if (!v.ok) {
      r.message = "Invalid BIP39 mnemonic: " + v.message;
      return r;
    }
  }
  r.mnemonic = mnemonic;

  uint8_t seed64[64];
  if (!bip39_mnemonic_to_seed(mnemonic, opt.bip39_passphrase, seed64, &err)) {
    r.message = "mnemonic_to_seed failed: " + err;
    return r;
  }
  r.seed_hex = to_hex(seed64, 64);

  Bip32Node master;
  if (!bip32_from_seed(seed64, &master)) {
    r.message = "BIP32 master from seed failed";
    return r;
  }
  r.bip32_master_priv_hex = to_hex(master.priv, 32);
  r.bip32_chain_hex = to_hex(master.chain, 32);
  r.xprv = make_xprv(master);
  r.xpub = make_xpub(master);

  /* BIP44 sample: m/44'/0'/0'/0/i */
  Bip32Node n44, n0h, n0a, next;
  if (!bip32_ckd_priv(master, 44, true, &n44) || !bip32_ckd_priv(n44, 0, true, &n0h) ||
      !bip32_ckd_priv(n0h, 0, true, &n0a) || !bip32_ckd_priv(n0a, 0, false, &next)) {
    r.message = "BIP44 derivation failed";
    return r;
  }
  int n_sample = opt.sample_address_count > 0 ? opt.sample_address_count : 5;
  for (int i = 0; i < n_sample; ++i) {
    Bip32Node leaf;
    if (!bip32_ckd_priv(next, (uint32_t)i, false, &leaf)) continue;
    RebuildKeyExport e;
    if (priv_to_export(leaf.priv, &e)) r.new_seed_keys.push_back(e);
  }
  /* Also export master as research identity key #0-style note (not BIP44) */
  {
    RebuildKeyExport e;
    if (priv_to_export(master.priv, &e)) {
      e.address = e.address + " (BIP32 master, not BIP44)";
      /* keep as first sample only in txt note; don't mix into keys list */
    }
  }

  /* Research mkey encrypted under NEW wallet passphrase (NEW master = BIP32 master priv) */
  r.research_mkey_iters = opt.new_iterations ? opt.new_iterations : 50000;
  if (!opt.new_wallet_passphrase.empty()) {
    uint8_t salt[8];
    for (int i = 0; i < 8; ++i) salt[i] = (uint8_t)(0x5A ^ i ^ (r.research_mkey_iters & 0xff));
    uint8_t enc48[48];
    if (craft_encrypted_mkey48(opt.new_wallet_passphrase, salt, r.research_mkey_iters, master.priv,
                               enc48)) {
      r.research_mkey_enc_hex = to_hex(enc48, 48);
      r.research_mkey_salt_hex = to_hex(salt, 8);
    }
  }

  /* Bundles */
  std::ostringstream json;
  json << "{\n";
  json << "  \"product\": \"TrueScent Force Rebuild Experimental\",\n";
  json << "  \"decrypts_original_ckeys\": false,\n";
  json << "  \"magic_bypass\": false,\n";
  json << "  \"warning\": \"Does NOT unlock original encrypted wallet funds\",\n";
  json << "  \"mnemonic\": \"" << r.mnemonic << "\",\n";
  json << "  \"seed_hex\": \"" << r.seed_hex << "\",\n";
  json << "  \"xprv\": \"" << r.xprv << "\",\n";
  json << "  \"xpub\": \"" << r.xpub << "\",\n";
  json << "  \"bip32_master_priv_hex\": \"" << r.bip32_master_priv_hex << "\",\n";
  json << "  \"research_mkey_enc_hex\": \"" << r.research_mkey_enc_hex << "\",\n";
  json << "  \"research_mkey_salt_hex\": \"" << r.research_mkey_salt_hex << "\",\n";
  json << "  \"research_mkey_iters\": " << r.research_mkey_iters << ",\n";
  json << "  \"new_seed_keys\": [\n";
  for (size_t i = 0; i < r.new_seed_keys.size(); ++i) {
    auto& k = r.new_seed_keys[i];
    json << "    {\"path\":\"m/44'/0'/0'/0/" << i << "\",\"address\":\"" << k.address
         << "\",\"priv_hex\":\"" << k.priv_hex << "\",\"wif_c\":\"" << k.wif_compressed << "\"}";
    if (i + 1 < r.new_seed_keys.size()) json << ",";
    json << "\n";
  }
  json << "  ],\n";
  json << "  \"salvaged_UNENCRYPTED_KEY\": [\n";
  for (size_t i = 0; i < r.salvaged_plain.size(); ++i) {
    auto& k = r.salvaged_plain[i];
    json << "    {\"address\":\"" << k.address << "\",\"priv_hex\":\"" << k.priv_hex
         << "\",\"wif_c\":\"" << k.wif_compressed << "\"}";
    if (i + 1 < r.salvaged_plain.size()) json << ",";
    json << "\n";
  }
  json << "  ],\n";
  json << "  \"inventory\": \"" << r.inventory_summary << "\",\n";
  json << "  \"carve_summary\": \"";
  for (char c : r.carve.summary) {
    if (c == '\n')
      json << "\\n";
    else if (c == '"')
      json << "\\\"";
    else
      json << c;
  }
  json << "\"\n}\n";
  r.json_bundle = json.str();

  std::ostringstream txt;
  txt << "=== Force Rebuild (Experimental) ===\n";
  txt << r.warning_banner << "\n\n";
  txt << r.inventory_summary << "\n";
  txt << r.carve.summary << "\n";
  txt << "NEW BIP39 mnemonic:\n" << r.mnemonic << "\n";
  txt << "seed_hex: " << r.seed_hex << "\n";
  txt << "xprv: " << r.xprv << "\n";
  txt << "xpub: " << r.xpub << "\n";
  if (!r.research_mkey_enc_hex.empty()) {
    txt << "research_mkey_enc (under NEW passphrase): " << r.research_mkey_enc_hex << "\n";
    txt << "research_mkey_salt: " << r.research_mkey_salt_hex
        << " iters=" << r.research_mkey_iters << "\n";
  }
  txt << "\n--- NEW seed sample keys (BIP44 m/44'/0'/0'/0/i) ---\n";
  for (size_t i = 0; i < r.new_seed_keys.size(); ++i) {
    auto& k = r.new_seed_keys[i];
    txt << "[" << i << "] " << k.address << "\n  priv=" << k.priv_hex << "\n  WIF_c=" << k.wif_compressed
        << "\n";
  }
  if (!r.salvaged_plain.empty()) {
    txt << "\n--- SALVAGED UNENCRYPTED_KEY (from original carve/parse) ---\n";
    for (auto& k : r.salvaged_plain) {
      txt << "addr=" << k.address << "\n  priv=" << k.priv_hex << "\n  WIF_c=" << k.wif_compressed
         << "\n";
    }
  } else {
    txt << "\n(no UNENCRYPTED_KEY found - encrypted ckeys remain locked)\n";
  }
  r.txt_bundle = txt.str();

  /* Write export dir (never overwrite original by default) */
  std::string dir = opt.export_dir.empty() ? "rebuilt_NEW_wallet_EXPORT" : opt.export_dir;
  if (ensure_dir(dir)) {
    std::string prefix = dir + "/force_rebuild";
#ifdef _WIN32
    for (char& c : prefix)
      if (c == '/') c = '\\';
#endif
    std::ofstream j(prefix + ".json");
    std::ofstream t(prefix + ".txt");
    if (j && t) {
      j << r.json_bundle;
      t << r.txt_bundle;
      r.export_dir_written = dir;
    }
  }

  if (opt.write_side_wallet) {
    r.side_wallet_path = side_path_for(opt.original_wallet_path.empty() ? wallet.path
                                                                       : opt.original_wallet_path);
    std::ofstream side(r.side_wallet_path, std::ios::binary);
    if (side) {
      side << "# TrueScent wallet.dat.reweave_new — RESEARCH SIDECAR, NOT a drop-in Core wallet\n";
      side << "# Does NOT decrypt original ckeys. NEW keys only from new BIP39 seed.\n";
      side << r.json_bundle;
      r.wrote_side_wallet = true;
    }
  }

  r.ok = !r.new_seed_keys.empty() || !r.salvaged_plain.empty();
  r.message = r.ok ? ("Force Rebuild OK - NEW seed keys=" + std::to_string(r.new_seed_keys.size()) +
                      " salvaged_plain=" + std::to_string(r.salvaged_plain.size()) +
                      " (original encrypted ckeys UNAFFECTED)")
                   : "Force Rebuild produced no keys";
  return r;
}
