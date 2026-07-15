#include "BreakerRebuild.h"
#include "Passphrase.h"
#include "Salvage.h"
#include "ForensicTools.h"
#include "HashcatExport.h"
#include "CpuSimd.h"
#include "../crypto/crypto_wallet.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

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
        mh.note = "BIP39 checksum OK — likely seed scrap (NOT typical Core wallet.dat storage)";
        r.classic_core_has_no_bip39 = false;
      } else if (bip.word_count == 12 || bip.word_count == 24) {
        mh.note = "mnemonic-shaped string; BIP39 checksum FAIL or unknown words";
      } else {
        mh.note = "space-separated words; may be Electrum/other — not validated as BIP39";
      }
      r.mnemonics.push_back(mh);
      if (r.mnemonics.size() >= 32) break;
    }
  }

  std::ostringstream s;
  s << "Carve: mkeys=" << r.mkeys.size() << " ckeys=" << r.ckeys.size()
    << " mnemonic_candidates=" << r.mnemonics.size() << "\n";
  if (r.classic_core_has_no_bip39 && r.mnemonics.empty()) {
    s << "Honesty: classic Bitcoin Core wallet.dat typically stores NO BIP39 mnemonic — "
         "none found in this sample.\n";
  } else if (!r.mnemonics.empty()) {
    s << "Found mnemonic-looking scrap(s) — may be from descriptors/import/user scrap, "
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
    log << "[" << (hit ? "HIT" : ran ? "ok" : "skip") << "] " << name << " — " << d << "\n";
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
         "prefix=" + opt.partial_prefix_hex + " — launch AES Partial / CUDA Crack in GUI with this prefix");
  }

  if (rep.success)
    log << "RESULT: SUCCESS master=" << rep.master_hex << "\n";
  else
    log << "RESULT: no native hit — external crackers may still be running\n";
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
    pkg.new_passphrase_note = "No new passphrase — export-only rematerialization.";
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
  txt << "TrueScent Rebuild Lab — AUTHORIZED USE ONLY\n";
  txt << "Made by TrueScent — https://t.me/TrueScent\n";
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
  pkg.message = pkg.ok ? ("OK — " + std::to_string(pkg.keys.size()) + " keys rematerialized")
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
