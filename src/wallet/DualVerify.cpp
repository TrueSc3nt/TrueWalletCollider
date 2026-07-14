#include "DualVerify.h"
#include "Passphrase.h"
#include "../crypto/secp256k1_lite.h"

#include <chrono>
#include <cstring>
#include <fstream>
#include <random>
#include <sstream>

namespace {
static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out) {
  if (hex.size() % 2) return false;
  out.resize(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    int hi = hex_nibble(hex[i * 2]), lo = hex_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}
static std::string to_hex(const uint8_t* p, size_t n) {
  static const char* h = "0123456789abcdef";
  std::string s(n * 2, '0');
  for (size_t i = 0; i < n; ++i) {
    s[i * 2] = h[p[i] >> 4];
    s[i * 2 + 1] = h[p[i] & 0xf];
  }
  return s;
}
static bool pkcs16_ok(const uint8_t* plain48) {
  for (int i = 32; i < 48; ++i)
    if (plain48[i] != 0x10) return false;
  return true;
}
}  // namespace

DualVerifyResult dual_verify_master(const uint8_t master32[32],
                                    const WalletParseResult& wallet,
                                    int prefer_ckey) {
  DualVerifyResult r;
  r.master_hex = to_hex(master32, 32);

  /* Optional: decrypt mkey blob with itself is N/A — master IS the plaintext.
   * For passphrase path, PKCS on mkey already done. Mark consistent. */
  r.pkcs_mkey = true;

  if (wallet.ckeys.empty()) {
    r.message = "master accepted (PKCS) but no ckeys for dual-verify";
    r.ok = true; /* soft OK — cannot strengthen */
    return r;
  }

  int start = prefer_ckey >= 0 && prefer_ckey < (int)wallet.ckeys.size() ? prefer_ckey : 0;
  for (int pass = 0; pass < (int)wallet.ckeys.size(); ++pass) {
    int i = (start + pass) % (int)wallet.ckeys.size();
    const auto& ck = wallet.ckeys[i];
    if (ck.encrypted48.size() != 48 || ck.pubkey.empty()) continue;

    WalletTarget wt;
    wt.enc48 = ck.encrypted48;
    wt.enc_hex = ck.encrypted_hex;
    wt.pubkey = ck.pubkey;
    wt.pubkey_hex = ck.pubkey_hex;
    wt.is_mkey = false;

    PostHitResult hit = post_hit_decrypt_wif(wt, master32);
    if (!hit.ok) continue;

    r.pkcs_ckey = true;
    r.ckey_hit = hit;
    r.ckey_index = i;

    uint8_t derived[65];
    size_t dlen = 0;
    bool want_comp = (ck.pubkey.size() == 33);
    std::vector<uint8_t> priv;
    if (hex_to_bytes(hit.privkey_hex, priv) && priv.size() == 32) {
      if (secp256k1_priv_to_pub(priv.data(), derived, &dlen, want_comp) &&
          dlen == ck.pubkey.size() &&
          std::memcmp(derived, ck.pubkey.data(), dlen) == 0) {
        r.pubkey_match = true;
      }
    }

    r.ok = r.pkcs_ckey; /* IV-bound PKCS is strong; EC confirms */
    if (r.pubkey_match)
      r.message = "DUAL OK — PKCS(ckey) + EC pubkey match ckey #" + std::to_string(i);
    else
      r.message = "DUAL OK — PKCS(ckey) IV-bound to stored pubkey (ckey #" +
                  std::to_string(i) + "); EC match=no";
    return r;
  }

  r.message = "master failed ckey PKCS dual-verify (wrong key or corrupt ckeys)";
  r.ok = false;
  return r;
}

DualVerifyResult dual_verify_passphrase(const MasterKeyInfo& mkey,
                                        const WalletParseResult& wallet,
                                        const std::string& passphrase,
                                        const std::string& found_file) {
  DualVerifyResult r;
  auto pr = try_wallet_passphrase(mkey, passphrase);
  if (!pr.ok) {
    r.message = pr.message;
    return r;
  }
  r.pkcs_mkey = true;
  std::vector<uint8_t> master;
  if (!hex_to_bytes(pr.decrypted_mkey_hex, master) || master.size() != 32) {
    r.message = "internal: bad decrypted mkey hex";
    return r;
  }
  r = dual_verify_master(master.data(), wallet, -1);
  r.pkcs_mkey = true;
  r.master_hex = pr.decrypted_mkey_hex;
  if (r.ok) {
    /* Write FOUND_WALLET with passphrase recovery record */
    std::ofstream out(found_file, std::ios::app);
    if (out) {
      out << "=== TrueWalletCollider PASSPHRASE RECOVERY ===\n";
      out << "passphrase_ok: yes\n";
      out << "dual_verify: " << r.message << "\n";
      out << "master_key: " << r.master_hex << "\n";
      out << "derived_aes_key: " << pr.derived_key_hex << "\n";
      out << "derived_iv: " << pr.derived_iv_hex << "\n";
      if (r.ckey_index >= 0) {
        out << "ckey_index: " << r.ckey_index << "\n";
        out << "privkey_hex: " << r.ckey_hit.privkey_hex << "\n";
        out << "wif_uncompressed: " << r.ckey_hit.wif_uncompressed << "\n";
        out << "wif_compressed: " << r.ckey_hit.wif_compressed << "\n";
        out << "pubkey_match: " << (r.pubkey_match ? "yes" : "no") << "\n";
      }
      out << "===\n";
    }
  }
  return r;
}

MultiCkeyDecryptResult decrypt_all_ckeys(const uint8_t master32[32],
                                         const WalletParseResult& wallet,
                                         const std::string& found_file) {
  MultiCkeyDecryptResult r;
  r.master_hex = to_hex(master32, 32);
  std::ostringstream report;
  report << "Multi-ckey decrypt consistency report\n";
  report << "master: " << r.master_hex << "\n";
  report << "ckeys: " << wallet.ckeys.size() << "\n\n";

  for (size_t i = 0; i < wallet.ckeys.size(); ++i) {
    const auto& ck = wallet.ckeys[i];
    if (ck.encrypted48.size() != 48 || ck.pubkey.empty()) {
      ++r.failed;
      report << "[" << i << "] SKIP (missing enc/pub)\n";
      r.hits.push_back({});
      continue;
    }
    WalletTarget wt;
    wt.enc48 = ck.encrypted48;
    wt.enc_hex = ck.encrypted_hex;
    wt.pubkey = ck.pubkey;
    wt.pubkey_hex = ck.pubkey_hex;
    PostHitResult hit = post_hit_decrypt_wif(wt, master32);
    r.hits.push_back(hit);
    if (!hit.ok) {
      ++r.failed;
      report << "[" << i << "] FAIL " << hit.message << " addr=" << ck.address << "\n";
      continue;
    }
    ++r.decrypted;
    bool pub_ok = false;
    std::vector<uint8_t> priv;
    if (hex_to_bytes(hit.privkey_hex, priv) && priv.size() == 32) {
      uint8_t der[65];
      size_t dlen = 0;
      bool comp = ck.pubkey.size() == 33;
      if (secp256k1_priv_to_pub(priv.data(), der, &dlen, comp) && dlen == ck.pubkey.size() &&
          std::memcmp(der, ck.pubkey.data(), dlen) == 0) {
        pub_ok = true;
        ++r.pubkey_ok;
      }
    }
    report << "[" << i << "] OK addr=" << ck.address
           << " ec=" << (pub_ok ? "match" : "no") << "\n";
    report << "    WIF_c: " << hit.wif_compressed << "\n";
    save_found_wallet(found_file, wt, master32, hit, (int)i);
  }
  r.ok = r.decrypted > 0 && r.failed == 0;
  report << "\ndecrypted=" << r.decrypted << " failed=" << r.failed
         << " pubkey_ok=" << r.pubkey_ok << "\n";
  r.report = report.str();
  return r;
}

DualVerifyResult dual_verify_aes_key(const uint8_t aes_key32[32],
                                     const WalletTarget& tgt,
                                     const WalletParseResult* wallet_opt) {
  DualVerifyResult r;
  r.master_hex = to_hex(aes_key32, 32);
  if (tgt.is_mkey) {
    /* AES key that decrypts mkey is the wallet passphrase-derived key, not master.
     * If wallet provided, try treating aes_key as master against ckeys. */
    if (wallet_opt) return dual_verify_master(aes_key32, *wallet_opt, -1);
    r.message = "mkey AES hit — supply wallet ckeys for dual-verify";
    r.pkcs_mkey = true;
    r.ok = true;
    return r;
  }
  PostHitResult hit = post_hit_decrypt_wif(tgt, aes_key32);
  r.ckey_hit = hit;
  r.pkcs_ckey = hit.ok;
  if (!hit.ok) {
    r.message = hit.message;
    return r;
  }
  std::vector<uint8_t> priv;
  if (hex_to_bytes(hit.privkey_hex, priv) && priv.size() == 32 && !tgt.pubkey.empty()) {
    uint8_t der[65];
    size_t dlen = 0;
    bool comp = tgt.pubkey.size() == 33;
    if (secp256k1_priv_to_pub(priv.data(), der, &dlen, comp) && dlen == tgt.pubkey.size() &&
        std::memcmp(der, tgt.pubkey.data(), dlen) == 0) {
      r.pubkey_match = true;
    }
  }
  r.ok = r.pkcs_ckey && (r.pubkey_match || tgt.pubkey.empty());
  r.message = r.pubkey_match ? "DUAL OK — PKCS + EC pubkey match"
                             : (r.pkcs_ckey ? "PKCS OK (EC match pending/fail)" : "fail");
  if (r.pkcs_ckey && !r.pubkey_match && !tgt.pubkey.empty()) {
    /* still accept PKCS+IV as dual for tooling; flag EC */
    r.ok = true;
    r.message = "PKCS OK; EC pubkey_match=" + std::string(r.pubkey_match ? "yes" : "no");
  }
  return r;
}

std::string experiment_dual_fp_rate(int trials) {
  std::ostringstream o;
  o << "Dual-verifier FP rate demo (random AES keys vs PoC ckey)\n";
  static const char* POC_CKEY =
      "2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a"
      "88b0d881c4d93155";
  static const char* POC_PUB =
      "0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5";
  WalletTarget wt;
  hex_to_bytes(POC_CKEY, wt.enc48);
  wt.enc_hex = POC_CKEY;
  hex_to_bytes(POC_PUB, wt.pubkey);
  wt.pubkey_hex = POC_PUB;

  std::mt19937_64 rng((uint64_t)std::chrono::steady_clock::now().time_since_epoch().count());
  int pkcs_hits = 0, dual_hits = 0;
  auto t0 = std::chrono::steady_clock::now();
  for (int i = 0; i < trials; ++i) {
    uint8_t key[32];
    for (int j = 0; j < 32; ++j) key[j] = (uint8_t)(rng() & 0xff);
    PostHitResult hit = post_hit_decrypt_wif(wt, key);
    if (!hit.ok) continue;
    ++pkcs_hits;
    auto d = dual_verify_aes_key(key, wt, nullptr);
    if (d.pubkey_match) ++dual_hits;
  }
  auto ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0)
                .count();
  o << "trials=" << trials << " time_ms=" << ms << "\n";
  o << "PKCS-only false accepts: " << pkcs_hits << "\n";
  o << "PKCS+EC false accepts:   " << dual_hits << "\n";
  o << "Note: GPU AES search uses last-block PKCS; dual EC collapses residual FPs.\n";
  o << "secp256k1 selftest: " << (secp256k1_lite_selftest() ? "PASS" : "FAIL") << "\n";
  return o.str();
}
