#include "Experiment.h"
#include "DualVerify.h"
#include "HashcatExport.h"
#include "Passphrase.h"
#include "../crypto/secp256k1_lite.h"

#include <cstring>
#include <sstream>
#include <vector>

std::string experiment_help() {
  return "Experiments (authorized recovery R&D):\n"
         "  dual_fp       Random AES-key FP rate: PKCS vs PKCS+EC\n"
         "  passphrase    Method-0 KDF craft → decrypt → dual-verify smoke\n"
         "  secp          secp256k1 compressed-G selftest\n"
         "  hashcat_fmt   Document $bitcoin$ / hashcat -m 11300 interop\n";
}

int experiment_passphrase_selftest(std::string* log_out) {
  std::ostringstream log;
  log << "[+] Experiment: passphrase KDF selftest (method 0)\n";

  const std::string pass = "truescent-lab";
  const uint8_t salt[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  const uint32_t iters = 100;
  uint8_t master[32];
  for (int i = 0; i < 32; ++i) master[i] = (uint8_t)(0xA0 + i);

  uint8_t enc48[48];
  if (!craft_encrypted_mkey48(pass, salt, iters, master, enc48)) {
    log << "[E] craft_encrypted_mkey48 failed\n";
    if (log_out) *log_out = log.str();
    return 1;
  }

  MasterKeyInfo mk;
  mk.found = true;
  mk.encrypted48.assign(enc48, enc48 + 48);
  mk.salt.assign(salt, salt + 8);
  mk.method = 0;
  mk.iterations = iters;
  static const char* h = "0123456789abcdef";
  mk.encrypted_hex.assign(96, '0');
  for (int i = 0; i < 48; ++i) {
    mk.encrypted_hex[i * 2] = h[enc48[i] >> 4];
    mk.encrypted_hex[i * 2 + 1] = h[enc48[i] & 0xf];
  }
  mk.salt_hex = "1122334455667788";

  auto bad = try_wallet_passphrase(mk, "wrong-password");
  if (bad.ok) {
    log << "[E] wrong password unexpectedly OK\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  log << "[+] wrong password rejected\n";

  auto good = try_wallet_passphrase(mk, pass);
  if (!good.ok) {
    log << "[E] correct password failed: " << good.message << "\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  log << "[+] passphrase decrypted mkey\n";
  log << "    master=" << good.decrypted_mkey_hex << "\n";

  for (int i = 0; i < 32; ++i) {
    int hi = good.decrypted_mkey_hex[i * 2], lo = good.decrypted_mkey_hex[i * 2 + 1];
    auto nib = [](char c) {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      return c - 'A' + 10;
    };
    if ((uint8_t)((nib((char)hi) << 4) | nib((char)lo)) != master[i]) {
      log << "[E] master plaintext mismatch\n";
      if (log_out) *log_out = log.str();
      return 1;
    }
  }

  std::string hc = export_bitcoin_hashcat_line(mk);
  log << "[+] hashcat line: " << hc << "\n";
  if (hc.find("$bitcoin$") != 0) {
    log << "[E] bad hashcat export\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  log << "[+] passphrase experiment PASSED\n";
  if (log_out) *log_out = log.str();
  return 0;
}

int experiment_dual_fp(std::string* log_out, int trials) {
  std::string s = experiment_dual_fp_rate(trials);
  if (log_out) *log_out = s;
  return 0;
}

int run_experiment(const std::string& name, std::string* log_out) {
  if (name == "help" || name == "--help" || name.empty()) {
    if (log_out) *log_out = experiment_help();
    return 0;
  }
  if (name == "dual_fp") return experiment_dual_fp(log_out, 5000);
  if (name == "secp") {
    std::ostringstream o;
    bool ok = secp256k1_lite_selftest();
    o << (ok ? "[+] secp256k1 selftest PASS\n" : "[E] secp256k1 selftest FAIL\n");
    if (log_out) *log_out = o.str();
    return ok ? 0 : 1;
  }
  if (name == "passphrase") return experiment_passphrase_selftest(log_out);
  if (name == "hashcat_fmt") {
    std::ostringstream o;
    o << "Format: $bitcoin$64$<last32encHEX>$16$<saltHEX>$<iters>$2$00$2$00\n";
    o << "Hashcat: hashcat -m 11300 -a 0 hash.txt wordlist.txt\n";
    o << "John:    john --format=bitcoin hash.txt\n";
    o << "(Export from Recovery Lab → Hashcat Bridge; optional spawn if on PATH)\n";
    if (log_out) *log_out = o.str();
    return 0;
  }
  if (log_out) *log_out = "unknown experiment: " + name + "\n" + experiment_help();
  return 1;
}
