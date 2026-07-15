#include "WalletDat.h"
#include "../crypto/crypto_wallet.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

/* ---- local helpers ---- */

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static std::string to_hex(const uint8_t* p, size_t n) {
  static const char* h = "0123456789abcdef";
  std::string s;
  s.resize(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s[i * 2] = h[p[i] >> 4];
    s[i * 2 + 1] = h[p[i] & 0xf];
  }
  return s;
}

static std::string to_hex(const std::vector<uint8_t>& v) {
  return to_hex(v.data(), v.size());
}

/* RIPEMD-160 (public-domain style compact) */
namespace {
uint32_t rol(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

void ripemd160(const uint8_t* msg, size_t len, uint8_t out[20]) {
  uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476,
           h4 = 0xC3D2E1F0;
  auto f = [](int j, uint32_t x, uint32_t y, uint32_t z) -> uint32_t {
    if (j <= 15) return x ^ y ^ z;
    if (j <= 31) return (x & y) | (~x & z);
    if (j <= 47) return (x | ~y) ^ z;
    if (j <= 63) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  };
  static const uint32_t K1[5] = {0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
  static const uint32_t K2[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0};
  static const int R1[80] = {
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
      3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
      4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
  static const int R2[80] = {
      5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
      15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
      12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
  static const int S1[80] = {
      11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
      11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
      9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
  static const int S2[80] = {
      8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
      9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
      8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};

  size_t new_len = ((len + 8) / 64 + 1) * 64;
  std::vector<uint8_t> buf(new_len, 0);
  std::memcpy(buf.data(), msg, len);
  buf[len] = 0x80;
  uint64_t bitlen = (uint64_t)len * 8;
  std::memcpy(buf.data() + new_len - 8, &bitlen, 8);

  for (size_t i = 0; i < new_len; i += 64) {
    uint32_t X[16];
    for (int j = 0; j < 16; ++j)
      X[j] = (uint32_t)buf[i + j * 4] | ((uint32_t)buf[i + j * 4 + 1] << 8) |
             ((uint32_t)buf[i + j * 4 + 2] << 16) | ((uint32_t)buf[i + j * 4 + 3] << 24);
    uint32_t al = h0, bl = h1, cl = h2, dl = h3, el = h4;
    uint32_t ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (int j = 0; j < 80; ++j) {
      uint32_t t = rol(al + f(j, bl, cl, dl) + X[R1[j]] + K1[j / 16], S1[j]) + el;
      al = el;
      el = dl;
      dl = rol(cl, 10);
      cl = bl;
      bl = t;
      t = rol(ar + f(79 - j, br, cr, dr) + X[R2[j]] + K2[j / 16], S2[j]) + er;
      ar = er;
      er = dr;
      dr = rol(cr, 10);
      cr = br;
      br = t;
    }
    uint32_t t = h1 + cl + dr;
    h1 = h2 + dl + er;
    h2 = h3 + el + ar;
    h3 = h4 + al + br;
    h4 = h0 + bl + cr;
    h0 = t;
  }
  auto store = [](uint32_t v, uint8_t* p) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
  };
  store(h0, out);
  store(h1, out + 4);
  store(h2, out + 8);
  store(h3, out + 12);
  store(h4, out + 16);
}
}  // namespace

static bool pubkey_to_address(const std::vector<uint8_t>& pubkey, CKeyInfo& out) {
  if (pubkey.size() != 33 && pubkey.size() != 65) return false;
  uint8_t digest[32];
  sha256(pubkey.data(), pubkey.size(), digest);
  out.sha256_hex = to_hex(digest, 32);
  uint8_t ripe[20];
  ripemd160(digest, 32, ripe);
  out.ripemd160_hex = to_hex(ripe, 20);
  uint8_t payload[25];
  payload[0] = 0x00;
  std::memcpy(payload + 1, ripe, 20);
  uint8_t chk[32];
  double_sha256(payload, 21, chk);
  std::memcpy(payload + 21, chk, 4);
  out.address_raw_hex = to_hex(payload, 25);
  out.address = base58_encode(payload, 25);
  out.address_ok = !out.address.empty();
  return out.address_ok;
}

static void add_meta(WalletParseResult& r, const char* tag, size_t off,
                     const uint8_t* data, size_t len, const char* note) {
  MetaHit m;
  m.tag = tag;
  m.offset = off;
  m.note = note ? note : "";
  size_t prev = 24;
  size_t start = off > 8 ? off - 8 : 0;
  size_t end = std::min(len, start + prev);
  m.preview_hex = to_hex(data + start, end - start);
  r.meta.push_back(std::move(m));
}

static void scan_meta_tags(WalletParseResult& r, const uint8_t* data, size_t len) {
  struct Tag {
    const char* name;
    const char* note;
  };
  static const Tag tags[] = {
      {"version", "wallet version key"},
      {"minversion", "minimum client version"},
      {"bestblock", "best block locator"},
      {"defaultkey", "default public key"},
      {"pool", "keypool entry"},
      {"name", "address book name"},
      {"purpose", "address purpose"},
      {"tx", "transaction record marker"},
      {"ckey", "encrypted private key"},
      {"mkey", "master key"},
      {"key", "unencrypted key (rare)"},
      {"wkey", "wallet key metadata"},
      {"keymeta", "key metadata"},
      {"hdchain", "HD chain state"},
      {"hdpubkey", "HD public key"},
      {"cscript", "redeem script"},
      {"watchs", "watch-only script"},
      {"destdata", "destination data"},
  };
  for (const auto& t : tags) {
    size_t n = std::strlen(t.name);
    for (size_t i = 0; i + n <= len; ++i) {
      if (std::memcmp(data + i, t.name, n) == 0) {
        /* avoid dense spam: keep first few of each, plus ckeys handled elsewhere */
        int count = 0;
        for (auto& m : r.meta)
          if (m.tag == t.name) ++count;
        if (count < 8 || std::strcmp(t.name, "ckey") == 0 || std::strcmp(t.name, "mkey") == 0) {
          if (std::strcmp(t.name, "ckey") != 0 && std::strcmp(t.name, "mkey") != 0)
            add_meta(r, t.name, i, data, len, t.note);
        }
        i += n;
      }
    }
  }
}

WalletParseResult WalletDatParser::parse_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  WalletParseResult r;
  r.path = path;
  if (!in) {
    r.warnings.push_back("cannot open file: " + path);
    r.log.push_back("[E] cannot open " + path);
    return r;
  }
  in.seekg(0, std::ios::end);
  auto sz = in.tellg();
  in.seekg(0, std::ios::beg);
  if (sz <= 0) {
    r.warnings.push_back("empty file");
    return r;
  }
  std::vector<uint8_t> buf((size_t)sz);
  in.read(reinterpret_cast<char*>(buf.data()), sz);
  return parse_bytes(buf.data(), buf.size(), path);
}

WalletParseResult WalletDatParser::parse_bytes(const uint8_t* data, size_t len,
                                               const std::string& path_label) {
  WalletParseResult r;
  r.path = path_label;
  r.file_size = len;
  r.log.push_back("[+] parsing " + path_label + " (" + std::to_string(len) + " bytes)");

  /* Storage auto-detect: SQLite (Core ≥0.21) vs classic BDB */
  if (len >= 15 && std::memcmp(data, "SQLite format 3", 15) == 0) {
    r.is_sqlite = true;
    r.storage_kind = "SQLite";
    r.magic_ok = true;
    r.magic_hex = to_hex(data, 15);
    r.bdb_note = "Bitcoin Core / Core-fork SQLite wallet (format 3) — mkey/ckey still carved; "
                 "$bitcoin$ Hashcat 11300 applies";
    r.log.push_back("[+] " + r.bdb_note);
  }

  /* Coin hint from path (BTC / BCH / LTC / DOGE / Core fork) */
  {
    std::string pl = path_label;
    for (char& c : pl)
      if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    if (pl.find("bitcoincash") != std::string::npos || pl.find("\\bch\\") != std::string::npos)
      r.coin_label = "Bitcoin Cash";
    else if (pl.find("litecoin") != std::string::npos)
      r.coin_label = "Litecoin";
    else if (pl.find("dogecoin") != std::string::npos)
      r.coin_label = "Dogecoin";
    else if (pl.find("bitcoin") != std::string::npos)
      r.coin_label = "Bitcoin";
    else
      r.coin_label = "Core fork";
  }

  /* Berkeley DB magic check at offset 12 (BitcoinWalletAnalyzer style) */
  if (!r.is_sqlite && len >= 20) {
    static const uint8_t kMagic[8] = {0x62, 0x31, 0x05, 0x00, 0x09, 0x00, 0x00, 0x00};
    r.magic_hex = to_hex(data + 12, 8);
    r.magic_ok = (std::memcmp(data + 12, kMagic, 8) == 0);
    if (r.magic_ok) {
      r.is_bdb = true;
      r.storage_kind = "BDB";
      r.bdb_note = r.coin_label + " Core BDB magic OK (offset 12) — Hashcat 11300 / $bitcoin$";
      r.log.push_back("[+] " + r.bdb_note);
    } else {
      r.storage_kind = "raw/unknown";
      r.bdb_note = "magic mismatch — may still contain keys (raw dump / truncated / Core fork)";
      r.warnings.push_back("file is not a standard Bitcoin Core wallet magic: " + r.magic_hex);
      r.log.push_back("[!] " + r.bdb_note + " magic=" + r.magic_hex);
    }
  } else if (!r.is_sqlite) {
    r.storage_kind = "raw/unknown";
  }
  if (!r.coin_label.empty())
    r.log.push_back("[+] coin_label=" + r.coin_label + " storage=" + r.storage_kind);

  /* Primary: BitcoinWalletAnalyzer read_wallet — 48 bytes preceding ASCII "mkey" */
  {
    const char* needle = "mkey";
    for (size_t i = 0; i + 4 <= len; ++i) {
      if (std::memcmp(data + i, needle, 4) != 0) continue;
      if (i < 72) continue;
      MasterKeyInfo mk;
      mk.found = true;
      mk.file_offset = i - 72;
      mk.encrypted48.assign(data + i - 72, data + i - 72 + 48);
      mk.encrypted_hex = to_hex(mk.encrypted48);
      mk.iv_hex = to_hex(mk.encrypted48.data() + 16, 16);
      mk.ct_hex = to_hex(mk.encrypted48.data() + 32, 16);
      r.mkey = mk;
      r.log.push_back("[+] mkey enc48 @ " + std::to_string(mk.file_offset) + " (mkey-72)");
      r.log.push_back("    enc48=" + mk.encrypted_hex);
      break;
    }
  }

  /* Structured: \x04mkey\x01\x00\x00\x00 then 49s+9s+II (analyzer read_encrypted_key).
   * Note: Mizogg uses offset+8 into a 9-byte marker — we mirror that packing. */
  {
    static const uint8_t marker[] = {0x04, 'm', 'k', 'e', 'y', 0x01, 0x00, 0x00, 0x00};
    for (size_t i = 0; i + 8 + 49 + 9 + 8 <= len; ++i) {
      if (std::memcmp(data + i, marker, sizeof(marker)) != 0) continue;
      size_t o = i + 8; /* match Python: mkey_offset + 8 */
      uint32_t method = 0, iterations = 0;
      std::memcpy(&method, data + o + 49 + 9, 4);
      std::memcpy(&iterations, data + o + 49 + 9 + 4, 4);
      if (method > 2 || iterations == 0 || iterations > 100000000u) {
        r.log.push_back("[!] structured mkey @ " + std::to_string(i) +
                        " rejected (method=" + std::to_string(method) +
                        " iter=" + std::to_string(iterations) + ")");
        continue;
      }
      if (!r.mkey.found) {
        r.mkey.found = true;
        r.mkey.file_offset = i;
      }
      r.mkey.encrypted49.assign(data + o, data + o + 49);
      /* Prefer trailing 48 of the 49-byte field when leading byte is length/null */
      if (r.mkey.encrypted48.size() != 48) {
        if (data[o] == 0x00 || data[o] == 0x30)
          r.mkey.encrypted48.assign(data + o + 1, data + o + 49);
        else
          r.mkey.encrypted48.assign(data + o, data + o + 48);
        r.mkey.encrypted_hex = to_hex(r.mkey.encrypted48);
        r.mkey.iv_hex = to_hex(r.mkey.encrypted48.data() + 16, 16);
        r.mkey.ct_hex = to_hex(r.mkey.encrypted48.data() + 32, 16);
      }
      r.mkey.salt.assign(data + o + 49, data + o + 49 + 8);
      r.mkey.method = method;
      r.mkey.iterations = iterations;
      r.mkey.salt_hex = to_hex(r.mkey.salt);
      {
        std::ostringstream oss;
        oss << r.mkey.encrypted_hex << r.mkey.salt_hex << std::hex << std::setfill('0')
            << std::setw(8) << iterations;
        r.mkey.target_mkey_hex = oss.str();
      }
      r.log.push_back("[+] structured mkey meta method=" + std::to_string(method) +
                      " iter=" + std::to_string(iterations) + " salt=" + r.mkey.salt_hex);
      break;
    }
  }
  if (!r.mkey.found) {
    r.warnings.push_back("no master key (mkey) found");
    r.log.push_back("[!] no mkey in file");
  }

  /* Enumerate all ckeys — BitcoinWalletAnalyzer layout:
   * at ckey_offset-52: 123 bytes; [0..48)=enc, [56]=pubkey_len, [57..]=pubkey */
  {
    const char* needle = "ckey";
    size_t offset = 0;
    while (offset + 4 <= len) {
      size_t ckey_offset = (size_t)-1;
      for (size_t i = offset; i + 4 <= len; ++i) {
        if (std::memcmp(data + i, needle, 4) == 0) {
          ckey_offset = i;
          break;
        }
      }
      if (ckey_offset == (size_t)-1) break;
      if (ckey_offset >= 52 && ckey_offset - 52 + 123 <= len) {
        const uint8_t* blk = data + (ckey_offset - 52);
        CKeyInfo ck;
        ck.file_offset = ckey_offset - 52;
        ck.encrypted48.assign(blk, blk + 48);
        ck.encrypted_hex = to_hex(ck.encrypted48);
        uint8_t pklen = blk[56];
        if (!(pklen == 33 || pklen == 65)) {
          offset = ckey_offset + 4;
          continue;
        }
        if (57 + pklen > 123) {
          offset = ckey_offset + 4;
          continue;
        }
        uint8_t prefix = blk[57];
        if (!(prefix == 0x02 || prefix == 0x03 || prefix == 0x04)) {
          offset = ckey_offset + 4;
          continue;
        }
        ck.pubkey.assign(blk + 57, blk + 57 + pklen);
        ck.pubkey_hex = to_hex(ck.pubkey);
        pubkey_to_address(ck.pubkey, ck);
        /* de-dupe by encrypted hex */
        bool dup = false;
        for (auto& e : r.ckeys)
          if (e.encrypted_hex == ck.encrypted_hex) {
            dup = true;
            break;
          }
        if (!dup) {
          r.ckeys.push_back(std::move(ck));
          auto& last = r.ckeys.back();
          r.log.push_back("[+] ckey #" + std::to_string(r.ckeys.size()) +
                          " enc=" + last.encrypted_hex.substr(0, 16) + "...");
          if (last.address_ok)
            r.log.push_back("    addr=" + last.address + " pub=" + last.pubkey_hex);
        }
      }
      offset = ckey_offset + 4;
    }
    r.log.push_back("[+] total unique ckeys: " + std::to_string(r.ckeys.size()));
  }

  scan_meta_tags(r, data, len);
  r.log.push_back("[+] metadata tags recorded: " + std::to_string(r.meta.size()));
  return r;
}

std::string WalletDatParser::export_txt(const WalletParseResult& r) {
  std::ostringstream o;
  o << "TrueWalletCollider export\n";
  o << "path: " << r.path << "\n";
  o << "size: " << r.file_size << "\n";
  o << "magic_ok: " << (r.magic_ok ? "yes" : "no") << " magic=" << r.magic_hex << "\n";
  o << "storage: " << r.storage_kind << " coin: " << r.coin_label << "\n";
  o << "bdb: " << r.bdb_note << "\n\n";
  if (r.mkey.found) {
    o << "=== MASTER KEY ===\n";
    o << "offset: " << r.mkey.file_offset << "\n";
    o << "encrypted48: " << r.mkey.encrypted_hex << "\n";
    o << "salt: " << r.mkey.salt_hex << "\n";
    o << "method: " << r.mkey.method << "\n";
    o << "iterations: " << r.mkey.iterations << "\n";
    o << "iv: " << r.mkey.iv_hex << "\n";
    o << "ct: " << r.mkey.ct_hex << "\n";
    o << "target_mkey: " << r.mkey.target_mkey_hex << "\n\n";
  }
  o << "=== CKEYS (" << r.ckeys.size() << ") ===\n";
  for (size_t i = 0; i < r.ckeys.size(); ++i) {
    const auto& c = r.ckeys[i];
    o << "[" << i << "] offset=" << c.file_offset << "\n";
    o << "  encrypted: " << c.encrypted_hex << "\n";
    o << "  pubkey:    " << c.pubkey_hex << "\n";
    o << "  address:   " << c.address << "\n";
    o << "  sha256:    " << c.sha256_hex << "\n";
    o << "  ripemd160: " << c.ripemd160_hex << "\n";
    o << "  rawaddr:   " << c.address_raw_hex << "\n\n";
  }
  o << "=== METADATA TAGS ===\n";
  for (auto& m : r.meta) {
    o << m.tag << " @ " << m.offset << " — " << m.note << "\n";
    o << "  preview: " << m.preview_hex << "\n";
  }
  if (!r.warnings.empty()) {
    o << "\n=== WARNINGS ===\n";
    for (auto& w : r.warnings) o << "- " << w << "\n";
  }
  return o.str();
}

std::string WalletDatParser::export_json(const WalletParseResult& r) {
  auto esc = [](const std::string& s) {
    std::string o;
    for (char c : s) {
      if (c == '"' || c == '\\') o.push_back('\\');
      if (c == '\n') {
        o += "\\n";
        continue;
      }
      o.push_back(c);
    }
    return o;
  };
  std::ostringstream o;
  o << "{\n";
  o << "  \"tool\": \"TrueWalletCollider\",\n";
  o << "  \"path\": \"" << esc(r.path) << "\",\n";
  o << "  \"file_size\": " << r.file_size << ",\n";
  o << "  \"magic_ok\": " << (r.magic_ok ? "true" : "false") << ",\n";
  o << "  \"magic_hex\": \"" << r.magic_hex << "\",\n";
  o << "  \"mkey\": {\n";
  o << "    \"found\": " << (r.mkey.found ? "true" : "false") << ",\n";
  o << "    \"encrypted_hex\": \"" << r.mkey.encrypted_hex << "\",\n";
  o << "    \"salt_hex\": \"" << r.mkey.salt_hex << "\",\n";
  o << "    \"method\": " << r.mkey.method << ",\n";
  o << "    \"iterations\": " << r.mkey.iterations << ",\n";
  o << "    \"iv_hex\": \"" << r.mkey.iv_hex << "\",\n";
  o << "    \"ct_hex\": \"" << r.mkey.ct_hex << "\",\n";
  o << "    \"target_mkey_hex\": \"" << r.mkey.target_mkey_hex << "\"\n";
  o << "  },\n";
  o << "  \"ckeys\": [\n";
  for (size_t i = 0; i < r.ckeys.size(); ++i) {
    const auto& c = r.ckeys[i];
    o << "    {\n";
    o << "      \"encrypted_hex\": \"" << c.encrypted_hex << "\",\n";
    o << "      \"pubkey_hex\": \"" << c.pubkey_hex << "\",\n";
    o << "      \"address\": \"" << esc(c.address) << "\",\n";
    o << "      \"sha256_hex\": \"" << c.sha256_hex << "\",\n";
    o << "      \"ripemd160_hex\": \"" << c.ripemd160_hex << "\",\n";
    o << "      \"offset\": " << c.file_offset << "\n";
    o << "    }" << (i + 1 < r.ckeys.size() ? "," : "") << "\n";
  }
  o << "  ],\n";
  o << "  \"meta\": [\n";
  for (size_t i = 0; i < r.meta.size(); ++i) {
    o << "    {\"tag\":\"" << esc(r.meta[i].tag) << "\",\"offset\":" << r.meta[i].offset
      << ",\"note\":\"" << esc(r.meta[i].note) << "\"}"
      << (i + 1 < r.meta.size() ? "," : "") << "\n";
  }
  o << "  ]\n}\n";
  return o.str();
}

bool WalletDatParser::write_ckeys_file(const WalletParseResult& r, const std::string& path) {
  std::ofstream out(path);
  if (!out) return false;
  out << "# TrueWalletCollider ckeys export (HEX96 [PUBHEX])\n";
  for (auto& c : r.ckeys) {
    out << c.encrypted_hex;
    if (!c.pubkey_hex.empty()) out << " " << c.pubkey_hex;
    out << "\n";
  }
  return true;
}

bool WalletDatParser::write_mkeys_file(const WalletParseResult& r, const std::string& path) {
  std::ofstream out(path);
  if (!out) return false;
  out << "# TrueWalletCollider mkey export (HEX96)\n";
  if (r.mkey.found && r.mkey.encrypted_hex.size() == 96)
    out << r.mkey.encrypted_hex << "\n";
  return true;
}
