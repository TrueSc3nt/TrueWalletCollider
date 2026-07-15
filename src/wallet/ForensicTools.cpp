#include "ForensicTools.h"
#include "../crypto/crypto_wallet.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
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
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

static int hex_nib(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool hex_decode(const std::string& hex, std::vector<uint8_t>& out) {
  out.clear();
  std::string h;
  for (char c : hex)
    if (!std::isspace((unsigned char)c) && c != ':') h.push_back(c);
  if (h.size() % 2) return false;
  for (size_t i = 0; i + 1 < h.size(); i += 2) {
    int a = hex_nib(h[i]), b = hex_nib(h[i + 1]);
    if (a < 0 || b < 0) return false;
    out.push_back((uint8_t)((a << 4) | b));
  }
  return true;
}

static std::string to_hex(const uint8_t* p, size_t n) {
  static const char* H = "0123456789abcdef";
  std::string s;
  s.resize(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s[i * 2] = H[p[i] >> 4];
    s[i * 2 + 1] = H[p[i] & 0xf];
  }
  return s;
}

static std::string exe_dir() {
#ifdef _WIN32
  char module[MAX_PATH] = {};
  if (GetModuleFileNameA(nullptr, module, MAX_PATH)) {
    std::string dir = module;
    size_t slash = dir.find_last_of("\\/");
    if (slash != std::string::npos) return dir.substr(0, slash + 1);
  }
#endif
  return {};
}

bool bip39_load_wordlist(std::vector<std::string>* words_out, std::string* err) {
  if (!words_out) return false;
  words_out->clear();
  std::vector<std::string> cands = {"data/bip39_english.txt", "data\\bip39_english.txt",
                                    exe_dir() + "data/bip39_english.txt",
                                    exe_dir() + "data\\bip39_english.txt"};
  for (auto& p : cands) {
    std::ifstream f(p);
    if (!f) continue;
    std::string line;
    while (std::getline(f, line)) {
      while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
      if (!line.empty()) words_out->push_back(line);
    }
    if (words_out->size() == 2048) return true;
    if (err) *err = "wordlist size " + std::to_string(words_out->size()) + " from " + p;
  }
  if (err) *err = "data/bip39_english.txt not found (2048 words)";
  return false;
}

static int bip39_word_index(const std::vector<std::string>& words, const std::string& w) {
  auto it = std::lower_bound(words.begin(), words.end(), w);
  if (it == words.end() || *it != w) return -1;
  return (int)(it - words.begin());
}

Bip39Result bip39_validate_mnemonic(const std::string& mnemonic) {
  Bip39Result r;
  std::vector<std::string> words;
  std::string err;
  if (!bip39_load_wordlist(&words, &err)) {
    r.message = err;
    return r;
  }
  std::vector<std::string> toks;
  std::string cur;
  for (char c : mnemonic) {
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      if (!cur.empty()) {
        toks.push_back(cur);
        cur.clear();
      }
    } else
      cur.push_back((char)std::tolower((unsigned char)c));
  }
  if (!cur.empty()) toks.push_back(cur);
  r.word_count = (int)toks.size();
  if (!(r.word_count == 12 || r.word_count == 15 || r.word_count == 18 || r.word_count == 21 ||
        r.word_count == 24)) {
    r.message = "unsupported length (need 12/15/18/21/24), got " + std::to_string(r.word_count);
    return r;
  }
  std::vector<int> idx;
  for (auto& t : toks) {
    int i = bip39_word_index(words, t);
    if (i < 0) {
      r.unknown_words.push_back(t);
    } else
      idx.push_back(i);
  }
  if (!r.unknown_words.empty()) {
    r.message = "unknown words: " + std::to_string(r.unknown_words.size());
    return r;
  }
  /* Build bitstring */
  int ent_bits = r.word_count * 11 * 32 / 33; /* entropy bits */
  int cs_bits = ent_bits / 32;
  int total_bits = ent_bits + cs_bits;
  std::vector<uint8_t> bits((total_bits + 7) / 8, 0);
  int bitpos = 0;
  for (int v : idx) {
    for (int b = 10; b >= 0; --b) {
      if (v & (1 << b)) bits[bitpos / 8] |= (uint8_t)(1 << (7 - (bitpos % 8)));
      ++bitpos;
    }
  }
  std::vector<uint8_t> entropy(ent_bits / 8);
  for (size_t i = 0; i < entropy.size(); ++i) entropy[i] = bits[i];
  uint8_t hash[32];
  sha256(entropy.data(), entropy.size(), hash);
  unsigned expect = hash[0] >> (8 - cs_bits);
  unsigned got = 0;
  for (int i = 0; i < cs_bits; ++i) {
    int bp = ent_bits + i;
    if (bits[bp / 8] & (1 << (7 - (bp % 8)))) got |= (1u << (cs_bits - 1 - i));
  }
  r.checksum_ok = (got == expect);
  r.ok = r.checksum_ok;
  r.message = r.checksum_ok ? ("OK BIP39 checksum (" + std::to_string(r.word_count) + " words)")
                            : "checksum FAIL";
  return r;
}

BrainwalletResult brainwallet_sha256_to_wif(const std::string& passphrase) {
  BrainwalletResult r;
  r.passphrase = passphrase;
  if (passphrase.empty()) {
    r.message = "empty passphrase";
    return r;
  }
  uint8_t priv[32];
  sha256((const uint8_t*)passphrase.data(), passphrase.size(), priv);
  r.priv_hex = to_hex(priv, 32);
  r.wif_uncompressed = privkey_to_wif(priv, false);
  r.wif_compressed = privkey_to_wif(priv, true);
  r.ok = !r.wif_compressed.empty();
  r.message = r.ok ? "SHA256(passphrase) → WIF" : "WIF encode failed";
  return r;
}

std::string base58_encode_hex(const std::string& hex_payload) {
  std::vector<uint8_t> b;
  if (!hex_decode(hex_payload, b) || b.empty()) return {};
  return base58_encode(b.data(), b.size());
}

std::string base58check_encode_versioned(uint8_t version, const uint8_t* payload, size_t len) {
  std::vector<uint8_t> data;
  data.push_back(version);
  data.insert(data.end(), payload, payload + len);
  uint8_t chk[32];
  double_sha256(data.data(), data.size(), chk);
  data.insert(data.end(), chk, chk + 4);
  return base58_encode(data.data(), data.size());
}

/* ---- Bech32 (BIP173) ---- */
static const char* BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
  static const uint32_t GEN[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
  uint32_t chk = 1;
  for (uint8_t v : values) {
    uint8_t b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (int i = 0; i < 5; ++i)
      if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

static std::vector<uint8_t> bech32_hrp_expand(const std::string& hrp) {
  std::vector<uint8_t> r;
  for (char c : hrp) r.push_back((uint8_t)(c >> 5));
  r.push_back(0);
  for (char c : hrp) r.push_back((uint8_t)(c & 31));
  return r;
}

static bool convert_bits(const std::vector<uint8_t>& in, int from, int to, bool pad,
                         std::vector<uint8_t>& out) {
  out.clear();
  int acc = 0, bits = 0;
  int maxv = (1 << to) - 1;
  for (uint8_t v : in) {
    if (v >> from) return false;
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push_back((uint8_t)((acc >> bits) & maxv));
    }
  }
  if (pad) {
    if (bits) out.push_back((uint8_t)((acc << (to - bits)) & maxv));
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    return false;
  }
  return true;
}

std::string bech32_encode(const std::string& hrp, int witver, const uint8_t* prog, size_t prog_len) {
  if (witver < 0 || witver > 16 || prog_len < 2 || prog_len > 40) return {};
  std::vector<uint8_t> data;
  data.push_back((uint8_t)witver);
  std::vector<uint8_t> progv(prog, prog + prog_len);
  std::vector<uint8_t> conv;
  if (!convert_bits(progv, 8, 5, true, conv)) return {};
  data.insert(data.end(), conv.begin(), conv.end());
  auto values = bech32_hrp_expand(hrp);
  values.insert(values.end(), data.begin(), data.end());
  for (int i = 0; i < 6; ++i) values.push_back(0);
  uint32_t polymod = bech32_polymod(values) ^ 1;
  std::string out = hrp + "1";
  for (uint8_t d : data) out.push_back(BECH32_CHARSET[d]);
  for (int i = 0; i < 6; ++i) out.push_back(BECH32_CHARSET[(polymod >> (5 * (5 - i))) & 31]);
  return out;
}

static double shannon(const uint8_t* data, size_t len) {
  if (!len) return 0;
  size_t hist[256] = {};
  for (size_t i = 0; i < len; ++i) ++hist[data[i]];
  double h = 0;
  for (int i = 0; i < 256; ++i) {
    if (!hist[i]) continue;
    double p = (double)hist[i] / (double)len;
    h -= p * std::log2(p);
  }
  return h;
}

HexDumpResult hex_dump_entropy(const uint8_t* data, size_t len, size_t max_bytes) {
  HexDumpResult r;
  r.size = len;
  size_t n = (std::min)(len, max_bytes);
  r.shannon_entropy = shannon(data, n);
  std::ostringstream o;
  for (size_t i = 0; i < n; i += 16) {
    char line[128];
    std::snprintf(line, sizeof(line), "%08zx  ", i);
    o << line;
    for (size_t j = 0; j < 16; ++j) {
      if (i + j < n) {
        std::snprintf(line, sizeof(line), "%02x ", data[i + j]);
        o << line;
      } else
        o << "   ";
    }
    o << " |";
    for (size_t j = 0; j < 16 && i + j < n; ++j) {
      unsigned char c = data[i + j];
      o << (char)((c >= 32 && c < 127) ? c : '.');
    }
    o << "|\n";
  }
  if (len > max_bytes) o << "... truncated (" << len << " bytes total)\n";
  r.hex_dump = o.str();
  char sum[128];
  std::snprintf(sum, sizeof(sum), "size=%zu entropy=%.3f bits/byte (sample %zu)", len,
                r.shannon_entropy, n);
  r.summary = sum;
  return r;
}

HexDumpResult hex_dump_file(const std::string& path, size_t max_bytes) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    HexDumpResult r;
    r.summary = "cannot open " + path;
    return r;
  }
  std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  return hex_dump_entropy(buf.data(), buf.size(), max_bytes);
}

WalletDiffResult wallet_dat_diff(const std::string& path_a, const std::string& path_b) {
  WalletDiffResult r;
  std::ifstream fa(path_a, std::ios::binary), fb(path_b, std::ios::binary);
  if (!fa || !fb) {
    r.report = "cannot open one or both files";
    return r;
  }
  std::vector<uint8_t> a((std::istreambuf_iterator<char>(fa)), std::istreambuf_iterator<char>());
  std::vector<uint8_t> b((std::istreambuf_iterator<char>(fb)), std::istreambuf_iterator<char>());
  r.size_a = a.size();
  r.size_b = b.size();
  size_t n = (std::min)(a.size(), b.size());
  for (size_t i = 0; i < n; ++i)
    if (a[i] != b[i]) ++r.bytes_differ;
  r.bytes_differ += (std::max)(a.size(), b.size()) - n;

  WalletDatParser p;
  auto wa = p.parse_file(path_a);
  auto wb = p.parse_file(path_b);
  r.ckeys_a = wa.ckey_count();
  r.ckeys_b = wb.ckey_count();
  r.same_ckey_count = (r.ckeys_a == r.ckeys_b);
  r.same_mkey = wa.mkey.found && wb.mkey.found && wa.mkey.encrypted_hex == wb.mkey.encrypted_hex &&
                wa.mkey.salt_hex == wb.mkey.salt_hex;

  std::ostringstream o;
  o << "A: " << path_a << " (" << r.size_a << " bytes, ckeys=" << r.ckeys_a << ")\n";
  o << "B: " << path_b << " (" << r.size_b << " bytes, ckeys=" << r.ckeys_b << ")\n";
  o << "byte diffs: " << r.bytes_differ << "\n";
  o << "same mkey blob: " << (r.same_mkey ? "yes" : "no") << "\n";
  o << "same ckey count: " << (r.same_ckey_count ? "yes" : "no") << "\n";
  if (wa.mkey.found && wb.mkey.found) {
    o << "iters A/B: " << wa.mkey.iterations << " / " << wb.mkey.iterations << "\n";
  }
  r.report = o.str();
  r.ok = true;
  return r;
}

std::vector<StringsHit> strings_scavenge(const uint8_t* data, size_t len, size_t min_len,
                                         size_t max_hits) {
  std::vector<StringsHit> hits;
  size_t i = 0;
  while (i < len && hits.size() < max_hits) {
    if (data[i] >= 32 && data[i] < 127) {
      size_t j = i;
      while (j < len && data[j] >= 32 && data[j] < 127) ++j;
      if (j - i >= min_len) {
        StringsHit h;
        h.offset = i;
        h.text.assign((const char*)data + i, j - i);
        /* Prefer interesting strings */
        std::string low = h.text;
        for (char& c : low) c = (char)std::tolower((unsigned char)c);
        bool interesting = low.find("bitcoin") != std::string::npos ||
                           low.find("wallet") != std::string::npos ||
                           low.find("mkey") != std::string::npos ||
                           low.find("pass") != std::string::npos ||
                           low.find("seed") != std::string::npos ||
                           low.find("ckey") != std::string::npos || h.text.size() >= 12;
        if (interesting) hits.push_back(h);
      }
      i = j;
    } else
      ++i;
  }
  return hits;
}

std::vector<StringsHit> strings_scavenge_file(const std::string& path, size_t min_len) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  return strings_scavenge(buf.data(), buf.size(), min_len);
}

BalanceLookupResult address_balance_lookup(const std::string& address, bool enable_http) {
  BalanceLookupResult r;
  r.address = address;
  if (address.empty()) {
    r.message = "empty address";
    return r;
  }
  if (!enable_http) {
    r.message = "HTTP lookup disabled — enable optional read-only network in GUI";
    return r;
  }
#ifdef _WIN32
  r.http_attempted = true;
  std::wstring host = L"blockchain.info";
  std::string path = "/rawaddr/" + address + "?limit=0";
  std::wstring wpath(path.begin(), path.end());
  HINTERNET ses = WinHttpOpen(L"TrueWalletCollider/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!ses) {
    r.message = "WinHttpOpen failed";
    return r;
  }
  HINTERNET conn = WinHttpConnect(ses, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (!conn) {
    WinHttpCloseHandle(ses);
    r.message = "WinHttpConnect failed";
    return r;
  }
  HINTERNET req = WinHttpOpenRequest(conn, L"GET", wpath.c_str(), nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!req) {
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(ses);
    r.message = "WinHttpOpenRequest failed";
    return r;
  }
  BOOL ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
  if (ok) ok = WinHttpReceiveResponse(req, nullptr);
  if (!ok) {
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(ses);
    r.message = "HTTP request failed";
    return r;
  }
  std::string body;
  for (;;) {
    DWORD avail = 0;
    if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
    std::vector<char> buf(avail);
    DWORD read = 0;
    if (!WinHttpReadData(req, buf.data(), avail, &read) || read == 0) break;
    body.append(buf.data(), read);
    if (body.size() > 200000) break;
  }
  WinHttpCloseHandle(req);
  WinHttpCloseHandle(conn);
  WinHttpCloseHandle(ses);
  r.raw_json = body;
  r.ok = !body.empty();
  r.message = r.ok ? "OK (blockchain.info rawaddr)" : "empty response";
  return r;
#else
  r.message = "HTTP balance lookup is Windows-only in this build";
  return r;
#endif
}

std::vector<TriageWalletRow> multi_wallet_triage(const std::string& folder) {
  std::vector<TriageWalletRow> out;
#ifdef _WIN32
  std::string base = folder;
  if (base.empty()) return out;
  if (base.back() != '\\' && base.back() != '/') base += "\\";
  WIN32_FIND_DATAA fd{};
  HANDLE h = FindFirstFileA((base + "*.dat").c_str(), &fd);
  if (h == INVALID_HANDLE_VALUE) return out;
  WalletDatParser parser;
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    TriageWalletRow row;
    row.path = base + fd.cFileName;
    auto w = parser.parse_file(row.path);
    row.size = w.file_size;
    row.mkey = w.mkey.found;
    row.ckeys = w.ckey_count();
    row.iterations = w.mkey.found ? w.mkey.iterations : 0;
    if (!w.magic_ok) row.note = "no BDB magic";
    else if (!w.mkey.found) row.note = "unencrypted or unknown";
    else row.note = "iters=" + std::to_string(row.iterations);
    out.push_back(row);
  } while (FindNextFileA(h, &fd));
  FindClose(h);
  std::sort(out.begin(), out.end(), [](const TriageWalletRow& a, const TriageWalletRow& b) {
    if (a.iterations != b.iterations) {
      if (a.iterations == 0) return false;
      if (b.iterations == 0) return true;
      return a.iterations < b.iterations;
    }
    return a.size < b.size;
  });
#else
  (void)folder;
#endif
  return out;
}
