#include "Salvage.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

static std::string to_hex(const uint8_t* p, size_t n) {
  static const char* h = "0123456789abcdef";
  std::string s(n * 2, '0');
  for (size_t i = 0; i < n; ++i) {
    s[i * 2] = h[p[i] >> 4];
    s[i * 2 + 1] = h[p[i] & 0xf];
  }
  return s;
}

SalvageReport salvage_carve(const uint8_t* data, size_t len, const std::string& path_label) {
  SalvageReport r;
  r.path = path_label;
  r.file_size = len;

  if (len >= 20) {
    static const uint8_t kMagic[8] = {0x62, 0x31, 0x05, 0x00, 0x09, 0x00, 0x00, 0x00};
    r.magic_ok = std::memcmp(data + 12, kMagic, 8) == 0;
  }

  /* Reuse full parser for structured hits, then aggressive carve */
  WalletDatParser parser;
  auto parsed = parser.parse_bytes(data, len, path_label);
  if (parsed.mkey.found) {
    r.mkeys.push_back(parsed.mkey);
    r.mkey_candidates = 1;
  }
  for (auto& ck : parsed.ckeys) {
    SalvageCKey s;
    s.ckey = ck;
    s.score = 50;
    if (ck.address_ok) s.score += 30;
    if (ck.pubkey.size() == 33 || ck.pubkey.size() == 65) s.score += 20;
    s.rank_note = "structured ckey parse";
    r.ckeys_ranked.push_back(std::move(s));
  }

  /* Aggressive: every "mkey" ASCII with plausible 48-byte prefix */
  for (size_t i = 4; i + 4 <= len; ++i) {
    if (std::memcmp(data + i, "mkey", 4) != 0) continue;
    if (i < 72) continue;
    MasterKeyInfo mk;
    mk.found = true;
    mk.file_offset = i - 72;
    mk.encrypted48.assign(data + i - 72, data + i - 72 + 48);
    mk.encrypted_hex = to_hex(mk.encrypted48.data(), 48);
    bool dup = false;
    for (auto& e : r.mkeys)
      if (e.encrypted_hex == mk.encrypted_hex) {
        dup = true;
        break;
      }
    if (!dup) {
      r.mkeys.push_back(mk);
      r.notes.push_back("carved mkey-72 @ " + std::to_string(mk.file_offset));
    }
  }
  r.mkey_candidates = (int)r.mkeys.size();

  /* Carve compressed pubkeys 02/03 + 32 bytes */
  for (size_t i = 0; i + 33 <= len; ++i) {
    if (data[i] != 0x02 && data[i] != 0x03) continue;
    /* cheap entropy-ish: not all zeros */
    bool nz = false;
    for (int j = 1; j < 33; ++j)
      if (data[i + j]) {
        nz = true;
        break;
      }
    if (!nz) continue;
    ++r.pubkey_scraps;
    if (r.pubkey_scraps > 200) break;
  }

  std::sort(r.ckeys_ranked.begin(), r.ckeys_ranked.end(),
            [](const SalvageCKey& a, const SalvageCKey& b) { return a.score > b.score; });
  r.ckey_candidates = (int)r.ckeys_ranked.size();

  /* Heatmap: 64 buckets */
  const int buckets = 64;
  std::vector<int> heat(buckets, 0);
  auto mark = [&](size_t off, int w) {
    if (len == 0) return;
    int b = (int)((off * (size_t)buckets) / len);
    if (b < 0) b = 0;
    if (b >= buckets) b = buckets - 1;
    heat[b] += w;
  };
  for (auto& m : r.mkeys) mark(m.file_offset, 5);
  for (auto& c : r.ckeys_ranked) mark(c.ckey.file_offset, 2);

  std::ostringstream hm;
  hm << "offset heatmap (" << buckets << " bins):\n";
  int mx = 1;
  for (int v : heat)
    if (v > mx) mx = v;
  for (int i = 0; i < buckets; ++i) {
    int bar = (heat[i] * 16) / mx;
    hm << (bar ? std::string(bar, '#') : ".");
    if ((i + 1) % 16 == 0) hm << "\n";
  }
  r.heatmap_ascii = hm.str();

  if (!r.magic_ok) r.notes.push_back("BDB magic mismatch — treated as raw dump carve");
  if (r.mkey_candidates == 0) r.notes.push_back("no mkey candidates carved");
  if (r.ckey_candidates == 0) r.notes.push_back("no ckey candidates carved");
  return r;
}

SalvageReport salvage_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    SalvageReport r;
    r.path = path;
    r.notes.push_back("cannot open");
    return r;
  }
  in.seekg(0, std::ios::end);
  auto sz = in.tellg();
  in.seekg(0, std::ios::beg);
  std::vector<uint8_t> buf((size_t)std::max<std::streamoff>(0, sz));
  if (!buf.empty()) in.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
  return salvage_carve(buf.data(), buf.size(), path);
}

std::string salvage_export_txt(const SalvageReport& r) {
  std::ostringstream o;
  o << "TrueWalletCollider SALVAGE REPORT\n";
  o << "path: " << r.path << "\nsize: " << r.file_size << " magic_ok: " << (r.magic_ok ? 1 : 0)
    << "\n";
  o << "mkey_candidates: " << r.mkey_candidates << "\n";
  o << "ckey_candidates: " << r.ckey_candidates << "\n";
  o << "pubkey_scraps: " << r.pubkey_scraps << "\n\n";
  o << r.heatmap_ascii << "\n";
  o << "=== MKEYS ===\n";
  for (size_t i = 0; i < r.mkeys.size(); ++i) {
    o << "[" << i << "] off=" << r.mkeys[i].file_offset << " enc=" << r.mkeys[i].encrypted_hex
      << " salt=" << r.mkeys[i].salt_hex << " iter=" << r.mkeys[i].iterations << "\n";
  }
  o << "\n=== CKEYS (ranked) ===\n";
  for (size_t i = 0; i < r.ckeys_ranked.size(); ++i) {
    const auto& c = r.ckeys_ranked[i];
    o << "[" << i << "] score=" << c.score << " " << c.rank_note << "\n";
    o << "  addr=" << c.ckey.address << "\n";
    o << "  enc=" << c.ckey.encrypted_hex << "\n";
    o << "  pub=" << c.ckey.pubkey_hex << "\n";
  }
  o << "\n=== NOTES ===\n";
  for (auto& n : r.notes) o << "- " << n << "\n";
  return o.str();
}

std::string salvage_export_json(const SalvageReport& r) {
  auto esc = [](const std::string& s) {
    std::string o;
    for (char c : s) {
      if (c == '"' || c == '\\') o.push_back('\\');
      o.push_back(c);
    }
    return o;
  };
  std::ostringstream o;
  o << "{\n  \"tool\": \"TrueWalletCollider-salvage\",\n";
  o << "  \"path\": \"" << esc(r.path) << "\",\n";
  o << "  \"file_size\": " << r.file_size << ",\n";
  o << "  \"magic_ok\": " << (r.magic_ok ? "true" : "false") << ",\n";
  o << "  \"mkey_candidates\": " << r.mkey_candidates << ",\n";
  o << "  \"ckey_candidates\": " << r.ckey_candidates << ",\n";
  o << "  \"pubkey_scraps\": " << r.pubkey_scraps << ",\n";
  o << "  \"ckeys\": [\n";
  for (size_t i = 0; i < r.ckeys_ranked.size(); ++i) {
    const auto& c = r.ckeys_ranked[i];
    o << "    {\"score\":" << c.score << ",\"address\":\"" << esc(c.ckey.address)
      << "\",\"encrypted_hex\":\"" << c.ckey.encrypted_hex << "\",\"pubkey_hex\":\""
      << c.ckey.pubkey_hex << "\",\"offset\":" << c.ckey.file_offset << "}"
      << (i + 1 < r.ckeys_ranked.size() ? "," : "") << "\n";
  }
  o << "  ]\n}\n";
  return o.str();
}

bool salvage_write_report(const SalvageReport& r, const std::string& path_txt,
                          const std::string& path_json) {
  bool ok = true;
  if (!path_txt.empty()) {
    std::ofstream o(path_txt);
    if (!o)
      ok = false;
    else
      o << salvage_export_txt(r);
  }
  if (!path_json.empty()) {
    std::ofstream o(path_json);
    if (!o)
      ok = false;
    else
      o << salvage_export_json(r);
  }
  return ok;
}
