#pragma once
#include "WalletDat.h"
#include <string>
#include <vector>

struct SalvageCKey {
  CKeyInfo ckey;
  int score = 0; /* higher = more salvageable */
  std::string rank_note;
};

struct SalvageReport {
  std::string path;
  size_t file_size = 0;
  bool magic_ok = false;
  int mkey_candidates = 0;
  int ckey_candidates = 0;
  int pubkey_scraps = 0;
  std::vector<MasterKeyInfo> mkeys;
  std::vector<SalvageCKey> ckeys_ranked;
  std::vector<std::string> notes;
  std::string heatmap_ascii; /* offset intensity bars */
};

/** Carve mkey/ckey/pubkey blobs from damaged BDB / raw dumps. */
SalvageReport salvage_carve(const uint8_t* data, size_t len, const std::string& path_label);
SalvageReport salvage_file(const std::string& path);

std::string salvage_export_txt(const SalvageReport& r);
std::string salvage_export_json(const SalvageReport& r);
bool salvage_write_report(const SalvageReport& r, const std::string& path_txt,
                          const std::string& path_json);
