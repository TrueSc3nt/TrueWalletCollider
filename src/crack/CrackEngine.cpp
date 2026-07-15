#include "CrackEngine.h"
#include "../wallet/DualVerify.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

static const unsigned char PADDING16[16] = {
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10};

static const char* POC_CKEY =
    "2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155";
static const char* POC_KEY =
    "563758754506d53828c5383d2cb6296efe7f217c5ef6a84b13bce3ecec66da2e";
static const char* POC_PUB =
    "0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5";
static const char* POC_WIF_U =
    "5JHsqscg3o1iAWjRP83nWWJFbgMrjnXwVQoxejtAqp4t6cCVgbo";
static const char* POC_WIF_C =
    "KyKVQiQTML68gzEEce7HsEK9S4j4XqyZWQ6GdaGrSSk8XZJHqNWe";

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
    int hi = hex_nibble(hex[i * 2]);
    int lo = hex_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

static std::string bytes_to_hex(const uint8_t* p, size_t n) {
  static const char* hexd = "0123456789abcdef";
  std::string s;
  s.resize(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s[i * 2] = hexd[p[i] >> 4];
    s[i * 2 + 1] = hexd[p[i] & 0xf];
  }
  return s;
}

static TargetCipher make_target(const std::vector<uint8_t>& blob48) {
  TargetCipher t{};
  std::memcpy(t.c3, blob48.data() + 32, 16);
  for (int i = 0; i < 16; ++i)
    t.expected[i] = (uint8_t)(blob48[16 + i] ^ PADDING16[i]);
  return t;
}

static void key_hex_to_u256(const std::string& hex64, uint64_t out[4]) {
  std::vector<uint8_t> b;
  hex_to_bytes(hex64, b);
  out[0] = out[1] = out[2] = out[3] = 0;
  for (int i = 0; i < 32; ++i) {
    int word = i / 8;
    int shift = (7 - (i % 8)) * 8;
    out[word] |= ((uint64_t)b[i]) << shift;
  }
}

static void u256_sub_u64(uint64_t w[4], uint64_t sub) {
  uint64_t borrow = sub;
  for (int i = 3; i >= 0; --i) {
    uint64_t old = w[i];
    w[i] = old - borrow;
    borrow = (old < borrow) ? 1ull : 0ull;
  }
}

CrackEngine::CrackEngine() = default;

CrackEngine::~CrackEngine() {
  request_stop();
  join_timeout(2000);
}

void CrackEngine::set_targets(std::vector<CrackTarget> targets) {
  targets_ = std::move(targets);
}

void CrackEngine::set_config(const CrackConfig& cfg) { cfg_ = cfg; }

std::string CrackEngine::format_rate(double keys_per_sec) {
  const char* units[] = {"keys/s", "Kkeys/s", "Mkeys/s", "Gkeys/s", "Tkeys/s",
                         "Pkeys/s", "Ekeys/s"};
  double v = keys_per_sec;
  int u = 0;
  while (v >= 1000.0 && u < 6) {
    v /= 1000.0;
    ++u;
  }
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%.2f %s", v, units[u]);
  return buf;
}

std::vector<std::string> CrackEngine::list_devices() {
  std::vector<std::string> out;
  int n = 0;
  if (cudaGetDeviceCount(&n) != cudaSuccess) return out;
  for (int i = 0; i < n; ++i) {
    cudaDeviceProp p{};
    if (cudaGetDeviceProperties(&p, i) != cudaSuccess) continue;
    char buf[256];
    std::snprintf(buf, sizeof(buf), "%d: %s (sm_%d%d, %d SMs)", i, p.name,
                  p.major, p.minor, p.multiProcessorCount);
    out.emplace_back(buf);
  }
  return out;
}

bool CrackEngine::try_key(const std::string& hex64, std::string* msg_out) {
  std::vector<uint8_t> key;
  if (!hex_to_bytes(hex64, key) || key.size() != 32) {
    if (msg_out) *msg_out = "need 64 hex chars";
    return false;
  }
  if (targets_.empty()) {
    if (msg_out) *msg_out = "no targets loaded";
    return false;
  }
  bool any = false;
  std::ostringstream oss;
  for (size_t i = 0; i < targets_.size(); ++i) {
    int m = 0;
    host_aes256_check_key(key.data(), &targets_[i].cipher, &m);
    if (!m) continue;
    any = true;
    PostHitResult pr = post_hit_decrypt_wif(targets_[i].wallet, key.data());
    save_found_wallet(cfg_.found_file, targets_[i].wallet, key.data(), pr, (int)i);
    {
      std::lock_guard<std::mutex> lock(status_.mu);
      status_.hit = true;
      status_.hit_result = pr;
      status_.hit_key_hex = hex64;
      status_.hit_target_index = (int)i;
      status_.last_message = pr.message;
    }
    oss << "HIT target " << i << "\n" << pr.message << "\n";
  }
  if (!any) {
    if (msg_out) *msg_out = "key did not match any target";
    return false;
  }
  if (msg_out) *msg_out = oss.str();
  return true;
}

bool CrackEngine::start() {
  if (status_.running.load()) return false;
  if (targets_.empty()) {
    std::lock_guard<std::mutex> lock(status_.mu);
    status_.last_message = "no targets";
    return false;
  }
  if (targets_.size() > 64) {
    std::lock_guard<std::mutex> lock(status_.mu);
    status_.last_message = "max 64 targets";
    return false;
  }
  status_.stop_requested = false;
  status_.keys_total = 0;
  status_.launches = 0;
  status_.rate = 0;
  status_.peak_rate = 0;
  status_.hit = false;
  if (thread_.joinable()) thread_.join();
  thread_ = std::thread([this] { worker(); });
  return true;
}

void CrackEngine::request_stop() { status_.stop_requested = true; }

void CrackEngine::stop() {
  request_stop();
  join_timeout(15000);
}

bool CrackEngine::join_timeout(int timeout_ms) {
  if (!thread_.joinable()) return true;
  if (timeout_ms <= 0) {
    thread_.detach();
    return false;
  }
#ifdef _WIN32
  HANDLE h = (HANDLE)thread_.native_handle();
  DWORD w = WaitForSingleObject(h, (DWORD)timeout_ms);
  if (w == WAIT_OBJECT_0) {
    thread_.join();
    return true;
  }
  /* Still running — detach so ~thread does not std::terminate() and freeze exit. */
  thread_.detach();
  return false;
#else
  (void)timeout_ms;
  thread_.join();
  return true;
#endif
}

void CrackEngine::worker() {
  status_.running = true;
  auto fail = [&](const std::string& m) {
    std::lock_guard<std::mutex> lock(status_.mu);
    status_.last_message = m;
    status_.running = false;
  };

  std::vector<TargetCipher> ciphers;
  ciphers.reserve(targets_.size());
  for (auto& t : targets_) ciphers.push_back(t.cipher);

  if (cuda_aes_init(cfg_.device) != 0) {
    fail("cuda_aes_init failed");
    return;
  }
  if (cuda_aes_upload_targets(ciphers.data(), (int)ciphers.size()) != 0) {
    cuda_aes_shutdown();
    fail("upload targets failed");
    return;
  }

  int blocks = cfg_.blocks;
  int threads = cfg_.threads;
  if (blocks <= 0 || threads <= 0) {
    int sb = 256, st = 256;
    cuda_aes_suggest_grid(cfg_.device, &sb, &st);
    if (blocks <= 0) blocks = sb;
    if (threads <= 0) threads = st;
  }
  status_.blocks = blocks;
  status_.threads = threads;
  status_.device = cfg_.device;

  size_t free_b = cuda_free_vram_bytes(cfg_.device);
  size_t budget_mb = 0;
  if (cfg_.mem == "auto" || cfg_.mem == "AUTO") {
    budget_mb = (size_t)((free_b * 90) / 100 / (1024ull * 1024ull));
    if (budget_mb < 128) budget_mb = 128;
  } else {
    budget_mb = (size_t)std::strtoull(cfg_.mem.c_str(), nullptr, 10);
  }
  uint64_t keys_per = (uint64_t)cuda_estimate_keys_for_vram_mb(budget_mb);
  uint64_t grid_keys = (uint64_t)blocks * (uint64_t)threads;
  if (keys_per < grid_keys * (uint64_t)cfg_.streams)
    keys_per = grid_keys * (uint64_t)cfg_.streams;
  keys_per = (keys_per / grid_keys) * grid_keys;
  if (keys_per == 0) keys_per = grid_keys;
  status_.keys_per_launch = keys_per;

  cudaDeviceProp prop{};
  cudaGetDeviceProperties(&prop, cfg_.device);
  {
    std::lock_guard<std::mutex> lock(status_.mu);
    status_.device_name = prop.name;
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "Device %s | grid %d,%d | streams %d | keys/launch %llu | VRAM budget %zu MiB",
                  prop.name, blocks, threads, cfg_.streams,
                  (unsigned long long)keys_per, budget_mb);
    status_.last_message = buf;
  }

  LaunchConfig lcfg{};
  lcfg.device = cfg_.device;
  lcfg.blocks = blocks;
  lcfg.threads = threads;
  lcfg.keys_per_launch = keys_per;
  lcfg.mode = cfg_.mode;
  lcfg.mixed_span = cfg_.mixed_span;
  lcfg.streams = cfg_.streams;
  lcfg.partial_prefix_len = 0;
  std::memset(lcfg.partial_prefix, 0, 32);
  if (cfg_.mode == MODE_SEQUENTIAL) {
    if (cfg_.seq_start.empty()) {
      key_hex_to_u256(POC_KEY, lcfg.seq_base);
      u256_sub_u64(lcfg.seq_base, 1024);
    } else if (cfg_.seq_start.size() == 64) {
      key_hex_to_u256(cfg_.seq_start, lcfg.seq_base);
    }
  } else if (cfg_.mode == MODE_PARTIAL) {
    std::vector<uint8_t> pref;
    if (!hex_to_bytes(cfg_.partial_prefix_hex, pref) || pref.empty() || pref.size() > 31) {
      fail("MODE_PARTIAL needs even hex prefix (1..31 bytes)");
      cuda_aes_shutdown();
      return;
    }
    std::memcpy(lcfg.partial_prefix, pref.data(), pref.size());
    lcfg.partial_prefix_len = (int)pref.size();
  }

  auto t0 = std::chrono::steady_clock::now();
  uint64_t total = 0;
  uint64_t launch_id = 0;
  double peak = 0;
  HitRecord hit{};

  while (!status_.stop_requested.load()) {
    if (cfg_.max_keys && total >= cfg_.max_keys) break;
    uint64_t this_done = 0;
    if (cfg_.max_keys && total + keys_per > cfg_.max_keys)
      lcfg.keys_per_launch = cfg_.max_keys - total;
    else
      lcfg.keys_per_launch = keys_per;

    if (cuda_aes_launch(&lcfg, &hit, &this_done, launch_id) != 0) {
      cuda_aes_shutdown();
      fail("cuda_aes_launch failed");
      return;
    }
    total += this_done;
    ++launch_id;
    status_.keys_total = total;
    status_.launches = launch_id;

    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    double rate = sec > 0 ? (double)total / sec : 0;
    if (rate > peak) peak = rate;
    status_.rate = rate;
    status_.peak_rate = peak;

    if (hit.found) {
      int ti = hit.target_idx;
      if (ti < 0 || ti >= (int)targets_.size()) ti = 0;
      PostHitResult pr = post_hit_decrypt_wif(targets_[ti].wallet, hit.key);
      /* Dual-verify strengthens PKCS padding hits when pubkey present */
      if (pr.ok && !targets_[ti].wallet.pubkey.empty()) {
        DualVerifyResult dv = dual_verify_aes_key(hit.key, targets_[ti].wallet, nullptr);
        if (!dv.message.empty()) pr.message = dv.message;
      }
      save_found_wallet(cfg_.found_file, targets_[ti].wallet, hit.key, pr, ti);
      {
        std::ofstream shortlog(cfg_.out_file, std::ios::app);
        if (shortlog)
          shortlog << bytes_to_hex(hit.key, 32) << " target=" << ti << "\n";
      }
      {
        std::lock_guard<std::mutex> lock(status_.mu);
        status_.hit = true;
        status_.hit_result = pr;
        status_.hit_key_hex = bytes_to_hex(hit.key, 32);
        status_.hit_target_index = ti;
        status_.last_message = "HIT — " + pr.message;
      }
      break;
    }
  }

  cuda_aes_shutdown();
  status_.running = false;
  if (!status_.hit.load()) {
    std::lock_guard<std::mutex> lock(status_.mu);
    if (status_.stop_requested.load())
      status_.last_message = "stopped by user";
    else
      status_.last_message = "search finished (no hit)";
  }
}

int CrackEngine::run_selftest(int device, const std::string& found_file,
                              std::string* log_out) {
  std::ostringstream log;
  log << "[+] Selftest: host PoC key against sample ckey\n";

  WalletTarget wt;
  hex_to_bytes(POC_CKEY, wt.enc48);
  wt.enc_hex = POC_CKEY;
  hex_to_bytes(POC_PUB, wt.pubkey);
  wt.pubkey_hex = POC_PUB;
  TargetCipher tc = make_target(wt.enc48);

  std::vector<uint8_t> key;
  hex_to_bytes(POC_KEY, key);
  int match = 0;
  host_aes256_check_key(key.data(), &tc, &match);
  if (!match) {
    log << "[E] Host AES padding check FAIL\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  log << "[+] Host AES padding check OK\n";
  PostHitResult pr = post_hit_decrypt_wif(wt, key.data());
  if (!pr.ok) {
    log << "[E] post-hit failed: " << pr.message << "\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  log << "[+] CBC decrypt + padding OK\n";
  log << "    privkey: " << pr.privkey_hex << "\n";
  log << "    WIF_u:   " << pr.wif_uncompressed << "\n";
  log << "    WIF_c:   " << pr.wif_compressed << "\n";
  if (pr.wif_uncompressed != POC_WIF_U || pr.wif_compressed != POC_WIF_C) {
    log << "[E] WIF mismatch\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  log << "[+] WIF matches crackBTCwallet PoC\n";
  save_found_wallet(found_file, wt, key.data(), pr, 0);
  log << "[+] Wrote " << found_file << "\n";

  if (cuda_aes_init(device) != 0) {
    log << "[E] cuda init failed\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  if (cuda_aes_upload_targets(&tc, 1) != 0) {
    cuda_aes_shutdown();
    log << "[E] upload failed\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  LaunchConfig cfg{};
  cfg.device = device;
  cfg.blocks = 1;
  cfg.threads = 64;
  cfg.keys_per_launch = 64;
  cfg.streams = 1;
  cfg.mode = MODE_SEQUENTIAL;
  key_hex_to_u256(POC_KEY, cfg.seq_base);
  u256_sub_u64(cfg.seq_base, 16);
  HitRecord hit{};
  uint64_t done = 0;
  log << "[+] GPU sequential smoke (±16 around PoC key)...\n";
  if (cuda_aes_launch(&cfg, &hit, &done, 0) != 0) {
    cuda_aes_shutdown();
    log << "[E] launch failed\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  cuda_aes_shutdown();
  if (!hit.found) {
    log << "[E] GPU did not find PoC key\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  std::string found = bytes_to_hex(hit.key, 32);
  log << "[+] GPU found key: " << found << "\n";
  if (found != POC_KEY) {
    log << "[E] key mismatch\n";
    if (log_out) *log_out = log.str();
    return 1;
  }
  log << "[+] Selftest PASSED (AES + auto WIF + file save)\n";
  if (log_out) *log_out = log.str();
  return 0;
}

/* Expose make_target for GUI loaders */
TargetCipher crack_make_target(const std::vector<uint8_t>& blob48) {
  return make_target(blob48);
}
