#pragma once
/**
 * Threaded CUDA AES-256 search wrapper — TrueMkeyCollider core embedded.
 */
#include "../crypto/crypto_wallet.h"
#include "../../cuda/aes256_cuda.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct CrackTarget {
  WalletTarget wallet;
  TargetCipher cipher;
};

struct CrackConfig {
  int device = 0;
  int blocks = 0;   /* 0 = auto */
  int threads = 0;
  int streams = 4;
  std::string mem = "auto";
  CrackModeCuda mode = MODE_RANDOM;
  uint64_t max_keys = 0;
  uint32_t mixed_span = 256;
  std::string seq_start; /* 64 hex for sequential */
  std::string found_file = "FOUND_WALLET.txt";
  std::string out_file = "key_found.txt";
};

struct CrackStatus {
  std::atomic<bool> running{false};
  std::atomic<bool> stop_requested{false};
  std::atomic<uint64_t> keys_total{0};
  std::atomic<uint64_t> launches{0};
  std::atomic<double> rate{0};
  std::atomic<double> peak_rate{0};
  std::atomic<bool> hit{false};
  int device = 0;
  int blocks = 0;
  int threads = 0;
  uint64_t keys_per_launch = 0;
  std::string device_name;
  std::string last_message;
  PostHitResult hit_result;
  std::string hit_key_hex;
  int hit_target_index = -1;
  std::mutex mu;
};

TargetCipher crack_make_target(const std::vector<uint8_t>& blob48);

class CrackEngine {
 public:
  CrackEngine();
  ~CrackEngine();

  CrackEngine(const CrackEngine&) = delete;
  CrackEngine& operator=(const CrackEngine&) = delete;

  void set_targets(std::vector<CrackTarget> targets);
  void set_config(const CrackConfig& cfg);

  bool start();
  void stop();
  bool is_running() const { return status_.running.load(); }

  CrackStatus& status() { return status_; }
  const CrackStatus& status() const { return status_; }

  /** Host verify one key against loaded targets; runs post-hit on match. */
  bool try_key(const std::string& hex64, std::string* msg_out);

  /** GPU+host PoC selftest (TrueMkeyCollider). */
  static int run_selftest(int device, const std::string& found_file,
                          std::string* log_out);

  static std::string format_rate(double keys_per_sec);
  static std::vector<std::string> list_devices();

 private:
  void worker();
  std::vector<CrackTarget> targets_;
  CrackConfig cfg_;
  CrackStatus status_;
  std::thread thread_;
};
