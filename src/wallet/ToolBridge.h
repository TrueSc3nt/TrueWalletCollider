#pragma once
#include "HashcatExport.h"
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

/** Discover bundled forensic tools under third_party/. */
std::string find_python_exe();
std::string find_btcrecover_py();
std::string find_john_exe();
std::string find_bitcoin2john_py();

struct ToolDetectStatus {
  std::string hashcat;
  std::string python;
  std::string btcrecover;
  std::string john;
  std::string bitcoin2john;
  std::string status_text;
};

ToolDetectStatus detect_forensics_tools();

/** Background process with streamed stdout/stderr into a ring buffer. */
class ProcessStreamer {
 public:
  ProcessStreamer() = default;
  ~ProcessStreamer();
  bool start(const std::string& cmdline, const std::string& work_dir = "");
  void stop();
  bool running() const { return running_.load(); }
  std::string take_output();
  std::string snapshot() const;
  void clear();
  std::string last_error() const { return last_error_; }

 private:
  ProcessStreamer(const ProcessStreamer&) = delete;
  ProcessStreamer& operator=(const ProcessStreamer&) = delete;
  mutable std::mutex mu_;
  std::string output_;
  std::string last_error_;
  std::atomic<bool> running_{false};
  std::thread reader_;
#ifdef _WIN32
  void* process_handle_ = nullptr;
  void* thread_handle_ = nullptr;
  void* pipe_rd_ = nullptr;
#endif
};

struct BtcRecoverOptions {
  std::string wallet_dat;
  std::string tokenlist;
  std::string passwordlist;
  std::string bip39_mnemonic; /* optional seedrecover path */
  bool bip39_mode = false;
  bool electrum_mode = false;
  bool typos = false;
  int typo_max = 1;
  std::string extra_args;
  bool seedrecover = false;
};

std::string build_btcrecover_cmdline(const BtcRecoverOptions& opt);
HashcatSpawnResult spawn_btcrecover(const BtcRecoverOptions& opt, ProcessStreamer* streamer);
HashcatSpawnResult spawn_john_bitcoin(const std::string& hash_file, ProcessStreamer* streamer);
HashcatSpawnResult spawn_hashcat_streamed(const std::string& hash_file, const std::string& wordlist,
                                          const std::string& hashcat_exe, ProcessStreamer* streamer);
