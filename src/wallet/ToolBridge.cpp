#include "ToolBridge.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

static bool file_exists_path(const std::string& p) {
  std::ifstream f(p, std::ios::binary);
  return (bool)f;
}

static std::string module_dir() {
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

static std::string first_existing(const std::vector<std::string>& cands) {
  for (auto& c : cands)
    if (!c.empty() && file_exists_path(c)) return c;
  return {};
}

std::string find_python_exe() {
  std::string root = module_dir();
  return first_existing({
      "third_party\\python\\python.exe",
      "third_party/python/python.exe",
      root + "third_party\\python\\python.exe",
      "third_party\\python-embed\\python.exe",
      root + "third_party\\python-embed\\python.exe",
  });
}

std::string find_btcrecover_py() {
  std::string root = module_dir();
  return first_existing({
      "third_party\\btcrecover\\btcrecover.py",
      "third_party/btcrecover/btcrecover.py",
      root + "third_party\\btcrecover\\btcrecover.py",
      "third_party\\btcrecover\\seedrecover.py",
  });
}

std::string find_john_exe() {
  std::string root = module_dir();
  return first_existing({
      "third_party\\john\\run\\john.exe",
      "third_party/john/run/john.exe",
      root + "third_party\\john\\run\\john.exe",
      "third_party\\john\\john.exe",
      root + "third_party\\john\\john.exe",
  });
}

std::string find_bitcoin2john_py() {
  std::string root = module_dir();
  auto local = first_existing({
      "third_party\\john\\run\\bitcoin2john.py",
      "third_party\\john\\bitcoin2john.py",
      root + "third_party\\john\\run\\bitcoin2john.py",
      "third_party\\btcrecover\\lib\\bitcoin2john.py",
      "third_party\\hashcat\\tools\\bitcoin2john.py",
  });
  if (!local.empty()) return local;
  return {};
}

ToolDetectStatus detect_forensics_tools() {
  ToolDetectStatus s;
  s.hashcat = find_hashcat_exe();
  s.python = find_python_exe();
  s.btcrecover = find_btcrecover_py();
  s.john = find_john_exe();
  s.bitcoin2john = find_bitcoin2john_py();
  std::ostringstream o;
  o << "Hashcat: " << (s.hashcat.empty() ? "MISSING (run setup_forensics.bat)" : s.hashcat) << "\n";
  o << "Python:  " << (s.python.empty() ? "MISSING" : s.python) << "\n";
  o << "BTCRecover: " << (s.btcrecover.empty() ? "MISSING" : s.btcrecover) << "\n";
  o << "John: " << (s.john.empty() ? "MISSING" : s.john) << "\n";
  o << "bitcoin2john: " << (s.bitcoin2john.empty() ? "(optional)" : s.bitcoin2john) << "\n";
  s.status_text = o.str();
  return s;
}

std::string build_btcrecover_cmdline(const BtcRecoverOptions& opt) {
  std::string py = find_python_exe();
  std::string script = opt.seedrecover ? first_existing({
                                               "third_party\\btcrecover\\seedrecover.py",
                                               module_dir() + "third_party\\btcrecover\\seedrecover.py",
                                           })
                                       : find_btcrecover_py();
  if (py.empty() || script.empty()) return {};
  std::ostringstream cmd;
  cmd << "\"" << py << "\" \"" << script << "\"";
  if (!opt.wallet_dat.empty()) cmd << " --wallet \"" << opt.wallet_dat << "\"";
  if (!opt.tokenlist.empty()) cmd << " --tokenlist \"" << opt.tokenlist << "\"";
  if (!opt.passwordlist.empty()) cmd << " --passwordlist \"" << opt.passwordlist << "\"";
  if (opt.typos) cmd << " --typos " << (std::max)(1, opt.typo_max);
  if (opt.bip39_mode) cmd << " --bip39";
  if (opt.electrum_mode) cmd << " --electrum";
  if (!opt.bip39_mnemonic.empty()) cmd << " --mnemonic \"" << opt.bip39_mnemonic << "\"";
  if (!opt.extra_args.empty()) cmd << " " << opt.extra_args;
  return cmd.str();
}

static HashcatSpawnResult spawn_cmdline(const std::string& cmdline, ProcessStreamer* streamer,
                                        const std::string& work_dir = "") {
  HashcatSpawnResult r;
  r.cmdline = cmdline;
  if (cmdline.empty()) {
    r.message = "empty cmdline — tool not found (run setup_forensics.bat)";
    return r;
  }
  if (streamer) {
    if (streamer->start(cmdline, work_dir)) {
      r.launched = true;
      r.message = "streaming: " + cmdline;
    } else {
      r.message = "spawn failed: " + streamer->last_error();
    }
    return r;
  }
#ifdef _WIN32
  STARTUPINFOA si{};
  PROCESS_INFORMATION pi{};
  si.cb = sizeof(si);
  std::string mutable_cmd = cmdline;
  if (CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE,
                     nullptr, work_dir.empty() ? nullptr : work_dir.c_str(), &si, &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    r.launched = true;
    r.message = "spawned (new console): " + cmdline;
  } else {
    r.message = "CreateProcess failed for: " + cmdline;
  }
#else
  r.message = "Run manually: " + cmdline;
#endif
  return r;
}

HashcatSpawnResult spawn_btcrecover(const BtcRecoverOptions& opt, ProcessStreamer* streamer) {
  std::string cmd = build_btcrecover_cmdline(opt);
  std::string wd;
  auto py = find_btcrecover_py();
  if (!py.empty()) {
    size_t slash = py.find_last_of("\\/");
    if (slash != std::string::npos) wd = py.substr(0, slash);
  }
#ifdef _WIN32
  /* Embeddable Python ._pth isolates site; PYTHONPATH makes btcrecover imports work. */
  if (!wd.empty()) {
    std::string env = "PYTHONPATH=" + wd;
    _putenv(env.c_str());
  }
#endif
  return spawn_cmdline(cmd, streamer, wd);
}

HashcatSpawnResult spawn_john_bitcoin(const std::string& hash_file, ProcessStreamer* streamer) {
  std::string john = find_john_exe();
  if (john.empty()) {
    HashcatSpawnResult r;
    r.message = "john.exe not found — run setup_forensics.bat";
    return r;
  }
  std::ostringstream cmd;
  cmd << "\"" << john << "\" --format=bitcoin \"" << hash_file << "\"";
  std::string wd;
  size_t slash = john.find_last_of("\\/");
  if (slash != std::string::npos) wd = john.substr(0, slash);
  return spawn_cmdline(cmd.str(), streamer, wd);
}

HashcatSpawnResult spawn_hashcat_streamed(const std::string& hash_file, const std::string& wordlist,
                                          const std::string& hashcat_exe,
                                          ProcessStreamer* streamer) {
  std::string exe = hashcat_exe.empty() ? find_hashcat_exe() : hashcat_exe;
  if (exe.empty()) {
    HashcatSpawnResult r;
    r.message = "hashcat.exe not found";
    return r;
  }
  std::ostringstream cmd;
  cmd << "\"" << exe << "\" -m 11300 -a 0 \"" << hash_file << "\"";
  if (!wordlist.empty()) cmd << " \"" << wordlist << "\"";
  std::string wd;
  size_t slash = exe.find_last_of("\\/");
  if (slash != std::string::npos) wd = exe.substr(0, slash);
  return spawn_cmdline(cmd.str(), streamer, wd);
}

/* ---- ProcessStreamer ---- */

ProcessStreamer::~ProcessStreamer() { stop(); }

void ProcessStreamer::clear() {
  std::lock_guard<std::mutex> lock(mu_);
  output_.clear();
}

std::string ProcessStreamer::snapshot() const {
  std::lock_guard<std::mutex> lock(mu_);
  return output_;
}

std::string ProcessStreamer::take_output() { return snapshot(); }

void ProcessStreamer::stop() {
  running_ = false;
#ifdef _WIN32
  if (process_handle_) {
    TerminateProcess((HANDLE)process_handle_, 1);
  }
  /* Close pipe first so ReadFile unblocks; avoids hang on join. */
  if (pipe_rd_) {
    CloseHandle((HANDLE)pipe_rd_);
    pipe_rd_ = nullptr;
  }
  if (reader_.joinable()) {
    HANDLE h = (HANDLE)reader_.native_handle();
    if (WaitForSingleObject(h, 3000) == WAIT_OBJECT_0)
      reader_.join();
    else
      reader_.detach();
  }
  if (thread_handle_) {
    CloseHandle((HANDLE)thread_handle_);
    thread_handle_ = nullptr;
  }
  if (process_handle_) {
    CloseHandle((HANDLE)process_handle_);
    process_handle_ = nullptr;
  }
#else
  if (reader_.joinable()) reader_.join();
#endif
}

bool ProcessStreamer::start(const std::string& cmdline, const std::string& work_dir) {
  stop();
  clear();
  last_error_.clear();
#ifdef _WIN32
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  HANDLE rd = nullptr, wr = nullptr;
  if (!CreatePipe(&rd, &wr, &sa, 0)) {
    last_error_ = "CreatePipe failed";
    return false;
  }
  SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOA si{};
  PROCESS_INFORMATION pi{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = wr;
  si.hStdError = wr;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  std::string mutable_cmd = cmdline;
  BOOL ok = CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                           nullptr, work_dir.empty() ? nullptr : work_dir.c_str(), &si, &pi);
  CloseHandle(wr);
  if (!ok) {
    CloseHandle(rd);
    last_error_ = "CreateProcess failed";
    return false;
  }
  process_handle_ = pi.hProcess;
  thread_handle_ = pi.hThread;
  pipe_rd_ = rd;
  running_ = true;
  reader_ = std::thread([this]() {
    char buf[512];
    DWORD n = 0;
    while (running_.load()) {
      BOOL rok = ReadFile((HANDLE)pipe_rd_, buf, sizeof(buf) - 1, &n, nullptr);
      if (!rok || n == 0) break;
      buf[n] = 0;
      std::lock_guard<std::mutex> lock(mu_);
      output_.append(buf, n);
      if (output_.size() > 500000) output_.erase(0, output_.size() - 400000);
    }
    running_ = false;
  });
  return true;
#else
  (void)cmdline;
  (void)work_dir;
  last_error_ = "streaming unsupported on this platform";
  return false;
#endif
}
