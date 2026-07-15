#include "CaseManager.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;

static std::string now_iso() {
  auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::tm tm{};
#ifdef _WIN32
  localtime_s(&tm, &t);
#else
  localtime_r(&t, &tm);
#endif
  char buf[64];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
  return buf;
}

static std::string sanitize_id(std::string s) {
  for (char& c : s) {
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
          c == '_'))
      c = '_';
  }
  if (s.empty()) s = "case";
  return s;
}

std::string case_root_dir() {
#ifdef _WIN32
  char module[MAX_PATH] = {};
  if (GetModuleFileNameA(nullptr, module, MAX_PATH)) {
    std::string dir = module;
    size_t slash = dir.find_last_of("\\/");
    if (slash != std::string::npos) {
      std::string cand = dir.substr(0, slash + 1) + "cases";
      return cand;
    }
  }
#endif
  return "cases";
}

std::string case_dir(const std::string& id) {
  return case_root_dir() + "/" + sanitize_id(id);
}

static bool write_meta(const CaseRecord& c) {
  fs::create_directories(case_dir(c.id));
  std::ofstream f(case_dir(c.id) + "/meta.json");
  if (!f) return false;
  f << "{\n";
  f << "  \"id\": \"" << c.id << "\",\n";
  f << "  \"title\": \"" << c.title << "\",\n";
  f << "  \"created\": \"" << c.created << "\",\n";
  f << "  \"operator\": \"" << c.operator_name << "\",\n";
  f << "  \"evidence_path\": \"" << c.evidence_path << "\"\n";
  f << "}\n";
  return true;
}

CaseRecord case_create(const std::string& title, const std::string& operator_name,
                       const std::string& evidence_path) {
  CaseRecord c;
  c.created = now_iso();
  c.title = title.empty() ? "untitled" : title;
  c.operator_name = operator_name.empty() ? "operator" : operator_name;
  c.evidence_path = evidence_path;
  c.id = sanitize_id(c.created.substr(0, 10) + "_" + c.title.substr(0, 24));
  /* uniquify */
  std::string base = c.id;
  int n = 1;
  while (fs::exists(case_dir(c.id))) {
    c.id = base + "_" + std::to_string(n++);
  }
  fs::create_directories(case_dir(c.id) + "/artifacts");
  write_meta(c);
  {
    std::ofstream notes(case_dir(c.id) + "/notes.txt", std::ios::app);
    notes << "[" << c.created << "] " << c.operator_name << ": case opened — " << c.title << "\n";
    if (!evidence_path.empty()) notes << "  evidence: " << evidence_path << "\n";
  }
  if (!evidence_path.empty()) case_add_artifact(c.id, evidence_path);
  {
    std::ofstream banner(case_dir(c.id) + "/AUTHORIZED_USE_ONLY.txt");
    banner << "Authorized recovery / DFIR only.\n"
              "Unauthorized access to wallets or systems is illegal.\n";
  }
  return case_load(c.id);
}

bool case_append_note(const std::string& id, const std::string& author, const std::string& body) {
  std::ofstream notes(case_dir(id) + "/notes.txt", std::ios::app);
  if (!notes) return false;
  notes << "[" << now_iso() << "] " << (author.empty() ? "operator" : author) << ":\n";
  notes << body << "\n\n";
  return true;
}

bool case_add_artifact(const std::string& id, const std::string& src_path) {
  if (src_path.empty() || !fs::exists(src_path)) return false;
  fs::path src(src_path);
  fs::path dest = fs::path(case_dir(id)) / "artifacts" / src.filename();
  try {
    fs::copy_file(src, dest, fs::copy_options::overwrite_existing);
  } catch (...) {
    return false;
  }
  std::ofstream idx(case_dir(id) + "/artifacts/index.txt", std::ios::app);
  if (idx) idx << now_iso() << "\t" << src_path << "\t->\t" << dest.string() << "\n";
  return true;
}

CaseRecord case_load(const std::string& id) {
  CaseRecord c;
  c.id = sanitize_id(id);
  std::ifstream meta(case_dir(c.id) + "/meta.json");
  std::string line;
  while (std::getline(meta, line)) {
    auto grab = [&](const char* key, std::string& out) {
      auto p = line.find(key);
      if (p == std::string::npos) return;
      auto q1 = line.find('"', p + strlen(key));
      if (q1 == std::string::npos) return;
      auto q2 = line.find('"', q1 + 1);
      if (q2 == std::string::npos) return;
      out = line.substr(q1 + 1, q2 - q1 - 1);
    };
    grab("\"id\"", c.id);
    grab("\"title\"", c.title);
    grab("\"created\"", c.created);
    grab("\"operator\"", c.operator_name);
    grab("\"evidence_path\"", c.evidence_path);
  }
  std::ifstream notes(case_dir(c.id) + "/notes.txt");
  std::ostringstream all;
  all << notes.rdbuf();
  c.notes_joined = all.str();
  if (fs::exists(case_dir(c.id) + "/artifacts")) {
    for (auto& e : fs::directory_iterator(case_dir(c.id) + "/artifacts")) {
      if (e.is_regular_file()) c.artifact_files.push_back(e.path().filename().string());
    }
  }
  return c;
}

std::vector<std::string> case_list_ids() {
  std::vector<std::string> out;
  std::string root = case_root_dir();
  if (!fs::exists(root)) return out;
  for (auto& e : fs::directory_iterator(root)) {
    if (e.is_directory() && fs::exists(e.path() / "meta.json"))
      out.push_back(e.path().filename().string());
  }
  return out;
}

bool case_export_zip(const std::string& id, const std::string& zip_out_path, std::string* message) {
  std::string dir = case_dir(id);
  if (!fs::exists(dir)) {
    if (message) *message = "case not found";
    return false;
  }
#ifdef _WIN32
  std::ostringstream ps;
  ps << "powershell -NoProfile -ExecutionPolicy Bypass -Command "
     << "\"Compress-Archive -Path '" << dir << "\\*' -DestinationPath '" << zip_out_path
     << "' -Force\"";
  int rc = std::system(ps.str().c_str());
  if (rc == 0 && fs::exists(zip_out_path)) {
    if (message) *message = "exported " + zip_out_path;
    return true;
  }
  if (message) *message = "Compress-Archive failed (rc=" + std::to_string(rc) + ")";
  return false;
#else
  (void)zip_out_path;
  if (message) *message = "zip export is Windows-only in this build";
  return false;
#endif
}

std::string case_summary_text(const CaseRecord& c) {
  std::ostringstream o;
  o << "Case " << c.id << "\n";
  o << "title: " << c.title << "\n";
  o << "operator: " << c.operator_name << "\n";
  o << "created: " << c.created << "\n";
  o << "evidence: " << c.evidence_path << "\n";
  o << "artifacts: " << c.artifact_files.size() << "\n";
  o << "--- notes ---\n" << c.notes_joined;
  return o.str();
}
