#pragma once
#include <string>
#include <vector>

struct CaseNote {
  std::string timestamp;
  std::string author;
  std::string body;
};

struct CaseRecord {
  std::string id;
  std::string title;
  std::string created;
  std::string operator_name;
  std::string evidence_path;
  std::string notes_joined;
  std::vector<CaseNote> notes;
  std::vector<std::string> artifact_files;
};

std::string case_root_dir(); /* cases/ relative to cwd / exe */
std::string case_dir(const std::string& id);

/** Create cases/<id>/ with meta.json + notes.txt. Returns case id. */
CaseRecord case_create(const std::string& title, const std::string& operator_name,
                       const std::string& evidence_path = "");

bool case_append_note(const std::string& id, const std::string& author, const std::string& body);
bool case_add_artifact(const std::string& id, const std::string& src_path);
CaseRecord case_load(const std::string& id);
std::vector<std::string> case_list_ids();

/** Export evidence zip via PowerShell Compress-Archive (Windows). */
bool case_export_zip(const std::string& id, const std::string& zip_out_path, std::string* message);

std::string case_summary_text(const CaseRecord& c);
