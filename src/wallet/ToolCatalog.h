#pragma once
#include <string>
#include <vector>

enum class ToolCategory {
  Crackers,
  Carvers,
  SeedGPU,
  Browser,
  Mobile,
  Memory,
  DiskVSS,
  OCREmail,
  Password,
  CommercialLE,
  OnChain,
  Native,
  Research,
  Imaging
};

enum class ToolKind {
  Native,       /* built into TWC — runnable now */
  SetupFetch,   /* setup_forensics.bat downloads/vendors */
  Bridge,       /* launch if installed / user path */
  Commercial,   /* Integration Hub — never pirate */
  Experimental, /* clone + launcher; may need build */
  Idea          /* research checklist — documented in bay */
};

enum class ToolInstallStatus {
  Runnable,
  Installed,
  Missing,
  BridgeAvailable,
  CommercialMissing,
  IdeaOnly,
  Unknown
};

struct CatalogEntry {
  std::string id;
  std::string name;
  ToolCategory category = ToolCategory::Research;
  ToolKind kind = ToolKind::Idea;
  std::string description;
  std::string docs_url;
  std::string detect_hint;   /* relative path under third_party or absolute pattern */
  std::string setup_key;     /* setup_forensics section key */
  std::string native_action; /* GUI action id for native pipelines */
  std::string notes;
};

struct CatalogEntryRuntime : CatalogEntry {
  ToolInstallStatus status = ToolInstallStatus::Unknown;
  std::string resolved_path;
  std::string status_label; /* Runnable / Setup / Bridge / Commercial / Idea */
};

struct CatalogStats {
  int total = 0;
  int native_runnable = 0;
  int setup_installed = 0;
  int setup_missing = 0;
  int bridge = 0;
  int commercial = 0;
  int experimental = 0;
  int idea = 0;
  std::string summary;
};

const char* tool_category_name(ToolCategory c);
const char* tool_kind_name(ToolKind k);
const char* tool_status_name(ToolInstallStatus s);

/** Full DFIR research catalog (100+). Nothing from research left docs-only. */
std::vector<CatalogEntry> tool_catalog_all();
std::vector<CatalogEntryRuntime> tool_catalog_refresh();
CatalogStats tool_catalog_stats(const std::vector<CatalogEntryRuntime>& rows);

std::vector<CatalogEntryRuntime> tool_catalog_filter(const std::vector<CatalogEntryRuntime>& rows,
                                                     const std::string& search,
                                                     ToolCategory* category_filter /* nullable */,
                                                     bool only_runnable);

/** Recommend tools for an input path (wallet.dat / folder / dump). */
std::vector<std::string> tool_catalog_recommend(const std::string& path_or_hint);

/** Expanded CLI --tools-status text including catalog counts. */
std::string tool_catalog_status_report();

/** Commercial Integration Hub — detect common install paths / user config. */
struct CommercialBridge {
  std::string id;
  std::string name;
  std::string detected_path;
  bool found = false;
  std::string twc_covers_instead;
};
std::vector<CommercialBridge> commercial_integration_hub();
bool commercial_try_launch(const std::string& id, std::string* err);
void commercial_set_user_path(const std::string& id, const std::string& path);
std::string commercial_config_path();
