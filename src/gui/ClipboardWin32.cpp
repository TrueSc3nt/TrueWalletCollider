#include "ClipboardWin32.h"

#ifdef _WIN32
#include "imgui.h"

#include <cstdio>
#include <cstring>
#include <string>

static HWND g_clip_owner = nullptr;
static HWND g_clip_fallback = nullptr;
static std::string g_clip_utf8;

static HWND clipboard_owner_hwnd() {
  if (g_clip_owner && IsWindow(g_clip_owner)) return g_clip_owner;
  if (!g_clip_fallback) {
    /* Message-only HWND so EmptyClipboard has a real owner (OpenClipboard(NULL) breaks Set). */
    g_clip_fallback = CreateWindowExW(0, L"STATIC", L"twc_clipboard", 0, 0, 0, 0, 0, HWND_MESSAGE,
                                      nullptr, GetModuleHandleW(nullptr), nullptr);
  }
  return g_clip_fallback;
}

static bool open_clipboard_retry(HWND hwnd, int max_tries = 12) {
  for (int i = 0; i < max_tries; ++i) {
    if (OpenClipboard(hwnd)) return true;
    Sleep(i == 0 ? 1 : 2);
  }
  return false;
}

void clipboard_win32_set_owner(HWND hwnd) { g_clip_owner = hwnd; }

bool clipboard_win32_set_utf8(const char* text) {
  if (!text) text = "";
  HWND hwnd = clipboard_owner_hwnd();
  if (!hwnd) return false;
  if (!open_clipboard_retry(hwnd)) return false;

  const int wlen = MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
  if (wlen <= 0) {
    CloseClipboard();
    return false;
  }
  HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)wlen * sizeof(wchar_t));
  if (!h) {
    CloseClipboard();
    return false;
  }
  wchar_t* dst = (wchar_t*)GlobalLock(h);
  if (!dst) {
    GlobalFree(h);
    CloseClipboard();
    return false;
  }
  MultiByteToWideChar(CP_UTF8, 0, text, -1, dst, wlen);
  GlobalUnlock(h);

  EmptyClipboard();
  if (SetClipboardData(CF_UNICODETEXT, h) == nullptr) {
    GlobalFree(h);
    CloseClipboard();
    return false;
  }
  CloseClipboard();
  return true;
}

const char* clipboard_win32_get_utf8() {
  g_clip_utf8.clear();
  HWND hwnd = clipboard_owner_hwnd();
  if (!hwnd) return g_clip_utf8.c_str();
  if (!open_clipboard_retry(hwnd)) return g_clip_utf8.c_str();

  HANDLE h = GetClipboardData(CF_UNICODETEXT);
  if (h) {
    const wchar_t* w = (const wchar_t*)GlobalLock(h);
    if (w) {
      /* buf_len includes the trailing NUL — keep it (prior bug: resized to len-1 then wrote len bytes). */
      int buf_len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
      if (buf_len > 0) {
        g_clip_utf8.resize((size_t)buf_len);
        WideCharToMultiByte(CP_UTF8, 0, w, -1, g_clip_utf8.data(), buf_len, nullptr, nullptr);
        if (!g_clip_utf8.empty() && g_clip_utf8.back() == '\0') g_clip_utf8.pop_back();
      }
      GlobalUnlock(h);
    }
  } else if ((h = GetClipboardData(CF_TEXT)) != nullptr) {
    const char* a = (const char*)GlobalLock(h);
    if (a) {
      g_clip_utf8 = a;
      GlobalUnlock(h);
    }
  }
  CloseClipboard();
  return g_clip_utf8.c_str();
}

bool clipboard_win32_selftest(std::string* detail_out) {
  const char* probe = "TWC_CLIP_SELFTEST_adam\xE2\x9C\x93"; /* UTF-8 checkmark */
  std::string detail;
  if (!clipboard_win32_set_utf8(probe)) {
    detail = "FAIL: SetClipboard (OpenClipboard/SetClipboardData) — check HWND owner";
    if (detail_out) *detail_out = detail;
    return false;
  }
  const char* got = clipboard_win32_get_utf8();
  if (!got || std::strcmp(got, probe) != 0) {
    detail = "FAIL: GetClipboard round-trip mismatch (got=\"";
    detail += got ? got : "(null)";
    detail += "\")";
    if (detail_out) *detail_out = detail;
    return false;
  }
  detail = "PASS: clipboard Set/Get UTF-8 round-trip OK (same path ImGui Ctrl+V uses)";
  if (detail_out) *detail_out = detail;
  return true;
}

static void imgui_platform_set(ImGuiContext*, const char* text) { clipboard_win32_set_utf8(text); }
static const char* imgui_platform_get(ImGuiContext*) { return clipboard_win32_get_utf8(); }

#ifndef IMGUI_DISABLE_OBSOLETE_FUNCTIONS
static void imgui_legacy_set(void*, const char* text) { clipboard_win32_set_utf8(text); }
static const char* imgui_legacy_get(void*) { return clipboard_win32_get_utf8(); }
#endif

void clipboard_win32_install_imgui_handlers() {
  ImGuiPlatformIO& pio = ImGui::GetPlatformIO();
  pio.Platform_SetClipboardTextFn = imgui_platform_set;
  pio.Platform_GetClipboardTextFn = imgui_platform_get;
#ifndef IMGUI_DISABLE_OBSOLETE_FUNCTIONS
  ImGuiIO& io = ImGui::GetIO();
  io.SetClipboardTextFn = imgui_legacy_set;
  io.GetClipboardTextFn = imgui_legacy_get;
  io.ClipboardUserData = nullptr;
#endif
}
#endif
