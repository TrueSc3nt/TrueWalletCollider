#pragma once
/** Bulletproof Win32 clipboard for Dear ImGui (UTF-8 ↔ CF_UNICODETEXT). */
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

/** Preferred owner HWND. Pass GLFW's glfwGetWin32Window(); NULL falls back to a message-only window. */
void clipboard_win32_set_owner(HWND hwnd);

/** Set OS clipboard from UTF-8 (retries OpenClipboard; never uses EmptyClipboard with NULL owner). */
bool clipboard_win32_set_utf8(const char* text);

/** Get OS clipboard as UTF-8. Pointer valid until next get/set. Empty string on failure. */
const char* clipboard_win32_get_utf8();

/** Round-trip self-test using the same get/set path ImGui will call. Returns true on PASS. */
bool clipboard_win32_selftest(std::string* detail_out);

/** Install ImGui PlatformIO + legacy IO clipboard hooks (ImGui 1.89+ / 1.91). Call after CreateContext
 *  and again each frame after ImGui_ImplGlfw_NewFrame so GLFW cannot silently own a broken path. */
void clipboard_win32_install_imgui_handlers();
#endif
