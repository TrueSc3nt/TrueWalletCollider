#pragma once
#include "imgui.h"

/** TrueScent lab / KeyCollider brass-noir palette */
inline void ApplyTrueScentTheme(bool light = false) {
  ImGuiStyle& s = ImGui::GetStyle();
  s.WindowRounding = 6.f;
  s.ChildRounding = 4.f;
  s.FrameRounding = 3.f;
  s.PopupRounding = 4.f;
  s.ScrollbarRounding = 4.f;
  s.GrabRounding = 3.f;
  s.TabRounding = 3.f;
  s.WindowPadding = ImVec2(12, 10);
  s.FramePadding = ImVec2(8, 5);
  s.ItemSpacing = ImVec2(8, 6);
  s.ScrollbarSize = 12.f;
  s.WindowBorderSize = 1.f;
  s.FrameBorderSize = 0.f;

  ImVec4* c = s.Colors;
  if (!light) {
    /* noir */
    const ImVec4 bg(0.06f, 0.06f, 0.07f, 1.f);
    const ImVec4 panel(0.10f, 0.09f, 0.08f, 1.f);
    const ImVec4 brass(0.78f, 0.62f, 0.28f, 1.f);
    const ImVec4 brassDim(0.55f, 0.44f, 0.20f, 1.f);
    const ImVec4 phosphor(0.55f, 0.92f, 0.55f, 1.f);
    const ImVec4 text(0.92f, 0.90f, 0.84f, 1.f);
    const ImVec4 muted(0.55f, 0.52f, 0.45f, 1.f);

    c[ImGuiCol_Text] = text;
    c[ImGuiCol_TextDisabled] = muted;
    c[ImGuiCol_WindowBg] = bg;
    c[ImGuiCol_ChildBg] = ImVec4(0.08f, 0.07f, 0.06f, 1.f);
    c[ImGuiCol_PopupBg] = panel;
    c[ImGuiCol_Border] = ImVec4(0.28f, 0.24f, 0.16f, 0.70f);
    c[ImGuiCol_FrameBg] = ImVec4(0.14f, 0.13f, 0.11f, 1.f);
    c[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.18f, 0.12f, 1.f);
    c[ImGuiCol_FrameBgActive] = ImVec4(0.24f, 0.20f, 0.12f, 1.f);
    c[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.07f, 0.06f, 1.f);
    c[ImGuiCol_TitleBgActive] = ImVec4(0.14f, 0.12f, 0.08f, 1.f);
    c[ImGuiCol_MenuBarBg] = panel;
    c[ImGuiCol_ScrollbarBg] = bg;
    c[ImGuiCol_ScrollbarGrab] = brassDim;
    c[ImGuiCol_ScrollbarGrabHovered] = brass;
    c[ImGuiCol_ScrollbarGrabActive] = phosphor;
    c[ImGuiCol_CheckMark] = phosphor;
    c[ImGuiCol_SliderGrab] = brass;
    c[ImGuiCol_SliderGrabActive] = phosphor;
    c[ImGuiCol_Button] = ImVec4(0.22f, 0.18f, 0.10f, 1.f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.35f, 0.28f, 0.12f, 1.f);
    c[ImGuiCol_ButtonActive] = ImVec4(0.45f, 0.36f, 0.14f, 1.f);
    c[ImGuiCol_Header] = ImVec4(0.22f, 0.18f, 0.10f, 1.f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.32f, 0.26f, 0.12f, 1.f);
    c[ImGuiCol_HeaderActive] = ImVec4(0.40f, 0.32f, 0.14f, 1.f);
    c[ImGuiCol_Separator] = ImVec4(0.32f, 0.28f, 0.18f, 0.60f);
    c[ImGuiCol_Tab] = ImVec4(0.14f, 0.12f, 0.08f, 1.f);
    c[ImGuiCol_TabHovered] = ImVec4(0.35f, 0.28f, 0.12f, 1.f);
    c[ImGuiCol_TabSelected] = ImVec4(0.28f, 0.22f, 0.10f, 1.f);
    c[ImGuiCol_TableHeaderBg] = ImVec4(0.16f, 0.14f, 0.10f, 1.f);
    c[ImGuiCol_TableBorderStrong] = ImVec4(0.30f, 0.26f, 0.16f, 1.f);
    c[ImGuiCol_TableBorderLight] = ImVec4(0.22f, 0.20f, 0.14f, 1.f);
    c[ImGuiCol_TableRowBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt] = ImVec4(1, 1, 1, 0.03f);
    c[ImGuiCol_PlotLines] = phosphor;
    c[ImGuiCol_PlotHistogram] = brass;
    c[ImGuiCol_TextSelectedBg] = ImVec4(0.45f, 0.36f, 0.14f, 0.45f);
    c[ImGuiCol_NavHighlight] = brass;
  } else {
    ImGui::StyleColorsLight();
    c[ImGuiCol_Button] = ImVec4(0.72f, 0.58f, 0.28f, 1.f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.82f, 0.68f, 0.35f, 1.f);
    c[ImGuiCol_Header] = ImVec4(0.90f, 0.82f, 0.60f, 1.f);
  }
}
