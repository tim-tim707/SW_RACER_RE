#include "imgui_utils.h"
#include "debug_ui.h"
#include "n64_shader.h"

#include <string>
#include <set>
#include <format>
#include <cstdio>
#include <cstring>

#include <imgui.h>
#include <imgui_stdlib.h>

#include "gltf_utils.h"

#include "replacements.h"
#include "renderer_utils.h"
#include "texture_replacement.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include "game_deltas/window_mode.h"

extern "C" {
#include <globals.h>
#include <macros.h>
#include <Swr/swrModel.h>
#include <Swr/swrRace.h>
#include <Swr/swrSound.h>
}

extern rdVector3 debugCameraPos;
extern rdVector3 cameraFront;
extern rdVector3 cameraUp;
extern float cameraPitch;
extern float cameraYaw;
extern float cameraSpeed;

// Defined in main.cpp: writes/reverts the AI full-LOD .text patches (gated by ai_full_lod).
extern "C" void set_ai_full_lod(bool on);

// Registers the built-in overlay panels with the debug-ui shell. Defined at the
// bottom of this file alongside the panel bodies it splits opengl_render_imgui into.
static void register_builtin_debug_panels();

// Applies the enabled cheats. Called every frame from imgui_Update so the cheats
// hold whether or not the overlay window is open.
static void apply_cheats();

extern uint8_t replacedTries[323];// 323 MODELIDs
extern std::map<int, ReplacementModel> replacement_map;
extern const char *modelid_cstr[];

// imgui menu open by default on debug build
#if !defined(NDEBUG)
char show_imgui = 1;
#else
char show_imgui = 0;
#endif
bool imgui_initialized = false;
ImGuiState imgui_state = {
    .draw_test_scene = false,
    .draw_meshes = true,
    .draw_renderList = true,
    .debug_lambertian_cubemap = false,
    .debug_ggx_cubemap = false,
    .debug_ggxLut = false,
    .show_replacementTries = false,
    .replacementTries = std::string(""),
    .debug_env_cubemap = false,
    .HD_replacement = true,
    .show_original_and_replacements = false,
    .collect_textures_skip_pod_textures = true,
};

static std::wstring ini_path = [] {
    wchar_t buff[1024];
    GetModuleFileNameW(nullptr, std::data(buff), std::size(buff));
    return (std::filesystem::path(buff).parent_path() / "SW_RACER_RE.ini").wstring();
}();

void read_settings_ini() {
    const UINT msaa_samples =
        GetPrivateProfileIntW(L"settings", L"msaa_samples", 0, ini_path.c_str());
    if (msaa_samples != 0) {
        imgui_state.msaa_samples = msaa_samples;
    }

    const UINT anisotropy = GetPrivateProfileIntW(L"settings", L"anisotropy", 0, ini_path.c_str());
    if (anisotropy != 0) {
        imgui_state.anisotropy = anisotropy;
    }

    imgui_state.enable_fog = GetPrivateProfileIntW(L"settings", L"enable_fog", 1, ini_path.c_str());

    imgui_state.ai_full_lod =
        GetPrivateProfileIntW(L"settings", L"ai_full_lod", 1, ini_path.c_str());
    set_ai_full_lod(imgui_state.ai_full_lod);

    g_window_mode =
        GetPrivateProfileIntW(L"settings", L"window_mode", WINDOW_MODE_WINDOWED, ini_path.c_str());
    if (g_window_mode < WINDOW_MODE_WINDOWED || g_window_mode > WINDOW_MODE_FULLSCREEN)
        g_window_mode = WINDOW_MODE_WINDOWED;
    // The window starts as a maximized windowed window, so only apply non-windowed modes here.
    if (g_window_mode != WINDOW_MODE_WINDOWED)
        set_window_mode(g_window_mode);
}

void save_settings_ini() {
    WritePrivateProfileStringW(L"settings", L"msaa_samples",
                               std::to_wstring(imgui_state.msaa_samples).c_str(), ini_path.c_str());
    WritePrivateProfileStringW(L"settings", L"anisotropy",
                               std::to_wstring(imgui_state.anisotropy).c_str(), ini_path.c_str());
    WritePrivateProfileStringW(L"settings", L"enable_fog", imgui_state.enable_fog ? L"1" : L"0",
                               ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"ai_full_lod", imgui_state.ai_full_lod ? L"1" : L"0",
                               ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"window_mode", std::to_wstring(g_window_mode).c_str(),
                               ini_path.c_str());
}

// Called from the (C) window key callbacks so Alt+Enter persists the chosen mode too.
extern "C" void save_window_mode_setting(void) {
    save_settings_ini();
}

const wchar_t *settings_ini_path() {
    return ini_path.c_str();
}

const char *swrModel_NodeTypeStr(uint32_t nodeType) {
    switch (nodeType) {
        case NODE_MESH_GROUP:
            return "NODE_MESH_GROUP";
        case NODE_BASIC:
            return "NODE_BASIC";
        case NODE_SELECTOR:
            return "NODE_SELECTOR";
        case NODE_LOD_SELECTOR:
            return "NODE_LOD_SELECTOR";
        case NODE_TRANSFORMED:
            return "NODE_TRANSFORMED";
        case NODE_TRANSFORMED_WITH_PIVOT:
            return "NODE_TRANSFORMED_WITH_PIVOT";
        case NODE_TRANSFORMED_COMPUTED:
            return "NODE_TRANSFORMED_COMPUTED";
        default:
            return "UNKNOWN";
    }
    return "UNKNOWN";
}

void imgui_render_node(swrModel_Node *node) {
    if (!node)
        return;

    if (node->type & NODE_HAS_CHILDREN) {
        for (int i = 0; i < node->num_children; i++) {
            if (!node->children.nodes[i])
                continue;

            swrModel_Node *child_node = node->children.nodes[i];
            if (!(child_node->flags_1 & 0x4))
                continue;

            ImGui::PushID(i);
            bool visible = child_node->flags_1 & 0x2;
            if (ImGui::SmallButton(visible ? "-V" : "+V")) {
                child_node->flags_1 ^= 0x2;
            }
            ImGui::SameLine();

            const std::optional<MODELID> model_id = find_model_id_for_node(child_node);
            if (ImGui::TreeNodeEx(std::format("{}: {} 0x{:08x} {}", i,
                                              swrModel_NodeTypeStr((uint32_t) child_node->type),
                                              (uintptr_t) child_node,
                                              model_id ? modelid_cstr[model_id.value()] : "")
                                      .c_str())) {
                imgui_render_node(child_node);
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
    }
    if (node->type == NODE_MESH_GROUP) {
        ImGui::Text("num meshes: %d", node->num_children);
        for (int i = 0; i < node->num_children; i++) {
            const swrModel_Mesh *mesh = node->children.meshes[i];
            ImGui::Text("mesh %d: num_vertices=%d, vertex_offset=%d, vertex_ptr=%p", i,
                        mesh->num_vertices, mesh->vertex_base_offset, mesh->vertices);
            ImGui::Text("    referenced_node=%p", mesh->referenced_node);
            Gfx *command = swrModel_MeshGetDisplayList(mesh);
            while (command->type != 0xdf) {
                if (command->type == 0x1) {
                    const uint8_t n = (SWAP16(command->gSPVertex.n_packed) >> 4) & 0xFF;
                    const uint8_t v0 = command->gSPVertex.v0_plus_n - n;
                    ImGui::Text("    n=%d v0=%d offset=%d", n, v0,
                                command->gSPVertex.vertex_offset - mesh->vertices);
                }
                command++;
            }
        }
    }
}

void collect_all_visual_textures(const swrViewport &current_vp, bool skip_pod_textures,
                                 const swrModel_Node *node, std::set<RdMaterial *> &textures) {
    if (!node)
        return;

    if ((current_vp.node_flags1_exact_match_for_rendering & node->flags_1) !=
        current_vp.node_flags1_exact_match_for_rendering)
        return;

    if ((current_vp.node_flags1_any_match_for_rendering & node->flags_1) == 0)
        return;

    if (node->type == NODE_MESH_GROUP) {
        if (skip_pod_textures) {
            auto model_id = find_model_id_for_node(node);
            if (model_id && isPodModel(*model_id) || isAIPodModel(*model_id))
                return;
        }

        for (int i = 0; i < node->num_children; i++) {
            const swrModel_Mesh *mesh = node->children.meshes[i];
            if (mesh && mesh->mesh_material && mesh->mesh_material->material_texture &&
                mesh->mesh_material->material_texture->loaded_material) {
                textures.insert(mesh->mesh_material->material_texture->loaded_material);
            }
        }
    } else if (node->type == NODE_LOD_SELECTOR) {
        const swrModel_NodeLODSelector *lods = (const swrModel_NodeLODSelector *) node;
        // find correct lod node
        int i = 1;
        for (; i < 8; i++) {
            if (lods->lod_distances[i] == -1 || lods->lod_distances[i] >= 10)
                break;
        }
        if (i - 1 < node->num_children)
            collect_all_visual_textures(current_vp, skip_pod_textures, node->children.nodes[i - 1],
                                        textures);
    } else if (node->type == NODE_SELECTOR) {
        const swrModel_NodeSelector *selector = (const swrModel_NodeSelector *) node;
        int child = selector->selected_child_node;
        switch (child) {
            case -2:
                // dont render any child node
                break;
            case -1:
                // render all child nodes
                for (int i = 0; i < node->num_children; i++)
                    collect_all_visual_textures(current_vp, skip_pod_textures,
                                                node->children.nodes[i], textures);
                break;
            default:
                if (child >= 0 && child < node->num_children)
                    collect_all_visual_textures(current_vp, skip_pod_textures,
                                                node->children.nodes[child], textures);

                break;
        }
    } else {
        for (int i = 0; i < node->num_children; i++)
            collect_all_visual_textures(current_vp, skip_pod_textures, node->children.nodes[i],
                                        textures);
    }
}

extern void **texture_buffer_replacement;

const RdMaterial *material_from_texture_id(TEXID id) {
    if (!texture_buffer_replacement || !texture_buffer_replacement[id])
        return nullptr;

    return *(const RdMaterial **) texture_buffer_replacement[id];
}

GLuint gl_texture_from_texture_id(TEXID id) {
    const auto *mat = material_from_texture_id(id);
    if (!mat)
        return 0;

    return (GLuint) mat->aTextures[0].pD3DSrcTexture;
}

void set_texture_highlighting(TEXID tex, bool enable) {
    glBindTexture(GL_TEXTURE_2D, gl_texture_from_texture_id(tex));
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_SWIZZLE_R, enable ? GL_ONE : GL_RED);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_SWIZZLE_G, enable ? GL_ZERO : GL_GREEN);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_SWIZZLE_B, enable ? GL_ONE : GL_BLUE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_SWIZZLE_A, enable ? GL_ONE : GL_ALPHA);
    glBindTexture(GL_TEXTURE_2D, 0);
}

void imgui_Update() {
    GLFWwindow *glfw_window = glfwGetCurrentContext();
    if (!imgui_initialized) {
        imgui_initialized = true;
        IMGUI_CHECKVERSION();
        if (!ImGui::CreateContext())
            std::abort();

        ImGuiIO &io = ImGui::GetIO();
        (void) io;

        ImGui::StyleColorsDark();

        const HWND wnd = GetActiveWindow();
        if (!ImGui_ImplGlfw_InitForOpenGL(glfw_window, true))
            std::abort();
        if (!ImGui_ImplOpenGL3_Init("#version 330"))
            std::abort();

        fprintf(hook_log, "[OGL_imgui_Update] imgui initialized.\n");

        read_settings_ini();
        register_builtin_debug_panels();
        debug_ui_register_builtin_shell_panels();
        debug_ui_load_settings();
    }

    if (imgui_initialized) {
        apply_cheats();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        debug_ui_render();

        ImGui::EndFrame();
        ImGui::Render();
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    }
}

// Live view of the mod's hook.log. The rest of the codebase logs through
// fprintf(hook_log, ...) into "hook.log" on disk; rather than rewire every call
// site we tail that file and mirror new bytes into this buffer. The window
// chrome (Options/Clear/Copy/Filter/auto-scroll) follows imgui's ExampleAppLog
// from imgui_demo.cpp.
struct DebugLog {
    ImGuiTextBuffer Buf;
    ImGuiTextFilter Filter;
    ImVector<int> LineOffsets;// byte offset of each line start, kept in sync by Append()
    bool AutoScroll = true;
    static constexpr int MaxLines = 20000;// liberal scrollback cap; older lines are dropped

    DebugLog() {
        Clear();
    }

    void Clear() {
        Buf.clear();
        LineOffsets.clear();
        LineOffsets.push_back(0);
    }

    void Append(const char *str, const char *str_end) {
        int old_size = Buf.size();
        Buf.append(str, str_end);
        for (int new_size = Buf.size(); old_size < new_size; old_size++)
            if (Buf[old_size] == '\n')
                LineOffsets.push_back(old_size + 1);
    }

    // Drop the oldest lines once past the cap so a long session can't grow the
    // buffer without bound. Cheap once stable (early-out), and a single tail copy
    // when it does fire. Call once per pump rather than per Append() chunk.
    void Trim() {
        if (LineOffsets.Size <= MaxLines)
            return;
        const int drop = LineOffsets.Size - MaxLines;
        const int byte_off = LineOffsets[drop];
        std::string tail(Buf.begin() + byte_off, Buf.end());
        Clear();
        Append(tail.data(), tail.data() + tail.size());
    }

    // hook.log lines are free-form (no severity field), so tint heuristically to
    // make failures and warnings stand out. Matching is case-insensitive, so a
    // needle like "fail" catches "FAIL", "Failed", and "failed" alike.
    static bool line_contains_ci(const char *s, const char *e, const char *needle) {
        auto fold = [](char c) -> char { return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c; };
        size_t n = strlen(needle);
        for (const char *p = s; p + n <= e; p++) {
            size_t i = 0;
            while (i < n && fold(p[i]) == fold(needle[i]))
                i++;
            if (i == n)
                return true;
        }
        return false;
    }

    static bool line_color(const char *s, const char *e, ImVec4 &out) {
        if (line_contains_ci(s, e, "fail") || line_contains_ci(s, e, "error") ||
            line_contains_ci(s, e, "couldnt") || line_contains_ci(s, e, "abort")) {
            out = ImVec4(1.0f, 0.4f, 0.4f, 1.0f);
            return true;
        }
        if (line_contains_ci(s, e, "warn")) {
            out = ImVec4(1.0f, 0.8f, 0.4f, 1.0f);
            return true;
        }
        return false;
    }

    void DrawLine(const char *line_start, const char *line_end) {
        ImVec4 col;
        if (line_color(line_start, line_end, col)) {
            ImGui::PushStyleColor(ImGuiCol_Text, col);
            ImGui::TextUnformatted(line_start, line_end);
            ImGui::PopStyleColor();
        } else {
            ImGui::TextUnformatted(line_start, line_end);
        }
    }

    // Render the toolbar + scrolling region into the current window. child_height
    // bounds the scroll region (0 = fill remaining space); the debug-ui shell
    // renders this inside the Hook Log accordion section (see panel_hook_log).
    void DrawBody(float child_height) {
        if (ImGui::BeginPopup("Options")) {
            ImGui::Checkbox("Auto-scroll", &AutoScroll);
            ImGui::EndPopup();
        }

        if (ImGui::Button("Options"))
            ImGui::OpenPopup("Options");
        ImGui::SameLine();
        bool clear = ImGui::Button("Clear");
        ImGui::SameLine();
        bool copy = ImGui::Button("Copy");
        ImGui::SameLine();
        Filter.Draw("Filter", -100.0f);

        ImGui::Separator();

        if (ImGui::BeginChild("scrolling", ImVec2(0, child_height), ImGuiChildFlags_None,
                              ImGuiWindowFlags_HorizontalScrollbar)) {
            if (clear)
                Clear();
            if (copy)
                ImGui::LogToClipboard();

            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
            const char *buf = Buf.begin();
            const char *buf_end = Buf.end();
            if (Filter.IsActive()) {
                // No clipper while filtering: we don't have random access into the result.
                for (int line_no = 0; line_no < LineOffsets.Size; line_no++) {
                    const char *line_start = buf + LineOffsets[line_no];
                    const char *line_end = (line_no + 1 < LineOffsets.Size)
                                               ? (buf + LineOffsets[line_no + 1] - 1)
                                               : buf_end;
                    if (Filter.PassFilter(line_start, line_end))
                        DrawLine(line_start, line_end);
                }
            } else {
                ImGuiListClipper clipper;
                clipper.Begin(LineOffsets.Size);
                while (clipper.Step()) {
                    for (int line_no = clipper.DisplayStart; line_no < clipper.DisplayEnd;
                         line_no++) {
                        const char *line_start = buf + LineOffsets[line_no];
                        const char *line_end = (line_no + 1 < LineOffsets.Size)
                                                   ? (buf + LineOffsets[line_no + 1] - 1)
                                                   : buf_end;
                        DrawLine(line_start, line_end);
                    }
                }
                clipper.End();
            }
            ImGui::PopStyleVar();

            // Stay pinned to the bottom unless the user scrolled up.
            if (AutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                ImGui::SetScrollHereY(1.0f);
        }
        ImGui::EndChild();
    }
};

static DebugLog g_debug_log;

// Pull any bytes appended to hook.log since the last call into g_debug_log.
// Uses a private shared read handle (main.cpp opens hook.log "wb"; the UCRT's
// default share mode permits a concurrent reader). The handle keeps its
// position between frames, and clearerr() drops the EOF latch so freshly
// flushed lines are picked up on the next frame.
static void pump_hook_log() {
    static FILE *reader = nullptr;
    if (!reader) {
        reader = fopen("hook.log", "rb");
        if (!reader)
            return;
    }

    clearerr(reader);
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), reader)) > 0)
        g_debug_log.Append(buf, buf + n);
    g_debug_log.Trim();
}

// --- Panels (the old opengl_render_imgui monolith, split by audience) ---------
//
// Each function below draws one registered panel's body; the debug-ui shell wraps
// it in a window and a menu entry (see register_builtin_debug_panels). The widget
// logic is unchanged from the monolith -- only the per-section TreeNode wrappers
// became panels, and the "show X" gating checkboxes became the panel open-state.

// Player: persisted graphics settings (back the same SW_RACER_RE.ini keys).
static void panel_graphics_settings() {
    int max_msaa_samples = 1;
    glGetIntegerv(GL_MAX_SAMPLES, &max_msaa_samples);
    if (imgui_state.msaa_samples > max_msaa_samples) {
        imgui_state.msaa_samples = max_msaa_samples;
        save_settings_ini();
    }
    if (ImGui::SliderInt("MSAA samples", &imgui_state.msaa_samples, 1, max_msaa_samples)) {
        save_settings_ini();
    }

    int max_anisotropy = 1;
    glGetIntegerv(GL_MAX_TEXTURE_MAX_ANISOTROPY, &max_anisotropy);
    if (imgui_state.anisotropy > max_anisotropy) {
        imgui_state.anisotropy = max_anisotropy;
        save_settings_ini();
    }
    if (ImGui::SliderInt("Anisotropy", &imgui_state.anisotropy, 1, 16)) {
        for (int i = 0; i < texture_count; i++) {
            GLuint handle = gl_texture_from_texture_id((TEXID) i);
            if (handle != 0) {
                glBindTexture(GL_TEXTURE_2D, handle);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY, imgui_state.anisotropy);
                glBindTexture(GL_TEXTURE_2D, 0);
            }
        }
        save_settings_ini();
    }
    if (ImGui::Checkbox("Enable fog", &imgui_state.enable_fog)) {
        save_settings_ini();
    }

    if (ImGui::Checkbox("AI full LOD (no model pop-in)", &imgui_state.ai_full_lod)) {
        set_ai_full_lod(imgui_state.ai_full_lod);
    }

    static const char *window_mode_items[] = {"Windowed", "Borderless", "Fullscreen"};
    int window_mode = g_window_mode;
    if (ImGui::Combo("Window mode", &window_mode, window_mode_items,
                     IM_ARRAYSIZE(window_mode_items))) {
        set_window_mode(window_mode);
        save_settings_ini();
    }
}

// Player: HD model + texture replacement toggles.
static void panel_hd_models() {
    if (ImGui::Button("Reload Models from assets/gltf")) {
        for (auto &[key, replacement]: replacement_map) {
            if (replacement.fileExist) {
                deleteModel(replacement.model);
            }
        }
        replacement_map.clear();
    }

    ImGui::Checkbox("Enable HD model replacement.", &imgui_state.HD_replacement);
    ImGui::Checkbox("Show original on top of replacements.",
                    &imgui_state.show_original_and_replacements);
    ImGui::Checkbox("Show replacement tries", &imgui_state.show_replacementTries);
    if (imgui_state.show_replacementTries) {
        ImGui::Text("%s\n", imgui_state.replacementTries.c_str());
        imgui_state.replacementTries.clear();
    }

    ImGui::SeparatorText("Replacement textures");
    ImGui::Checkbox("enable", &enable_texture_replacement);
    if (ImGui::Button("refresh replacement textures"))
        refresh_replacement_textures();
    ImGui::Text("Found %d replacement textures.", int(replacement_textures.size()));
}

// Dev: render-pipeline debug toggles (read by renderer_hook / renderer_utils).
static void panel_render_debug() {
#if !defined(NDEBUG)
    ImGui::Checkbox("Draw test scene instead", &imgui_state.draw_test_scene);
    if (imgui_state.draw_test_scene) {
        ImGui::Text("Position: %.2f %.2f %.2f, Front: %.2f %.2f %.2f, Up: %.2f %.2f %.2f",
                    debugCameraPos.x, debugCameraPos.y, debugCameraPos.z, cameraFront.x,
                    cameraFront.y, cameraFront.z, cameraUp.x, cameraUp.y, cameraUp.z);
        ImGui::Text("Pitch: %.2f, Yaw: %.2f", cameraPitch, cameraYaw);
        ImGui::Text("Camera Speed: %.3f", cameraSpeed);
    }
    ImGui::Separator();
#endif

    ImGui::Checkbox("Draw meshes", &imgui_state.draw_meshes);
    ImGui::Checkbox("Draw RenderList", &imgui_state.draw_renderList);
    ImGui::Checkbox("debug lambertian", &imgui_state.debug_lambertian_cubemap);
    ImGui::Checkbox("debug ggx cubemap", &imgui_state.debug_ggx_cubemap);
    ImGui::Checkbox("debug env cubemap", &imgui_state.debug_env_cubemap);
    ImGui::Checkbox("debug ggx lut", &imgui_state.debug_ggxLut);
}

// Dev: scene graph + (debug-build only) per-frame node/material property tallies.
static void panel_scene_inspector() {
#ifndef NDEBUG
    auto dump_member = [](auto &member) {
        ImGui::PushID(member.name);
        ImGui::Text("%s", member.name);
        std::set<uint32_t> new_banned;
        for (const auto &[value, count]: member.count) {
            ImGui::PushID(value);
            bool banned = member.banned.contains(value);
            ImGui::Checkbox("##banned", &banned);
            ImGui::SameLine();
            ImGui::Text("0x%08x : %d", value, count);
            ImGui::PopID();

            if (banned)
                new_banned.insert(value);
        }
        ImGui::PopID();
        member.count.clear();
        member.banned = std::move(new_banned);
    };

    if (ImGui::TreeNodeEx("node props:")) {
        for (NodeMember &member: node_members) {
            dump_member(member);
        }
        ImGui::TreePop();
    }

    if (ImGui::TreeNodeEx("mesh material props:")) {
        for (MaterialMember &member: node_material_members) {
            dump_member(member);
        }
        ImGui::TreePop();
    }

    if (ImGui::TreeNodeEx("render modes:")) {
        auto dump_mode = [](std::string_view name, auto printer) {
            for (const MaterialMember &material_member: node_material_members) {
                if (material_member.name == name) {
                    ImGui::Text("%s", material_member.name);
                    for (const auto &[m, count]: material_member.count)
                        ImGui::Text("    %s: %d", printer(m).c_str(), count);
                }
            }
        };

        dump_mode("render_mode_1", [](const uint32_t x) {
            return dump_blend_mode((const RenderMode &) x, false);
        });
        dump_mode("render_mode_2", [](const uint32_t x) {
            return dump_blend_mode((const RenderMode &) x, true);
        });
        dump_mode("cc_cycle1", [](const uint32_t x) { return CombineMode(x, false).to_string(); });
        dump_mode("ac_cycle1", [](const uint32_t x) { return CombineMode(x, true).to_string(); });
        dump_mode("cc_cycle2", [](const uint32_t x) { return CombineMode(x, false).to_string(); });
        dump_mode("ac_cycle2", [](const uint32_t x) { return CombineMode(x, true).to_string(); });
        ImGui::TreePop();
    }

    if (ImGui::TreeNodeEx("banned sprite flags")) {
        for (int i = 0; i < 17; i++) {
            bool banned = banned_sprite_flags & (1 << i);
            if (ImGui::Checkbox(
                    std::format("0x{:X} ({} times)", 1 << i, num_sprites_with_flag[i]).c_str(),
                    &banned))
                banned_sprite_flags ^= (1 << i);
        }
        ImGui::TreePop();
    }
    std::fill(std::begin(num_sprites_with_flag), std::end(num_sprites_with_flag), 0);
#endif

    if (ImGui::TreeNodeEx("scene root node")) {
        ImGui::Text("Root node address: %p", root_node);
        imgui_render_node(root_node);
        ImGui::TreePop();
    }
}

// Dev: hover-pick a texture and collect the textures visible this frame.
static void panel_textures() {
    ImGui::Checkbox("Show texture hovered by mouse cursor",
                    &imgui_state.enable_picking_texture_when_hovering);
    if (imgui_state.enable_picking_texture_when_hovering) {
        ImGui::Checkbox("Ignore transparent objects",
                        &imgui_state.pick_through_transparent_objects);
        if (imgui_state.picked_texture_id) {
            ImGui::Text("Hovered texture:");
            ImGui::SameLine();
            ImGui::Image((ImTextureID) gl_texture_from_texture_id(*imgui_state.picked_texture_id),
                         ImVec2(50, 50));
            ImGui::SameLine();
            ImGui::Text("#%d", *imgui_state.picked_texture_id);
        }
    }

    ImGui::Separator();
    ImGui::Checkbox("skip pod textures", &imgui_state.collect_textures_skip_pod_textures);
    if (ImGui::Button(imgui_state.collected_textures.empty()
                          ? "collect visible textures"
                          : "collect visible textures (press again to refresh)")) {
        std::set<RdMaterial *> visible_textures;
        for (const auto &vp: swrViewport_array) {
            if ((vp.flag & 1) == 0)
                continue;

            collect_all_visual_textures(vp, imgui_state.collect_textures_skip_pod_textures,
                                        vp.model_root_node, visible_textures);
        }
        // convert RdMaterial* to TEXIDs
        imgui_state.collected_textures.clear();
        for (const auto &tex: visible_textures) {
            for (int i = 0; i < texture_count; i++) {
                if (material_from_texture_id((TEXID) i) == tex) {
                    imgui_state.collected_textures.insert((TEXID) i);
                    break;
                }
            }
        }
    }

    int i = 0;
    for (const auto &tex: imgui_state.collected_textures) {
        ImGui::PushID(tex);
        ImGui::Image((ImTextureID) gl_texture_from_texture_id(tex), ImVec2(50, 50));
        if (ImGui::IsItemHovered()) {
            set_texture_highlighting(tex, true);
        } else {
            set_texture_highlighting(tex, false);
        }

        ImGui::SameLine();
        ImGui::Text("#%d", tex);

        if (i % 3 != 2) {
            ImGui::SameLine();
        }
        i++;

        ImGui::PopID();
    }
}

// Dev: live pod engine/cockpit transforms (falls back to a hardcoded node path).
static void panel_pod_transforms() {
    if (currentPlayer_Test == nullptr) {
        if (root_node == nullptr) {
            ImGui::Text("root_node is NULL");
        } else {
            ImGui::Text("player test is null. Trying hardcoded path for pod");
            swrModel_Node *pod_node = root_node->children.nodes[15];
            if (pod_node == nullptr) {
                ImGui::Text("Pod slot is null");
            } else {
                swrModel_Node *node =
                    pod_node->children.nodes[0]->children.nodes[2]->children.nodes[0];
                ImGui::Text("%s", std::format("{} 0x{:08x}",
                                              swrModel_NodeTypeStr((uint32_t) node->type),
                                              (uintptr_t) node)
                                      .c_str());
                rdMatrix44 mat{};
                swrModel_NodeGetTransform((const swrModel_NodeTransformed *) node, &mat);

                ImGui::Text("engine XfR Position %.2f %.2f %.2f", mat.vD.x, mat.vD.y, mat.vD.z);
            }
        }
    } else {
        ImGui::Text("350 mat Position: %.2f %.2f %.2f", currentPlayer_Test->unk350_mat.vD.x,
                    currentPlayer_Test->unk350_mat.vD.y, currentPlayer_Test->unk350_mat.vD.z);
        ImGui::Text("engine XfR Position: %.2f %.2f %.2f", currentPlayer_Test->engineXfR.vD.x,
                    currentPlayer_Test->engineXfR.vD.y, currentPlayer_Test->engineXfR.vD.z);
        ImGui::Text("engine XfL Position: %.2f %.2f %.2f", currentPlayer_Test->engineXfL.vD.x,
                    currentPlayer_Test->engineXfL.vD.y, currentPlayer_Test->engineXfL.vD.z);
        ImGui::Text("cockpitXf Position: %.2f %.2f %.2f", currentPlayer_Test->cockpitXf.vD.x,
                    currentPlayer_Test->cockpitXf.vD.y, currentPlayer_Test->cockpitXf.vD.z);
    }
}

// Dev: read-only live telemetry for the local player's pod (swrRace fields).
static void panel_pod_readout() {
    swrRace *pod = currentPlayer_Test;
    if (pod == nullptr) {
        ImGui::TextUnformatted("No local pod (currentPlayer_Test is null).");
        return;
    }

    ImGui::Text("Speed:         %.2f  (x%.2f applied)", pod->speedValue, pod->multiplayerStats);
    ImGui::Text("Thrust:        %.2f", pod->thrust);

    const char *boost_state = pod->boostIndicatorStatus == 0   ? "not ready"
                              : pod->boostIndicatorStatus == 1 ? "charging"
                              : pod->boostIndicatorStatus == 2 ? "ready"
                                                               : "?";
    ImGui::Text("Boost:         %.2f  (%s, charge %.2f)", pod->boostValue, boost_state,
                pod->boostChargeTimer);

    ImGui::Text("Engine temp:   %.2f", pod->engineTemp);
    ImGui::Text("Total damage:  %.2f", pod->totalDamage);
    ImGui::Text("Engine health: %.0f %.0f %.0f / %.0f %.0f %.0f", pod->engineHealth[0],
                pod->engineHealth[1], pod->engineHealth[2], pod->engineHealth[3],
                pod->engineHealth[4], pod->engineHealth[5]);

    ImGui::Separator();
    ImGui::Text("Tilt %.2f   Pitch %.2f   Turn %.2f", pod->tiltAngle, pod->pitch, pod->turnRate);
    ImGui::Text("Position: %.1f %.1f %.1f", pod->position.x, pod->position.y, pod->position.z);
    ImGui::Text("Velocity: %.2f %.2f %.2f", pod->velocityDir.x, pod->velocityDir.y,
                pod->velocityDir.z);
    ImGui::Text("Lap progress:  %.2f / %.2f", pod->lapComp, pod->lapCompMax);
    ImGui::Text("Respawn invuln: %.2f", pod->respawnInvincibilityTimer);
}

// Player: quick race-setup knobs. AI count is a global consumed at the next race
// start; the rest live on the hangar state and only apply in the front-end menu.
static void panel_race() {
    ImGui::SliderInt("AI racers", &nb_AI_racers, 1, 20);
    ImGui::TextDisabled("(applies to a race started from the menu, not an in-race Restart)");

    swrObjHang *hang = g_objHang2;
    if (hang == nullptr) {
        ImGui::TextDisabled("Laps / mirror / etc. are editable in the hangar menu.");
        return;
    }

    int laps = hang->numLaps;
    if (ImGui::SliderInt("Laps", &laps, 1, 125))
        hang->numLaps = (char) laps;

    bool mirror = hang->bMirror != 0;
    if (ImGui::Checkbox("Mirror mode", &mirror))
        hang->bMirror = mirror ? 1 : 0;

    const char *ai_speed_items[] = {"Slow", "Average", "Fast"};
    int ai_speed = (hang->AISpeed >= 1 && hang->AISpeed <= 3) ? hang->AISpeed - 1 : 1;
    if (ImGui::Combo("AI speed", &ai_speed, ai_speed_items, IM_ARRAYSIZE(ai_speed_items)))
        hang->AISpeed = (char) (ai_speed + 1);

    const char *winnings_items[] = {"Fair", "Skilled", "Winner takes all"};
    int winnings = (hang->WinningsID >= 1 && hang->WinningsID <= 3) ? hang->WinningsID - 1 : 0;
    if (ImGui::Combo("Winnings", &winnings, winnings_items, IM_ARRAYSIZE(winnings_items)))
        hang->WinningsID = (char) (winnings + 1);
}

// Player: audio controls. Master volume drives the A3D device output gain (the
// one knob that scales every channel); music uses the fade state machine so the
// toggle stops/starts playback live, not just on the next track change.
static void panel_audio() {
    static float master = -1.0f;
    if (master < 0.0f)
        master = a3dOutputGain > 0.0f ? a3dOutputGain : Main_sound_gain_const;
    if (ImGui::SliderFloat("Master volume", &master, 0.0f, 1.0f, "%.2f"))
        swrSound_SetOutputGain(master);

    bool sound_3d = Sound_enabled_3d != 0;
    if (ImGui::Checkbox("3D sound", &sound_3d))
        Sound_enabled_3d = sound_3d;
    bool doppler = Main_doppler_sound != 0;
    if (ImGui::Checkbox("Doppler", &doppler))
        Main_doppler_sound = doppler;
    bool music = swrRace_music_enabled != 0;
    if (ImGui::Checkbox("Music", &music)) {
        swrRace_music_enabled = music;
        swrSound_SetMusicFade(music ? 1 : 0);// 1 = arm/resume, 0 = stop now
    }
    bool voices = swrRace_voices_enabled != 0;
    if (ImGui::Checkbox("In-race voices", &voices))
        swrRace_voices_enabled = voices;
}

// Cheats. The toggles are held in these flags; apply_cheats() enforces them every
// frame (see imgui_Update) so they persist with the overlay closed.
static bool g_cheat_god = false;
static bool g_cheat_fast = false;
static bool g_cheat_no_overheat = false;
static bool g_cheat_no_fall = false;
static bool g_cheat_fly = false;

static void apply_cheats() {
    // engineTemp is a 0..100 "coolness" gauge: it drains while boosting and the
    // engine blows when it hits 0, so "no overheat" means pinning it full, not 0.
    static bool prev_fly = false;

    swrRace_IsInvincible = g_cheat_god ? 1 : 0;
    swr_FastMode = g_cheat_fast ? 1 : 0;

    swrRace *pod = currentPlayer_Test;
    if (pod != nullptr) {
        if (g_cheat_no_overheat)
            pod->engineTemp = 100.0f;
        if (g_cheat_no_fall)
            pod->fallTimer = 0.0f;
        if (g_cheat_fly)
            pod->flags0 = (swrObjTest_FLAG0) (pod->flags0 | swrObjTest_FLAG0_ZON);
        else if (prev_fly)
            // Clear the bit once on untoggle; afterwards the game owns it again so
            // we don't fight legitimate anti-grav track sections every frame.
            pod->flags0 = (swrObjTest_FLAG0) (pod->flags0 & ~swrObjTest_FLAG0_ZON);
    }

    prev_fly = g_cheat_fly;
}

static void panel_cheats() {
    ImGui::Checkbox("God mode (no damage)", &g_cheat_god);
    ImGui::Checkbox("Infinite boost / no overheat", &g_cheat_no_overheat);
    ImGui::Checkbox("Disable out-of-bounds timer", &g_cheat_no_fall);
    ImGui::Checkbox("Anti-grav / fly", &g_cheat_fly);
    ImGui::Checkbox("Fast mode (speed up time)", &g_cheat_fast);

    if (currentPlayer_Test == nullptr)
        ImGui::TextDisabled("Pod cheats take effect once you're in a race.");

    ImGui::Separator();
    // swrRace_CheatUnlockAll is not reimplemented yet (no linkable body), so call
    // the original through its named _ADDR rather than by symbol.
    if (ImGui::Button("Unlock all pods & tracks"))
        ((void (*)(void)) swrRace_CheatUnlockAll_ADDR)();
    ImGui::SameLine();
    if (ImGui::Button("+1000 truguts"))
        swrRace_truguts += 1000;
}

// Dev: live tail of the mod's hook.log (pumped only while this section is open).
static void panel_hook_log() {
    pump_hook_log();
    g_debug_log.DrawBody(320.0f);
}

static DebugPanel g_panel_graphics_settings = {
    .category = "Render", .name = "Graphics Settings", .draw = panel_graphics_settings,
    .dev_only = false, .open = true};
static DebugPanel g_panel_hd_models = {
    .category = "Render", .name = "HD Models", .draw = panel_hd_models, .dev_only = false};
static DebugPanel g_panel_race = {
    .category = "Race", .name = "Quick Race", .draw = panel_race, .dev_only = false};
static DebugPanel g_panel_audio = {
    .category = "Settings", .name = "Audio", .draw = panel_audio, .dev_only = false};
static DebugPanel g_panel_cheats = {
    .category = "Cheats", .name = "Cheats", .draw = panel_cheats, .dev_only = false};
static DebugPanel g_panel_render_debug = {
    .category = "Debug", .name = "Render Debug", .draw = panel_render_debug, .dev_only = true};
static DebugPanel g_panel_scene_inspector = {
    .category = "Inspect", .name = "Scene", .draw = panel_scene_inspector, .dev_only = true};
static DebugPanel g_panel_textures = {
    .category = "Inspect", .name = "Textures", .draw = panel_textures, .dev_only = true};
static DebugPanel g_panel_pod_transforms = {
    .category = "Inspect", .name = "Pod Transforms", .draw = panel_pod_transforms,
    .dev_only = true};
static DebugPanel g_panel_pod_readout = {
    .category = "Inspect", .name = "Pod Readout", .draw = panel_pod_readout, .dev_only = true};
static DebugPanel g_panel_hook_log = {
    .category = "Tools", .name = "Hook Log", .draw = panel_hook_log, .dev_only = true};

static void register_builtin_debug_panels() {
    debug_ui_register(&g_panel_graphics_settings);
    debug_ui_register(&g_panel_hd_models);
    debug_ui_register(&g_panel_race);
    debug_ui_register(&g_panel_audio);
    debug_ui_register(&g_panel_cheats);
    debug_ui_register(&g_panel_render_debug);
    debug_ui_register(&g_panel_scene_inspector);
    debug_ui_register(&g_panel_textures);
    debug_ui_register(&g_panel_pod_transforms);
    debug_ui_register(&g_panel_pod_readout);
    debug_ui_register(&g_panel_hook_log);
}
