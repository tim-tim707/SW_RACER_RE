#include "imgui_utils.h"
#include "n64_shader.h"

#include <string>
#include <set>
#include <format>
#include <cstdio>
#include <cstring>
#include <cwchar>

#include <imgui.h>
#include <imgui_stdlib.h>

#include "gltf_utils.h"

#include "replacements.h"
#include "renderer_utils.h"
#include "texture_replacement.h"
#include "ui_transform.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include "game_deltas/window_mode.h"

extern "C" {
#include <globals.h>
#include <macros.h>
#include <Swr/swrModel.h>
}

extern rdVector3 debugCameraPos;
extern rdVector3 cameraFront;
extern rdVector3 cameraUp;
extern float cameraPitch;
extern float cameraYaw;
extern float cameraSpeed;

// Defined in main.cpp: writes/reverts the AI full-LOD .text patches (gated by ai_full_lod).
extern "C" void set_ai_full_lod(bool on);

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
    .show_debug = false,
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

    imgui_state.ui_resolution_independent =
        GetPrivateProfileIntW(L"settings", L"ui_resolution_independent", 0, ini_path.c_str()) != 0;
    wchar_t ui_scale_buf[32] = {0};
    GetPrivateProfileStringW(L"settings", L"ui_scale", L"1.0", ui_scale_buf, 32, ini_path.c_str());
    float ui_scale = (float) wcstod(ui_scale_buf, nullptr);
    imgui_state.ui_scale = (ui_scale >= 0.5f && ui_scale <= 2.0f) ? ui_scale : 1.0f;

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

    WritePrivateProfileStringW(L"settings", L"ui_resolution_independent",
                               imgui_state.ui_resolution_independent ? L"1" : L"0",
                               ini_path.c_str());
    WritePrivateProfileStringW(L"settings", L"ui_scale",
                               std::to_wstring(imgui_state.ui_scale).c_str(), ini_path.c_str());
}

// Called from the (C) window key callbacks so Alt+Enter persists the chosen mode too.
extern "C" void save_window_mode_setting(void) {
    save_settings_ini();
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
    }

    if (imgui_initialized) {
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        opengl_render_imgui();

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

    void Draw(const char *title, bool *p_open) {
        ImGui::SetNextWindowSize(ImVec2(700, 400), ImGuiCond_FirstUseEver);
        if (!ImGui::Begin(title, p_open)) {
            ImGui::End();
            return;
        }

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

        if (ImGui::BeginChild("scrolling", ImVec2(0, 0), ImGuiChildFlags_None,
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
        ImGui::End();
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

void opengl_render_imgui() {
    // Toggled with F5
    if (!show_imgui)
        return;

    ImGui::Text("FPS rolling 120 frames: %f (%.3f ms)", ImGui::GetIO().Framerate,
                (1.0f / ImGui::GetIO().Framerate) * 1000);
    if (ImGui::TreeNodeEx("graphics settings")) {
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
                    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY,
                                    imgui_state.anisotropy);
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

        if (ImGui::Checkbox("Resolution-independent UI (experimental)",
                            &imgui_state.ui_resolution_independent)) {
            save_settings_ini();
        }
        if (ImGui::SliderFloat("UI scale", &imgui_state.ui_scale, 0.5f, 2.0f, "%.2f")) {
            save_settings_ini();
        }
        if (imgui_state.ui_resolution_independent) {
            const ImGuiIO &io = ImGui::GetIO();
            // Live per-domain scales: sprite scale = what GetUIScale_delta returns;
            // text X/Y = the Add2DQuad2 scale (screen dim * recip) after the recip patch. All three
            // should read equal when uniform; any divergence localizes the remaining stretch.
            const float text_x = (float) ((double) swrDisplay_screenWidth * swrText_designWidthRecip);
            const float text_y =
                (float) ((double) swrDisplay_screenHeight * swrText_designHeightRecip);
            const float spr_x = (float) ((double) swrDisplay_screenWidth * swrUI_designWidthRecip);
            const float spr_y = (float) ((double) swrDisplay_screenHeight * swrUI_designHeightRecip);
            ImGui::Text("swrDisplay %dx%d | imgui %.0fx%.0f", swrDisplay_screenWidth,
                        swrDisplay_screenHeight, io.DisplaySize.x, io.DisplaySize.y);
            ImGui::Text("widget %.3f | sprite %.3f | spriteRecip %.3f x %.3f | text %.3f x %.3f",
                        ui_layout_scale(), ui_sprite_scale(), spr_x, spr_y, text_x, text_y);
        }

        static const char *window_mode_items[] = {"Windowed", "Borderless", "Fullscreen"};
        int window_mode = g_window_mode;
        if (ImGui::Combo("Window mode", &window_mode, window_mode_items,
                         IM_ARRAYSIZE(window_mode_items))) {
            set_window_mode(window_mode);

            save_settings_ini();
        }
        ImGui::TreePop();
    }

    ImGui::Checkbox("Show Debug informations", &imgui_state.show_debug);
    if (imgui_state.show_debug) {
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
            dump_mode("cc_cycle1",
                      [](const uint32_t x) { return CombineMode(x, false).to_string(); });
            dump_mode("ac_cycle1",
                      [](const uint32_t x) { return CombineMode(x, true).to_string(); });
            dump_mode("cc_cycle2",
                      [](const uint32_t x) { return CombineMode(x, false).to_string(); });
            dump_mode("ac_cycle2",
                      [](const uint32_t x) { return CombineMode(x, true).to_string(); });
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
    }// !show debug information

    static bool toto = false;
    ImGui::Checkbox("matrices pos", &toto);
    if (toto) {// matrices from test object
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

#if !defined(NDEBUG)
    ImGui::Checkbox("Draw test scene instead", &imgui_state.draw_test_scene);
    if (imgui_state.draw_test_scene) {
        ImGui::Text("Position: %.2f %.2f %.2f, Front: %.2f %.2f %.2f, Up: %.2f %.2f %.2f",
                    debugCameraPos.x, debugCameraPos.y, debugCameraPos.z, cameraFront.x,
                    cameraFront.y, cameraFront.z, cameraUp.x, cameraUp.y, cameraUp.z);
        ImGui::Text("Pitch: %.2f, Yaw: %.2f", cameraPitch, cameraYaw);
        ImGui::Text("Camera Speed: %.3f", cameraSpeed);
    }
#endif

    ImGui::Checkbox("Draw meshes", &imgui_state.draw_meshes);
    ImGui::Checkbox("Draw RenderList", &imgui_state.draw_renderList);
    ImGui::Checkbox("debug lambertian", &imgui_state.debug_lambertian_cubemap);
    ImGui::Checkbox("debug ggx cubemap", &imgui_state.debug_ggx_cubemap);
    ImGui::Checkbox("debug env cubemap", &imgui_state.debug_env_cubemap);
    ImGui::Checkbox("debug ggx lut", &imgui_state.debug_ggxLut);

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

    if (ImGui::Button("Show Log"))
        imgui_state.show_logs = true;

    if (ImGui::TreeNodeEx("highlight textures from map")) {
        ImGui::Checkbox("Show texture hovered by mouse cursor",
                        &imgui_state.enable_picking_texture_when_hovering);
        if (imgui_state.enable_picking_texture_when_hovering) {
            ImGui::Checkbox("Ignore transparent objects",
                            &imgui_state.pick_through_transparent_objects);
            if (imgui_state.picked_texture_id) {
                ImGui::Text("Hovered texture:");
                ImGui::SameLine();
                ImGui::Image(
                    (ImTextureID) gl_texture_from_texture_id(*imgui_state.picked_texture_id),
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

        ImGui::TreePop();
    }

    if (ImGui::TreeNodeEx("replacement textures")) {
        ImGui::Checkbox("enable", &enable_texture_replacement);
        if (ImGui::Button("refresh replacement textures"))
            refresh_replacement_textures();

        ImGui::Text("Found %d replacement textures.", int(replacement_textures.size()));
        ImGui::TreePop();
    }

    // Floating log window, opened by the "Show Log" button above. Only tail the
    // file while it is open so the buffer doesn't grow while it isn't being used.
    if (imgui_state.show_logs) {
        pump_hook_log();
        g_debug_log.Draw("Hook Log", &imgui_state.show_logs);
    }
}
