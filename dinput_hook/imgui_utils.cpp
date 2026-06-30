#include "imgui_utils.h"
#include "debug_ui.h"
#include "update_check.h"
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
#include "node_utils.h"
#include "texture_replacement.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include "game_deltas/window_mode.h"
#include "game_deltas/tracks_delta.h"

extern "C" {
#include <globals.h>
#include <macros.h>
#include <Swr/swrModel.h>
#include <Swr/swrRace.h>
#include <Swr/swrSound.h>
#include <Swr/swrObj.h>
#include <Swr/swrEvent.h>
#include <Swr/swrText.h>
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

// Pinned top-right FPS overlay; drawn every frame from imgui_Update, independent of
// the F5 debug menu. Defined below alongside the panel bodies.
static void draw_fps_overlay();

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

    imgui_state.target_fps =
        GetPrivateProfileIntW(L"settings", L"target_fps", 0, ini_path.c_str());
    if (imgui_state.target_fps != 0) {
        if (imgui_state.target_fps < 10) {
            imgui_state.target_fps = 10;
        } else if (imgui_state.target_fps > 200) {
            imgui_state.target_fps = 200;
        }
    }

    imgui_state.show_fps_overlay =
        GetPrivateProfileIntW(L"settings", L"show_fps_overlay", 0, ini_path.c_str());

    imgui_state.show_fps_graph =
        GetPrivateProfileIntW(L"settings", L"show_fps_graph", 0, ini_path.c_str());

    imgui_state.enable_fog = GetPrivateProfileIntW(L"settings", L"enable_fog", 1, ini_path.c_str());
    imgui_state.enable_gamepad_nav =
        GetPrivateProfileIntW(L"settings", L"enable_gamepad_nav", 1, ini_path.c_str());

    imgui_state.cache_meshes =
        GetPrivateProfileIntW(L"settings", L"cache_meshes", 1, ini_path.c_str());

    imgui_state.ai_full_lod =
        GetPrivateProfileIntW(L"settings", L"ai_full_lod", 1, ini_path.c_str());
    set_ai_full_lod(imgui_state.ai_full_lod);

    imgui_state.HD_replacement =
        GetPrivateProfileIntW(L"settings", L"hd_replacement", 1, ini_path.c_str());

    // Default to the build's compiled-in visibility (debug shows, release hides).
    show_imgui = (char) GetPrivateProfileIntW(L"settings", L"show_imgui", show_imgui, ini_path.c_str());

    wchar_t fov_scale_buf[32] = {0};
    GetPrivateProfileStringW(L"settings", L"fov_scale", L"1.0", fov_scale_buf, 32, ini_path.c_str());
    float fov_scale = (float) wcstod(fov_scale_buf, nullptr);
    imgui_state.fov_scale = (fov_scale >= 0.5f && fov_scale <= 2.0f) ? fov_scale : 1.0f;

    imgui_state.show_pod_names =
        GetPrivateProfileIntW(L"settings", L"show_pod_names", 1, ini_path.c_str());

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
    WritePrivateProfileStringW(L"settings", L"target_fps",
                               std::to_wstring(imgui_state.target_fps).c_str(), ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"show_fps_overlay",
                               imgui_state.show_fps_overlay ? L"1" : L"0", ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"show_fps_graph",
                               imgui_state.show_fps_graph ? L"1" : L"0", ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"enable_fog", imgui_state.enable_fog ? L"1" : L"0",
                               ini_path.c_str());
    WritePrivateProfileStringW(L"settings", L"enable_gamepad_nav",
                               imgui_state.enable_gamepad_nav ? L"1" : L"0", ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"cache_meshes",
                               imgui_state.cache_meshes ? L"1" : L"0", ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"ai_full_lod", imgui_state.ai_full_lod ? L"1" : L"0",
                               ini_path.c_str());
    WritePrivateProfileStringW(L"settings", L"fov_scale",
                               std::to_wstring(imgui_state.fov_scale).c_str(), ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"hd_replacement",
                               imgui_state.HD_replacement ? L"1" : L"0", ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"show_imgui", show_imgui ? L"1" : L"0",
                               ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"show_pod_names",
                               imgui_state.show_pod_names ? L"1" : L"0", ini_path.c_str());

    WritePrivateProfileStringW(L"settings", L"window_mode", std::to_wstring(g_window_mode).c_str(),
                               ini_path.c_str());
}

// C-callable persistence for the window key callbacks (window-mode changes and
// the F5 overlay toggle); writes the whole settings block.
extern "C" void persist_settings_ini(void) {
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

        // Fire the one-shot "newer release?" check on a background thread; the
        // overlay header polls the result and shows a banner if one lands.
        update_check_start();
    }

    if (imgui_initialized) {
        apply_cheats();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // The FPS overlay is independent of the F5 debug menu (debug_ui_render gates that).
        draw_fps_overlay();
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

// Draws white text stamped with a black outline (ImGui has no native outline);
// `outline` is the stamp radius in pixels.
static void draw_outlined_text(ImDrawList *draw, ImFont *font, float size, ImVec2 pos,
                               const char *text, int outline) {
    for (int dx = -outline; dx <= outline; dx++) {
        for (int dy = -outline; dy <= outline; dy++) {
            if (dx != 0 || dy != 0) {
                draw->AddText(font, size, {pos.x + (float) dx, pos.y + (float) dy},
                              IM_COL32(0, 0, 0, 255), text);
            }
        }
    }
    draw->AddText(font, size, pos, IM_COL32(255, 255, 255, 255), text);
}

// Pinned top-right overlay: a large, outlined FPS number with the frame time
// beneath it, plus an optional rolling graph of the smoothed frame rate with a
// horizontal line at its average. Drawn every frame (from imgui_Update)
// independently of the F5 debug menu.
static void draw_fps_overlay() {
    if (!imgui_state.show_fps_overlay)
        return;

    const ImGuiIO &io = ImGui::GetIO();
    const float graph_w = 200.0f;
    const float margin = 10.0f;

    const ImGuiViewport *viewport = ImGui::GetMainViewport();
    const ImVec2 anchor = {viewport->WorkPos.x + viewport->WorkSize.x - margin,
                           viewport->WorkPos.y + margin};
    ImGui::SetNextWindowPos(anchor, ImGuiCond_Always, ImVec2(1.0f, 0.0f));

    const ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoInputs |
        ImGuiWindowFlags_NoBackground;
    if (ImGui::Begin("FPS overlay", nullptr, flags)) {
        ImDrawList *draw = ImGui::GetWindowDrawList();
        ImFont *font = ImGui::GetFont();

        // Large FPS number, right-aligned within the graph width.
        char fps_text[32];
        snprintf(fps_text, sizeof(fps_text), "%.0f FPS", io.Framerate);
        const float big_size = ImGui::GetFontSize() * 2.0f;
        const ImVec2 big_dim = font->CalcTextSizeA(big_size, FLT_MAX, 0.0f, fps_text);
        ImVec2 cursor = ImGui::GetCursorScreenPos();
        draw_outlined_text(draw, font, big_size, {cursor.x + graph_w - big_dim.x, cursor.y},
                           fps_text, 2);
        ImGui::Dummy({graph_w, big_dim.y});

        // Frame time beneath the number.
        char ms_text[24];
        snprintf(ms_text, sizeof(ms_text), "%.2f ms", 1000.0f / io.Framerate);
        const float small_size = ImGui::GetFontSize();
        const ImVec2 small_dim = font->CalcTextSizeA(small_size, FLT_MAX, 0.0f, ms_text);
        cursor = ImGui::GetCursorScreenPos();
        draw_outlined_text(draw, font, small_size, {cursor.x + graph_w - small_dim.x, cursor.y},
                           ms_text, 1);
        ImGui::Dummy({graph_w, small_dim.y});

        if (imgui_state.show_fps_graph) {
            // History of the smoothed frame rate (the value the number shows),
            // which is far steadier to plot than raw per-frame delta time.
            static float fps_history[120] = {};
            static int fps_offset = 0;
            fps_history[fps_offset] = io.Framerate;
            fps_offset = (fps_offset + 1) % IM_ARRAYSIZE(fps_history);

            float fps_max = 0.0f, fps_sum = 0.0f;
            int fps_count = 0;
            for (float f: fps_history) {
                if (f <= 0.0f)
                    continue;
                fps_max = f > fps_max ? f : fps_max;
                fps_sum += f;
                fps_count++;
            }
            const float fps_avg = fps_count > 0 ? fps_sum / fps_count : io.Framerate;

            // Fixed 0-based scale, quantized to 30-fps steps so the bounds hold
            // still instead of rescaling every frame.
            const float scale_min = 0.0f;
            const int steps = (int) ((fps_max + 5.0f) / 30.0f) + 1;
            float scale_max = steps * 30.0f;
            if (scale_max < 60.0f)
                scale_max = 60.0f;

            ImGui::PushStyleColor(ImGuiCol_PlotLines, IM_COL32(120, 230, 140, 255));
            ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(0, 0, 0, 110));
            ImGui::PlotLines("##fps", fps_history, IM_ARRAYSIZE(fps_history), fps_offset, nullptr,
                             scale_min, scale_max, {graph_w, 60.0f});
            ImGui::PopStyleColor(2);

            // Horizontal reference line at the average frame rate.
            const ImVec2 plot_min = ImGui::GetItemRectMin();
            const ImVec2 plot_max = ImGui::GetItemRectMax();
            const float y = plot_max.y - (fps_avg / scale_max) * (plot_max.y - plot_min.y);
            draw->AddLine({plot_min.x, y}, {plot_max.x, y}, IM_COL32(255, 235, 120, 180), 1.0f);
        }
    }
    ImGui::End();
}

// --- Panels (the old opengl_render_imgui monolith, split by audience) ---------
//
// Each function below draws one registered panel's body; the debug-ui shell wraps
// it in a window and a menu entry (see register_builtin_debug_panels). The widget
// logic is unchanged from the monolith -- only the per-section TreeNode wrappers
// became panels, and the "show X" gating checkboxes became the panel open-state.

// Player: FPS overlay toggles + frame-rate cap (the overlay itself draws every frame
// from imgui_Update; this panel only configures it).
static void panel_fps() {
    // Live readout + rolling sparkline (auto-scaled, most recent sample on the
    // right). Moved here from the overlay header so the FPS stats live in the
    // FPS section with their controls.
    const ImGuiIO &io = ImGui::GetIO();
    ImGui::Text("%.0f FPS (%.2f ms)", io.Framerate, 1000.0f / io.Framerate);

    static float fps_history[120] = {};
    static int fps_cursor = 0;
    fps_history[fps_cursor] = io.Framerate;
    fps_cursor = (fps_cursor + 1) % IM_ARRAYSIZE(fps_history);
    ImGui::PlotLines("##fps", fps_history, IM_ARRAYSIZE(fps_history), fps_cursor, nullptr, 0.0f,
                     FLT_MAX, ImVec2(-FLT_MIN, 40));
    ImGui::Separator();

    if (ImGui::Checkbox("Show FPS overlay (top-right)", &imgui_state.show_fps_overlay)) {
        save_settings_ini();
    }
    if (imgui_state.show_fps_overlay) {
        ImGui::Indent();
        if (ImGui::Checkbox("Show graph", &imgui_state.show_fps_graph)) {
            save_settings_ini();
        }
        ImGui::Unindent();
    }

    // Slider runs 10..200 FPS; the far-right notch (past 200) reads "Unlimited"
    // and is stored as 0 to match the ini's "0 == off" convention. Flanked by
    // -/+ paddle buttons (hold to repeat) for one-FPS nudges.
    constexpr int fps_unlimited_pos = 201;
    int fps_slider = imgui_state.target_fps == 0 ? fps_unlimited_pos : imgui_state.target_fps;
    const char *fps_fmt = fps_slider >= fps_unlimited_pos ? "Unlimited" : "%d FPS";

    const float fps_btn_w = ImGui::GetFrameHeight();
    const float fps_spacing = ImGui::GetStyle().ItemInnerSpacing.x;
    float fps_slider_w = ImGui::CalcItemWidth() - 2.0f * (fps_btn_w + fps_spacing);
    if (fps_slider_w < 50.0f)
        fps_slider_w = 50.0f;
    bool fps_changed = false;

    ImGui::PushButtonRepeat(true);
    if (ImGui::ArrowButton("##fps_dec", ImGuiDir_Left)) {
        fps_slider--;
        fps_changed = true;
    }
    ImGui::SameLine(0.0f, fps_spacing);
    ImGui::SetNextItemWidth(fps_slider_w);
    if (ImGui::SliderInt("##fps_slider", &fps_slider, 10, fps_unlimited_pos, fps_fmt,
                         ImGuiSliderFlags_AlwaysClamp)) {
        fps_changed = true;
    }
    ImGui::SameLine(0.0f, fps_spacing);
    if (ImGui::ArrowButton("##fps_inc", ImGuiDir_Right)) {
        fps_slider++;
        fps_changed = true;
    }
    ImGui::PopButtonRepeat();
    ImGui::SameLine(0.0f, fps_spacing);
    ImGui::TextUnformatted("Frame rate cap");

    if (fps_changed) {
        fps_slider = fps_slider < 10 ? 10 : fps_slider;
        fps_slider = fps_slider > fps_unlimited_pos ? fps_unlimited_pos : fps_slider;
        imgui_state.target_fps = fps_slider >= fps_unlimited_pos ? 0 : fps_slider;
        save_settings_ini();
    }

    // Quick-set presets (24..60 fps, step 6), spread evenly across the row.
    ImGui::TextUnformatted("Quick set:");
    const int fps_presets[] = {24, 30, 36, 42, 48, 54, 60};
    const int fps_preset_count = IM_ARRAYSIZE(fps_presets);
    const float quick_spacing = ImGui::GetStyle().ItemSpacing.x;
    float quick_w = (ImGui::GetContentRegionAvail().x - quick_spacing * (fps_preset_count - 1)) /
                    fps_preset_count;
    if (quick_w < 28.0f)
        quick_w = 28.0f;
    for (int i = 0; i < fps_preset_count; i++) {
        if (i != 0)
            ImGui::SameLine();
        char label[8];
        snprintf(label, sizeof(label), "%d", fps_presets[i]);
        if (ImGui::Button(label, {quick_w, 0.0f})) {
            imgui_state.target_fps = fps_presets[i];
            save_settings_ini();
        }
    }
}

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
    if (ImGui::Checkbox("Gamepad navigation (D-pad menus, START pause/skip, "
                        "BACK cycle HUD)",
                        &imgui_state.enable_gamepad_nav)) {
        save_settings_ini();
    }

    // Per-mesh GL geometry cache: static meshes upload once instead of re-streaming every frame
    // (the profiled #1 per-draw CPU cost). Off = the old rebuild-every-frame path.
    if (ImGui::Checkbox("Cache mesh geometry (perf)", &imgui_state.cache_meshes)) {
        save_settings_ini();
    }

    if (ImGui::Checkbox("AI full LOD (no model pop-in)", &imgui_state.ai_full_lod)) {
        set_ai_full_lod(imgui_state.ai_full_lod);
    }

    // Camera FOV multiplier (1.0 = game default; aspect handled automatically via Hor+).
    if (ImGui::SliderFloat("FOV scale", &imgui_state.fov_scale, 0.5f, 2.0f, "%.2f")) {
        save_settings_ini();
    }

    if (ImGui::Checkbox("Overhead racer labels (MP names / SP place)",
                        &imgui_state.show_pod_names)) {
        save_settings_ini();
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

    if (ImGui::Checkbox("Enable HD model replacement.", &imgui_state.HD_replacement))
        save_settings_ini();
    ImGui::Checkbox("Show original on top of replacements.",
                    &imgui_state.show_original_and_replacements);
    ImGui::Checkbox("Show replacement tries", &imgui_state.show_replacementTries);
    if (imgui_state.show_replacementTries) {
        ImGui::Text("%s\n", imgui_state.replacementTries.c_str());
        imgui_state.replacementTries.clear();
    }

    // Phase 0 readout (HD_REPLACEMENT_ROADMAP): the live pod-node -> racer-entity map. In a race this
    // should list one entry per racer, each resolving to a distinct pod MODELID + owning entity, with
    // exactly the local player(s) flagged LOCAL (flags0 & 0x20). Confirms the resolver populates.
    if (currentPlayer_Test != nullptr) {
        if (ImGui::TreeNodeEx(
                ("Pod node owners: " + std::to_string(pod_node_owners.size())).c_str())) {
            swrRace *p1 = (firstLocalPlayer != nullptr) ? firstLocalPlayer->obj_test_ptr : nullptr;
            for (const PodNodeOwner &o: pod_node_owners) {
                std::optional<MODELID> id = find_model_id_for_node((const swrModel_Node *) o.begin);
                const char *name = id.has_value() ? modelid_cstr[id.value()] : "?";
                bool isLocal = (o.entity->flags0 & 0x20) != 0;
                ImGui::Text("%-26s %p f0=%08X %s%s", name, (void *) o.entity,
                            (unsigned) o.entity->flags0, isLocal ? "LOCAL" : "AI",
                            (o.entity == p1) ? " (P1)" : "");
            }
            ImGui::TreePop();
        }
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
    // engineHealth[] is a 0..1 damage accumulator (0 = pristine, 1 = blown), so
    // show it as a health percentage.
    ImGui::Text("Engine health %%: %.0f %.0f %.0f / %.0f %.0f %.0f",
                (1.0f - pod->engineHealth[0]) * 100.0f, (1.0f - pod->engineHealth[1]) * 100.0f,
                (1.0f - pod->engineHealth[2]) * 100.0f, (1.0f - pod->engineHealth[3]) * 100.0f,
                (1.0f - pod->engineHealth[4]) * 100.0f, (1.0f - pod->engineHealth[5]) * 100.0f);

    ImGui::Separator();
    ImGui::Text("Tilt %.2f   Pitch %.2f   Turn %.2f", pod->tiltAngle, pod->pitch, pod->turnRate);
    ImGui::Text("Position: %.1f %.1f %.1f", pod->position.x, pod->position.y, pod->position.z);
    ImGui::Text("Velocity: %.2f %.2f %.2f", pod->velocityDir.x, pod->velocityDir.y,
                pod->velocityDir.z);
    ImGui::Text("Lap progress:  %.2f / %.2f", pod->lapComp, pod->lapCompMax);
    ImGui::Text("Respawn invuln: %.2f", pod->respawnInvincibilityTimer);
}

// The game's name strings carry swrText render codes ("~~", "~c", "~f5", ...)
// that its own text renderer consumes; strip them so the names read cleanly in
// plain ImGui widgets. (swrText_Translate already removes the /SCREENTEXT_id/ key.)
static std::string strip_text_codes(const char *s) {
    std::string out;
    if (s == nullptr)
        return out;
    for (const char *p = s; *p;) {
        if (*p == '~') {
            p++;
            if (*p == '~') {
                p++;
                continue;
            }
            if (*p)
                p++;// the code letter (c / s / r / f ...)
            while (*p >= '0' && *p <= '9')
                p++;// optional digits, e.g. ~f5
            continue;
        }
        out.push_back(*p++);
    }
    return out;
}

// Player: quick race-setup knobs. AI count is a global consumed at the next race
// start; the rest live on the hangar state and only apply in the front-end menu.
static void panel_race() {
    ImGui::SliderInt("AI racers", &nb_AI_racers, 1, 20);

    // The hangar entity (reachable mid-race via the event registry, like annodue)
    // holds the rest of the race setup; keep its racer count synced to the slider.
    swrObjHang *hang = (swrObjHang *) swrEvent_GetItem('Hang', 0);
    if (hang != nullptr) {
        hang->num_players = (char) nb_AI_racers;

        // Track combo: enumerate the real tracks only -- the 4 vanilla circuits'
        // populated slots (via g_aTrackIDs / g_aTracksInCircuits) plus any custom
        // tracks -- so the empty planet slots don't show as phantom entries.
        auto track_item = [&](int tid) {
            std::string label = strip_text_codes(swrUI_GetTrackNameFromId_delta(tid));
            ImGui::PushID(tid);
            bool sel = hang->track_index == tid;
            if (ImGui::Selectable(label.c_str(), sel))
                hang->track_index = (char) tid;
            if (sel)
                ImGui::SetItemDefaultFocus();
            ImGui::PopID();
        };
        std::string track_preview =
            (hang->track_index >= 0 && hang->track_index < (int) trackCount)
                ? strip_text_codes(swrUI_GetTrackNameFromId_delta(hang->track_index))
                : "(none)";
        if (ImGui::BeginCombo("Track", track_preview.c_str())) {
            for (int c = 0; c < 4; c++)
                for (int s = 0; s < g_aTracksInCircuits[c]; s++)
                    track_item(g_aTrackIDs[c * DEFAULT_NB_CIRCUIT + s]);
            for (int tid = DEFAULT_NB_TRACKS; tid < (int) trackCount; tid++)
                track_item(tid);
            ImGui::EndCombo();
        }

        // Pod combo: full pilot names via the game's formatter (translated +
        // name/lastname combined), ~ codes stripped for display.
        char pod_buf[128] = {0};
        if (hang->vehiclePlayer >= 0 && hang->vehiclePlayer < 23)
            swrText_FormatPodName(hang->vehiclePlayer, pod_buf, sizeof(pod_buf));
        std::string pod_preview = strip_text_codes(pod_buf);
        if (ImGui::BeginCombo("Pod", pod_preview.c_str())) {
            for (int i = 0; i < 23; i++) {
                char buf[128] = {0};
                swrText_FormatPodName(i, buf, sizeof(buf));
                std::string label = strip_text_codes(buf);
                ImGui::PushID(i);
                bool sel = hang->vehiclePlayer == i;
                if (ImGui::Selectable(label.c_str(), sel))
                    hang->vehiclePlayer = (char) i;
                if (sel)
                    ImGui::SetItemDefaultFocus();
                ImGui::PopID();
            }
            ImGui::EndCombo();
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

    // Apply by re-running the game's own in-race load (annodue's technique): the
    // setup above is written, then an 'RStr' on the judge respawns the field --
    // the same path the pause-menu Restart uses, so no live entity surgery.
    ImGui::Separator();
    swrObjJdge *jdge = (swrObjJdge *) swrEvent_GetItem('Jdge', 0);
    ImGui::BeginDisabled(jdge == nullptr);
    if (ImGui::Button("Restart race (apply settings)"))
        swrObjJdge_Clear(jdge, 'RStr');
    ImGui::EndDisabled();
    if (jdge == nullptr)
        ImGui::TextDisabled("Restart is available during a race.");
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

    ImGui::SliderFloat("Sound effects volume", &Main_sound_gain, 0.0f, 2.0f, "%.2f");

    int music_vol = sound_music_volume;
    if (ImGui::SliderInt("Music volume", &music_vol, 0, 100))
        sound_music_volume = (short) music_vol;

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

    bool hires = Main_hiRes_sound != 0;
    if (ImGui::Checkbox("Use hi-res sounds (22kHz)", &hires))
        Main_hiRes_sound = hires;
    ImGui::TextDisabled("(hi-res applies to sounds loaded afterwards)");
}

// Player: the game's native video/detail flags (loaded from video.cfg). These
// gate game-side effect/LOD generation, so they still affect the GL renderer.
static void panel_video() {
    auto flag_checkbox = [](const char *label, int &flag) {
        bool b = flag != 0;
        if (ImGui::Checkbox(label, &b))
            flag = b;
    };
    flag_checkbox("Reflections", swrConfig_VIDEO_REFLECTIONS);
    flag_checkbox("Z-buffer effects", swrConfig_VIDEO_ZEFFECTS);
    flag_checkbox("Dynamic lighting", swrConfig_VIDEO_DYNAMIC_LIGHTING);
    flag_checkbox("Engine exhaust (smoke)", swrConfig_VIDEO_ENGINEEXHAUST);
    // (Lens flare omitted: its native flag gated the original D3D path that the
    //  GL renderer bypasses, so toggling it has no effect.)

    const char *detail_items[] = {"Low", "Medium", "High"};
    int model_detail = (swrConfig_VIDEO_MODEL_DETAIL >= 0 && swrConfig_VIDEO_MODEL_DETAIL <= 2)
                           ? swrConfig_VIDEO_MODEL_DETAIL
                           : 2;
    if (ImGui::Combo("Model detail", &model_detail, detail_items, IM_ARRAYSIZE(detail_items)))
        swrConfig_VIDEO_MODEL_DETAIL = model_detail;
}

// Player: joystick basics. Per-axis sensitivity / invert live in the swrControl
// axis registrations, not single globals, so they're not exposed here.
static void panel_controls() {
    bool joy = swrConfig_joystick_enabled != 0;
    if (ImGui::Checkbox("Joystick enabled", &joy))
        swrConfig_joystick_enabled = joy;

    ImGui::SliderFloat("Joystick deadzone", &Deadzone, 0.0f, 1.0f, "%.2f");
    ImGui::TextDisabled("(per-axis sensitivity / invert not exposed here)");
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

// Live tail of the mod's hook.log in its own floating window (toggled from the
// overlay footer). Only pump while open so the buffer doesn't grow unused.
void imgui_draw_log_window(bool *p_open) {
    if (!*p_open)
        return;
    pump_hook_log();
    ImGui::SetNextWindowSize(ImVec2(700, 400), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Hook Log", p_open))
        g_debug_log.DrawBody(0.0f);// 0 = fill the window
    ImGui::End();
}

static DebugPanel g_panel_fps = {
    .category = "Render", .name = "FPS",
    .keywords = "frame rate framerate cap limit unlimited overlay graph performance ms latency",
    .draw = panel_fps, .dev_only = false};
static DebugPanel g_panel_graphics_settings = {
    .category = "Render", .name = "Graphics Settings",
    .keywords = "msaa antialiasing aliasing anisotropy filtering fog gamepad navigation dpad d-pad "
                "mesh cache lod ai full lod fov field of view zoom overhead racer labels names "
                "window mode windowed borderless fullscreen",
    .draw = panel_graphics_settings, .dev_only = false, .open = true};
static DebugPanel g_panel_hd_models = {
    .category = "Render", .name = "HD Models",
    .keywords = "hd model replacement gltf pbr reload texture replacement pod node owners",
    .draw = panel_hd_models, .dev_only = false};
static DebugPanel g_panel_race = {
    .category = "Settings", .name = "Race",
    .keywords = "ai racers track pod pilot laps mirror ai speed winnings restart quick race circuit",
    .draw = panel_race, .dev_only = false};
static DebugPanel g_panel_audio = {
    .category = "Settings", .name = "Audio",
    .keywords = "volume master sound effects sfx music doppler 3d voices hi-res hires 22khz mute",
    .draw = panel_audio, .dev_only = false};
static DebugPanel g_panel_video = {
    .category = "Settings", .name = "Video",
    .keywords = "reflections z-buffer zeffects dynamic lighting engine exhaust smoke model detail "
                "video config",
    .draw = panel_video, .dev_only = false};
static DebugPanel g_panel_controls = {
    .category = "Settings", .name = "Controls",
    .keywords = "controller gamepad joystick keyboard deadzone sensitivity invert enabled",
    .draw = panel_controls, .dev_only = false};
static DebugPanel g_panel_cheats = {
    .category = "Cheats", .name = "Cheats",
    .keywords = "god mode damage invincible boost overheat infinite out of bounds fall anti-grav "
                "antigrav fly fast time truguts money unlock pods tracks",
    .draw = panel_cheats, .dev_only = false};
static DebugPanel g_panel_render_debug = {
    .category = "Debug", .name = "Render Debug",
    .keywords = "test scene meshes renderlist render list lambertian ggx cubemap env lut debug pbr",
    .draw = panel_render_debug, .dev_only = true};
static DebugPanel g_panel_scene_inspector = {
    .category = "Inspect", .name = "Scene",
    .keywords = "scene graph node props material render modes blend sprite flags root inspector",
    .draw = panel_scene_inspector, .dev_only = true};
static DebugPanel g_panel_textures = {
    .category = "Inspect", .name = "Textures",
    .keywords = "texture picker hovered cursor collect visible dump browse",
    .draw = panel_textures, .dev_only = true};
static DebugPanel g_panel_pod_transforms = {
    .category = "Inspect", .name = "Pod Transforms",
    .keywords = "pod transform engine cockpit xform matrix position node",
    .draw = panel_pod_transforms, .dev_only = true};
static DebugPanel g_panel_pod_readout = {
    .category = "Inspect", .name = "Pod Readout",
    .keywords = "pod readout telemetry speed thrust boost engine temp damage health tilt pitch turn "
                "position velocity lap respawn",
    .draw = panel_pod_readout, .dev_only = true};

static void register_builtin_debug_panels() {
    debug_ui_register(&g_panel_fps);
    debug_ui_register(&g_panel_graphics_settings);
    debug_ui_register(&g_panel_hd_models);
    debug_ui_register(&g_panel_race);
    debug_ui_register(&g_panel_audio);
    debug_ui_register(&g_panel_video);
    debug_ui_register(&g_panel_controls);
    debug_ui_register(&g_panel_cheats);
    debug_ui_register(&g_panel_render_debug);
    debug_ui_register(&g_panel_scene_inspector);
    debug_ui_register(&g_panel_textures);
    debug_ui_register(&g_panel_pod_transforms);
    debug_ui_register(&g_panel_pod_readout);
}
