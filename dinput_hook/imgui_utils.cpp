#include "imgui_utils.h"
#include "n64_shader.h"

#include <string>
#include <set>
#include <format>

#include <imgui.h>
#include <imgui_stdlib.h>

#include "gltf_utils.h"

#include "replacements.h"
#include "renderer_utils.h"
#include "texture_replacement.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"

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

extern uint8_t replacedTries[323];// 323 MODELIDs
extern std::map<int, ReplacementModel> replacement_map;
extern const char *modelid_cstr[];

extern int uiX;
extern int uiY;

extern int ui2X;
extern int ui2Y;

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
    .logs = std::string(""),
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
    imgui_state.enable_gamepad_nav =
        GetPrivateProfileIntW(L"settings", L"enable_gamepad_nav", 1, ini_path.c_str());
}

void save_settings_ini() {
    WritePrivateProfileStringW(L"settings", L"msaa_samples",
                               std::to_wstring(imgui_state.msaa_samples).c_str(), ini_path.c_str());
    WritePrivateProfileStringW(L"settings", L"anisotropy",
                               std::to_wstring(imgui_state.anisotropy).c_str(), ini_path.c_str());
    WritePrivateProfileStringW(L"settings", L"enable_fog", imgui_state.enable_fog ? L"1" : L"0",
                               ini_path.c_str());
    WritePrivateProfileStringW(L"settings", L"enable_gamepad_nav",
                               imgui_state.enable_gamepad_nav ? L"1" : L"0", ini_path.c_str());
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
        if (ImGui::Checkbox("Gamepad navigation (D-pad menus, START pause/skip, "
                            "BACK cycle HUD)",
                            &imgui_state.enable_gamepad_nav)) {
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

    ImGui::Checkbox("Show logs", &imgui_state.show_logs);
    if (imgui_state.show_logs) {
        ImGui::Text("%s\n", imgui_state.logs.c_str());
    }

    ImGui::SliderInt("some Ui x", &uiX, 0, 300);
    ImGui::SliderInt("some Ui y", &uiY, 0, 300);
    ImGui::SliderInt("some Ui x 2", &ui2X, 0, 300);
    ImGui::SliderInt("some Ui y 2", &ui2Y, 0, 300);

    imgui_state.logs.clear();

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
}
