#include "imgui_utils.h"

#include <string>
#include <set>
#include <format>

#include <imgui.h>
#include <imgui_stdlib.h>

#include "tinygltf/tiny_gltf.h"
#include "tinygltf/gltf_utils.h"

extern "C" {
#include <macros.h>
#include <Swr/swrModel.h>
}

extern std::vector<gltfModel> g_models;

extern rdVector3 debugCameraPos;
extern rdVector3 cameraFront;
extern rdVector3 cameraUp;
extern float cameraPitch;
extern float cameraYaw;
extern float cameraSpeed;

bool imgui_initialized = false;
ImGuiState imgui_state = {
    .show_debug = false,
    .draw_test_scene = false,
    .draw_meshes = true,
    .draw_renderList = true,
    .show_gltf_data = true,
    .vertex_shd = std::string(""),
    .fragment_shd = std::string(""),
    .shader_flags = ImGuiStateFlags_RESET,
    .show_fragment = false,
    .debug_lambertian_cubemap = false,
    .debug_ggx_cubemap = false,
    .debug_ggxLut = false,
    .show_replacementTries = false,
    .replacedTries = {0},
    .replacementTries = std::string(""),
    .debug_env_cubemap = false,
    .modelMatScale = {0.0, 0.0, 0.0},
};

std::set<std::string> blend_modes_cycle1;
std::set<std::string> blend_modes_cycle2;
std::set<std::string> cc_cycle1;
std::set<std::string> ac_cycle1;
std::set<std::string> cc_cycle2;
std::set<std::string> ac_cycle2;

void imgui_render_node(swrModel_Node *node) {
    if (!node)
        return;

    if (node->type & NODE_HAS_CHILDREN) {
        for (int i = 0; i < node->num_children; i++) {
            if (!node->children.nodes[i])
                continue;

            auto *child_node = node->children.nodes[i];
            if (!(child_node->flags_1 & 0x4))
                continue;

            ImGui::PushID(i);
            bool visible = child_node->flags_1 & 0x2;
            if (ImGui::SmallButton(visible ? "-V" : "+V")) {
                child_node->flags_1 ^= 0x2;
            }
            ImGui::SameLine();

            const auto model_id = find_model_id_for_node(child_node);
            if (ImGui::TreeNodeEx(
                    std::format("{}: {:04x} 0x{:08x} {}", i, (uint32_t) child_node->type,
                                (uintptr_t) child_node,
                                model_id ? std::format("MODEL: {}", int(*model_id)) : "")
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
            const auto *mesh = node->children.meshes[i];
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

void opengl_render_imgui() {
    ImGui::Text("FPS rolling 120 frames: %f", ImGui::GetIO().Framerate);
    ImGui::Checkbox("Show Debug informations", &imgui_state.show_debug);
    if (imgui_state.show_debug) {
        auto dump_member = [](auto &member) {
            ImGui::PushID(member.name);
            ImGui::Text(member.name);
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
            for (auto &member: node_members) {
                dump_member(member);
            }
            ImGui::TreePop();
        }

        if (ImGui::TreeNodeEx("mesh material props:")) {
            for (auto &member: node_material_members) {
                dump_member(member);
            }
            ImGui::TreePop();
        }

        if (ImGui::TreeNodeEx("render modes:")) {
            auto dump_mode = [](const char *name, auto &set) {
                ImGui::Text("%s", name);
                for (const auto &m: set)
                    ImGui::Text("    %s", m.c_str());

                set.clear();
            };

            dump_mode("blend_modes_cycle1", blend_modes_cycle1);
            dump_mode("blend_modes_cycle2", blend_modes_cycle2);
            dump_mode("cc_cycle1", cc_cycle1);
            dump_mode("ac_cycle1", ac_cycle1);
            dump_mode("cc_cycle2", cc_cycle2);
            dump_mode("ac_cycle2", ac_cycle2);
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

        if (ImGui::TreeNodeEx("scene root node")) {
            imgui_render_node(root_node);
            ImGui::TreePop();
        }
    }// !show debug information

    ImGui::Checkbox("Draw test scene instead", &imgui_state.draw_test_scene);
    if (imgui_state.draw_test_scene) {
        ImGui::Text("Position: %.2f %.2f %.2f, Front: %.2f %.2f %.2f, Up: %.2f %.2f %.2f",
                    debugCameraPos.x, debugCameraPos.y, debugCameraPos.z, cameraFront.x,
                    cameraFront.y, cameraFront.z, cameraUp.x, cameraUp.y, cameraUp.z);
        ImGui::Text("Pitch: %.2f, Yaw: %.2f", cameraPitch, cameraYaw);
        ImGui::Text("Camera Speed: %.3f", cameraSpeed);
    }
    ImGui::Text("Model Matrix scale: %.2f %.2f %.2f", imgui_state.modelMatScale[0],
                imgui_state.modelMatScale[1], imgui_state.modelMatScale[2]);
    ImGui::Checkbox("Draw meshes", &imgui_state.draw_meshes);
    ImGui::Checkbox("Draw RenderList", &imgui_state.draw_renderList);
    ImGui::Checkbox("Show GLTF Data", &imgui_state.show_gltf_data);
    ImGui::Checkbox("debug lambertian", &imgui_state.debug_lambertian_cubemap);
    ImGui::Checkbox("debug ggx cubemap", &imgui_state.debug_ggx_cubemap);
    ImGui::Checkbox("debug env cubemap", &imgui_state.debug_env_cubemap);
    ImGui::Checkbox("debug ggx lut", &imgui_state.debug_ggxLut);
    if (imgui_state.show_gltf_data) {
        gltfModel_to_imgui(g_models[1]);
    }

    if (ImGui::TreeNodeEx("Shader edition:")) {
        ImGui::Checkbox("Show Fragment", &imgui_state.show_fragment);
        if (!imgui_state.show_fragment) {
            ImGui::InputTextMultiline("Vertex Input", &imgui_state.vertex_shd, ImVec2(480, 320));
        } else {
            ImGui::InputTextMultiline("Fragment Input", &imgui_state.fragment_shd,
                                      ImVec2(480, 320));
        }

        if (ImGui::Button("Reset")) {
            imgui_state.shader_flags =
                static_cast<ImGuiStateFlags>(imgui_state.shader_flags | ImGuiStateFlags_RESET);
        }
        if (ImGui::Button("Recompile")) {
            imgui_state.shader_flags =
                static_cast<ImGuiStateFlags>(imgui_state.shader_flags | ImGuiStateFlags_RECOMPILE);
        }
        ImGui::TreePop();
    }

    ImGui::Checkbox("Show replacement tries", &imgui_state.show_replacementTries);
    if (imgui_state.show_replacementTries) {
        ImGui::Text("%s\n", imgui_state.replacementTries.c_str());
        imgui_state.replacementTries.clear();
        std::memset(imgui_state.replacedTries, 0, std::size(imgui_state.replacedTries));
    }
}

void gltfModel_to_imgui(gltfModel &model) {
    ImGui::Text("Meshes: %zu,\nAccessors: %zu,\nMaterials: %zu,\nBufferViews: %zu",
                model.gltf.meshes.size(), model.gltf.accessors.size(), model.gltf.materials.size(),
                model.gltf.bufferViews.size());
    double *color = model.gltf.materials[0].pbrMetallicRoughness.baseColorFactor.data();
    double *metallicFactor = &model.gltf.materials[0].pbrMetallicRoughness.metallicFactor;

    float colorf[4] = {(float) color[0], (float) color[1], (float) color[2], (float) color[3]};
    float metallicFactorf = (float) (*metallicFactor);

    ImGui::SliderFloat4("pbr baseColorFactor", colorf, 0.0, 1.0);
    ImGui::SliderFloat("pbr metallicFactor", &metallicFactorf, 0.0, 1.0);

    color[0] = colorf[0];
    color[1] = colorf[1];
    color[2] = colorf[2];
    color[3] = colorf[3];
    *metallicFactor = metallicFactorf;
}
