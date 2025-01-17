//
// Created by tly on 10.03.2024.
//
#include "renderer_hook.h"
#include "hook_helper.h"
#include "node_utils.h"
#include "imgui_utils.h"
#include "renderer_utils.h"
#include "replacements.h"
#include "tinygltf/stb_image.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include "n64_shader.h"
#include "types.h"
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <format>
#include <functional>
#include <future>
#include <globals.h>
#include <imgui.h>
#include <imgui_stdlib.h>
#include <macros.h>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <vector>
#include <algorithm>

#ifdef GLFW_BACKEND
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#else
#include "backends/imgui_impl_d3d.h"
#include "backends/imgui_impl_win32.h"
#endif

extern "C" {
#include <Swr/swrAssetBuffer.h>
#include <Engine/rdMaterial.h>
#include <Platform/std3D.h>
#include <Primitives/rdMatrix.h>
#include <Raster/rdCache.h>
#include <Swr/swrModel.h>
#include <Swr/swrRender.h>
#include <Swr/swrSprite.h>
#include <Swr/swrViewport.h>
#include <Swr/swrViewport.h>
#include <Swr/swrEvent.h>
#include <Win95/stdConsole.h>
#include <Win95/stdDisplay.h>
#include <swr.h>
}

extern "C" FILE *hook_log;
extern swrModel_Node *root_node;
extern uint32_t banned_sprite_flags;
extern int num_sprites_with_flag[32];
extern NodeMember node_members[5];
extern MaterialMember node_material_members[9];
extern std::vector<AssetPointerToModel> asset_pointer_to_model;
extern bool imgui_initialized;
extern ImGuiState imgui_state;
extern const char *modelid_cstr[];
extern uint8_t replacedTries[323];// 323 MODELIDs

static bool environment_setuped = false;
static bool skybox_initialized = false;
static EnvInfos envInfos;

static int frameCount = 0;

GLuint GL_CreateDefaultWhiteTexture() {
    GLuint gl_tex = 0;
    glGenTextures(1, &gl_tex);

    glBindTexture(GL_TEXTURE_2D, gl_tex);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    const uint32_t white = 0xFF'FF'FF'FF;
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, &white);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glBindTexture(GL_TEXTURE_2D, 0);
    return gl_tex;
}

void glDrawAABBLines(const rdVector3 &aabb_min, const rdVector3 &aabb_max) {
    glColor3f(1, 1, 1);
    glLineWidth(1.0);
    glPushMatrix();
    glTranslatef(aabb_min.x, aabb_min.y, aabb_min.z);
    glScalef(aabb_max.x - aabb_min.x, aabb_max.y - aabb_min.y, aabb_max.x - aabb_min.y);
    glBegin(GL_LINES);
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            int pos0[3]{j / 2, j % 2, 0};
            std::swap(pos0[i], pos0[2]);
            glVertex3iv(&pos0[0]);

            int pos1[3]{j / 2, j % 2, 1};
            std::swap(pos1[i], pos1[2]);
            glVertex3iv(&pos1[0]);
        }
    }
    glEnd();
    glPopMatrix();
}

struct Vertex {
    rdVector3 pos;
    uint16_t tu, tv;
    union {
        struct {
            rdVector4 color;
        };
        struct {
            rdVector3 normal;
            float alpha;
        };
    };
};

void parse_display_list_commands(const rdMatrix44 &model_matrix, const swrModel_Mesh *mesh,
                                 std::vector<Vertex> &triangles) {
    triangles.clear();

    static std::map<const swrModel_Mesh *, rdMatrix44> cached_model_matrix;
    cached_model_matrix[mesh] = model_matrix;

    bool vertices_have_normals = mesh->mesh_material->type & 0x11;
    auto load_vertex = [&](const rdMatrix44 &model_matrix, Vtx *ptr) {
        // TODO
        rdMatrix44 normal_matrix = model_matrix;

        Vtx v = *ptr;
        v.v.x = SWAP16(v.v.x);
        v.v.y = SWAP16(v.v.y);
        v.v.z = SWAP16(v.v.z);
        v.v.u = SWAP16(v.v.u);
        v.v.v = SWAP16(v.v.v);

        Vertex vf{};
        vf.pos.x = v.v.x;
        vf.pos.y = v.v.y;
        vf.pos.z = v.v.z;

        // pretransform position
        rdMatrix_Transform3(&vf.pos, &vf.pos, &model_matrix);

        vf.tu = v.v.u;
        vf.tv = v.v.v;

        if (vertices_have_normals) {
            vf.normal.x = v.n.nx / 128.0;
            vf.normal.y = v.n.ny / 128.0;
            vf.normal.z = v.n.nz / 128.0;
            vf.alpha = v.n.a / 255.0;

            // pretransform normal
            rdMatrix_Multiply3(&vf.normal, &vf.normal, &normal_matrix);
        } else {
            vf.color.x = v.v.r / 255.0;
            vf.color.y = v.v.g / 255.0;
            vf.color.z = v.v.b / 255.0;
            vf.color.w = v.v.a / 255.0;
        }
        return vf;
    };

    Vertex vertices[32];

    const Gfx *command = swrModel_MeshGetDisplayList(mesh);
    while (command->type != 0xdf) {
        switch (command->type) {
            case 0x1: {
                const uint8_t n = (SWAP16(command->gSPVertex.n_packed) >> 4) & 0xFF;
                const uint8_t v0 = command->gSPVertex.v0_plus_n - n;
                if (v0 != mesh->vertex_base_offset)
                    std::abort();

                if (v0 + n > 32)
                    std::abort();

                if (v0 != 0) {
                    const rdMatrix44 &prev_matrix =
                        cached_model_matrix.at(mesh->referenced_node->children.meshes[0]);
                    for (int i = 0; i < v0; i++)
                        vertices[i] =
                            load_vertex(prev_matrix, command->gSPVertex.vertex_offset - v0 + i);
                }

                for (int i = 0; i < n; i++) {
                    vertices[v0 + i] =
                        load_vertex(model_matrix, command->gSPVertex.vertex_offset + i);
                }
                break;
            }
            case 0x3:
                break;
            case 0x5:
                triangles.push_back(vertices[command->gSP1Triangle.index0 / 2]);
                triangles.push_back(vertices[command->gSP1Triangle.index1 / 2]);
                triangles.push_back(vertices[command->gSP1Triangle.index2 / 2]);
                break;
            case 0x6:
                triangles.push_back(vertices[command->gSP1Triangle.index0 / 2]);
                triangles.push_back(vertices[command->gSP1Triangle.index1 / 2]);
                triangles.push_back(vertices[command->gSP1Triangle.index2 / 2]);

                triangles.push_back(vertices[command->gSP2Triangles.index3 / 2]);
                triangles.push_back(vertices[command->gSP2Triangles.index4 / 2]);
                triangles.push_back(vertices[command->gSP2Triangles.index5 / 2]);
                break;
            default:
                std::abort();
        }
        command++;
    }
}

static bool environment_models_drawn = false;
static const int ignoredModels[] = {
    MODELID_dustkick1_vlec,      MODELID_shadow_square_part, MODELID_shadow_circle_part,
    MODELID_fireball_1_part,     MODELID_fx_flameanim_part,  MODELID_fx_lavafoof_part,
    MODELID_fx_methanefoof_part, MODELID_fx_rocksmall_part,  MODELID_fx_rockbig_part,
    MODELID_fx_rockgiant_part,   MODELID_fx_shards_part,     MODELID_fx_treesmash_part,
};

static bool isEnvModel(int modelId) {
    // Places and tracks
    if (modelId == MODELID_hangar18_part || modelId == MODELID_loc_watto_part ||
        modelId == MODELID_loc_junkyard_part || modelId == MODELID_loc_awards_part ||
        modelId == MODELID_loc_cantina_part || modelId == MODELID_tatooine_track ||
        modelId == MODELID_tatooine_mini_track ||
        (modelId >= MODELID_planeth_track && modelId <= MODELID_planetf1_track) ||
        modelId == MODELID_planetf2_track ||
        (modelId >= MODELID_planetf3_track && modelId <= MODELID_planetj2_track) ||
        modelId == MODELID_planetj3_track)
        return true;

    // Various elements
    if (modelId == MODELID_holo_proj02_puppet || modelId == MODELID_balloon01_part ||
        modelId == MODELID_gate01_part)
        return true;

    for (size_t i = 0; i < std::size(ignoredModels); i++) {
        if (modelId == ignoredModels[i])
            return true;
    }

    return false;
}

static bool isPodModel(int modelId) {
    if (modelId == MODELID_alt_anakin_pod || modelId == MODELID_anakin_pod ||
        modelId == MODELID_alt_teemto_pod || modelId == MODELID_teemto_pod ||
        modelId == MODELID_alt_sebulba_pod || modelId == MODELID_sebulba_pod ||
        modelId == MODELID_alt_ratts_pod || modelId == MODELID_ratts_pod ||
        modelId == MODELID_aldar_beedo_pod || modelId == MODELID_alt_aldar_beedo_pod ||
        modelId == MODELID_alt_mawhonic_pod || modelId == MODELID_mawhonic_pod ||
        modelId == MODELID_alt_bumpy_roose_pod || modelId == MODELID_bumpy_roose_pod ||
        modelId == MODELID_alt_wan_sandage_pod || modelId == MODELID_mars_guo_pod ||
        modelId == MODELID_wan_sandage_pod || modelId == MODELID_alt_mars_guo_pod ||
        modelId == MODELID_alt_ebe_endicott_pod || modelId == MODELID_ebe_endicott_pod ||
        modelId == MODELID_alt_dud_bolt_pod || modelId == MODELID_dud_bolt_pod ||
        modelId == MODELID_alt_gasgano_pod || modelId == MODELID_gasgano_pod ||
        modelId == MODELID_alt_clegg_holdfast_pod || modelId == MODELID_clegg_holdfast_pod ||
        modelId == MODELID_alt_elan_mak_pod || modelId == MODELID_elan_mak_pod ||
        modelId == MODELID_alt_neva_kee_pod || modelId == MODELID_neva_kee_pod ||
        modelId == MODELID_alt_bozzie_barada_pod || modelId == MODELID_bozzie_barada_pod ||
        modelId == MODELID_alt_boles_roor_pod || modelId == MODELID_boles_roor_pod ||
        modelId == MODELID_alt_ody_mandrell_pod || modelId == MODELID_ody_mandrell_pod ||
        modelId == MODELID_alt_fud_sang_pod || modelId == MODELID_fud_sang_pod ||
        modelId == MODELID_alt_ben_quadinaros_pod || modelId == MODELID_ben_quadinaros_pod ||
        modelId == MODELID_alt_slide_paramita_pod || modelId == MODELID_slide_paramita_pod ||
        modelId == MODELID_alt_toy_dampner_pod || modelId == MODELID_toy_dampner_pod ||
        modelId == MODELID_alt_bullseye_pod || modelId == MODELID_bullseye_pod ||
        modelId == MODELID_alt_jinn_reeso_pod || modelId == MODELID_jinn_reeso_pod ||
        modelId == MODELID_alt_cy_yunga_pod || modelId == MODELID_cy_yunga_pod) {
        return true;
    }
    return false;
}

void debug_render_mesh(const swrModel_Mesh *mesh, int light_index, int num_enabled_lights,
                       bool mirrored, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix, MODELID model_id) {

    if (!imgui_state.draw_meshes)
        return;

    const auto &aabb = mesh->aabb;
    // glDrawAABBLines({ aabb[0], aabb[1], aabb[2] }, { aabb[3], aabb[4], aabb[5] });

    if (!mesh->vertices)
        return;

    for (auto &member: node_material_members) {
        const uint32_t value = member.getter(*mesh->mesh_material);
        member.count[value]++;
    }

    for (const auto &member: node_material_members) {
        const uint32_t value = member.getter(*mesh->mesh_material);
        if (member.banned.contains(value))
            return;
    }

    if (imgui_state.show_replacementTries && environment_models_drawn == false &&
        !isEnvModel(model_id)) {
        imgui_state.replacementTries += std::string("=== ENV DONE ===\n");
        environment_models_drawn = true;
    }

    const auto &type = mesh->mesh_material->type;
    // replacements
    if (try_replace(model_id, proj_matrix, view_matrix, model_matrix, envInfos, mirrored, type)) {
        return;
    }

    // std::string debug_msg = std::format(
    //     "render mesh {}", modelid_cstr[model_id]);
    // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, debug_msg.length(), debug_msg.c_str());

    const bool vertices_have_normals = mesh->mesh_material->type & 0x11;

    const auto &n64_material = mesh->mesh_material->material;

    const uint32_t render_mode = n64_material->render_mode_1 | n64_material->render_mode_2;
    set_render_mode(render_mode);

    const auto &rm = (const RenderMode &) render_mode;

    const auto color_cycle1 = CombineMode(n64_material->color_combine_mode_cycle1, false);
    const auto alpha_cycle1 = CombineMode(n64_material->alpha_combine_mode_cycle1, true);
    const auto color_cycle2 = CombineMode(n64_material->color_combine_mode_cycle2, false);
    const auto alpha_cycle2 = CombineMode(n64_material->alpha_combine_mode_cycle2, true);

    float uv_scale_x = 1.0;
    float uv_scale_y = 1.0;
    float uv_offset_x = 0;
    float uv_offset_y = 0;
    if (mesh->mesh_material->material_texture &&
        mesh->mesh_material->material_texture->loaded_material) {
        const auto &tex = mesh->mesh_material->material_texture;
        auto *sys_tex = tex->loaded_material->aTextures;
        GLuint gl_tex = GLuint(sys_tex->pD3DSrcTexture);
        glBindTexture(GL_TEXTURE_2D, gl_tex);

        if (tex->specs[0]) {
            uv_scale_x = tex->specs[0]->flags & 0x10'00'00'00 ? 2.0 : 1.0;
            uv_scale_y = tex->specs[0]->flags & 0x01'00'00'00 ? 2.0 : 1.0;
            if (tex->specs[0]->flags & 0x20'00'00'00) {
                uv_offset_x -= 1;
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
            } else {
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
            }
            if (tex->specs[0]->flags & 0x02'00'00'00) {
                uv_offset_y -= 1;
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
            } else {
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
            }
        }
        uv_offset_x += 1 - (float) mesh->mesh_material->texture_offset[0] / (float) tex->res[0];
        uv_offset_y += 1 - (float) mesh->mesh_material->texture_offset[1] / (float) tex->res[1];
    } else {
        // some meshes don't render correctly without a default white texture.
        // they use the "TEXEL0" or "TEXEL1" color combiner input.
        static GLuint default_gl_tex = GL_CreateDefaultWhiteTexture();
        glBindTexture(GL_TEXTURE_2D, default_gl_tex);
    }
    if (type & 0x8) {
        glEnable(GL_CULL_FACE);
        glCullFace(mirrored ? GL_FRONT : GL_BACK);
    } else if (type & 0x40) {
        // mirrored geometry.
        glEnable(GL_CULL_FACE);
        glCullFace(mirrored ? GL_BACK : GL_FRONT);
    } else {
        // double sided geometry.
        glDisable(GL_CULL_FACE);
    }

    const ColorCombineShader shader = get_or_compile_color_combine_shader(
        imgui_state, {color_cycle1, alpha_cycle1, color_cycle2, alpha_cycle2});
    glUseProgram(shader.handle);

    glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &proj_matrix.vA.x);
    glUniformMatrix4fv(shader.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);

    rdMatrix44 identity_mat;
    rdMatrix_SetIdentity44(&identity_mat);
    glUniformMatrix4fv(shader.model_matrix_pos, 1, GL_FALSE, &identity_mat.vA.x);
    glUniform2f(shader.uv_offset_pos, uv_offset_x, uv_offset_y);
    glUniform2f(shader.uv_scale_pos, uv_scale_x, uv_scale_y);

    const auto &[r, g, b, a] = n64_material->primitive_color;
    glUniform4f(shader.primitive_color_pos, r / 255.0, g / 255.0, b / 255.0, a / 255.0);

    glUniform1i(shader.enable_gouraud_shading_pos, vertices_have_normals);
    glUniform3fv(shader.ambient_color_pos, 1, &lightAmbientColor[light_index].x);
    glUniform3fv(shader.light_color_pos, 1, &lightColor1[light_index].x);
    glUniform3fv(shader.light_dir_pos, 1, &lightDirection1[light_index].x);
    // TODO light 2

    const bool fog_enabled = (GameSettingFlags & 0x40) == 0;
    glUniform1i(shader.fog_enabled_pos, fog_enabled);
    if (fog_enabled) {
        glUniform1f(shader.fog_start_pos, fogStart);
        glUniform1f(shader.fog_end_pos, fogEnd);

        const rdVector4 fog_color = {
            fogColorInt16[0] / 255.0f,
            fogColorInt16[1] / 255.0f,
            fogColorInt16[2] / 255.0f,
            fogColorInt16[3] / 255.0f,
        };
        glUniform4fv(shader.fog_color_pos, 1, &fog_color.x);
    }

    glUniform1i(shader.model_id_pos, model_id);

    glBindVertexArray(shader.VAO);

    glEnableVertexAttribArray(0);
    glEnableVertexAttribArray(1);
    glEnableVertexAttribArray(2);
    glEnableVertexAttribArray(3);

    static std::vector<Vertex> triangles;
    parse_display_list_commands(model_matrix, mesh, triangles);

    glBindBuffer(GL_ARRAY_BUFFER, shader.VBO);
    glBufferData(GL_ARRAY_BUFFER, triangles.size() * sizeof(triangles[0]), &triangles[0],
                 GL_DYNAMIC_DRAW);

    glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, sizeof(triangles[0]),
                          reinterpret_cast<void *>(offsetof(Vertex, Vertex::pos)));
    glVertexAttribPointer(1, 4, GL_FLOAT, GL_FALSE, sizeof(triangles[0]),
                          reinterpret_cast<void *>(offsetof(Vertex, Vertex::color)));
    glVertexAttribPointer(2, 2, GL_SHORT, GL_FALSE, sizeof(triangles[0]),
                          reinterpret_cast<void *>(offsetof(Vertex, Vertex::tu)));
    glVertexAttribPointer(3, 3, GL_FLOAT, GL_FALSE, sizeof(triangles[0]),
                          reinterpret_cast<void *>(offsetof(Vertex, Vertex::normal)));

    glDrawArrays(GL_TRIANGLES, 0, triangles.size());

    if (!environment_models_drawn) {
        GLint old_viewport[4];
        glGetIntegerv(GL_VIEWPORT, old_viewport);
        glViewport(0, 0, 2048, 2048);
        // Env camera FBO
        glBindFramebuffer(GL_FRAMEBUFFER, envInfos.ibl_framebuffer);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT, GL_TEXTURE_2D,
                               envInfos.skybox.depthTexture, 0);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                               GL_TEXTURE_CUBE_MAP_POSITIVE_X + frameCount,
                               envInfos.skybox.GLCubeTexture, 0);

        const swrViewport &vp = swrViewport_array[1];

        // setup Camera position
        rdMatrix44 envViewMat{};
        rdVector3 envCameraPosition = {
            vp.model_matrix.vD.x,
            vp.model_matrix.vD.y,
            vp.model_matrix.vD.z,
        };
        rdVector3 targets[] = {
            {-1, 0, 0},// NEGATIVE X
            {1, 0, 0}, // POSITIVE X
            {0, -1, 0},// NEGATIVE Y
            {0, 1, 0}, // POSITIVE Y
            {0, 0, -1},// NEGATIVE Z
            {0, 0, 1}, // POSITIVE Z
        };

        rdVector3 envCameraUp[] = {
            {0, -1, 0}, {0, -1, 0}, {0, 0, 1}, {0, 0, -1}, {0, -1, 0}, {0, -1, 0},
        };

        renderer_lookAtForward(&envViewMat, &envCameraPosition, &targets[frameCount],
                               &envCameraUp[frameCount]);
        renderer_inverse4(&envViewMat, &envViewMat);
        glUniformMatrix4fv(shader.view_matrix_pos, 1, GL_FALSE, &envViewMat.vA.x);

        float f = 1000.0;
        float n = 0.001;
        const float t = 1.0f / tan(0.5 * 90 / 180.0 * 3.14159);
        float a = 1.0;
        const rdMatrix44 proj_mat{
            {t, 0, 0, 0},
            {0, t / a, 0, 0},
            {0, 0, -(f + n) / (f - n), -1},
            {0, 0, -2 * f * n / (f - n), 1},
        };
        glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &proj_mat.vA.x);

        glDrawArrays(GL_TRIANGLES, 0, triangles.size());

        glBindFramebuffer(GL_FRAMEBUFFER, 0);
        glViewport(old_viewport[0], old_viewport[1], old_viewport[2], old_viewport[3]);
    }

    glDisableVertexAttribArray(0);
    glDisableVertexAttribArray(1);
    glDisableVertexAttribArray(2);
    glDisableVertexAttribArray(3);

    glBindVertexArray(0);

    glUseProgram(0);

    // glPopDebugGroup();
}

void debug_render_node(const swrViewport &current_vp, const swrModel_Node *node, int light_index,
                       int num_enabled_lights, bool mirrored, const rdMatrix44 &proj_mat,
                       const rdMatrix44 &view_mat, rdMatrix44 model_mat) {
    if (!node)
        return;

    if ((current_vp.node_flags1_exact_match_for_rendering & node->flags_1) !=
        current_vp.node_flags1_exact_match_for_rendering)
        return;

    if ((current_vp.node_flags1_any_match_for_rendering & node->flags_1) == 0)
        return;

    for (auto &member: node_members) {
        const uint32_t value = member.getter(*node);
        member.count[value]++;
    }

    for (const auto &member: node_members) {
        const uint32_t value = member.getter(*node);
        if (member.banned.contains(value))
            return;
    }

    if (node->type == NODE_TRANSFORMED || node->type == NODE_TRANSFORMED_WITH_PIVOT ||
        node->type == NODE_TRANSFORMED_COMPUTED)
        apply_node_transform(model_mat, node, (const rdVector3 *) &current_vp.model_matrix.vD);

    if (node->flags_5 & 0x4) {
        light_index = node->light_index + 1;
        num_enabled_lights = numEnabledLights[node->light_index];
    }

    const std::optional<MODELID> node_model_id = find_model_id_for_node(node);
    // inspection hangar is pln_tatooine_part and not a pod ID
    if (node->type == NODE_BASIC && node_model_id.has_value() &&
        (isPodModel(node_model_id.value()) || node_model_id.value() == MODELID_pln_tatooine_part)) {
        if (try_replace_pod(node_model_id.value(), proj_mat, view_mat, model_mat, envInfos, false,
                            0)) {
            return;
        }
    }

    if (node->flags_5 & 0x1) {
        mirrored = !mirrored;
    }

    if (node->type == NODE_MESH_GROUP) {
        for (int i = 0; i < node->num_children; i++) {
            const std::optional<MODELID> model_id = find_model_id_for_node(node->children.nodes[i]);
            if (model_id.has_value())
                debug_render_mesh(node->children.meshes[i], light_index, num_enabled_lights,
                                  mirrored, proj_mat, view_mat, model_mat, model_id.value());
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
            debug_render_node(current_vp, node->children.nodes[i - 1], light_index,
                              num_enabled_lights, mirrored, proj_mat, view_mat, model_mat);
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
                    debug_render_node(current_vp, node->children.nodes[i], light_index,
                                      num_enabled_lights, mirrored, proj_mat, view_mat, model_mat);
                break;
            default:
                if (child >= 0 && child < node->num_children)
                    debug_render_node(current_vp, node->children.nodes[child], light_index,
                                      num_enabled_lights, mirrored, proj_mat, view_mat, model_mat);

                break;
        }
    } else {
        for (int i = 0; i < node->num_children; i++)
            debug_render_node(current_vp, node->children.nodes[i], light_index, num_enabled_lights,
                              mirrored, proj_mat, view_mat, model_mat);
    }
}

void debug_render_sprites() {
    fprintf(hook_log, "debug_render_sprites\n");
    fflush(hook_log);

    glUseProgram(0);
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
    glOrtho(0, 640, 0, 480, -100, 100);

    glDisable(GL_DEPTH_TEST);
    glEnable(GL_BLEND);
    glDisable(GL_CULL_FACE);
    glColor4f(1, 1, 1, 1);

    for (int i = 0; i < swrSprite_SpriteCount; i++) {
        const auto &sprite = swrSprite_array[i];
        for (int k = 0; k < 32; k++) {
            num_sprites_with_flag[k] += (sprite.flags & (1 << k)) != 0;
        }

        if (!sprite.texture)
            continue;

        if (sprite.flags & banned_sprite_flags)
            continue;

        if (!(sprite.flags & 0x20))
            continue;

        float scale = 2;
        if (sprite.flags & 0x10000)
            scale = 1;

        float sprite_x = sprite.x;
        float sprite_y = sprite.y;
        float total_width = sprite.width * sprite.texture->header.width;
        float total_height = sprite.height * sprite.texture->header.height;
        if (sprite.flags & 0x1000) {
            sprite_x -= total_width / 2.0f;
            sprite_y -= total_height / 2.0f;
        }

        int x_offset = 0;
        int y_offset = 0;
        for (int p = 0; p < sprite.texture->header.page_count; p++) {
            const auto &page = sprite.texture->header.page_table[p];
            const RdMaterial *material = (const RdMaterial *) page.offset;

            float x = sprite.width * x_offset;
            float y = sprite.height * y_offset;
            float width = sprite.width * page.width;
            float height = sprite.height * page.height;

            const GLuint tex = GLuint(material->aTextures->pD3DSrcTexture);
            fprintf(hook_log, "debug_render_sprites: glEnable(GL_TEXTURE) is deprecated\n");
            fflush(hook_log);
            glEnable(GL_TEXTURE);
            glBindTexture(GL_TEXTURE_2D, tex);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

            float uv_scale_x = float(page.width) / material->aTextures->ddsd.dwWidth;
            float uv_scale_y = float(page.height) / material->aTextures->ddsd.dwHeight;
            rdVector2 uvs[]{{0, uv_scale_y}, {uv_scale_x, uv_scale_y}, {0, 0}, {uv_scale_x, 0}};
            if (sprite.flags & 0x4) {
                x = total_width - x;
                width *= -1;
            }
            if (sprite.flags & 0x8) {
                y = total_height - y;
                height *= -1;
            }

            x += sprite_x;
            y += sprite_y;

            x *= scale;
            y *= scale;
            width *= scale;
            height *= scale;

            glColor4ubv(&sprite.r);
            glBegin(GL_TRIANGLE_STRIP);
            glTexCoord2fv(&uvs[0].x);
            glVertex2f(x, y);
            glTexCoord2fv(&uvs[1].x);
            glVertex2f(x + width, y);
            glTexCoord2fv(&uvs[2].x);
            glVertex2f(x, y + height);
            glTexCoord2fv(&uvs[3].x);
            glVertex2f(x + width, y + height);
            glEnd();

            x_offset += page.width;
            if (x_offset >= sprite.texture->header.width - 1) {
                x_offset = 0;
                y_offset += page.height;
            }
        }
    }
}

void swrViewport_Render_Hook(int x) {
    // fprintf(hook_log, "sub_483A90: %d\n", x);
    // fflush(hook_log);

    if (imgui_state.draw_test_scene) {
        draw_test_scene();
        return;
    }

    uint32_t temp_renderState = std3D_renderState;
    std3D_SetRenderState(Std3DRenderState(0));

    const swrViewport &vp = swrViewport_array[x];
    root_node = vp.model_root_node;

    const int default_light_index = 0;
    const int default_num_enabled_lights = 1;

    int w = screen_width;
    int h = screen_height;

    const bool fog_enabled = (GameSettingFlags & 0x40) == 0;
    if (fog_enabled)
        rdFace_ConfigureFogStartEnd(fogStartInt16, fogEndInt16);

    const bool mirrored = (GameSettingFlags & 0x4000) != 0;

    const auto &frustum = rdCamera_pCurCamera->pClipFrustum;
    float f = frustum->zFar;
    float n = frustum->zNear;
    const float t = 1.0f / tan(0.5 * rdCamera_pCurCamera->fov / 180.0 * 3.14159);
    float a = float(h) / w;
    const rdMatrix44 proj_mat{
        {mirrored ? -t : t, 0, 0, 0},
        {0, t / a, 0, 0},
        {0, 0, -(f + n) / (f - n), -1},
        {0, 0, -2 * f * n / (f - n), 1},
    };

    rdMatrix44 view_mat;
    rdMatrix_Copy44_34(&view_mat, &rdCamera_pCurCamera->view_matrix);

    rdMatrix44 rotation{
        {1, 0, 0, 0},
        {0, 0, -1, 0},
        {0, 1, 0, 0},
        {0, 0, 0, 1},
    };

    rdMatrix44 view_mat_corrected;
    rdMatrix_Multiply44(&view_mat_corrected, &view_mat, &rotation);

    rdMatrix44 model_mat;
    rdMatrix_SetIdentity44(&model_mat);

    // skybox and ibl
    if (!environment_setuped) {
        if (!skybox_initialized) {
            setupSkybox(envInfos.skybox);
            skybox_initialized = true;
        }

        // const char *debug_msg = "Setuping IBL";
        // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(debug_msg), debug_msg);

        // render env to cubemap
        setupIBL(envInfos, envInfos.skybox.GLCubeTexture, frameCount);
        frameCount += 1;

        if (frameCount > 5)
            frameCount = 0;

        glBindFramebuffer(GL_FRAMEBUFFER, envInfos.ibl_framebuffer);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT, GL_TEXTURE_2D,
                               envInfos.skybox.depthTexture, 0);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                               GL_TEXTURE_CUBE_MAP_POSITIVE_X + frameCount,
                               envInfos.skybox.GLCubeTexture, 0);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        glBindFramebuffer(GL_FRAMEBUFFER, 0);
        // environment_setuped = true;

        // glPopDebugGroup();
    }

    // const char *debug_msg = "Scene graph traversal";
    // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(debug_msg), debug_msg);
    environment_models_drawn = false;
    stbi_set_flip_vertically_on_load(false);
    // Nodes of interest
    // 0x0a0ca100 node slot 15 dynamic
    // 0x00e28a80 in race player pod static
    // 0x00e27800 in race bag of ai pods static
    debug_render_node(vp, root_node, default_light_index, default_num_enabled_lights, mirrored,
                      proj_mat, view_mat_corrected, model_mat);
    // glPopDebugGroup();

    // debug
    if (1) {
        GLuint debug_framebuffer;
        glGenFramebuffers(1, &debug_framebuffer);
        size_t ibl_textureSize = 256;
        int w, h;
        glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);

        if (imgui_state.debug_env_cubemap) {
            for (size_t i = 0; i < 6; i++) {
                glBindFramebuffer(GL_FRAMEBUFFER, debug_framebuffer);
                glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                                       GL_TEXTURE_CUBE_MAP_POSITIVE_X + i,
                                       envInfos.skybox.GLCubeTexture, 0);
                size_t start = i * ibl_textureSize;
                size_t end = start + ibl_textureSize;

                glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
                glBindFramebuffer(GL_READ_FRAMEBUFFER, debug_framebuffer);
                glBlitFramebuffer(0, 0, 2048, 2048, start, 0, end, ibl_textureSize,
                                  GL_COLOR_BUFFER_BIT, GL_LINEAR);
            }
        }

        glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
        glDeleteFramebuffers(1, &debug_framebuffer);
    }
    // if (1) {
    //     rdVector3 forward = {-view_mat_corrected.vA.z, -view_mat_corrected.vB.z,
    //                          -view_mat_corrected.vC.z};
    //     // model_mat = vp.model_matrix;
    //     // scaling down
    //     model_mat.vA.x *= 0.001;
    //     model_mat.vB.y *= 0.001;
    //     model_mat.vC.z *= 0.001;

    //     model_mat.vD.x += vp.model_matrix.vD.x;
    //     model_mat.vD.y += vp.model_matrix.vD.y;
    //     model_mat.vD.z += vp.model_matrix.vD.z;
    //     renderer_drawGLTF(proj_mat, view_mat_corrected, model_mat, g_models[5], envInfos);
    // }

    glDisable(GL_CULL_FACE);
    std3D_pD3DTex = 0;
    glUseProgram(0);
    std3D_SetRenderState(Std3DRenderState(temp_renderState));
}

static WNDPROC WndProcOrig;

LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT CALLBACK WndProc(HWND wnd, UINT code, WPARAM wparam, LPARAM lparam) {
    if (ImGui_ImplWin32_WndProcHandler(wnd, code, wparam, lparam))
        return 1;

    return WndProcOrig(wnd, code, wparam, lparam);
}

void imgui_Update() {
#if GLFW_BACKEND

    auto *glfw_window = glfwGetCurrentContext();
    if (!imgui_initialized) {
        imgui_initialized = true;
        IMGUI_CHECKVERSION();
        if (!ImGui::CreateContext())
            std::abort();

        ImGuiIO &io = ImGui::GetIO();
        (void) io;

        ImGui::StyleColorsDark();

        const auto wnd = GetActiveWindow();
        if (!ImGui_ImplGlfw_InitForOpenGL(glfw_window, true))
            std::abort();
        if (!ImGui_ImplOpenGL3_Init("#version 330"))
            std::abort();

        fprintf(hook_log, "[OGL_imgui_Update] imgui initialized.\n");
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
#else // !GLFW_BACKEND

    if (!imgui_initialized && std3D_pD3Device) {
        imgui_initialized = true;
        // Setup Dear ImGui context
        IMGUI_CHECKVERSION();
        if (!ImGui::CreateContext())
            std::abort();

        ImGuiIO &io = ImGui::GetIO();
        (void) io;
        // io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
        // io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls

        // Setup Dear ImGui style
        ImGui::StyleColorsDark();
        // ImGui::StyleColorsClassic();

        // Setup Platform/Renderer backends
        const auto wnd = GetActiveWindow();
        if (!ImGui_ImplWin32_Init(wnd))
            std::abort();
        if (!ImGui_ImplD3D_Init(std3D_pD3Device,
                                (IDirectDrawSurface4 *) stdDisplay_g_backBuffer.pVSurface.pDDSurf))
            std::abort();

        WndProcOrig = (WNDPROC) SetWindowLongA(wnd, GWL_WNDPROC, (LONG) WndProc);

        fprintf(hook_log, "[D3DDrawSurfaceToWindow] imgui initialized.\n");
    }

    if (imgui_initialized) {
        ImGui_ImplD3D_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        opengl_render_imgui();

        // Rendering
        ImGui::EndFrame();

        if (std3D_pD3Device->BeginScene() >= 0) {
            ImGui::Render();
            ImGui_ImplD3D_RenderDrawData(ImGui::GetDrawData());
            std3D_pD3Device->EndScene();
        }

        while (ShowCursor(true) <= 0)
            ;
    }
#endif// GLFW_BACKEND
}

int stdDisplay_Update_Hook() {
    // Inline previous stdDisplay_Update_Hook() in stdDisplay.c

    if (swrDisplay_SkipNextFrameUpdate == 1) {
        swrDisplay_SkipNextFrameUpdate = 0;
        return 0;
    }

    imgui_Update();// Added
#if GLFW_BACKEND
    std::memset(replacedTries, 0, std::size(replacedTries));
    glFinish();
    glfwSwapBuffers(glfwGetCurrentContext());
#else
    HANG("TODO");
#endif
    return 0;
}

static POINT virtual_cursor_pos{-100, -100};

int stdConsole_GetCursorPos_Hook(int *out_x, int *out_y) {
    if (!out_x || !out_y)
        return 0;

    if (!imgui_initialized)
        return hook_call_original(stdConsole_GetCursorPos, out_x, out_y);

    const auto &io = ImGui::GetIO();

    if (io.WantCaptureMouse) {
        // move mouse pos out of window
        virtual_cursor_pos = {-100, -100};
    } else {
        if (io.MouseDelta.x != 0 || io.MouseDelta.y != 0) {
            // mouse moved, update virtual mouse position
            virtual_cursor_pos.x = (io.MousePos.x * 640) / io.DisplaySize.x;
            virtual_cursor_pos.y = (io.MousePos.y * 480) / io.DisplaySize.y;
        }
    }

    *out_x = virtual_cursor_pos.x;
    *out_y = virtual_cursor_pos.y;
    swrSprite_SetVisible(249, 0);
    return 1;
}

void stdConsole_SetCursorPos_Hook(int X, int Y) {
    if (!imgui_initialized)
        return hook_call_original(stdConsole_SetCursorPos, X, Y);

    virtual_cursor_pos = POINT{X, Y};
}

void noop() {}

swrModel_Header *swrModel_LoadFromId_Hook(MODELID id) {
    char *model_asset_pointer_begin = swrAssetBuffer_GetBuffer();
    auto header = hook_call_original(swrModel_LoadFromId, id);
    char *model_asset_pointer_end = swrAssetBuffer_GetBuffer();

    // remove all models whose asset pointer is invalid:
    std::erase_if(asset_pointer_to_model, [&](const auto &elem) {
        return elem.asset_pointer_begin >= model_asset_pointer_begin;
    });

    asset_pointer_to_model.emplace_back() = {
        model_asset_pointer_begin,
        model_asset_pointer_end,
        id,
    };

    return header;
}

void init_renderer_hooks() {
    hook_replace(rdMaterial_InvertTextureAlphaR4G4B4A4, noop);
    hook_replace(rdMaterial_InvertTextureColorR4G4B4A4, noop);
    hook_replace(rdMaterial_RemoveTextureAlphaR4G4B4A4, noop);
    hook_replace(rdMaterial_RemoveTextureAlphaR5G5B5A1, noop);

    hook_replace(stdDisplay_Update, stdDisplay_Update_Hook);
    hook_replace(stdConsole_GetCursorPos, stdConsole_GetCursorPos_Hook);
    hook_replace(stdConsole_SetCursorPos, stdConsole_SetCursorPos_Hook);
    hook_replace(swrViewport_Render, swrViewport_Render_Hook);

    hook_replace(swrModel_LoadFromId, swrModel_LoadFromId_Hook);
}
