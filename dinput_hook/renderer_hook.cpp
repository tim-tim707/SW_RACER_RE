//
// Created by tly on 10.03.2024.
//
#include "renderer_hook.h"

#include "types.h"
#include "hook_helper.h"
#include "node_utils.h"
#include "imgui_utils.h"
#include "renderer_utils.h"
#include "replacements.h"
#include "n64_shader.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <Windows.h>
#include <commctrl.h>

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
#include <stdPlatform.h>
#include <Swr/swrAssetBuffer.h>
#include <Engine/rdMaterial.h>
#include <Platform/std3D.h>
#include <Platform/stdControl.h>
#include <Primitives/rdMatrix.h>
#include <Raster/rdCache.h>
#include <Swr/swrModel.h>
#include <Swr/swrRender.h>
#include <Swr/swrSprite.h>
#include <Swr/swrViewport.h>
#include <Swr/swrViewport.h>
#include <Swr/swrEvent.h>
#include <Swr/swrDisplay.h>
#include <Win95/stdConsole.h>
#include <Win95/stdDisplay.h>
#include <Main/swrMain2.h>
#include <Main/swrControl.h>
#include <Main/swrMain.h>
#include <Gui/swrGui.h>
#include <Win95/DirectX.h>
#include <Win95/Window.h>
#include <Swr/swrUI.h>
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

static bool environment_setuped = false;
static EnvInfos envInfos;

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

void debug_render_mesh(const swrModel_Mesh *mesh, int light_index, int num_enabled_lights,
                       bool mirrored, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix, std::optional<MODELID> model_id) {

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

    // replacements
    if (model_id.has_value() &&
        try_replace(model_id.value(), proj_matrix, view_matrix, model_matrix, envInfos)) {
        return;
    }

    // std::string debug_msg = std::format(
    //     "render mesh {}", model_id.has_value() ? modelid_cstr[model_id.value()] : "unknown");
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
    const auto &type = mesh->mesh_material->type;
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

    const auto shader = get_or_compile_color_combine_shader(
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

    glUniform1i(shader.model_id_pos, model_id ? model_id.value() : -1);

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

    glDisableVertexAttribArray(0);
    glDisableVertexAttribArray(1);
    glDisableVertexAttribArray(2);
    glDisableVertexAttribArray(3);

    glBindVertexArray(0);
    glUseProgram(0);

    // glPopDebugGroup();
}

void debug_render_node(const swrViewport &current, const swrModel_Node *node, int light_index,
                       int num_enabled_lights, bool mirrored, const rdMatrix44 &proj_mat,
                       const rdMatrix44 &view_mat, rdMatrix44 model_mat) {
    if (!node)
        return;

    if ((current.node_flags1_exact_match_for_rendering & node->flags_1) !=
        current.node_flags1_exact_match_for_rendering)
        return;

    if ((current.node_flags1_any_match_for_rendering & node->flags_1) == 0)
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

    if (node->type == NODE_TRANSFORMED || node->type == NODE_TRANSFORMED_WITH_PIVOT) {
        // this node has a transform.
        rdMatrix44 mat{};
        swrModel_NodeGetTransform((const swrModel_NodeTransformed *) node, &mat);
        if (node->type == NODE_TRANSFORMED_WITH_PIVOT && (node->flags_3 & 0x10)) {
            // some kind of pivot point: the translation v is removed from the transform and then added untransformed.
            const rdVector3 v = ((const swrModel_NodeTransformedWithPivot *) node)->pivot;
            const rdVector3 v_transformed = {
                mat.vA.x * v.x + mat.vB.x * v.y + mat.vC.x * v.z,
                mat.vA.y * v.x + mat.vB.y * v.y + mat.vC.y * v.z,
                mat.vA.z * v.x + mat.vB.z * v.y + mat.vC.z * v.z,
            };
            mat.vD.x += v.x - v_transformed.x;
            mat.vD.y += v.y - v_transformed.y;
            mat.vD.z += v.z - v_transformed.z;
        }

        rdMatrix44 model_mat_new;
        rdMatrix_Multiply44(&model_mat_new, &mat, &model_mat);
        model_mat = model_mat_new;
    } else if (node->type == NODE_TRANSFORMED_COMPUTED) {
        const swrModel_NodeTransformedComputed *transformed_node =
            (const swrModel_NodeTransformedComputed *) node;
        rdMatrix34 transform{
            *(const rdVector3 *) &model_mat.vA,
            *(const rdVector3 *) &model_mat.vB,
            *(const rdVector3 *) &model_mat.vC,
            *(const rdVector3 *) &model_mat.vD,
        };

        switch (transformed_node->orientation_option) {
            case 0:
                break;
            case 1: {
                rdVector3 forward;
                rdVector_Sub3(&forward, &transform.scale,
                              (const rdVector3 *) &current.model_matrix.vD);
                rdVector_Normalize3Acc(&forward);

                // first transform up vector into the current coordinate system:
                rdVector3 up;
                rdVector_Scale3(&up, transformed_node->up_vector.x, &transform.rvec);
                rdVector_Scale3Add3(&up, &up, transformed_node->up_vector.y, &transform.lvec);
                rdVector_Scale3Add3(&up, &up, transformed_node->up_vector.z, &transform.uvec);
                float length = rdVector_Normalize3Acc(&up);

                // now build an orthonormal basis
                transform.uvec = up;
                // forward x up -> right
                rdVector_Cross3(&transform.rvec, &forward, &transform.uvec);
                rdVector_Normalize3Acc(&transform.rvec);
                // up x right -> forward
                rdVector_Cross3(&transform.lvec, &transform.uvec, &transform.rvec);
                // no normalize, because uvec and rvec are orthogonal

                // scale
                rdVector_Scale3(&transform.rvec, length, &transform.rvec);
                rdVector_Scale3(&transform.lvec, length, &transform.lvec);
                rdVector_Scale3(&transform.uvec, length, &transform.uvec);
            } break;
            case 2:// TODO
            case 3:// TODO
            default:
                std::abort();
        }

        if (transformed_node->follow_model_position == 1)
            transform.scale = *(const rdVector3 *) &current.model_matrix.vD;

        rdMatrix_Copy44_34(&model_mat, &transform);
    }

    if (node->flags_5 & 0x4) {
        light_index = node->light_index + 1;
        num_enabled_lights = numEnabledLights[node->light_index];
    }
    if (node->flags_5 & 0x1) {
        mirrored = !mirrored;
    }

    if (node->type == NODE_MESH_GROUP) {
        for (int i = 0; i < node->num_children; i++) {
            const auto model_id = find_model_id_for_node(node->children.nodes[i]);
            debug_render_mesh(node->children.meshes[i], light_index, num_enabled_lights, mirrored,
                              proj_mat, view_mat, model_mat, model_id);
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
            debug_render_node(current, node->children.nodes[i - 1], light_index, num_enabled_lights,
                              mirrored, proj_mat, view_mat, model_mat);
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
                    debug_render_node(current, node->children.nodes[i], light_index,
                                      num_enabled_lights, mirrored, proj_mat, view_mat, model_mat);
                break;
            default:
                if (child >= 0 && child < node->num_children)
                    debug_render_node(current, node->children.nodes[child], light_index,
                                      num_enabled_lights, mirrored, proj_mat, view_mat, model_mat);

                break;
        }
    } else {
        for (int i = 0; i < node->num_children; i++)
            debug_render_node(current, node->children.nodes[i], light_index, num_enabled_lights,
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

    glEnable(GL_DEPTH_TEST);
    glDepthMask(GL_TRUE);
    glEnable(GL_BLEND);

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
    static int frameCount = 0;
    if (!environment_setuped) {
        setupSkybox();
        // const char *debug_msg = "Setuping IBL";
        // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(debug_msg), debug_msg);

        // render env to cubemap
        setupIBL(envInfos, skybox.GLCubeTexture, frameCount);
        frameCount += 1;
        if (frameCount > 5)
            frameCount = 0;
        // environment_setuped = true;

        // glPopDebugGroup();
    }

    // const char *debug_msg = "Scene graph traversal";
    // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(debug_msg), debug_msg);
    debug_render_node(vp, root_node, default_light_index, default_num_enabled_lights, mirrored,
                      proj_mat, view_mat_corrected, model_mat);
    // glPopDebugGroup();

    // Draw debug stuff
    // const char *debug_msg = "Tetrahedron debug";
    // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(debug_msg), debug_msg);
    // glDisable(GL_DEPTH_TEST);

    // typedef void *swrEvent_GetItem_Function(int event, int index);
    // swrEvent_GetItem_Function *swrEvent_GetItem =
    //     (swrEvent_GetItem_Function *) (swrEvent_GetItem_ADDR);
    // auto hang = (const swrObjHang *) swrEvent_GetItem('Hang', 0);
    // if (hang) {
    // swrCamera_unk &currentCam = unkCameraArray[vp.unkCameraIndex];
    // rdMatrix44 *focalMat = (rdMatrix44 *) (&(currentCam.unk4));
    // rdVector3 viewDirection = rdVector3{focalMat->vA.z, focalMat->vB.z, focalMat->vC.z};
    // rdVector3 cameraPos = rdVector3{currentCam.unk2->x, currentCam.unk2->y, currentCam.unk2->z};
    // model_mat.vD.x = viewDirection.x + cameraPos.x;
    // model_mat.vD.y = viewDirection.y + cameraPos.y;
    // model_mat.vD.z = viewDirection.z + cameraPos.z;
    // model_mat.vD.x = hang->unk44.x;
    // model_mat.vD.y = hang->unk44.y;
    // model_mat.vD.z = hang->unk44.z;
    // renderer_drawTetrahedron(proj_mat, view_mat_corrected, model_mat);
    // glEnable(GL_DEPTH_TEST);
    // glPopDebugGroup();
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
#else// !GLFW_BACKEND

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

// rdMaterial.c
#if GLFW_BACKEND
static void modify_texture_data(RdMaterial *mat, const char *name,
                                void (*modify_callback)(uint32_t *data, int w, int h)) {
    if (strncmp(mat->aName, name, strlen(name)) == 0)
        return;

    sprintf(mat->aName, name);

    tSystemTexture *tex = mat->aTextures;
    GLuint gl_tex = (GLuint) tex->pD3DSrcTexture;
    if (gl_tex == 0)
        abort();

    glBindTexture(GL_TEXTURE_2D, gl_tex);
    // clear error flag
    glGetError();

    uint32_t *pixel_data = (uint32_t *) malloc(tex->ddsd.dwWidth * tex->ddsd.dwHeight * 4);
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    glGetTexImage(GL_TEXTURE_2D, 0, GL_RGBA, GL_UNSIGNED_BYTE, pixel_data);
    if (glGetError() != GL_NO_ERROR)
        abort();

    modify_callback(pixel_data, tex->ddsd.dwWidth, tex->ddsd.dwHeight);

    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, tex->ddsd.dwWidth, tex->ddsd.dwHeight, 0, GL_RGBA,
                 GL_UNSIGNED_BYTE, pixel_data);
    glGenerateMipmap(GL_TEXTURE_2D);
    if (glGetError() != GL_NO_ERROR)
        abort();

    glBindTexture(GL_TEXTURE_2D, 0);
    free(pixel_data);
}

static void saturate_texture(uint32_t *data, int w, int h) {
    for (int i = 0; i < w * h; i++) {
        uint8_t *pixel = (uint8_t *) &data[i];
        pixel[0] = 255;
        pixel[1] = 255;
        pixel[2] = 255;
    }
}

void rdMaterial_SaturateTextureR4G4B4A4_hook(RdMaterial *mat) {
#if GLFW_BACKEND
    modify_texture_data(mat, "saturate", saturate_texture);
#else
    HANG("TODO");
#endif
}
#endif// rdMaterial.c GLFW_BACKEND

// std3D.c
#if GLFW_BACKEND

bool g_useFog;
/**
 * TODO: Set an uniform to do fog computation if enabled
 * Use fog parameters provided by renderer_setLinearFogParameters
 */
void renderer_setFog(bool useFog) {
    g_useFog = useFog;
}

int std3D_Startup_hook(void) {
    // Added
    fprintf(hook_log, "std3D_Startup\n");
    fflush(hook_log);

    memset(std3D_aTextureFormats, 0, sizeof(std3D_aTextureFormats));
    memset(std3D_aDevices, 0, sizeof(std3D_aDevices));

#if GLFW_BACKEND

    std3D_numDevices = 1;
    std3D_aDevices[0] = (Device3D){
        .caps =
            {
                .bHAL = true,
                .bTexturePerspectiveSupported = true,
                .hasZBuffer = true,
                .bColorkeyTextureSupported = false,
                .bStippledShadeSupported = false,
                .bAlphaBlendSupported = true,
                .bSqareOnlyTexture = false,
                .minTexWidth = 1,
                .minTexHeight = 1,
                .maxTexWidth = 4096,
                .maxTexHeight = 4096,
                .maxVertexCount = 65536,
            },
        .totalMemory = 1024 * 1024 * 1024,
        .availableMemory = 1024 * 1024 * 1024,
        .duid = {1, 2, 3, 4, 5, 6, 7, 8},
    };

    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LEQUAL);

    renderer_setAlphaMask(true);

    std3D_renderState = 0;
    std3D_SetRenderState(STD3D_RS_BLEND_MODULATE);
#else
    std3D_pDirectDraw = stdDisplay_GetDirectDraw();
    if (std3D_pDirectDraw == NULL)
        return 0;

    if (IDirectDraw4_QueryInterface(std3D_pDirectDraw, &IID_IDirect3D3,
                                    (void **) &std3D_pDirect3D) != S_OK)
        return 0;

    std3D_numDevices = 0;
    if (IDirect3D_EnumDevices(std3D_pDirect3D, Direct3d_EnumDevices_Callback, 0) != S_OK)
        return 0;
#endif
    if (std3D_numDevices == 0)
        return 0;

    std3D_bStartup = 1;
    return 1;
}

int std3D_Open_hook(unsigned int deviceNum) {
    if (std3D_bOpen)
        return 0;
    if (deviceNum >= std3D_numDevices)
        return 0;

    std3D_curDevice = deviceNum;
    std3D_pCurDevice = &std3D_aDevices[deviceNum];
    if (!std3D_pCurDevice->caps.hasZBuffer)
        return 0;

#if GLFW_BACKEND
    std3D_g_maxVertices = std3D_pCurDevice->caps.maxVertexCount;

    std3D_frameCount = 1;
    std3D_numCachedTextures = 0;
    std3D_pFirstTexCache = 0;
    std3D_pLastTexCache = 0;

    std3D_numTextureFormats = 3;
    std3D_aTextureFormats[0].texFormat = (ColorInfo){
        .colorMode = T_STDCOLOR_RGB,
        .bpp = 16,
        .redBPP = 5,
        .greenBPP = 6,
        .blueBPP = 5,
        .redPosShift = 0,
        .greenPosShift = 5,
        .bluePosShift = 11,
        .RedShr = 3,
        .GreenShr = 2,
        .BlueShr = 3,
        .alphaBPP = 0,
        .alphaPosShift = 0,
        .AlphaShr = 0,
    };
    std3D_aTextureFormats[1].texFormat = (ColorInfo){
        .colorMode = T_STDCOLOR_RGBA,
        .bpp = 16,
        .redBPP = 5,
        .greenBPP = 5,
        .blueBPP = 5,
        .redPosShift = 0,
        .greenPosShift = 5,
        .bluePosShift = 10,
        .RedShr = 3,
        .GreenShr = 3,
        .BlueShr = 3,
        .alphaBPP = 1,
        .alphaPosShift = 15,
        .AlphaShr = 7,
    };
    std3D_aTextureFormats[2].texFormat = (ColorInfo){
        .colorMode = T_STDCOLOR_RGBA,
        .bpp = 16,
        .redBPP = 4,
        .greenBPP = 4,
        .blueBPP = 4,
        .redPosShift = 0,
        .greenPosShift = 4,
        .bluePosShift = 8,
        .RedShr = 4,
        .GreenShr = 4,
        .BlueShr = 4,
        .alphaBPP = 4,
        .alphaPosShift = 12,
        .AlphaShr = 4,
    };
    std3D_bHasRGBTextureFormat = true;

    std3D_RGBTextureFormat = std3D_FindClosestMode(&std3D_cfRGB565);
    std3D_RGBAKeyTextureFormat = std3D_FindClosestMode(&std3D_cfRGB5551);
    std3D_RGBA_TextureFormat = std3D_FindClosestMode(&std3D_cfRGB4444);
#else
    DDPIXELFORMAT zBufferFormat;
    std3D_GetZBufferFormat(&zBufferFormat);

    if (stdDisplay_CreateZBuffer(
            &zBufferFormat, std3D_pCurDevice->caps.bHAL == 0,
            (d3dDeviceDesc.dpcTriCaps.dwRasterCaps & D3DPRASTERCAPS_ZBUFFERLESSHSR) != 0))
        return 0;

    PALETTEENTRY palette[256];
    for (int i = 0; i < 256; i++)
        palette[i] = (PALETTEENTRY){0xFE, 0xFE, 0xFE, 0x80};

    if (IDirectDraw4_CreatePalette(std3D_pDirectDraw,
                                   DDPCAPS_ALLOW256 | DDPCAPS_INITIALIZE | DDPCAPS_8BIT, palette,
                                   &std3D_pDDPalette, 0) != S_OK)
        return 0;

    if (IDirect3D3_CreateDevice(std3D_pDirect3D, &std3D_pCurDevice->duid,
                                stdDisplay_g_backBuffer.pVSurface.pDDSurf, &std3D_pD3Device,
                                0) != S_OK)
        return 0;

    d3dDeviceDesc.dwSize = sizeof(D3DDEVICEDESC);

    D3DDEVICEDESC desc;
    desc.dwSize = sizeof(D3DDEVICEDESC);

    if (IDirect3DDevice3_GetCaps(std3D_pD3Device, &d3dDeviceDesc, &desc) != S_OK)
        return 0;

    std3D_numTextureFormats = 0;
    std3D_bHasRGBTextureFormat = 0;
    if (IDirect3DDevice3_EnumTextureFormats(std3D_pD3Device, Direct3d_EnumTextureFormats_Callback,
                                            0))
        return 0;

    if (!std3D_numTextureFormats)
        return 0;
    if (!std3D_bHasRGBTextureFormat)
        return 0;

    if (!Direct3d_CreateAndAttachViewport())
        return 0;

    std3D_g_maxVertices = 512;
    if (std3D_pCurDevice->caps.maxVertexCount != 0)
        std3D_g_maxVertices = std3D_pCurDevice->caps.maxVertexCount;

    std3D_frameCount = 1;
    std3D_numCachedTextures = 0;
    std3D_pFirstTexCache = 0;
    std3D_pLastTexCache = 0;

    std3D_RGBTextureFormat = std3D_FindClosestMode(&std3D_cfRGB565);
    std3D_RGBAKeyTextureFormat = std3D_FindClosestMode(&std3D_cfRGB5551);
    std3D_RGBA_TextureFormat = std3D_FindClosestMode(&std3D_cfRGB4444);

    if (!std3D_aTextureFormats[std3D_RGBAKeyTextureFormat].texFormat.alphaBPP &&
        std3D_pCurDevice->caps.bColorkeyTextureSupported) {
        std3D_aTextureFormats[std3D_RGBAKeyTextureFormat].bColorKey = 1;
        std3D_aTextureFormats[std3D_RGBAKeyTextureFormat].pColorKey = 0;
    }

    if (!std3D_aTextureFormats[std3D_RGBA_TextureFormat].texFormat.alphaBPP &&
        std3D_pCurDevice->caps.bColorkeyTextureSupported) {
        std3D_aTextureFormats[std3D_RGBA_TextureFormat].bColorKey = 1;
        std3D_aTextureFormats[std3D_RGBA_TextureFormat].pColorKey = 0;
    }

    if (!std3D_InitRenderState())
        return 0;

    if (DirectDraw_GetAvailableVidMem(&std3D_pCurDevice->totalMemory,
                                      &std3D_pCurDevice->availableMemory))
        return 0;
#endif

    std3D_bOpen = 1;
    return 1;
}

int std3D_StartScene_hook(void) {
    ++std3D_frameCount;
    std3D_pD3DTex = 0;
#if GLFW_BACKEND
    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);
    glViewport(0, 0, w, h);

    return 0;
#else
    return IDirect3DDevice3_BeginScene(std3D_pD3Device);
#endif
}

void std3D_EndScene_hook(void) {
#if GLFW_BACKEND
    // nothing to do here
#else
    IDirect3DDevice3_EndScene(std3D_pD3Device);
#endif
    std3D_pD3DTex = 0;
}

void std3D_DrawRenderList_hook(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags,
                               LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices,
                               int indexCount) {
    if (verticesCount > std3D_g_maxVertices)
        return;

    std3D_SetRenderState(rdflags);
#if GLFW_BACKEND
    if (pTex != std3D_pD3DTex) {
        std3D_pD3DTex = pTex;
        if (pTex) {
            // glEnable(GL_TEXTURE_2D);
            glBindTexture(GL_TEXTURE_2D, (GLuint) pTex);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,
                            rdflags & STD3D_RS_TEX_CLAMP_U ? GL_CLAMP_TO_EDGE : GL_REPEAT);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T,
                            rdflags & STD3D_RS_TEX_CLAMP_V ? GL_CLAMP_TO_EDGE : GL_REPEAT);
        } else {
            // glDisable(GL_TEXTURE);
            glBindTexture(GL_TEXTURE_2D, 0);
        }
    }

    for (int i = 0; i < verticesCount; i++) {
        D3DTLVERTEX *vertex = &aVerticies[i];
        if (vertex->rhw != 0) {
            float w = 1.0 / vertex->rhw;
            vertex->sx *= w;
            vertex->sy *= w;
            vertex->sz *= w;
            vertex->rhw = w;
        }

        // BRGA to RGBA
        uint8_t *color = (uint8_t *) &vertex->color;
        uint8_t tmp = color[0];
        color[0] = color[2];
        color[2] = tmp;
    }

    renderer_drawRenderList(verticesCount, aVerticies, indexCount, lpwIndices);
#else
    if ((pTex != std3D_pD3DTex) && (IDirect3DDevice3_SetTexture(std3D_pD3Device, 0, pTex) == S_OK))
        std3D_pD3DTex = pTex;

    IDirect3DDevice3_DrawIndexedPrimitive(
        std3D_pD3Device, D3DPT_TRIANGLELIST,
        D3DFVF_XYZRHW | D3DFVF_DIFFUSE | D3DFVF_SPECULAR | D3DFVF_TEX1, aVerticies, verticesCount,
        lpwIndices, indexCount, D3DDP_DONOTUPDATEEXTENTS | D3DDP_DONOTLIGHT);
#endif
}

void std3D_SetRenderState_hook(Std3DRenderState rdflags) {
#if GLFW_BACKEND
    if (std3D_renderState == rdflags)
        return;

    // blend settings
    if (std3D_renderState ^ (rdflags & (STD3D_RS_BLEND_MODULATE | STD3D_RS_BLEND_MODULATEALPHA))) {
        if (rdflags & STD3D_RS_BLEND_MODULATEALPHA) {
            glEnable(GL_BLEND);
            // TODO modulate alpha
        } else if (rdflags & STD3D_RS_BLEND_MODULATE) {
            glEnable(GL_BLEND);
        } else {
            glDisable(GL_BLEND);
        }
    }

    // z write
    if (std3D_renderState ^ (rdflags & STD3D_RS_ZWRITE_DISABLED))
        glDepthMask((rdflags & STD3D_RS_ZWRITE_DISABLED) == 0);

    // texture wrap mode
    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_CLAMP_U)) {
        // is set when the texture is bound
    }

    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_CLAMP_V)) {
        // is set when the texture is bound
    }

    // fog
    if (std3D_renderState ^ (rdflags & STD3D_RS_FOG_ENABLED)) {
        if (rdflags & STD3D_RS_FOG_ENABLED) {
            renderer_setFog(true);
        } else {
            renderer_setFog(false);
        }
    }

    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_MAGFILTER_LINEAR))
        std3D_SetTexFilterMode();

    std3D_renderState = rdflags;
#else
    if (std3D_renderState == rdflags)
        return;

    // blend settings
    if (std3D_renderState ^ (rdflags & (STD3D_RS_BLEND_MODULATE | STD3D_RS_BLEND_MODULATEALPHA))) {
        if (rdflags & STD3D_RS_BLEND_MODULATEALPHA) {
            IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ALPHABLENDENABLE, 1);
            IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_TEXTUREMAPBLEND,
                                            D3DTBLEND_MODULATEALPHA);
        } else if (rdflags & STD3D_RS_BLEND_MODULATE) {
            IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ALPHABLENDENABLE, 1);
            IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_TEXTUREMAPBLEND,
                                            D3DTBLEND_MODULATE);
        } else {
            IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ALPHABLENDENABLE, 0);
        }
    }

    // z write
    if (std3D_renderState ^ (rdflags & STD3D_RS_ZWRITE_DISABLED))
        IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ZWRITEENABLE,
                                        (rdflags & STD3D_RS_ZWRITE_DISABLED) == 0);

    // texture wrap mode
    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_CLAMP_U))
        IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_ADDRESSU,
                                              (rdflags & STD3D_RS_TEX_CLAMP_U) ? D3DTADDRESS_CLAMP
                                                                               : D3DTADDRESS_WRAP);

    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_CLAMP_V))
        IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_ADDRESSV,
                                              (rdflags & STD3D_RS_TEX_CLAMP_V) ? D3DTADDRESS_CLAMP
                                                                               : D3DTADDRESS_WRAP);

    // fog
    if (std3D_renderState ^ (rdflags & STD3D_RS_FOG_ENABLED))
        IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_FOGENABLE,
                                        (rdflags & STD3D_RS_FOG_ENABLED) != 0 && d3d_FogEnabled);

    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_MAGFILTER_LINEAR))
        std3D_SetTexFilterMode();

    std3D_renderState = rdflags;
#endif
}

void std3D_AllocSystemTexture_hook(tSystemTexture *pTexture, tVBuffer **apVBuffers,
                                   unsigned int numMipLevels, StdColorFormatType formatType) {
    *pTexture = (tSystemTexture){0};
#if GLFW_BACKEND
    GLuint gl_tex = 0;
    glGenTextures(1, &gl_tex);
    if (gl_tex == 0)
        abort();

    GLenum format = GL_BGRA;
    GLenum type = GL_UNSIGNED_SHORT_4_4_4_4;
    const GLenum internal_format = GL_RGBA8;

    tVBuffer *buff = apVBuffers[0];
    tRasterInfo *info = &buff->rasterInfo;

    if (formatType == STDCOLOR_FORMAT_RGB) {
        format = GL_RGB;
        type = GL_UNSIGNED_SHORT_5_6_5;
    } else if (formatType == STDCOLOR_FORMAT_RGBA_1BIT_ALPHA) {
        format = GL_BGRA;
        type = GL_UNSIGNED_SHORT_1_5_5_5_REV;
    } else if (formatType == STDCOLOR_FORMAT_RGBA) {
        format = GL_BGRA;
        type = GL_UNSIGNED_SHORT_4_4_4_4_REV;
    } else {
        abort();
    }

    glBindTexture(GL_TEXTURE_2D, gl_tex);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, internal_format, info->width, info->height, 0, format, type,
                 buff->pPixels);
    glGenerateMipmap(GL_TEXTURE_2D);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY, 8);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
    glBindTexture(GL_TEXTURE_2D, 0);

    pTexture->ddsd.dwWidth = info->width;
    pTexture->ddsd.dwHeight = info->height;
    pTexture->pD3DSrcTexture = (LPDIRECT3DTEXTURE2) gl_tex;
    pTexture->textureSize = (info->width * info->height * 4);
#else
    if (std3D_numTextureFormats == 0)
        return;

    uint32_t valid_width;
    uint32_t valid_height;
    std3D_GetValidDimensions(apVBuffers[0]->rasterInfo.width, apVBuffers[0]->rasterInfo.height,
                             &valid_width, &valid_height);

    if (d3dMipFilter == 0)
        numMipLevels = 1;

    int format_index = formatType == STDCOLOR_FORMAT_RGBA_1BIT_ALPHA ? std3D_RGBAKeyTextureFormat
                       : formatType == STDCOLOR_FORMAT_RGBA          ? std3D_RGBA_TextureFormat
                                                                     : std3D_RGBTextureFormat;

    DDSURFACEDESC2 surface_desc = {};
    surface_desc.dwSize = sizeof(DDSURFACEDESC2);
    surface_desc.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PIXELFORMAT;
    surface_desc.ddsCaps.dwCaps = DDSCAPS_SYSTEMMEMORY | DDSCAPS_TEXTURE;
    surface_desc.dwWidth = apVBuffers[0]->rasterInfo.width;
    surface_desc.dwHeight = apVBuffers[0]->rasterInfo.height;
    surface_desc.ddpfPixelFormat = std3D_aTextureFormats[format_index].pixelFormat;
    if (numMipLevels > 1) {
        surface_desc.dwFlags |= DDSD_MIPMAPCOUNT;
        surface_desc.ddsCaps.dwCaps |= DDSCAPS_COMPLEX | DDSCAPS_MIPMAP;
        surface_desc.dwMipMapCount = numMipLevels;
    }

    IDirectDrawSurface4 *surface = NULL;
    IDirect3DTexture2 *texture = NULL;

    if (IDirectDraw4_CreateSurface(std3D_pDirectDraw, &surface_desc, &surface, 0) != S_OK)
        goto error;

    if (IDirectDraw4_QueryInterface(std3D_pDirectDraw, &IID_IDirect3DTexture2,
                                    (void **) &texture) != S_OK)
        goto error;

    for (int level = 0; level < numMipLevels; level++) {
        DDSURFACEDESC2 surface_desc2 = {};
        surface_desc2.dwSize = sizeof(DDSURFACEDESC2);
        if (IDirectDrawSurface4_Lock(surface, 0, &surface_desc2, 1, 0) != S_OK)
            goto error;

        // copy data
        tVBuffer *buff = apVBuffers[level];
        if (buff->rasterInfo.colorInfo.colorMode == T_STDCOLOR_RGB ||
            buff->rasterInfo.colorInfo.colorMode == T_STDCOLOR_RGBA) {
            stdDisplay_VBufferLock(buff);
            for (int y = 0; y < surface_desc2.dwHeight; y++)
                memcpy(surface_desc2.lpSurface + y * surface_desc2.lPitch,
                       buff->pPixels + y * buff->rasterInfo.rowSize, 2 * surface_desc2.dwWidth);

            stdDisplay_VBufferUnlock(buff);
        }

        if (IDirectDrawSurface4_Unlock(surface, 0) != S_OK)
            goto error;

        // retrieve next mip surface:
        if (level < numMipLevels - 1) {
            DDSCAPS2 caps = {};
            caps.dwCaps = DDSCAPS_MIPMAP | DDSCAPS_TEXTURE;
            if (IDirectDrawSurface4_GetAttachedSurface(surface, &caps, &surface) != S_OK)
                goto error;
        }
    }

    if (valid_width != surface_desc.dwWidth || valid_height != surface_desc.dwHeight)
        abort();

    if (surface)
        IDirectDrawSurface4_Release(surface);

    pTexture->pD3DSrcTexture = texture;
    pTexture->ddsd = surface_desc;
    pTexture->textureSize =
        (valid_width * valid_height * apVBuffers[0]->rasterInfo.colorInfo.bpp) / 8;

error:
    if (surface)
        IDirectDrawSurface4_Release(surface);
#endif
}

void std3D_ClearTexture_hook(tSystemTexture *pTex) {
#if GLFW_BACKEND
    if (pTex->pD3DSrcTexture) {
        GLuint gl_tex = (GLuint) pTex->pD3DSrcTexture;
        glDeleteTextures(1, &gl_tex);
    }

    pTex->pD3DCachedTex = NULL;
#else
    if (pTex->pD3DSrcTexture) {
        IDirect3DTexture2_Release(pTex->pD3DSrcTexture);
    }

    if (pTex->pD3DCachedTex) {
        std3D_RemoveTextureFromCacheList(pTex);
        IDirect3DTexture2_Release(pTex->pD3DCachedTex);
    }
#endif

    *pTex = (tSystemTexture){0};
}

void std3D_AddToTextureCache_hook(tSystemTexture *pCacheTexture, StdColorFormatType format) {
#if GLFW_BACKEND
    pCacheTexture->pD3DCachedTex = pCacheTexture->pD3DSrcTexture;
    pCacheTexture->frameNum = std3D_frameCount;
    std3D_AddTextureToCacheList(pCacheTexture);
#else
    IDirectDrawSurface4 *surface = NULL;
    IDirect3DTexture2 *texture = NULL;

    if (pCacheTexture->pD3DSrcTexture == NULL)
        goto error;

    if (pCacheTexture->textureSize > std3D_pCurDevice->availableMemory)
        std3D_PurgeTextureCache(pCacheTexture->textureSize);

    DDSURFACEDESC2 surface_desc = pCacheTexture->ddsd;
    surface_desc.ddsCaps.dwCaps &= ~DDSCAPS_SYSTEMMEMORY;
    surface_desc.ddsCaps.dwCaps |= DDSCAPS_VIDEOMEMORY;
    surface_desc.ddsCaps.dwCaps |= DDSCAPS_ALLOCONLOAD;

    HRESULT err = IDirectDraw_CreateSurface(std3D_pDirectDraw, &surface_desc, &surface, 0);
    while (err == DDERR_OUTOFVIDEOMEMORY && std3D_PurgeTextureCache(pCacheTexture->textureSize))
        err = IDirectDraw_CreateSurface(std3D_pDirectDraw, &surface_desc, &surface, 0);

    if (err != S_OK)
        goto error;

    if (std3D_aTextureFormats[format].bColorKey)
        IDirectDrawSurface4_SetColorKey(surface, DDCKEY_SRCBLT,
                                        std3D_aTextureFormats[format].pColorKey);

    if (IDirectDrawSurface4_QueryInterface(surface, &IID_IDirect3DTexture2, (void **) &texture) !=
        S_OK)
        goto error;

    err = IDirect3DTexture2_Load(texture, pCacheTexture->pD3DSrcTexture);
    while (err == DDERR_OUTOFVIDEOMEMORY && std3D_PurgeTextureCache(pCacheTexture->textureSize))
        err = IDirect3DTexture2_Load(texture, pCacheTexture->pD3DSrcTexture);

    if (err != S_OK)
        goto error;

    pCacheTexture->pD3DCachedTex = texture;
    IDirectDrawSurface4_Release(surface);
    pCacheTexture->frameNum = std3D_frameCount;
    std3D_AddTextureToCacheList(pCacheTexture);
    return;

error:
    if (surface)
        IDirectDrawSurface4_Release(surface);
    if (texture)
        IDirect3DTexture2_Release(texture);
    pCacheTexture->pD3DCachedTex = 0;
    pCacheTexture->frameNum = 0;
#endif
}

void std3D_ClearCacheList_hook(void) {
#if GLFW_BACKEND
    std3D_pFirstTexCache = 0;
    std3D_pLastTexCache = 0;
    std3D_numCachedTextures = 0;
    if (std3D_pCurDevice)
        std3D_pCurDevice->availableMemory = std3D_pCurDevice->totalMemory;
    std3D_frameCount = 1;
#else
    tSystemTexture *curr = std3D_pFirstTexCache;
    while (curr) {
        tSystemTexture *next = curr->pNextCachedTexture;

        if (curr->pD3DCachedTex) {
            IDirect3DTexture2_Release(curr->pD3DCachedTex);
            curr->pD3DCachedTex = NULL;
        }
        curr->frameNum = 0;
        curr->pPrevCachedTexture = NULL;
        curr->pNextCachedTexture = NULL;
        curr = next;
    }

    std3D_pFirstTexCache = 0;
    std3D_pLastTexCache = 0;
    std3D_numCachedTextures = 0;
    if (std3D_pCurDevice)
        std3D_pCurDevice->availableMemory = std3D_pCurDevice->totalMemory;
    if (std3D_pD3Device)
        IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_TEXTUREHANDLE, 0);
    std3D_frameCount = 1;
#endif
}

int std3D_SetTexFilterMode_hook(void) {
#if GLFW_BACKEND
    // texture filter mode is always set to mipmapping with anisotropy.
    return 0;
#else
    HRESULT result = S_OK;
    if ((result = IDirect3DDevice3_SetTextureStageState(
             std3D_pD3Device, 0, D3DTSS_MAGFILTER,
             std3D_renderState & STD3D_RS_TEX_MAGFILTER_LINEAR ? D3DTFG_LINEAR : D3DTFP_POINT)) !=
        S_OK)
        return result;
    if ((result = IDirect3DDevice3_SetTextureStageState(
             std3D_pD3Device, 0, D3DTSS_MINFILTER,
             std3D_renderState & STD3D_RS_TEX_MAGFILTER_LINEAR ? D3DTFG_LINEAR : D3DTFP_POINT)) !=
        S_OK)
        return result;

    return IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_MIPFILTER,
                                                 d3dMipFilter == 1 ? D3DTFP_POINT
                                                 : d3dMipFilter == 2 ? D3DTFP_LINEAR
                                                                     : D3DTFP_NONE);
#endif
}

int std3D_SetProjection_hook(float fov, float aspectRatio, float nearPlane, float farPlane) {
    if (fabs(farPlane - nearPlane) < 0.009999999776482582)
        return E_INVALIDARG;

    const float sf = sin(fov * 0.5);
    const float cf = cos(fov * 0.5);

    if (fabs(sf) < 0.009999999776482582)
        return E_INVALIDARG;

    rdMatrix44 proj_mat = {
        {aspectRatio * cf / sf, 0, 0},
        {0, cf / sf, 0, 0},
        {0, 0, farPlane / (farPlane - nearPlane), 0},
        {0, 0, -(farPlane / (farPlane - nearPlane) * nearPlane), 1},
    };

#if GLFW_BACKEND
    return 0;
#else
    return IDirect3DDevice3_SetTransform(std3D_pD3Device, D3DTRANSFORMSTATE_PROJECTION,
                                         (D3DMATRIX *) &proj_mat);
#endif
}

void std3D_AddTextureToCacheList_hook(tSystemTexture *pTexture) {
#if GLFW_BACKEND
    ++std3D_numCachedTextures;
    std3D_pCurDevice->availableMemory -= pTexture->textureSize;
#else
    if (std3D_pFirstTexCache) {
        std3D_pLastTexCache->pNextCachedTexture = pTexture;
        pTexture->pPrevCachedTexture = std3D_pLastTexCache;
        pTexture->pNextCachedTexture = 0;
        std3D_pLastTexCache = pTexture;
    } else {
        std3D_pLastTexCache = pTexture;
        std3D_pFirstTexCache = pTexture;
        pTexture->pPrevCachedTexture = 0;
        pTexture->pNextCachedTexture = 0;
    }
    ++std3D_numCachedTextures;
    std3D_pCurDevice->availableMemory -= pTexture->textureSize;
#endif
}

void std3D_RemoveTextureFromCacheList_hook(tSystemTexture *pCacheTexture) {
#if GLFW_BACKEND
    --std3D_numCachedTextures;
    std3D_pCurDevice->availableMemory += pCacheTexture->textureSize;
    pCacheTexture->pNextCachedTexture = 0;
    pCacheTexture->pPrevCachedTexture = 0;
    pCacheTexture->frameNum = 0;
#else
    if (pCacheTexture == std3D_pFirstTexCache) {
        std3D_pFirstTexCache = pCacheTexture->pNextCachedTexture;
        if (std3D_pFirstTexCache) {
            std3D_pFirstTexCache->pPrevCachedTexture = 0;
            if (!std3D_pFirstTexCache->pNextCachedTexture)
                std3D_pLastTexCache = std3D_pFirstTexCache;
        } else {
            std3D_pLastTexCache = 0;
        }
    } else {
        tSystemTexture *pPrevCachedTexture = pCacheTexture->pPrevCachedTexture;
        if (pCacheTexture == std3D_pLastTexCache) {
            std3D_pLastTexCache = pCacheTexture->pPrevCachedTexture;
            pPrevCachedTexture->pNextCachedTexture = 0;
        } else {
            pPrevCachedTexture->pNextCachedTexture = pCacheTexture->pNextCachedTexture;
            pCacheTexture->pNextCachedTexture->pPrevCachedTexture =
                pCacheTexture->pPrevCachedTexture;
        }
    }
    --std3D_numCachedTextures;
    std3D_pCurDevice->availableMemory += pCacheTexture->textureSize;
    pCacheTexture->pNextCachedTexture = 0;
    pCacheTexture->pPrevCachedTexture = 0;
    pCacheTexture->frameNum = 0;
#endif
}

int std3D_PurgeTextureCache_hook(unsigned int size) {
#if GLFW_BACKEND
    return true;
#else
    if (std3D_pFirstTexCache == NULL)
        return false;

    // first try to find an exact match...
    {
        tSystemTexture *curr = std3D_pFirstTexCache;
        while (curr && curr->frameNum != std3D_frameCount) {
            if (curr->textureSize == size) {
                IDirect3DTexture2_Release(curr->pD3DCachedTex);
                curr->pD3DCachedTex = NULL;
                std3D_RemoveTextureFromCacheList(curr);
                return true;
            }
            curr = curr->pNextCachedTexture;
        }
    }

    // ... or purge as much textures as needed.
    int purged_size = 0;
    {
        tSystemTexture *curr = std3D_pFirstTexCache;
        while (curr && purged_size < size) {
            if (curr->frameNum != std3D_frameCount) {
                purged_size += curr->textureSize;
                IDirect3DTexture2_Release(curr->pD3DCachedTex);
                curr->pD3DCachedTex = NULL;
                std3D_RemoveTextureFromCacheList(curr);
            }
            curr = curr->pNextCachedTexture;
        }
    }

    return purged_size != 0;
#endif
}

#endif// std3D.c GLFW_BACKEND

// stdControl.c
#if GLFW_BACKEND
int stdControl_Startup_hook(void) {
#if GLFW_BACKEND
    stdControl_g_bStartup = 1;
    return 0;
#else
    HANG("TODO");
#endif
}

void stdControl_ReadControls_hook(void) {
    if (!stdControl_bControlsActive)
        return;

    memset(stdControl_aKeyIdleTimes, 0, sizeof(stdControl_aKeyIdleTimes));
    memset(stdControl_g_aKeyPressCounter, 0, sizeof(stdControl_g_aKeyPressCounter));
    stdControl_bControlsIdle = 1;
    stdControl_curReadTime = timeGetTime();
    stdControl_readDeltaTime = stdControl_curReadTime - stdControl_lastReadTime;
    memset(stdControl_aAxisPos, 0, 0xF0u);
    sithControl_secFPS = 1.0 / (double) (stdControl_curReadTime - stdControl_lastReadTime);
    sithControl_msecFPS =
        1.0 / (double) (stdControl_curReadTime - stdControl_lastReadTime) * 1000.0;
#if GLFW_BACKEND
    glfwPollEvents();
#else
    stdControl_ReadKeyboard();
    if (stdControl_bReadJoysticks)
        stdControl_ReadJoysticks();
    stdControl_ReadMouse();
#endif
    stdControl_lastReadTime = stdControl_curReadTime;
}

int stdControl_SetActivation_hook(int bActive) {
#if GLFW_BACKEND
    stdControl_bControlsActive = bActive;

    return 0;
#else
    HANG("TODO");
#endif
}

#endif// stdControl.c GLFW_BACKEND

// swrDisplay.c
#if GLFW_BACKEND

int swrDisplay_SetWindowSize_hook(void) {
#if GLFW_BACKEND
    return 1;
#else
    if ((swrMainDisplay_windowed != 0) && (swrMainDisplay_currentDevice != 0)) {
        Window_SetWindowSize(200, 200);
        return 1;
    }
#endif
    return 0;
}
#endif// swrDisplay.c GLFW_BACKEND

// DirectX.c
#if GLFW_BACKEND

float g_fogColor[4];
float g_fogStart;
float g_fogEnd;

void renderer_setLinearFogParameters(float color[4], float start, float end) {
    memcpy(g_fogColor, color, sizeof(g_fogColor));
    g_fogStart = start;
    g_fogEnd = end;
}

void DirectDraw_InitProgressBar_hook(void) {
#if GLFW_BACKEND
    // nothing to do here
#else
    HANG("TODO");
#endif
}

void DirectDraw_Shutdown_hook(void) {
#if GLFW_BACKEND
    // nothing to do here
#else
    if (iDirectDraw4_error == 0) {
        (*ddSurfaceForProgressBar->lpVtbl->Release)(ddSurfaceForProgressBar);
    }
#endif
}

void DirectDraw_BlitProgressBar_hook(int progress) {
#if GLFW_BACKEND

    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);
    glViewport(0, 0, w, h);

    renderer_drawProgressBar(progress);

    stdDisplay_Update();
#else
    HANG("TODO");
#endif
}

#if GLFW_BACKEND
uint16_t *depth_data = NULL;
#endif

// 0x00431C40 HOOK
void DirectDraw_LockZBuffer_hook(uint32_t *bytes_per_depth_value, LONG *pitch, LPVOID *data,
                                 float *near_, float *far_) {
#if GLFW_BACKEND
    int w = screen_width;
    int h = screen_height;
    depth_data = (uint16_t *) malloc(w * h * 2);

    glGetError();
    glReadPixels(0, 0, w, h, GL_DEPTH_COMPONENT, GL_UNSIGNED_SHORT, depth_data);
    if (glGetError())
        abort();

    *bytes_per_depth_value = 2;
    *pitch = w * 2;
    *data = depth_data;

    // flip vertically
    uint16_t *src = depth_data;
    uint16_t *dst = &depth_data[w * (h - 1)];
    for (int y = 0; y < h / 2; y++) {
        for (int x = 0; x < w; x++) {
            uint16_t tmp = src[x];
            src[x] = dst[x];
            dst[x] = tmp;
        }
        src += w;
        dst -= w;
    }

    *near_ = rdCamera_pCurCamera->pClipFrustum->zNear;
    *far_ = rdCamera_pCurCamera->pClipFrustum->zFar;
#else
    HANG("TODO");
#endif
}

void DirectDraw_UnlockZBuffer_hook(void) {
#if GLFW_BACKEND
    if (depth_data)
        free(depth_data);

    depth_data = NULL;
#else
    LPDIRECTDRAWSURFACE4 This = DirectDraw_GetZBuffer();
    (*This->lpVtbl->Unlock)(This, NULL);
#endif
}

int Direct3d_SetFogMode_hook(void) {
#if GLFW_BACKEND
    return 2;
#else
    HRESULT hres;
    unsigned int light_result;
    unsigned int fog_result;

    if ((d3dDeviceDesc.dpcTriCaps.dwRasterCaps & 0x100) != 0) {
        hres = (*std3D_pD3Device->lpVtbl->SetRenderState)(std3D_pD3Device,
                                                          D3DRENDERSTATE_FOGTABLEMODE, 3);
        if (hres == 0) {
            return 2;
        }
    }
    if ((d3dDeviceDesc.dpcTriCaps.dwRasterCaps & 0x80) != 0) {
        light_result =
            (*std3D_pD3Device->lpVtbl->SetLightState)(std3D_pD3Device, D3DLIGHTSTATE_FOGMODE, 0);
        fog_result = (*std3D_pD3Device->lpVtbl->SetRenderState)(std3D_pD3Device,
                                                                D3DRENDERSTATE_FOGTABLEMODE, 0);
        if ((light_result | fog_result) == 0) {
            return 1;
        }
    }
    return 0;
#endif
}

int Direct3d_IsLensflareCompatible_hook(void) {
#if GLFW_BACKEND
    return true;
#else
    return (d3dDeviceDesc.dpcTriCaps.dwTextureBlendCaps & 0xff) >> 3 & 1;
#endif
}

void Direct3d_ConfigFog_hook(float r, float g, float b, float near_, float far_) {
#if GLFW_BACKEND
    float color[4] = {r, g, b, 1.0};
    renderer_setLinearFogParameters(color, 0.999, 1);
#else
    HANG("TODO");
#endif
}

#endif// DirectX.c GLFW_BACKEND

// stdDisplay.c
#if GLFW_BACKEND
int stdDisplay_Startup_hook(void) {
    if (stdDisplay_bStartup)
        return 1;

    stdDisplay_g_frontBuffer = (tVBuffer){0};
    stdDisplay_g_backBuffer = (tVBuffer){0};
    stdDisplay_zBuffer = (tVSurface){0};
    stdDisplay_bStartup = 1;
    stdDisplay_numDevices = 0;
#if GLFW_BACKEND
    stdDisplay_numDevices = 1;
    StdDisplayDevice *device = &stdDisplay_aDisplayDevices[0];
    snprintf(device->aDeviceName, 128, "OpenGL");
    snprintf(device->aDriverName, 128, "OpenGL");
    device->bHAL = true;
    device->bGuidNotSet = true;
    device->bWindowRenderNotSupported = false;
    device->totalVideoMemory = 1024 * 1024 * 1024;
    device->freeVideoMemory = 1024 * 1024 * 1024;
#else
    if (DirectDrawEnumerateA(DirectDraw_EnumerateA_Callback, NULL) != S_OK)
        return 0;
#endif
    stdDisplay_primaryVideoMode.rasterInfo.width = 640;
    stdDisplay_primaryVideoMode.rasterInfo.height = 480;

    return 1;
}

int stdDisplay_Open_hook(int deviceNum) {
    if (stdDisplay_bOpen)
        stdDisplay_Close();

    if (deviceNum >= stdDisplay_numDevices)
        return 0;

    stdDisplay_curDevice = deviceNum;
    stdDisplay_pcurDevice = &stdDisplay_aDisplayDevices[deviceNum];
#if GLFW_BACKEND
    glfwSwapInterval(1);
    gladLoadGLLoader((GLADloadproc) glfwGetProcAddress);

    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);

    stdDisplay_numVideoModes = 1;
    stdDisplay_aVideoModes[0] = (StdVideoMode){
        .aspectRatio = 1.0,
        .rasterInfo =
            {
                .width = w,
                .height = h,
                .size = w * h * 4,
                .rowSize = w * 4,
                .rowWidth = w,
                .colorInfo =
                    {
                        .colorMode = T_STDCOLOR_RGBA,
                        .bpp = 32,
                        .redBPP = 8,
                        .greenBPP = 8,
                        .blueBPP = 8,
                        .redPosShift = 0,
                        .greenPosShift = 8,
                        .bluePosShift = 16,
                        .RedShr = 0,
                        .GreenShr = 0,
                        .BlueShr = 0,
                        .alphaBPP = 8,
                        .alphaPosShift = 24,
                        .AlphaShr = 0,
                    },
            },
    };
#else
    if (!stdDisplay_InitDirectDraw(Window_GetHWND()))
        return 0;
#endif

    qsort(stdDisplay_aVideoModes, stdDisplay_numVideoModes, sizeof(StdVideoMode),
          (int (*)(const void *, const void *)) stdDisplay_VideoModeCompare);
    stdDisplay_bOpen = 1;
    return 1;
}

void stdDisplay_Close_hook(void) {
    if (!stdDisplay_bStartup || !stdDisplay_bOpen)
        return;

    if (stdDisplay_bModeSet)
        stdDisplay_ClearMode();

#if GLFW_BACKEND

#else
    stdDisplay_ReleaseDirectDraw();
#endif
    stdDisplay_curDevice = 0;
    memset(&stdDisplay_g_frontBuffer, 0, sizeof(stdDisplay_g_frontBuffer));
    memset(&stdDisplay_g_backBuffer, 0, sizeof(stdDisplay_g_backBuffer));
    memset(&stdDisplay_zBuffer, 0, sizeof(stdDisplay_zBuffer));
    stdDisplay_pcurDevice = 0;
    stdDisplay_FillMainSurface_ptr = noop;
    stdDisplay_bOpen = 0;
}

int stdDisplay_SetMode_hook(int modeNum, int bFullscreen) {
#if GLFW_BACKEND
    stdDisplay_g_frontBuffer.rasterInfo = stdDisplay_aVideoModes[0].rasterInfo;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwWidth =
        stdDisplay_g_frontBuffer.rasterInfo.width;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwHeight =
        stdDisplay_g_frontBuffer.rasterInfo.height;

    stdDisplay_g_backBuffer.rasterInfo = stdDisplay_aVideoModes[0].rasterInfo;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwHeight =
        stdDisplay_g_backBuffer.rasterInfo.height;

    stdDisplay_pCurVideMode = &stdDisplay_aVideoModes[0];
    stdDisplay_backbufWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    stdDisplay_backbufHeight = stdDisplay_g_backBuffer.rasterInfo.height;
    stdDisplay_bModeSet = 1;
    stdDisplay_bFullscreen = bFullscreen;
    return 1;
#else
    if (bFullscreen && modeNum >= stdDisplay_numVideoModes)
        return 0;

    if (stdDisplay_bModeSet)
        stdDisplay_ClearMode();

    if (bFullscreen) {
        stdDisplay_pCurVideMode = &stdDisplay_aVideoModes[modeNum];
        if (!stdDisplay_SetFullscreenMode(Window_GetHWND(), &stdDisplay_aVideoModes[modeNum]))
            return 0;
    } else {
        stdDisplay_pCurVideMode = &stdDisplay_primaryVideoMode;
        if (!stdDisplay_SetWindowMode(Window_GetHWND(), &stdDisplay_primaryVideoMode))
            return 0;
    }
    stdDisplay_hFont = CreateFontA(stdDisplay_pCurVideMode->rasterInfo.width < 640u ? 12 : 24, 0, 0,
                                   0, 400, 0, 0, 0, 0, 0, 0, 0, 2u, "Arial");

    // those 2 global vars are only used in this one function.
    // dword_529568 = 0;
    // dword_52956C = 0;
    stdDisplay_backbufWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    stdDisplay_backbufHeight = stdDisplay_g_backBuffer.rasterInfo.height;
    stdDisplay_bModeSet = 1;
    stdDisplay_bFullscreen = bFullscreen;
    stdDisplay_VBufferFill(&stdDisplay_g_backBuffer, 0, 0);
    stdDisplay_Update();
    if (bFullscreen)
        stdDisplay_VBufferFill(&stdDisplay_g_backBuffer, 0, 0);
    return 1;
#endif
}

void stdDisplay_Refresh_hook(int bReload) {
#if GLFW_BACKEND
    return;
#else
    if (!stdDisplay_bOpen || !stdDisplay_bModeSet || !bReload)
        return;

    if (IDirectDraw4_SetCooperativeLevel(stdDisplay_lpDD, Window_GetHWND(),
                                         stdDisplay_coopLevelFlags) != S_OK)
        return;

    if (stdDisplay_bFullscreen) {
        if (stdDisplay_lpDD) {
            const tRasterInfo *i = &stdDisplay_pCurVideMode->rasterInfo;
            if (IDirectDraw4_SetDisplayMode(stdDisplay_lpDD, i->width, i->height, i->colorInfo.bpp,
                                            0, 0) != S_OK)
                return;
        }

        if (stdDisplay_g_frontBuffer.pVSurface.pDDSurf) {
            if (IDirectDrawSurface4_Restore(stdDisplay_g_frontBuffer.pVSurface.pDDSurf) != S_OK)
                return;
        }
    } else {
        if (stdDisplay_g_backBuffer.pVSurface.pDDSurf) {
            if (IDirectDrawSurface4_Restore(stdDisplay_g_backBuffer.pVSurface.pDDSurf) != S_OK)
                return;
        }
    }

    if (stdDisplay_zBuffer.pDDSurf)
        IDirectDrawSurface4_Restore(stdDisplay_zBuffer.pDDSurf);
#endif
}

tVBuffer *stdDisplay_VBufferNew_hook(tRasterInfo *texFormat, int create_ddraw_surface,
                                     int use_video_memory) {
    tVBuffer *buffer = (tVBuffer *) stdPlatform_hostServices.alloc(sizeof(tVBuffer));
    if (!buffer)
        return NULL;

    *buffer = (tVBuffer){0};
    buffer->rasterInfo = *texFormat;

    int bytes_per_pixel = buffer->rasterInfo.colorInfo.bpp / 8;
    buffer->rasterInfo.rowSize = buffer->rasterInfo.width * bytes_per_pixel;
    buffer->rasterInfo.rowWidth = buffer->rasterInfo.width * bytes_per_pixel / bytes_per_pixel;
    buffer->rasterInfo.size =
        buffer->rasterInfo.width * buffer->rasterInfo.height * bytes_per_pixel;

    if (create_ddraw_surface && stdDisplay_bOpen) {
#if GLFW_BACKEND
        abort();
#else
        buffer->bVideoMemory = 0;
        buffer->bSurfaceAllocated = 1;

        DDSURFACEDESC2 *desc = &buffer->pVSurface.ddSurfDesc;
        desc->dwSize = sizeof(DDSURFACEDESC2);
        desc->dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH;
        desc->ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN;
        if (!use_video_memory)
            desc->ddsCaps.dwCaps |= DDSCAPS_SYSTEMMEMORY;
        desc->dwWidth = buffer->rasterInfo.width;
        desc->dwHeight = buffer->rasterInfo.height;

        if (IDirectDraw4_CreateSurface(stdDisplay_lpDD, desc, &buffer->pVSurface.pDDSurf, 0) !=
            S_OK)
            return NULL;

        if (IDirectDrawSurface4_GetSurfaceDesc(buffer->pVSurface.pDDSurf, desc) != S_OK)
            return NULL;

        if (desc->ddsCaps.dwCaps & DDSCAPS_VIDEOMEMORY)
            buffer->bVideoMemory = 1;

        buffer->rasterInfo.rowSize = desc->dwLinearSize;
        buffer->rasterInfo.rowWidth = desc->dwLinearSize / bytes_per_pixel;
        return buffer;
#endif
    }

    buffer->bSurfaceAllocated = 0;
    buffer->bVideoMemory = 0;
    buffer->pPixels = (BYTE *) stdPlatform_hostServices_ptr->alloc(buffer->rasterInfo.size);
    if (buffer->pPixels) {
        buffer->lockSurfRefCount = 1;
        return buffer;
    }
    return NULL;
}

int stdDisplay_SetWindowMode_hook(HWND hWnd, StdVideoMode *pDisplayMode) {
#if GLFW_BACKEND
    return 0;
#else
    HANG("TODO");
#endif
}

int stdDisplay_SetFullscreenMode_hook(HWND hwnd, StdVideoMode *pDisplayMode) {
#if GLFW_BACKEND
    return 0;
#else
    HANG("TODO");
#endif
}

int stdDisplay_VBufferFill_hook(tVBuffer *pVBuffer, DWORD dwFillColor, LECRECT *pRect) {
#if GLFW_BACKEND
    return stdDisplay_ColorFillSurface(&pVBuffer->pVSurface, dwFillColor, pRect);
#else
    HANG("TODO");
#endif
}

void stdDisplay_FillMainSurface_hook(void) {
#if GLFW_BACKEND
    glDepthMask(GL_TRUE);
    glClear(GL_DEPTH_BUFFER_BIT);
#else
    if (stdDisplay_FillMainSurface_ptr != NULL)
        stdDisplay_FillMainSurface_ptr();
#endif
}

int stdDisplay_ColorFillSurface_hook(tVSurface *pSurf, DWORD dwFillColor, LECRECT *lpRect) {
#if GLFW_BACKEND
    if (pSurf == &stdDisplay_g_backBuffer.pVSurface && lpRect == NULL) {
        uint8_t b = ((dwFillColor >> 0) & 0b11111) << 3;
        uint8_t g = ((dwFillColor >> 5) & 0b111111) << 2;
        uint8_t r = ((dwFillColor >> 11) & 0b11111) << 3;
        glClearColor(r / 255.0, g / 255.0, b / 255.0, 255.0);
        glClear(GL_COLOR_BUFFER_BIT);
    }

    return 0;
#else
    HANG("TODO");
#endif
}

#endif// stdDisplay.c GLFW_BACKEND

// Window.c
#if GLFW_BACKEND

void Window_SetActivated_hook(HWND hwnd, WPARAM activated) {
    if (activated != 0) {
        if (Window_Active == 0) {
#if !GLFW_BACKEND
            if ((swrMainDisplaySettings_g.RegFullScreen == 0) &&
                (swrMainDisplaySettings_g.RegDevMode == 0)) {
                ShowWindow(hwnd, 3);
            }
#endif
            swrDisplay_SetWindowSize();
            stdDisplay_Refresh(1);
            std3D_ClearCacheList();
            swrDisplay_SetWindowSize();
        }
        swrMain_GuiAdvanceFunction = (void *) swrMain2_GuiAdvance;
        Window_Active = 1;
        swrGui_Stop(0);
        stdControl_SetActivation(activated);
        return;
    }
    swrMain_GuiAdvanceFunction = (void *) noop;
    stdDisplay_Refresh(0);
    Window_Active = 0;
    swrGui_Stop(1);
    stdControl_SetActivation(0);
}

int Window_SmushPlayCallback_hook(const SmushImage *image) {
#if GLFW_BACKEND
    swrControl_ProcessInputs();

    renderer_drawSmushFrame(image);

    stdDisplay_Update();

    return stdControl_ReadKey(DIK_ESCAPE, 0) || stdControl_ReadKey(DIK_RETURN, 0) ||
           glfwWindowShouldClose(glfwGetCurrentContext());
#else
    HANG("TODO");
#endif
}

static int glfw_key_to_dik[349];

static int prev_window_x = 0;
static int prev_window_y = 0;
static int prev_window_width = 0;
static int prev_window_height = 0;

static int glfw_key_to_dik_initialized = false;

static void key_callback(GLFWwindow *window, int key, int scancode, int action, int mods) {
    if (!glfw_key_to_dik_initialized) {
        glfw_key_to_dik_initialized = true;

        glfw_key_to_dik[GLFW_KEY_SPACE] = DIK_SPACE;
        glfw_key_to_dik[GLFW_KEY_APOSTROPHE] = DIK_APOSTROPHE;
        glfw_key_to_dik[GLFW_KEY_COMMA] = DIK_COMMA;
        glfw_key_to_dik[GLFW_KEY_MINUS] = DIK_MINUS;
        glfw_key_to_dik[GLFW_KEY_PERIOD] = DIK_PERIOD;
        glfw_key_to_dik[GLFW_KEY_SLASH] = DIK_SLASH;
        glfw_key_to_dik[GLFW_KEY_0] = DIK_0;
        glfw_key_to_dik[GLFW_KEY_1] = DIK_1;
        glfw_key_to_dik[GLFW_KEY_2] = DIK_2;
        glfw_key_to_dik[GLFW_KEY_3] = DIK_3;
        glfw_key_to_dik[GLFW_KEY_4] = DIK_4;
        glfw_key_to_dik[GLFW_KEY_5] = DIK_5;
        glfw_key_to_dik[GLFW_KEY_6] = DIK_6;
        glfw_key_to_dik[GLFW_KEY_7] = DIK_7;
        glfw_key_to_dik[GLFW_KEY_8] = DIK_8;
        glfw_key_to_dik[GLFW_KEY_9] = DIK_9;
        glfw_key_to_dik[GLFW_KEY_SEMICOLON] = DIK_SEMICOLON;
        glfw_key_to_dik[GLFW_KEY_EQUAL] = DIK_EQUALS;
        glfw_key_to_dik[GLFW_KEY_A] = DIK_A;
        glfw_key_to_dik[GLFW_KEY_B] = DIK_B;
        glfw_key_to_dik[GLFW_KEY_C] = DIK_C;
        glfw_key_to_dik[GLFW_KEY_D] = DIK_D;
        glfw_key_to_dik[GLFW_KEY_E] = DIK_E;
        glfw_key_to_dik[GLFW_KEY_F] = DIK_F;
        glfw_key_to_dik[GLFW_KEY_G] = DIK_G;
        glfw_key_to_dik[GLFW_KEY_H] = DIK_H;
        glfw_key_to_dik[GLFW_KEY_I] = DIK_I;
        glfw_key_to_dik[GLFW_KEY_J] = DIK_J;
        glfw_key_to_dik[GLFW_KEY_K] = DIK_K;
        glfw_key_to_dik[GLFW_KEY_L] = DIK_L;
        glfw_key_to_dik[GLFW_KEY_M] = DIK_M;
        glfw_key_to_dik[GLFW_KEY_N] = DIK_N;
        glfw_key_to_dik[GLFW_KEY_O] = DIK_O;
        glfw_key_to_dik[GLFW_KEY_P] = DIK_P;
        glfw_key_to_dik[GLFW_KEY_Q] = DIK_Q;
        glfw_key_to_dik[GLFW_KEY_R] = DIK_R;
        glfw_key_to_dik[GLFW_KEY_S] = DIK_S;
        glfw_key_to_dik[GLFW_KEY_T] = DIK_T;
        glfw_key_to_dik[GLFW_KEY_U] = DIK_U;
        glfw_key_to_dik[GLFW_KEY_V] = DIK_V;
        glfw_key_to_dik[GLFW_KEY_W] = DIK_W;
        glfw_key_to_dik[GLFW_KEY_X] = DIK_X;
        glfw_key_to_dik[GLFW_KEY_Y] = DIK_Y;
        glfw_key_to_dik[GLFW_KEY_Z] = DIK_Z;
        glfw_key_to_dik[GLFW_KEY_LEFT_BRACKET] = DIK_LBRACKET;
        glfw_key_to_dik[GLFW_KEY_BACKSLASH] = DIK_BACKSLASH;
        glfw_key_to_dik[GLFW_KEY_RIGHT_BRACKET] = DIK_RBRACKET;
        glfw_key_to_dik[GLFW_KEY_GRAVE_ACCENT] = DIK_GRAVE;
        glfw_key_to_dik[GLFW_KEY_ESCAPE] = DIK_ESCAPE;
        glfw_key_to_dik[GLFW_KEY_ENTER] = DIK_RETURN;
        glfw_key_to_dik[GLFW_KEY_TAB] = DIK_TAB;
        glfw_key_to_dik[GLFW_KEY_BACKSPACE] = DIK_BACKSPACE;
        glfw_key_to_dik[GLFW_KEY_INSERT] = DIK_INSERT;
        glfw_key_to_dik[GLFW_KEY_DELETE] = DIK_DELETE;
        glfw_key_to_dik[GLFW_KEY_RIGHT] = DIK_RIGHT;
        glfw_key_to_dik[GLFW_KEY_LEFT] = DIK_LEFT;
        glfw_key_to_dik[GLFW_KEY_DOWN] = DIK_DOWN;
        glfw_key_to_dik[GLFW_KEY_UP] = DIK_UP;
        glfw_key_to_dik[GLFW_KEY_PAGE_UP] = DIK_PGUP;
        glfw_key_to_dik[GLFW_KEY_PAGE_DOWN] = DIK_PGDN;
        glfw_key_to_dik[GLFW_KEY_HOME] = DIK_HOME;
        glfw_key_to_dik[GLFW_KEY_END] = DIK_END;
        glfw_key_to_dik[GLFW_KEY_CAPS_LOCK] = DIK_CAPSLOCK;
        glfw_key_to_dik[GLFW_KEY_SCROLL_LOCK] = DIK_SCROLL;
        glfw_key_to_dik[GLFW_KEY_NUM_LOCK] = DIK_NUMLOCK;
        glfw_key_to_dik[GLFW_KEY_PAUSE] = DIK_PAUSE;
        glfw_key_to_dik[GLFW_KEY_F1] = DIK_F1;
        glfw_key_to_dik[GLFW_KEY_F2] = DIK_F2;
        glfw_key_to_dik[GLFW_KEY_F3] = DIK_F3;
        glfw_key_to_dik[GLFW_KEY_F4] = DIK_F4;
        glfw_key_to_dik[GLFW_KEY_F5] = DIK_F5;
        glfw_key_to_dik[GLFW_KEY_F6] = DIK_F6;
        glfw_key_to_dik[GLFW_KEY_F7] = DIK_F7;
        glfw_key_to_dik[GLFW_KEY_F8] = DIK_F8;
        glfw_key_to_dik[GLFW_KEY_F9] = DIK_F9;
        glfw_key_to_dik[GLFW_KEY_F10] = DIK_F10;
        glfw_key_to_dik[GLFW_KEY_F11] = DIK_F11;
        glfw_key_to_dik[GLFW_KEY_F12] = DIK_F12;
        glfw_key_to_dik[GLFW_KEY_F13] = DIK_F13;
        glfw_key_to_dik[GLFW_KEY_F14] = DIK_F14;
        glfw_key_to_dik[GLFW_KEY_F15] = DIK_F15;
        glfw_key_to_dik[GLFW_KEY_KP_0] = DIK_NUMPAD0;
        glfw_key_to_dik[GLFW_KEY_KP_1] = DIK_NUMPAD1;
        glfw_key_to_dik[GLFW_KEY_KP_2] = DIK_NUMPAD2;
        glfw_key_to_dik[GLFW_KEY_KP_3] = DIK_NUMPAD3;
        glfw_key_to_dik[GLFW_KEY_KP_4] = DIK_NUMPAD4;
        glfw_key_to_dik[GLFW_KEY_KP_5] = DIK_NUMPAD5;
        glfw_key_to_dik[GLFW_KEY_KP_6] = DIK_NUMPAD6;
        glfw_key_to_dik[GLFW_KEY_KP_7] = DIK_NUMPAD7;
        glfw_key_to_dik[GLFW_KEY_KP_8] = DIK_NUMPAD8;
        glfw_key_to_dik[GLFW_KEY_KP_9] = DIK_NUMPAD9;
        glfw_key_to_dik[GLFW_KEY_KP_DECIMAL] = DIK_NUMPADCOMMA;
        glfw_key_to_dik[GLFW_KEY_KP_DIVIDE] = DIK_NUMPADSLASH;
        glfw_key_to_dik[GLFW_KEY_KP_MULTIPLY] = DIK_NUMPADSTAR;
        glfw_key_to_dik[GLFW_KEY_KP_SUBTRACT] = DIK_NUMPADMINUS;
        glfw_key_to_dik[GLFW_KEY_KP_ADD] = DIK_NUMPADPLUS;
        glfw_key_to_dik[GLFW_KEY_KP_ENTER] = DIK_NUMPADENTER;
        glfw_key_to_dik[GLFW_KEY_KP_EQUAL] = DIK_NUMPADEQUALS;
        glfw_key_to_dik[GLFW_KEY_LEFT_SHIFT] = DIK_LSHIFT;
        glfw_key_to_dik[GLFW_KEY_LEFT_CONTROL] = DIK_LCONTROL;
        glfw_key_to_dik[GLFW_KEY_LEFT_ALT] = DIK_LALT;
        glfw_key_to_dik[GLFW_KEY_LEFT_SUPER] = DIK_LWIN;
        glfw_key_to_dik[GLFW_KEY_RIGHT_SHIFT] = DIK_RSHIFT;
        glfw_key_to_dik[GLFW_KEY_RIGHT_CONTROL] = DIK_RCONTROL;
        glfw_key_to_dik[GLFW_KEY_RIGHT_ALT] = DIK_RALT;
        glfw_key_to_dik[GLFW_KEY_RIGHT_SUPER] = DIK_RWIN;
        glfw_key_to_dik[GLFW_KEY_MENU] = DIK_RMENU;
    }
    if (key == GLFW_KEY_ENTER && action == GLFW_PRESS && mods & GLFW_MOD_ALT) {
        bool fullscreen = glfwGetWindowMonitor(window);
        if (!fullscreen) {
            glfwGetWindowPos(window, &prev_window_x, &prev_window_y);
            glfwGetWindowSize(window, &prev_window_width, &prev_window_height);
            GLFWmonitor *monitor = glfwGetPrimaryMonitor();
            const GLFWvidmode *mode = glfwGetVideoMode(monitor);
            glfwSetWindowMonitor(window, monitor, 0, 0, mode->width, mode->height,
                                 mode->refreshRate);
        } else {
            glfwSetWindowMonitor(window, NULL, prev_window_x, prev_window_y, prev_window_width,
                                 prev_window_height, 0);
        }
        return;
    }

    if (key >= ARRAYSIZE(glfw_key_to_dik))
        return;

    int dik_key = glfw_key_to_dik[key];
    if (dik_key == 0)
        return;

    const bool pressed = action != GLFW_RELEASE;

    stdControl_aKeyInfos[dik_key] = pressed;
    stdControl_g_aKeyPressCounter[dik_key] += pressed;

    UINT vk = MapVirtualKeyA(dik_key, MAPVK_VSC_TO_VK);
    if (vk == 0) {
        // TODO hack: for some reason the arrow keys return 0 on MapVirtualKeyA...
        switch (key) {
            case GLFW_KEY_DOWN:
                vk = VK_DOWN;
                break;
            case GLFW_KEY_UP:
                vk = VK_UP;
                break;
            case GLFW_KEY_LEFT:
                vk = VK_LEFT;
                break;
            case GLFW_KEY_RIGHT:
                vk = VK_RIGHT;
                break;
        }
    }

    // Window_AddKeyEvent(vk, 0, pressed); <-- not actually used by the game
    swrUI_HandleKeyEvent(vk, pressed);
}

static void mouse_button_callback(GLFWwindow *window, int button, int action, int mods) {
    const bool pressed = action != GLFW_RELEASE;
    stdControl_aKeyInfos[512 + button] = pressed;
    stdControl_g_aKeyPressCounter[512 + button] += pressed;
}

void GLAPIENTRY Window_glDebugMessageCallback(GLenum source, GLenum type, GLuint id,
                                              GLenum severity, GLsizei length,
                                              const GLchar *message, const void *userParam) {
    const char *source_str = "UNKNOWN";

    switch (source) {
        case GL_DEBUG_SOURCE_API:
            source_str = "API";
            break;

        case GL_DEBUG_SOURCE_WINDOW_SYSTEM:
            source_str = "WINDOW SYSTEM";
            break;

        case GL_DEBUG_SOURCE_SHADER_COMPILER:
            source_str = "SHADER COMPILER";
            break;

        case GL_DEBUG_SOURCE_THIRD_PARTY:
            source_str = "THIRD PARTY";
            break;

        case GL_DEBUG_SOURCE_APPLICATION:
            source_str = "APPLICATION";
            break;
    }

    const char *type_str = "UNKNOWN";
    switch (type) {
        case GL_DEBUG_TYPE_ERROR:
            type_str = "ERROR";
            break;
        case GL_DEBUG_TYPE_DEPRECATED_BEHAVIOR:
            type_str = "DEPRECATED_BEHAVIOR";
            break;
        case GL_DEBUG_TYPE_UNDEFINED_BEHAVIOR:
            type_str = "UNDEFINED_BEHAVIOR";
            break;
        case GL_DEBUG_TYPE_PORTABILITY:
            type_str = "PORTABILITY";
            break;
        case GL_DEBUG_TYPE_PERFORMANCE:
            type_str = "PERFORMANCE";
            break;
        case GL_DEBUG_TYPE_OTHER:
            type_str = "OTHER";
            break;
        case GL_DEBUG_TYPE_MARKER:
            type_str = "MARKER";
            break;
    }

    const char *severity_str = "UNKNOWN";
    switch (severity) {
        case GL_DEBUG_SEVERITY_LOW:
            severity_str = "LOW";
            break;
        case GL_DEBUG_SEVERITY_MEDIUM:
            severity_str = "MEDIUM";
            break;
        case GL_DEBUG_SEVERITY_HIGH:
            severity_str = "HIGH";
            break;
        case GL_DEBUG_SEVERITY_NOTIFICATION:
            severity_str = "NOTIFICATION";
            break;
    }

    // Filter out OTHER NOTIFICATION API
    if (type == GL_DEBUG_TYPE_OTHER && severity == GL_DEBUG_SEVERITY_NOTIFICATION &&
        source == GL_DEBUG_SOURCE_API) {
        return;
    }
    // Filter out PERFORMANCE MEDIUM API (usually shader recompilation)
    if (type == GL_DEBUG_TYPE_PERFORMANCE && severity == GL_DEBUG_SEVERITY_MEDIUM &&
        source == GL_DEBUG_SOURCE_API) {
        return;
    }

    fprintf(hook_log, "[OpenGL](%d, %s) %s (%s): %s\n", id, type_str, severity_str, source_str,
            message);
    fflush(hook_log);
}

int Window_Main_hook(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow,
                     const char *window_name) {
#if GLFW_BACKEND
    InitCommonControls();
    Window_SetHINSTANCE(hInstance);
    Window_SetGUID((GUID *) Window_UUID);

    glfwInit();

    {// Core compatibility for RenderDocs
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 4);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 5);
        glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
        glfwWindowHint(GLFW_OPENGL_DEBUG_CONTEXT, GL_TRUE);// OpenGL debug callback
    }

    GLFWwindow *window = glfwCreateWindow(640, 480, window_name, NULL, NULL);
    if (!window) {
        fprintf(hook_log, "GLFW Window couldn't be created, aborting\n");
        fflush(hook_log);

        abort();
    }

    glfwMaximizeWindow(window);
    glfwMakeContextCurrent(window);
    glfwSetKeyCallback(window, key_callback);
    glfwSetMouseButtonCallback(window, mouse_button_callback);

    Main_Startup((char *) pCmdLine);

    // NEEDS to be AFTER Main_Startup !
    glEnable(GL_DEBUG_OUTPUT_SYNCHRONOUS);
    glDebugMessageCallback(Window_glDebugMessageCallback, 0);

    while (!glfwWindowShouldClose(window)) {
        swrMain2_GuiAdvance();
    }
#else
    int iVar1;
    int iVar2;
    BOOL msg_res;
    LPCSTR unaff_ESI;
    int unaff_EDI;
    struct tagMSG msg;

    g_nCmdShow = nCmdShow;
    Window_CreateMainWindow(hInstance, nCmdShow, window_name, 0, NULL);
    Window_SetHWND(g_hWnd);
    Window_SetHINSTANCE(hInstance);
    Window_SetGUID((GUID *) Window_UUID);
    InitCommonControls();
    iVar1 = GetSystemMetrics(0x20);
    Window_border_width = iVar1 << 1;
    iVar1 = GetSystemMetrics(0x20);
    iVar2 = GetSystemMetrics(0xf);
    Window_border_height = iVar2 + iVar1 * 2;
    iVar1 = Main_Startup((char *) pCmdLine);
#if WINDOWED_MODE_FIXES
    ShowWindow(g_hWnd, SW_NORMAL);
#endif
    if (iVar1 == 0) {
        return 0;
    }
    do {
        while (msg_res = PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE), msg_res == 0) {
            swrMain2_GuiAdvance();
        }
        do {
            msg_res = GetMessageA(&msg, NULL, 0, 0);
            if (msg_res == -1) {
                return -1;
            }
            if (msg_res == 0) {
                return msg.wParam;
            }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
            msg_res = PeekMessageA(&msg, NULL, 0, 0, 0);
        } while (msg_res != 0);
    } while (true);
#endif

    return 0;
}

#endif// Window.c GLFW_BACKEND

void init_renderer_hooks() {
    fprintf(hook_log, "[Renderer Hooks]");
    fflush(hook_log);
#if GLFW_BACKEND
    // rdMaterial.c
    hook_replace(rdMaterial_SaturateTextureR4G4B4A4, rdMaterial_SaturateTextureR4G4B4A4_hook);

    // std3D.c
    hook_replace(std3D_Startup, std3D_Startup_hook);
    hook_replace(std3D_Open, std3D_Open_hook);
    hook_replace(std3D_StartScene, std3D_StartScene_hook);
    hook_replace(std3D_EndScene, std3D_EndScene_hook);
    hook_replace(std3D_DrawRenderList, std3D_DrawRenderList_hook);
    hook_replace(std3D_SetRenderState, std3D_SetRenderState_hook);
    hook_replace(std3D_AllocSystemTexture, std3D_AllocSystemTexture_hook);
    hook_replace(std3D_ClearTexture, std3D_ClearTexture_hook);
    hook_replace(std3D_AddToTextureCache, std3D_AddToTextureCache_hook);
    hook_replace(std3D_ClearCacheList, std3D_ClearCacheList_hook);
    hook_replace(std3D_SetTexFilterMode, std3D_SetTexFilterMode_hook);
    hook_replace(std3D_SetProjection, std3D_SetProjection_hook);
    hook_replace(std3D_AddTextureToCacheList, std3D_AddTextureToCacheList_hook);
    hook_replace(std3D_RemoveTextureFromCacheList, std3D_RemoveTextureFromCacheList_hook);
    hook_replace(std3D_PurgeTextureCache, std3D_PurgeTextureCache_hook);

    // stdControl.c
    hook_replace(stdControl_Startup, stdControl_Startup_hook);
    hook_replace(stdControl_ReadControls, stdControl_ReadControls_hook);
    hook_replace(stdControl_SetActivation, stdControl_SetActivation_hook);

    // swrDisplay.c
    hook_replace(swrDisplay_SetWindowSize, swrDisplay_SetWindowSize_hook);

    // DirectX.c
    hook_replace(DirectDraw_InitProgressBar, DirectDraw_InitProgressBar_hook);
    hook_replace(DirectDraw_Shutdown, DirectDraw_Shutdown_hook);
    hook_replace(DirectDraw_BlitProgressBar, DirectDraw_BlitProgressBar_hook);
    hook_replace(DirectDraw_LockZBuffer, DirectDraw_LockZBuffer_hook);
    hook_replace(DirectDraw_UnlockZBuffer, DirectDraw_UnlockZBuffer_hook);
    hook_replace(Direct3d_SetFogMode, Direct3d_SetFogMode_hook);
    hook_replace(Direct3d_IsLensflareCompatible, Direct3d_IsLensflareCompatible_hook);
    hook_replace(Direct3d_ConfigFog, Direct3d_ConfigFog_hook);

    // stdDisplay.c
    hook_replace(stdDisplay_Startup, stdDisplay_Startup_hook);
    hook_replace(stdDisplay_Open, stdDisplay_Open_hook);
    hook_replace(stdDisplay_Close, stdDisplay_Close_hook);
    hook_replace(stdDisplay_SetMode, stdDisplay_SetMode_hook);
    hook_replace(stdDisplay_Refresh, stdDisplay_Refresh_hook);
    hook_replace(stdDisplay_VBufferNew, stdDisplay_VBufferNew_hook);
    hook_replace(stdDisplay_SetWindowMode, stdDisplay_SetWindowMode_hook);
    hook_replace(stdDisplay_SetFullscreenMode, stdDisplay_SetFullscreenMode_hook);
    hook_replace(stdDisplay_VBufferFill, stdDisplay_VBufferFill_hook);
    hook_replace(stdDisplay_FillMainSurface, stdDisplay_FillMainSurface_hook);
    hook_replace(stdDisplay_ColorFillSurface, stdDisplay_ColorFillSurface_hook);

    // Window.c
    hook_replace(Window_SetActivated, Window_SetActivated_hook);
    hook_replace(Window_SmushPlayCallback, Window_SmushPlayCallback_hook);
    hook_replace(Window_Main, Window_Main_hook);

#endif
    // end
    hook_replace(rdMaterial_InvertTextureAlphaR4G4B4A4, noop);
    hook_replace(rdMaterial_InvertTextureColorR4G4B4A4, noop);
    hook_replace(rdMaterial_RemoveTextureAlphaR4G4B4A4, noop);
    hook_replace(rdMaterial_RemoveTextureAlphaR5G5B5A1, noop);

    //stdDisplay.c
    hook_replace(stdDisplay_Update, stdDisplay_Update_Hook);
    // stdConsole.c
    hook_replace(stdConsole_GetCursorPos, stdConsole_GetCursorPos_Hook);
    hook_replace(stdConsole_SetCursorPos, stdConsole_SetCursorPos_Hook);

    hook_replace(swrViewport_Render, swrViewport_Render_Hook);

    hook_replace(swrModel_LoadFromId, swrModel_LoadFromId_Hook);
}
