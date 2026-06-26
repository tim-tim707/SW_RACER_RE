//
// Created by tly on 10.03.2024.
//
#include "renderer_hook.h"
#include "hook_helper.h"
#include "node_utils.h"
#include "imgui_utils.h"
#include "renderer_utils.h"
#include "replacements.h"
#include "stb_image.h"
#include "texture_replacement.h"

extern "C" {
#include "./game_deltas/DirectX_delta.h"
#include "./game_deltas/main_delta.h"
#include "./game_deltas/rdMaterial_delta.h"
#include "./game_deltas/rdMatrix_delta.h"
#include "./game_deltas/std3D_delta.h"
#include "./game_deltas/stdControl_delta.h"
#include "./game_deltas/stdDisplay_delta.h"
#include "./game_deltas/swrDisplay_delta.h"
#include "./game_deltas/Window_delta.h"
// CUSTOM TRACKS
#include "./game_deltas/tracks_delta.h"
}

#include "./game_deltas/stdConsole_delta.h"
#include "./game_deltas/swrModel_delta.h"
#include "./game_deltas/swrSpline_delta.h"
#include "./game_deltas/swrObjJdge_delta.h"
#include "./game_deltas/swrMultiplayer_delta.h"
#include "./game_deltas/swrPlayerHUD_delta.h"
#include "./game_deltas/swrWeather_delta.h"
#include "./game_deltas/swrObjHang_delta.h"
#include "./game_deltas/swrRace_delta.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include "n64_shader.h"
#include "types.h"
#include <chrono>
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
#include <unordered_map>
#include <algorithm>


extern "C" {
#include <main.h>
#include <Swr/swrAssetBuffer.h>
#include <Platform/std3D.h>
#include <Platform/stdControl.h>
#include <Primitives/rdMatrix.h>
#include <Raster/rdCache.h>
#include <Swr/swrDisplay.h>
#include <Swr/swrModel.h>
#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
#include <Swr/swrRender.h>
#include <Swr/swrSpline.h>
#include <Swr/swrSprite.h>
#include <Swr/swrWeather.h>
#include <Swr/swrText.h>
#include <Swr/swrUI.h>
#include <Swr/swrViewport.h>
#include <Swr/swrViewport.h>
#include <Swr/swrEvent.h>
#include <Dss/sithMulti.h>
#include <Win95/stdComm.h>
#include <Win95/stdConsole.h>
#include <Win95/stdDisplay.h>
#include <Win95/DirectX.h>
#include <Win95/Window.h>
#include <swr.h>
#include <hook.h>
}

extern "C" FILE *hook_log;
extern bool imgui_initialized;
extern ImGuiState imgui_state;
extern const char *modelid_cstr[];
extern uint8_t replacedTries[323];// 323 MODELIDs
extern std::map<MODELID, uint8_t> additionnalReplacedTries;
extern "C" TrackInfo g_aNewTrackInfos[MAX_NB_TRACKS];

static bool environment_setuped = false;
static bool skybox_initialized = false;
static EnvInfos envInfos;

int faceIndex = 0;

bool environment_models_drawn = false;

// Per-mesh geometry cache (perf): a static mesh is parsed, CPU-transformed and uploaded once, then
// just bound + drawn while its model matrix is unchanged, instead of redoing all of that every
// frame. Meshes whose matrix changes (pods, animated parts) rebuild as before, so nothing
// regresses. Flushed on track unload via swrModel_ClearLoadedModels_delta so reused mesh pointers
// can't return stale geometry and the GL objects don't leak. Profiling (renderer_perf): the
// per-frame glBufferData re-upload was ~52% of the per-draw CPU cost.
struct CachedMeshGeometry {
    GLuint vao = 0;
    GLuint vbo = 0;
    int vertex_count = 0;
    rdMatrix44 model_matrix{};
};
static std::unordered_map<const swrModel_Mesh *, CachedMeshGeometry> g_mesh_geometry_cache;
// Model matrix of each mesh's most recent parse, used by parse_display_list_commands for the N64
// shared-vertex (soft-skinning) case. File-scope so the cache flush can clear it alongside the
// geometry cache.
static std::unordered_map<const swrModel_Mesh *, rdMatrix44> cached_model_matrix;

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

// Pod cable curve (see swrRace_delta.cpp): bend amplitude for the cable mesh currently being
// rendered, or -1 when the current mesh is not a curved cable. Set by debug_render_node when it
// descends into a curved cable node and consumed by parse_display_list_commands below.
static float g_active_cable_amplitude = -1.0f;

// FUN_00481c30 eases the per-ring parameter before the sine lookup (consts 0x4ae028..0x4ae058).
static float cable_ease_ring_param(float u) {
    if (u > 0.1f && u < 0.4f)
        return (u - 0.25f) * 0.75f + 0.25f;
    if (u > 0.6f && u < 0.99f)
        return (u - 0.75f) * 0.75f + 0.75f;
    return u;
}

// Build the cable mesh the game itself shows: FUN_00481c30 (0x481c30) rebuilds the cable into a
// 9-ring x 3-vert triangular tube from the templates at 0x4c7c30 (positions) / 0x4c7c78 (baked
// vertex colors: apex gray, base black), eased + bent along its length. The OpenGL replacement
// renders the original (thinner, flat-colored) authored mesh instead, so the curved cable looks
// thin/unshaded - this regenerates the game's version into mesh-local space, transformed by the
// node's stretched-quad matrix. amplitude A = (1-(dist/50)^2)*bend (see swrRace_delta.cpp).
static void generate_cable_tube(const rdMatrix44 &model_matrix, std::vector<Vertex> &triangles,
                                float amplitude) {
    triangles.clear();

    // Triangular cross-section (x,z) and baked per-vertex colors from the templates.
    const float cs_x[3] = {0.0f, 20.0f, -20.0f};
    const float cs_z[3] = {0.0f, -20.0f, -20.0f};
    const rdVector4 cs_color[3] = {
        {128.0f / 255.0f, 128.0f / 255.0f, 128.0f / 255.0f, 1.0f},
        {0.0f, 0.0f, 0.0f, 1.0f},
        {0.0f, 0.0f, 0.0f, 1.0f},
    };

    Vertex ring[9][3];
    for (int r = 0; r <= 8; r++) {
        const float s = cable_ease_ring_param(r * (1.0f / 8.0f));
        const float y = truncf(-100.0f * s);
        const float z_bend = (r >= 1 && r <= 7)
                                 ? truncf(-100.0f * amplitude * sinf(s * 6.28318530717958647692f))
                                 : 0.0f;
        for (int c = 0; c < 3; c++) {
            Vertex &v = ring[r][c];
            v = Vertex{};
            v.pos = {cs_x[c], y, cs_z[c] + z_bend};
            rdMatrix_Transform3(&v.pos, &v.pos, &model_matrix);
            v.tu = 0;
            v.tv = 0;
            v.color = cs_color[c];
        }
    }

    // 8 segments x 3 prism edges x 2 triangles. End caps are omitted (they sit inside the
    // cockpit/engine). Rendered double-sided by the caller so winding doesn't matter.
    for (int r = 0; r < 8; r++) {
        for (int c = 0; c < 3; c++) {
            const int c1 = (c + 1) % 3;
            triangles.push_back(ring[r][c]);
            triangles.push_back(ring[r][c1]);
            triangles.push_back(ring[r + 1][c1]);
            triangles.push_back(ring[r][c]);
            triangles.push_back(ring[r + 1][c1]);
            triangles.push_back(ring[r + 1][c]);
        }
    }
}

void parse_display_list_commands(const rdMatrix44 &model_matrix, const swrModel_Mesh *mesh,
                                 std::vector<Vertex> &triangles) {
    triangles.clear();

    cached_model_matrix[mesh] = model_matrix;

    bool vertices_have_normals = mesh->mesh_material->type & 0x11;

    // Pod cable curve: render the game's rebuilt curved tube (baked-shaded triangular prism)
    // instead of the original thin, flat-colored authored mesh.
    if (g_active_cable_amplitude >= 0.0f) {
        generate_cable_tube(model_matrix, triangles, g_active_cable_amplitude);
        return;
    }

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

    // the max number of vertices on the N64 is actually 32.
    // this value is set to 256 to support custom tracks built with
    // https://github.com/louriccia/blender-swe1r/
    // this should not have any consequences other than supporting more than 32 vertices.
    Vertex vertices[256];

    const Gfx *command = swrModel_MeshGetDisplayList(mesh);
    while (command->type != 0xdf) {
        switch (command->type) {
            case 0x1: {
                const uint8_t n = (SWAP16(command->gSPVertex.n_packed) >> 4) & 0xFF;
                const uint8_t v0 = command->gSPVertex.v0_plus_n - n;
                if (v0 != mesh->vertex_base_offset)
                    std::abort();

                if (v0 + n > std::size(vertices))
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
                       const rdMatrix44 &model_matrix, MODELID model_id) {

    if (!imgui_state.draw_meshes)
        return;

    const auto &aabb = mesh->aabb;
    // glDrawAABBLines({ aabb[0], aabb[1], aabb[2] }, { aabb[3], aabb[4], aabb[5] });

    if (!mesh->vertices)
        return;

#ifndef NDEBUG
    for (MaterialMember &member: node_material_members) {
        const uint32_t value = member.getter(*mesh->mesh_material);
        member.count[value]++;
    }

    for (const MaterialMember &member: node_material_members) {
        const uint32_t value = member.getter(*mesh->mesh_material);
        if (member.banned.contains(value))
            return;
    }
#endif

    const uint32_t &type = mesh->mesh_material->type;
    if (imgui_state.HD_replacement) {
        if (imgui_state.show_replacementTries && environment_models_drawn == false &&
            !isEnvModel(model_id)) {
            imgui_state.replacementTries += std::string("=== ENV DONE ===\n");
            environment_models_drawn = true;
        }

        // replacements
        if (try_replace(model_id, proj_matrix, view_matrix, model_matrix, envInfos, mirrored,
                        type) &&
            !imgui_state.show_original_and_replacements) {
            return;
        }
    }

    const bool vertices_have_normals = mesh->mesh_material->type & 0x11;

    const swrModel_Material *n64_material = mesh->mesh_material->material;

    const uint32_t render_mode = n64_material->render_mode_1 | n64_material->render_mode_2;
    set_render_mode(render_mode);

    const CombineMode color_cycle1(n64_material->color_combine_mode_cycle1, false);
    const CombineMode alpha_cycle1(n64_material->alpha_combine_mode_cycle1, true);
    const CombineMode color_cycle2(n64_material->color_combine_mode_cycle2, false);
    const CombineMode alpha_cycle2(n64_material->alpha_combine_mode_cycle2, true);

    glActiveTexture(GL_TEXTURE0);
    float uv_scale_x = 1.0;
    float uv_scale_y = 1.0;
    float uv_offset_x = 0;
    float uv_offset_y = 0;
    GLuint current_texture_handle = 0;
    if (mesh->mesh_material->material_texture &&
        mesh->mesh_material->material_texture->loaded_material) {
        const swrModel_MaterialTexture *tex = mesh->mesh_material->material_texture;
        tSystemTexture *sys_tex = tex->loaded_material->aTextures;
        current_texture_handle = GLuint(sys_tex->pD3DSrcTexture);
        glBindTexture(GL_TEXTURE_2D, current_texture_handle);

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
        current_texture_handle = default_gl_tex;
        glBindTexture(GL_TEXTURE_2D, current_texture_handle);
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
    if (g_active_cable_amplitude >= 0.0f) {
        // The generated cable tube isn't guaranteed CCW-wound, so render it double-sided.
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

    const bool fog_enabled = imgui_state.enable_fog && (GameSettingFlags & 0x40) == 0;
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

    if (imgui_state.enable_picking_texture_when_hovering) {
        // picking functionality, this could be generalized to pick model_id/mesh instead of the
        // texture.
        uint32_t pick_id = current_texture_handle;
        if (!imgui_state.pick_through_transparent_objects) {
            // when rendering with alpha blending, the alpha channel is 0 when setting the color to
            // unpackUnorm4x8(...) because the texture handle always contains a small number.
            // by setting the high bits of the pick id to 255, meshes rendered with alpha blending
            // can also be picked because their alpha value will be 1.0.
            pick_id |= 0xFF'00'00'00;
        }

        glUniform1ui(shader.model_id_pos, pick_id);
        const ImVec2 mouse_pos = ImGui::GetMousePos();
        glUniform2i(shader.mouse_position_pos, mouse_pos.x,
                    ImGui::GetIO().DisplaySize.y - 1 - mouse_pos.y);
    }

    struct VertexSpec {
        GLuint vao;
        GLuint buffer;
    };
    static VertexSpec spec = [] {
        VertexSpec spec{};
        glGenVertexArrays(1, &spec.vao);
        glGenBuffers(1, &spec.buffer);

        glBindVertexArray(spec.vao);

        glEnableVertexAttribArray(0);
        glEnableVertexAttribArray(1);
        glEnableVertexAttribArray(2);
        glEnableVertexAttribArray(3);

        glBindBuffer(GL_ARRAY_BUFFER, spec.buffer);
        glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, sizeof(Vertex),
                              reinterpret_cast<void *>(offsetof(Vertex, pos)));
        glVertexAttribPointer(1, 4, GL_FLOAT, GL_FALSE, sizeof(Vertex),
                              reinterpret_cast<void *>(offsetof(Vertex, color)));
        glVertexAttribPointer(2, 2, GL_SHORT, GL_FALSE, sizeof(Vertex),
                              reinterpret_cast<void *>(offsetof(Vertex, tu)));
        glVertexAttribPointer(3, 3, GL_FLOAT, GL_FALSE, sizeof(Vertex),
                              reinterpret_cast<void *>(offsetof(Vertex, normal)));

        glBindBuffer(GL_ARRAY_BUFFER, 0);
        return spec;
    }();

    static std::vector<Vertex> triangles;
    int mesh_vertex_count;

    // Geometry cache. Cable meshes are excluded: they regenerate their tube every frame from
    // g_active_cable_amplitude (which animates even when the node matrix is static), so caching
    // would freeze the sway.
    const bool cacheable = imgui_state.cache_meshes && g_active_cable_amplitude < 0.0f;
    if (cacheable) {
        CachedMeshGeometry &cached = g_mesh_geometry_cache[mesh];
        const bool needs_rebuild =
            cached.vao == 0 || memcmp(&cached.model_matrix, &model_matrix, sizeof(rdMatrix44)) != 0;
        if (needs_rebuild) {
            parse_display_list_commands(model_matrix, mesh, triangles);
            if (cached.vao == 0) {
                glGenVertexArrays(1, &cached.vao);
                glGenBuffers(1, &cached.vbo);
                glBindVertexArray(cached.vao);
                glBindBuffer(GL_ARRAY_BUFFER, cached.vbo);
                glEnableVertexAttribArray(0);
                glEnableVertexAttribArray(1);
                glEnableVertexAttribArray(2);
                glEnableVertexAttribArray(3);
                glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, sizeof(Vertex),
                                      reinterpret_cast<void *>(offsetof(Vertex, pos)));
                glVertexAttribPointer(1, 4, GL_FLOAT, GL_FALSE, sizeof(Vertex),
                                      reinterpret_cast<void *>(offsetof(Vertex, color)));
                glVertexAttribPointer(2, 2, GL_SHORT, GL_FALSE, sizeof(Vertex),
                                      reinterpret_cast<void *>(offsetof(Vertex, tu)));
                glVertexAttribPointer(3, 3, GL_FLOAT, GL_FALSE, sizeof(Vertex),
                                      reinterpret_cast<void *>(offsetof(Vertex, normal)));
            } else {
                glBindVertexArray(cached.vao);
                glBindBuffer(GL_ARRAY_BUFFER, cached.vbo);
            }
            // DYNAMIC_DRAW: a cached mesh whose matrix changes re-uploads here, so STATIC_DRAW would
            // be a misleading hint and can stall.
            glBufferData(GL_ARRAY_BUFFER, triangles.size() * sizeof(Vertex), triangles.data(),
                         GL_DYNAMIC_DRAW);
            cached.vertex_count = (int) triangles.size();
            cached.model_matrix = model_matrix;
        } else {
            glBindVertexArray(cached.vao);
        }
        mesh_vertex_count = cached.vertex_count;
    } else {
        parse_display_list_commands(model_matrix, mesh, triangles);
        glBindVertexArray(spec.vao);
        glBindBuffer(GL_ARRAY_BUFFER, spec.buffer);
        glBufferData(GL_ARRAY_BUFFER, triangles.size() * sizeof(Vertex), triangles.data(),
                     GL_DYNAMIC_DRAW);
        mesh_vertex_count = (int) triangles.size();
    }
    glDrawArrays(GL_TRIANGLES, 0, mesh_vertex_count);

    if (imgui_state.HD_replacement && !environment_models_drawn) {
        GLint old_viewport[4];
        glGetIntegerv(GL_VIEWPORT, old_viewport);
        glViewport(0, 0, 2048, 2048);
        // Env camera FBO
        glBindFramebuffer(GL_FRAMEBUFFER, envInfos.ibl_framebuffer);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT, GL_TEXTURE_2D,
                               envInfos.skybox.depthTexture, 0);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                               GL_TEXTURE_CUBE_MAP_POSITIVE_X + faceIndex,
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

        renderer_lookAtForward(&envViewMat, &envCameraPosition, &targets[faceIndex],
                               &envCameraUp[faceIndex]);
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

        // Reuses the VAO bound above (cached or scratch); vertex count must match that geometry.
        glDrawArrays(GL_TRIANGLES, 0, mesh_vertex_count);

        glBindFramebuffer(GL_FRAMEBUFFER, default_framebuffer);
        glViewport(old_viewport[0], old_viewport[1], old_viewport[2], old_viewport[3]);
    }

    glBindVertexArray(0);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
    glUseProgram(0);
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

#ifndef NDEBUG
    for (NodeMember &member: node_members) {
        const uint32_t value = member.getter(*node);
        member.count[value]++;
    }

    for (const NodeMember &member: node_members) {
        const uint32_t value = member.getter(*node);
        if (member.banned.contains(value))
            return;
    }
#endif

    if (node->type == NODE_TRANSFORMED || node->type == NODE_TRANSFORMED_WITH_PIVOT ||
        node->type == NODE_TRANSFORMED_COMPUTED)
        apply_node_transform(model_mat, node, (rdVector3 *) &current_vp.model_matrix.vD);

    if (node->flags_5 & 0x4) {
        light_index = node->light_index + 1;
        num_enabled_lights = numEnabledLights[node->light_index];
    }

    // Replacements
    const std::optional<MODELID> node_model_id = find_model_id_for_node(node);
    // inspection hangar is pln_tatooine_part and not a pod ID
    if (node->type == NODE_BASIC && node_model_id.has_value() &&
        (isPodModel(node_model_id.value()) || node_model_id.value() == MODELID_pln_tatooine_part)) {
        // Resolve the pod node to its owning racer. Non-null only for full-pod racers in a race (the
        // local player and, with ai_full_lod on, every AI) - draw from THAT entity's own transforms
        // instead of stamping the single global currentPlayer_Test. This is the fix for the "pile of
        // pods riding the player". Null in the hangar / for part-LOD AI -> legacy node-path draw.
        swrRace *pod_owner = find_entity_for_node(node);
        const bool replaced =
            pod_owner != nullptr
                ? try_replace_pod_entity(node_model_id.value(), pod_owner, proj_mat, view_mat,
                                         envInfos, false)
                : try_replace_pod(node_model_id.value(), proj_mat, view_mat, model_mat, envInfos,
                                  false);
        if (replaced && !imgui_state.show_original_and_replacements) {
            return;
        }
    }

    // AI pods are node_selector
    if (node->type == NODE_SELECTOR && node_model_id.has_value() &&
        isAIPodModel(node_model_id.value())) {
        if (try_replace_AIPod(node_model_id.value(), proj_mat, view_mat, model_mat, envInfos,
                              false) &&
            !imgui_state.show_original_and_replacements) {
            return;
        }
    }

    // Track replacements
    // In race, node 3 is the track, as a NODE_BASIC
    if (node->type == NODE_BASIC && node_model_id.has_value() &&
        (uint32_t) root_node == (uint32_t) &someRootNode && isTrackModel(node_model_id.value())) {
        if (try_replace_track(node_model_id.value(), proj_mat, view_mat, envInfos, false) &&
            !imgui_state.show_original_and_replacements) {
            return;
        }
    }
    // Env replacement: Hangar, Cantina, Shop and Scrapyard
    if ((node->type == NODE_TRANSFORMED_WITH_PIVOT) && node_model_id.has_value() &&
        (uint32_t) root_node == (uint32_t) &someUnkRootNode && isEnvModel(node_model_id.value())) {
        if (try_replace_env(node_model_id.value(), proj_mat, view_mat, envInfos, false) &&
            !imgui_state.show_original_and_replacements) {
            return;
        }
    }

    if (node->flags_5 & 0x1) {
        mirrored = !mirrored;
    }

    // Pod cable curve: if this is a curved cable node (nodeArray[10]/[11]), activate the bend so
    // the cable mesh in its subtree is curved in load_vertex; descendants inherit it. Restored
    // below so sibling/parent geometry is unaffected.
    const float prev_cable_amplitude = g_active_cable_amplitude;
    const float node_cable_amplitude = swrRace_GetCableBendAmplitude(node);
    if (node_cable_amplitude >= 0.0f)
        g_active_cable_amplitude = node_cable_amplitude;

    if (node->type == NODE_MESH_GROUP) {
        PushDebugGroup(std::format("render mesh group"));
        for (int i = 0; i < node->num_children; i++) {
            const std::optional<MODELID> model_id = find_model_id_for_node(node->children.nodes[i]);
            if (model_id.has_value()) {
                PushDebugGroup(std::format("render mesh {}", modelid_cstr[model_id.value()]));
                debug_render_mesh(node->children.meshes[i], light_index, num_enabled_lights,
                                  mirrored, proj_mat, view_mat, model_mat, model_id.value());
                PopDebugGroup();
            }
        }
        PopDebugGroup();
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

    g_active_cable_amplitude = prev_cable_amplitude;
}

#ifndef NDEBUG
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
        const swrSprite &sprite = swrSprite_array[i];
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
            const swrSpriteTexturePage &page = sprite.texture->header.page_table[p];
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
#endif

GLuint default_framebuffer = 0;
GLuint framebuffer_color_tex = 0;
GLuint framebuffer_depth_tex = 0;
int current_msaa_samples = 0;
int current_fb_width = 0;
int current_fb_height = 0;

void swrViewport_Render_Hook(int x) {
    begin_texture_replacement();

    GLint viewport[4];
    glGetIntegerv(GL_VIEWPORT, viewport);
    const int width = viewport[2];
    const int height = viewport[3];

    if (imgui_state.msaa_samples != current_msaa_samples || width != current_fb_width ||
        height != current_fb_height) {
        int max_msaa_samples = 1;
        glGetIntegerv(GL_MAX_SAMPLES, &max_msaa_samples);
        if (imgui_state.msaa_samples > max_msaa_samples) {
            imgui_state.msaa_samples = max_msaa_samples;
        }
        current_msaa_samples = imgui_state.msaa_samples;
        current_fb_width = width;
        current_fb_height = height;

        // cleanup old msaa framebuffer
        glDeleteFramebuffers(1, &default_framebuffer);
        glDeleteTextures(1, &framebuffer_color_tex);
        glDeleteTextures(1, &framebuffer_depth_tex);

        // create a new framebuffer
        glGenFramebuffers(1, &default_framebuffer);
        glBindFramebuffer(GL_FRAMEBUFFER, default_framebuffer);

        glGenTextures(1, &framebuffer_depth_tex);
        glBindTexture(GL_TEXTURE_2D_MULTISAMPLE, framebuffer_depth_tex);
        glTexImage2DMultisample(GL_TEXTURE_2D_MULTISAMPLE, current_msaa_samples,
                                GL_DEPTH_COMPONENT32, width, height, true);
        glFramebufferTexture(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, framebuffer_depth_tex, 0);

        glGenTextures(1, &framebuffer_color_tex);
        glBindTexture(GL_TEXTURE_2D_MULTISAMPLE, framebuffer_color_tex);
        glTexImage2DMultisample(GL_TEXTURE_2D_MULTISAMPLE, current_msaa_samples, GL_RGBA8, width,
                                height, true);
        glFramebufferTexture(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, framebuffer_color_tex, 0);

        const GLenum draw_buffer = GL_COLOR_ATTACHMENT0;
        glDrawBuffers(1, &draw_buffer);
    }

    if (default_framebuffer != 0) {
        glBindFramebuffer(GL_FRAMEBUFFER, default_framebuffer);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    }

#if !defined(NDEBUG)
    if (imgui_state.draw_test_scene) {
        draw_test_scene();
        return;
    }
#endif

    uint32_t temp_renderState = std3D_renderState;
    std3D_SetRenderState_delta(Std3DRenderState(0));

    const swrViewport &vp = swrViewport_array[x];
    root_node = vp.model_root_node;

    const int default_light_index = 0;
    const int default_num_enabled_lights = 1;

    int w = swrDisplay_screenWidth;
    int h = swrDisplay_screenHeight;

    const bool fog_enabled = (GameSettingFlags & 0x40) == 0;
    if (fog_enabled)
        rdFace_ConfigureFogStartEnd(fogStartInt16, fogEndInt16);

    const bool mirrored = (GameSettingFlags & 0x4000) != 0;

    const rdClipFrustum *frustum = rdCamera_pCurCamera->pClipFrustum;
    float f = frustum->zFar;
    float n = frustum->zNear;
    const float t = 1.0f / tan(0.5 * rdCamera_pCurCamera->fov / 180.0 * 3.14159);
    // The game's fov is the HORIZONTAL fov, calibrated for 4:3. Hold the 4:3 VERTICAL fov constant
    // across aspect ratios (Hor+) so widescreen reveals more horizontally instead of cropping the
    // top and bottom, then apply the user FOV multiplier (>1 = wider / zoom out). At 4:3 this is
    // identical to the original (xscale=t). w/h>0 guards the 0x0 framebuffer reported while minimized.
    const float design_aspect = 4.0f / 3.0f;
    const float fov_scale = imgui_state.fov_scale > 0.0f ? imgui_state.fov_scale : 1.0f;
    const float yscale = (h > 0) ? (float) (t * design_aspect / fov_scale) : t;
    const float xscale = (w > 0) ? (float) (yscale * (float) h / (float) w) : t;
    const rdMatrix44 proj_mat{
        {mirrored ? -xscale : xscale, 0, 0, 0},
        {0, yscale, 0, 0},
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

    // Hand the scene view/proj to the weather delta so it can depth-test particles against the scene
    // depth (blitted to the default framebuffer below) instead of drawing them as a flat overlay.
    swrWeather_SetSceneMatrices(&proj_mat, &view_mat_corrected);

    rdMatrix44 model_mat;
    rdMatrix_SetIdentity44(&model_mat);

    // skybox and ibl
    if (imgui_state.HD_replacement && !environment_setuped) {
        if (!skybox_initialized) {
            PushDebugGroup("Setuping skybox");
            setupSkybox(envInfos.skybox);
            skybox_initialized = true;
            PopDebugGroup();
        }

        PushDebugGroup("Setuping IBL");

        // render env to cubemap
        setupIBL(envInfos, envInfos.skybox.GLCubeTexture, faceIndex);
        faceIndex += 1;

        if (faceIndex > 5)
            faceIndex = 0;

        glBindFramebuffer(GL_FRAMEBUFFER, envInfos.ibl_framebuffer);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT, GL_TEXTURE_2D,
                               envInfos.skybox.depthTexture, 0);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                               GL_TEXTURE_CUBE_MAP_POSITIVE_X + faceIndex,
                               envInfos.skybox.GLCubeTexture, 0);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        glBindFramebuffer(GL_FRAMEBUFFER, default_framebuffer);
        // environment_setuped = true;

        PopDebugGroup();
    }

    PushDebugGroup("Scene graph traversal");
    environment_models_drawn = false;
    stbi_set_flip_vertically_on_load(false);

#ifndef NDEBUG
    for (MaterialMember &member: node_material_members) {
        member.count.clear();
    }
#endif
    // Phase 0 (HD_REPLACEMENT_ROADMAP): refresh the pod-node -> racer-entity map from the live roster
    // before traversal, so the replacement path can draw each pod from its owning racer's transforms.
    // In race only (currentPlayer_Test is the in-race signal); harmless to rebuild per viewport.
    // Outside a race (hangar/menu) clear it, so stale ranges from the last race can't mis-resolve a
    // hangar pod node to a dangling entity.
    if (currentPlayer_Test != nullptr)
        rebuild_pod_node_owners();
    else
        pod_node_owners.clear();

    debug_render_node(vp, root_node, default_light_index, default_num_enabled_lights, mirrored,
                      proj_mat, view_mat_corrected, model_mat);
    PopDebugGroup();

    debugEnvInfos(envInfos, proj_mat, view_mat);

    glDisable(GL_CULL_FACE);
    std3D_pD3DTex = 0;
    glUseProgram(0);
    std3D_SetRenderState_delta(Std3DRenderState(temp_renderState));

    if (default_framebuffer != 0) {
        glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
        glBindFramebuffer(GL_READ_FRAMEBUFFER, default_framebuffer);
        glBlitFramebuffer(0, 0, width, height, 0, 0, width, height,
                          GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT, GL_NEAREST);
        glBindFramebuffer(GL_FRAMEBUFFER, 0);
    }

    if (imgui_state.enable_picking_texture_when_hovering) {
        // read hovered pixel
        const auto mouse_pos = ImGui::GetMousePos();
        uint32_t picked_id;
        glReadPixels(mouse_pos.x, ImGui::GetIO().DisplaySize.y - 1 - mouse_pos.y, 1, 1, GL_RGBA,
                     GL_UNSIGNED_BYTE, &picked_id);
        // remove alpha channel (is used for masking in alpha blended models)
        picked_id &= 0x00'FF'FF'FF;

        imgui_state.picked_texture_id.reset();
        for (int i = 0; i < texture_count; i++) {
            if (gl_texture_from_texture_id((TEXID) i) == picked_id) {
                imgui_state.picked_texture_id = (TEXID) i;
                break;
            }
        }
    }

    end_texture_replacement();
}

static WNDPROC WndProcOrig;

LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT CALLBACK WndProc(HWND wnd, UINT code, WPARAM wparam, LPARAM lparam) {
    if (ImGui_ImplWin32_WndProcHandler(wnd, code, wparam, lparam))
        return 1;

    return WndProcOrig(wnd, code, wparam, lparam);
}

// Some toolchains' synchapi.h predates the high-resolution timer flag.
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

// Caps the present rate to target_fps (0 = unlimited). Sleeps the bulk of the
// frame on a high-resolution waitable timer (Win10 1803+), then busy-waits a
// short tail for sub-millisecond precision. The timer falls back to a coarse
// sleep on older systems.
static void limit_framerate(int target_fps) {
    using clock = std::chrono::steady_clock;
    static clock::time_point next_frame = clock::now();

    if (target_fps <= 0) {
        next_frame = clock::now();
        return;
    }

    const auto period = std::chrono::duration_cast<clock::duration>(
        std::chrono::duration<double>(1.0 / target_fps));
    next_frame += period;

    const clock::time_point now = clock::now();
    if (next_frame <= now) {
        // Already running at or below the cap: don't accumulate debt.
        next_frame = now;
        return;
    }

    // Resolved at runtime: CreateWaitableTimerExW is absent from the toolchain's
    // headers and missing on pre-Win8 systems, where this stays null and we fall
    // back to a coarse sleep.
    static HANDLE timer = []() -> HANDLE {
        using create_timer_ex_t = HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD);
        auto create_timer_ex = reinterpret_cast<create_timer_ex_t>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateWaitableTimerExW"));
        return create_timer_ex ? create_timer_ex(nullptr, nullptr,
                                                 CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                                 TIMER_ALL_ACCESS)
                               : nullptr;
    }();

    const auto spin_margin = std::chrono::microseconds(500);
    const auto wait = next_frame - now;
    if (wait > spin_margin) {
        const auto coarse = wait - spin_margin;
        if (timer) {
            LARGE_INTEGER due;
            // Relative due time in negative 100ns units.
            due.QuadPart = -static_cast<LONGLONG>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(coarse).count() / 100);
            if (SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE)) {
                WaitForSingleObject(timer, INFINITE);
            }
        } else {
            std::this_thread::sleep_for(coarse);
        }
    }
    while (clock::now() < next_frame) {
        std::this_thread::yield();
    }
}

extern "C" int stdDisplay_Update_Hook() {
    if (swrDisplay_SkipNextFrameUpdate == 1) {
        swrDisplay_SkipNextFrameUpdate = 0;
        return 0;
    }

    begin_texture_replacement();
    imgui_Update();// Added
    end_texture_replacement();

    std::memset(replacedTries, 0, std::size(replacedTries));
    for (auto &[key, value]: additionnalReplacedTries) {
        value = 0;
    }
    glFinish();
    glfwSwapBuffers(glfwGetCurrentContext());

    limit_framerate(imgui_state.target_fps);

    return 0;
}

void noop() {}

// Flush the per-mesh geometry cache when loaded models are cleared (track change) so reused mesh
// pointers can't return stale geometry and the cached GL objects don't leak.
extern "C" void swrModel_ClearLoadedModels_delta(void) {
    for (auto &[mesh, cached]: g_mesh_geometry_cache) {
        if (cached.vbo)
            glDeleteBuffers(1, &cached.vbo);
        if (cached.vao)
            glDeleteVertexArrays(1, &cached.vao);
    }
    g_mesh_geometry_cache.clear();
    cached_model_matrix.clear();
    hook_call_original(swrModel_ClearLoadedModels);
}

extern "C" void init_renderer_hooks() {

    // ========================================
    // Hooks required for renderer replacement
    // ========================================

    // main
    hook_function("WinMain", (uint32_t) WinMain_ADDR, (uint8_t *) WinMain_delta);

    // rdMaterial
    hook_function("rdMaterial_InvertTextureAlphaR4G4B4A4 nooped",
                  (uint32_t) rdMaterial_InvertTextureAlphaR4G4B4A4_ADDR, (uint8_t *) noop);
    hook_function("rdMaterial_InvertTextureColorR4G4B4A4 nooped",
                  (uint32_t) rdMaterial_InvertTextureColorR4G4B4A4_ADDR, (uint8_t *) noop);
    hook_function("rdMaterial_RemoveTextureAlphaR5G5B5A1 nooped",
                  (uint32_t) rdMaterial_RemoveTextureAlphaR5G5B5A1_ADDR, (uint8_t *) noop);
    hook_function("rdMaterial_RemoveTextureAlphaR4G4B4A4 nooped",
                  (uint32_t) rdMaterial_RemoveTextureAlphaR4G4B4A4_ADDR, (uint8_t *) noop);
    hook_function("rdMaterial_SaturateTextureR4G4B4A4",
                  (uint32_t) rdMaterial_SaturateTextureR4G4B4A4_ADDR,
                  (uint8_t *) rdMaterial_SaturateTextureR4G4B4A4_delta);

    // rdMatrix
    hook_function("rdMatrix_Multiply44", (uint32_t) rdMatrix_Multiply44_ADDR,
                  (uint8_t *) rdMatrix_Multiply44_delta);
    hook_function("rdMatrix_Multiply44Acc", (uint32_t) rdMatrix_Multiply44Acc_ADDR,
                  (uint8_t *) rdMatrix_Multiply44Acc_delta);
    hook_function("rdMatrix_Multiply3", (uint32_t) rdMatrix_Multiply3_ADDR,
                  (uint8_t *) rdMatrix_Multiply3_delta);
    hook_function("rdMatrix_Transform3", (uint32_t) rdMatrix_Transform3_ADDR,
                  (uint8_t *) rdMatrix_Transform3_delta);
    hook_function("rdMatrix_Multiply4", (uint32_t) rdMatrix_Multiply4_ADDR,
                  (uint8_t *) rdMatrix_Multiply4_delta);
    hook_function("rdMatrix_ScaleBasis44", (uint32_t) rdMatrix_ScaleBasis44_ADDR,
                  (uint8_t *) rdMatrix_ScaleBasis44_delta);

    hook_function("rdMatrix_TransformPoint44", (uint32_t) rdMatrix_TransformPoint44_ADDR,
                  (uint8_t *) rdMatrix_TransformPoint44_delta);

    hook_function("rdMatrix_Multiply34", (uint32_t) rdMatrix_Multiply34_ADDR,
                  (uint8_t *) rdMatrix_Multiply34_delta);
    hook_function("rdMatrix_PreMultiply34", (uint32_t) rdMatrix_PreMultiply34_ADDR,
                  (uint8_t *) rdMatrix_PreMultiply34_delta);
    hook_function("rdMatrix_PostMultiply34", (uint32_t) rdMatrix_PostMultiply34_ADDR,
                  (uint8_t *) rdMatrix_PostMultiply34_delta);
    hook_function("rdMatrix_TransformVector34", (uint32_t) rdMatrix_TransformVector34_ADDR,
                  (uint8_t *) rdMatrix_TransformVector34_delta);
    hook_function("rdMatrix_TransformPoint34", (uint32_t) rdMatrix_TransformPoint34_ADDR,
                  (uint8_t *) rdMatrix_TransformPoint34_delta);

    // std3D
    hook_function("std3D_Startup", (uint32_t) 0x00489dc0, (uint8_t *) std3D_Startup_delta);
    hook_function("std3D_Open", (uint32_t) 0x00489ec0, (uint8_t *) std3D_Open_delta);
    hook_function("std3D_StartScene", (uint32_t) 0x0048a300, (uint8_t *) std3D_StartScene_delta);
    hook_function("std3D_EndScene", (uint32_t) 0x0048a330, (uint8_t *) std3D_EndScene_delta);
    hook_function("std3D_DrawRenderList", (uint32_t) 0x0048a350,
                  (uint8_t *) std3D_DrawRenderList_delta);
    hook_function("std3D_SetRenderState", (uint32_t) 0x0048a450,
                  (uint8_t *) std3D_SetRenderState_delta);
    hook_function("std3D_AllocSystemTexture", (uint32_t) 0x0048a5e0,
                  (uint8_t *) std3D_AllocSystemTexture_delta);
    hook_function("std3D_ClearTexture", (uint32_t) 0x0048aa40,
                  (uint8_t *) std3D_ClearTexture_delta);
    hook_function("std3D_AddToTextureCache", (uint32_t) 0x0048aa80,
                  (uint8_t *) std3D_AddToTextureCache_delta);
    hook_function("std3D_ClearCacheList", (uint32_t) 0x0048ac50,
                  (uint8_t *) std3D_ClearCacheList_delta);
    hook_function("std3D_SetTexFilterMode", (uint32_t) 0x0048b1b0,
                  (uint8_t *) std3D_SetTexFilterMode_delta);
    hook_function("std3D_SetProjection", (uint32_t) 0x0048b260,
                  (uint8_t *) std3D_SetProjection_delta);
    hook_function("std3D_AddTextureToCacheList", (uint32_t) 0x0048ba20,
                  (uint8_t *) std3D_AddTextureToCacheList_delta);
    hook_function("std3D_RemoveTextureFromCacheList", (uint32_t) 0x0048ba90,
                  (uint8_t *) std3D_RemoveTextureFromCacheList_delta);
    hook_function("std3D_PurgeTextureCache", (uint32_t) 0x0048bb50,
                  (uint8_t *) std3D_PurgeTextureCache_delta);

    // stdControl: enumerate only game device classes so a non-game HID device
    // (e.g. some USB headsets) can't crash DirectInput startup on launch.
    hook_function("stdControl_Startup", (uint32_t) 0x00485360,
                  (uint8_t *) stdControl_Startup_delta);
#if ENABLE_GLFW_INPUT_HANDLING
    hook_function("stdControl_ReadControls", (uint32_t) 0x00485630,
                  (uint8_t *) stdControl_ReadControls_delta);
    hook_function("stdControl_SetActivation", (uint32_t) 0x00485a30,
                  (uint8_t *) stdControl_SetActivation_delta);
#endif

    // swrDisplay
    hook_function("swrDisplay_SetWindowSize", (uint32_t) 0x004238a0,
                  (uint8_t *) swrDisplay_SetWindowSize_delta);

    // DirectDraw
    hook_function("DirectDraw_InitProgressBar", (uint32_t) 0x00408510,
                  (uint8_t *) DirectDraw_InitProgressBar_delta);
    hook_function("DirectDraw_Shutdown", (uint32_t) 0x00408620,
                  (uint8_t *) DirectDraw_Shutdown_delta);
    hook_function("swrUI_UpdateProgressBar", (uint32_t) swrUI_UpdateProgressBar_ADDR,
                  (uint8_t *) swrUI_UpdateProgressBar_delta);
    hook_function("DirectDraw_LockZBuffer", (uint32_t) 0x00431C40,
                  (uint8_t *) DirectDraw_LockZBuffer_delta);
    hook_function("DirectDraw_UnlockZBuffer", (uint32_t) 0x00431cd0,
                  (uint8_t *) DirectDraw_UnlockZBuffer_delta);
    hook_function("Direct3d_SetFogMode", (uint32_t) 0x0048a140,
                  (uint8_t *) Direct3d_SetFogMode_delta);
    hook_function("Direct3d_IsLensflareCompatible", (uint32_t) 0x0048a1a0,
                  (uint8_t *) Direct3d_IsLensflareCompatible_delta);
    hook_function("Direct3d_ConfigFog", (uint32_t) 0x0048b340,
                  (uint8_t *) Direct3d_ConfigFog_delta);

    // stdConsole
    hook_function("stdConsole_GetCursorPos", (uint32_t) 0x004082e0,
                  (uint8_t *) stdConsole_GetCursorPos_delta);
    hook_function("stdConsole_SetCursorPos", (uint32_t) 0x00408360,
                  (uint8_t *) stdConsole_SetCursorPos_delta);

    // stdDisplay
    hook_function("stdDisplay_Startup", (uint32_t) 0x00487d20,
                  (uint8_t *) stdDisplay_Startup_delta);
    hook_function("stdDisplay_Open", (uint32_t) 0x00487e00, (uint8_t *) stdDisplay_Open_delta);
    hook_function("stdDisplay_Close", (uint32_t) 0x00487e80, (uint8_t *) stdDisplay_Close_delta);
    hook_function("stdDisplay_SetMode", (uint32_t) 0x00487f00,
                  (uint8_t *) stdDisplay_SetMode_delta);
    hook_function("stdDisplay_Refresh", (uint32_t) 0x00488100,
                  (uint8_t *) stdDisplay_Refresh_delta);
    hook_function("stdDisplay_VBufferNew", (uint32_t) 0x004881c0,
                  (uint8_t *) stdDisplay_VBufferNew_delta);
    hook_function("stdDisplay_VBufferFill", (uint32_t) 0x00488410,
                  (uint8_t *) stdDisplay_VBufferFill_delta);
    hook_function("stdDisplay_SetWindowMode", (uint32_t) 0x00489270,
                  (uint8_t *) stdDisplay_SetWindowMode_delta);
    hook_function("stdDisplay_SetFullscreenMode", (uint32_t) 0x00489790,
                  (uint8_t *) stdDisplay_SetFullscreenMode_delta);

    hook_function("stdDisplay_Update", (uint32_t) 0x00489ab0, (uint8_t *) stdDisplay_Update_Hook);

    hook_function("stdDisplay_FillMainSurface", (uint32_t) 0x00489bc0,
                  (uint8_t *) stdDisplay_FillMainSurface_delta);
    hook_function("stdDisplay_ColorFillSurface", (uint32_t) 0x00489bd0,
                  (uint8_t *) stdDisplay_ColorFillSurface_delta);

    // swrViewport
    hook_function("swrViewport_Render", (uint32_t) swrViewport_Render, (uint8_t *) 0x00483A90);
    hook_replace(swrViewport_Render, swrViewport_Render_Hook);

    // swrModel
    hook_function("swrModel_LoadFonts", (uint32_t) 0x0042d720,
                  (uint8_t *) swrModel_LoadFonts_delta);

    hook_function("swrModel_LoadFromId", (uint32_t) swrModel_LoadFromId, (uint8_t *) 0x00448780);
    hook_replace(swrModel_LoadFromId, swrModel_LoadFromId_delta);

    hook_function("swrModel_InitializeTextureBuffer", (uint32_t) swrModel_InitializeTextureBuffer,
                  (uint8_t *) 0x00447420);
    hook_replace(swrModel_InitializeTextureBuffer, swrModel_InitializeTextureBuffer_delta);

    // Window
    hook_function("Window_SetActivated", (uint32_t) Window_SetActivated_ADDR,
                  (uint8_t *) Window_SetActivated_delta);
    hook_function("Window_Resize", (uint32_t) Window_Resize_ADDR, (uint8_t *) Window_Resize_delta);
    hook_function("Window_SmushPlayCallback", (uint32_t) Window_SmushPlayCallback_ADDR,
                  (uint8_t *) Window_SmushPlayCallback_delta);
    hook_function("Window_Main", (uint32_t) Window_Main_ADDR, (uint8_t *) Window_Main_delta);
    hook_function("Window_CreateMainWindow", (uint32_t) Window_CreateMainWindow_ADDR,
                  (uint8_t *) Window_CreateMainWindow_delta);

    // ========================================
    // Hooks required for custom tracks
    // ========================================

    // fileOpen
    // fileRead
    // fileClose

    hook_function("swrUI_Front_HandleCircuits", (uint32_t) swrUI_Front_HandleCircuits_ADDR,
                  (uint8_t *) HandleCircuits_delta);
    hook_function("isTrackPlayable", (uint32_t) isTrackPlayable_ADDR,
                  (uint8_t *) isTrackPlayable_delta);
    hook_function("VerifySelectedTrack", (uint32_t) VerifySelectedTrack_ADDR,
                  (uint8_t *) VerifySelectedTrack_delta);

    hook_function("swrUI_Front_GetTrackNameFromId", (uint32_t) swrUI_Front_GetTrackNameFromId_ADDR,
                  (uint8_t *) swrUI_GetTrackNameFromId_delta);

    hook_function("swrObjHang_InitTrackSprites", (uint32_t) swrObjHang_InitTrackSprites_ADDR,
                  (uint8_t *) swrObjHang_InitTrackSprites_delta);
    hook_function("swrObjJdge_InitTrack", (uint32_t) swrObjJdge_InitTrack,
                  (uint8_t *) swrObjJdge_InitTrack_ADDR);
    hook_replace(swrObjJdge_InitTrack, swrObjJdge_InitTrack_delta);

    // Flush the per-mesh geometry cache when loaded models are cleared (track change).
    hook_function("swrModel_ClearLoadedModels", (uint32_t) swrModel_ClearLoadedModels,
                  (uint8_t *) swrModel_ClearLoadedModels_ADDR);
    hook_replace(swrModel_ClearLoadedModels, swrModel_ClearLoadedModels_delta);

    // Multiplayer netcode stability: async DirectPlay sends (no game-thread stall under packet
    // loss) + a per-pump incoming-packet cap. See swrMultiplayer_delta.cpp.
    hook_function("sithMulti_HandleIncomingPacket", (uint32_t) sithMulti_HandleIncomingPacket,
                  (uint8_t *) sithMulti_HandleIncomingPacket_ADDR);
    hook_replace(sithMulti_HandleIncomingPacket, sithMulti_HandleIncomingPacket_delta);
    hook_function("stdComm_Send", (uint32_t) stdComm_Send, (uint8_t *) stdComm_Send_ADDR);
    hook_replace(stdComm_Send, stdComm_Send_delta);

    // Multiplayer fix: restore racer-selection input after a race (both host and clients).
    hook_function("swrObjHang_F0", (uint32_t) swrObjHang_F0, (uint8_t *) swrObjHang_F0_ADDR);
    hook_replace(swrObjHang_F0, swrObjHang_F0_delta);

    // Multiplayer: draw player names above pods instead of the position number. The wrapper on
    // swrPlayerHUD_RenderDistanceText (hooked by address; not reimplemented) reuses the game's own
    // projection/occlusion/fade and only redirects the text it draws -- via swrText_CreateTextEntry2
    // -- to the racer's name. Single-player is untouched (redirect only when multiplayer_enabled).
    hook_function("swrPlayerHUD_RenderDistanceText", (uint32_t) swrPlayerHUD_RenderDistanceText_ADDR,
                  (uint8_t *) swrPlayerHUD_RenderDistanceText_delta);
    // swrText_CreateTextEntry2 is reimplemented (already registered in hook_generated.c), so a plain
    // hook_replace overrides it -- same as the other reimplemented-function deltas above.
    hook_replace(swrText_CreateTextEntry2, swrText_CreateTextEntry2_delta);
    // Clear the "~F" half-scale flag after the text batch so the minimap text the half-size player
    // labels would otherwise leave shrunk renders at full size.
    hook_function("swrText_RenderEntries1", (uint32_t) swrText_RenderEntries1_ADDR,
                  (uint8_t *) swrText_RenderEntries1_delta);

    // Record each pod's cable-curve state per frame so the GL walk can bend the cables
    // (the game's cable deformer only touches the rd3d mesh the replacement doesn't use).
    hook_function("swrRace_PoddAnimateVariousThings",
                  (uint32_t) swrRace_PoddAnimateVariousThings,
                  (uint8_t *) swrRace_PoddAnimateVariousThings_ADDR);
    hook_replace(swrRace_PoddAnimateVariousThings, swrRace_PoddAnimateVariousThings_delta);

    // Display-pod animator (hangar inspect / selection menu / cutscenes) - register its cables too.
    hook_function("swrRace_AnimateDisplayPod", (uint32_t) swrRace_AnimateDisplayPod_ADDR,
                  (uint8_t *) swrRace_AnimateDisplayPod_delta);

    // 100-lap support: de-index swrObjJdge_F2's fixed 5-slot per-lap split-time array so lap
    // counts above 5 no longer corrupt the score struct (the real hardcoded 5-lap limit). The
    // hangar menu cap was also raised to 100 in tracks_delta.c.
    swrObjJdge_PatchLapTimeOverflow();

    // High-res weather (Layer 2): patch swrViewport_ProjectToScreen's -1000.0f off-screen sentinel
    // to -INF so the weather particle pool keeps despawning/respawning at screen_width >= 1000.
    // Without this, rain/snow renders for one cycle then vanishes on modern displays. See
    // swrWeather_delta.h / the KNOWN ISSUES block in src/Swr/swrWeather.h.
    swrWeather_PatchHiResParticleSentinel();

    // High-res weather (Layer 3-A): snow/rain vanish the moment the pod moves because at high
    // resolution any camera motion pushes each particle's per-frame screen movement past the
    // absolute 3-px streak threshold, flipping it to the streak path (sprite flag 0x4000) -- which
    // the PC port stubbed (swr_noop2), so it draws nothing. Instead of forcing the point path
    // (swrWeather_PatchForcePointParticles), reimplement the cut motion-blur streak: hook
    // swrSprite_Draw2 and draw a quad from each streaking particle's head to its stored tail.
    hook_function("swrSprite_Draw2", (uint32_t) swrSprite_Draw2_ADDR,
                  (uint8_t *) swrSprite_Draw2_delta);

    // Graceful weather transitions: on a SNW->NSNW boundary, stop the spawner and let the existing
    // particles fall out naturally instead of instantly clearing/hiding all weather. Enable/Disable
    // just flip the spawner; RenderParticles keeps the live particles updating until the pool drains.
    hook_function("swrWeather_Enable", (uint32_t) swrWeather_Enable_ADDR,
                  (uint8_t *) swrWeather_Enable_delta);
    hook_function("swrWeather_Disable", (uint32_t) swrWeather_Disable_ADDR,
                  (uint8_t *) swrWeather_Disable_delta);
    hook_function("swrWeather_RenderParticles", (uint32_t) swrWeather_RenderParticles_ADDR,
                  (uint8_t *) swrWeather_RenderParticles_delta);

    // 5+ laps in multiplayer: the MP lobby's host lap stepper was the only thing still capping the
    // count at 5 (the race itself shares the crash-safe single-player path above). Give it free-play
    // parity -- fine +/-1 to 5, then jump-by-5, wrapping at 1/125. Hooked by address (the handler is
    // not reimplemented), so the delta calls the original back through swrUI_Menu_MpRaceSetup_ADDR.
    hook_function("swrUI_Menu_MpRaceSetup", (uint32_t) swrUI_Menu_MpRaceSetup_ADDR,
                  (uint8_t *) swrUI_Menu_MpRaceSetup_delta);

    // 1hr+ race-time support: raise the 50:00 race-time clamp so the timer can show past one hour,
    // and replace the time formatters with hour-aware versions (H:MM:SS.frac).
    swrObjJdge_PatchRaceTimeCap();
    hook_function("swrText_CreateTimeEntry", (uint32_t) swrText_CreateTimeEntry,
                  (uint8_t *) swrText_CreateTimeEntry_ADDR);
    hook_replace(swrText_CreateTimeEntry, swrText_CreateTimeEntry_delta);
    hook_function("swrText_CreateTimeEntryPrecise", (uint32_t) swrText_CreateTimeEntryPrecise,
                  (uint8_t *) swrText_CreateTimeEntryPrecise_ADDR);
    hook_replace(swrText_CreateTimeEntryPrecise, swrText_CreateTimeEntryPrecise_delta);

    // 100-lap support: wrap swrObjJdge_F2 to reconstruct per-lap times (best/worst/average) and
    // replace the on-track per-lap results list with a summary that fits any lap count.
    hook_function("swrObjJdge_F2", (uint32_t) swrObjJdge_F2, (uint8_t *) swrObjJdge_F2_ADDR);
    hook_replace(swrObjJdge_F2, swrObjJdge_F2_delta);
    hook_function("swrRace_InRaceEndStatistics", (uint32_t) swrRace_InRaceEndStatistics,
                  (uint8_t *) swrRace_InRaceEndStatistics_ADDR);
    hook_replace(swrRace_InRaceEndStatistics, swrRace_InRaceEndStatistics_delta);

    // 1hr+ race-time support follow-up: re-assign finishing positions finished-first so a finished
    // racer always places above a still-racing one even past the old 50:00 ceiling (the vanilla
    // 10000-total_time rank key goes negative once a race passes ~2h46m). See swrObjJdge_delta.cpp.
    hook_function("swrObjJdge_UpdateStandings", (uint32_t) swrObjJdge_UpdateStandings_ADDR,
                  (uint8_t *) swrObjJdge_UpdateStandings_delta);

    hook_function("swrRace_CourseSelectionMenu", (uint32_t) swrRace_CourseSelectionMenu_ADDR,
                  (uint8_t *) swrRace_CourseSelectionMenu_delta);
    hook_function("swrRace_CourseInfoMenu", (uint32_t) swrRace_CourseInfoMenu_ADDR,
                  (uint8_t *) swrRace_CourseInfoMenu_delta);
    hook_function("swrRace_MainMenu", (uint32_t) swrRace_MainMenu_ADDR,
                  (uint8_t *) swrRace_MainMenu_delta);
    hook_function("DrawTracks", (uint32_t) DrawTracks_ADDR, (uint8_t *) DrawTracks_delta);

    // swrModel_LoadFromId is already hooked for model replacement
    hook_function("swrSpline_LoadSplineById", (uint32_t) swrSpline_LoadSplineById,
                  (uint8_t *) swrSpline_LoadSplineById_ADDR);
    hook_replace(swrSpline_LoadSplineById, swrSpline_LoadSplineById_delta);

    fprintf(hook_log, "Done\n");
    fflush(hook_log);
}
