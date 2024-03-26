//
// Created by tly on 10.03.2024.
//
#include "renderer_hook.h"
#include "hook_helper.h"

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <glad/glad.h>

#include "n64_shader.h"
#include <cmath>
#include <condition_variable>
#include <format>
#include <functional>
#include <future>
#include <globals.h>
#include <imgui.h>
#include <macros.h>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <types_model.h>
#include <vector>

extern "C" {
#include <Platform/std3D.h>
#include <Primitives/rdMatrix.h>
#include <Raster/rdCache.h>
#include <Swr/swrModel.h>
#include <swr.h>
}

std::mutex renderer_tasks_mutex;
std::vector<std::function<void()>> renderer_tasks;
std::condition_variable renderer_flush_cvar;
bool rendered_anything = false;

template<typename F>
void run_on_gl_thread(F &&f) {
    std::promise<void> promise;
    std::future<void> future = promise.get_future();
    {
        std::lock_guard lock(renderer_tasks_mutex);
        renderer_tasks.push_back([&] {
            f();
            promise.set_value();
        });
        renderer_flush_cvar.notify_one();
    }

    future.get();
}

struct MaterialMember {
    const char *name;
    uint32_t (*getter)(const swrModel_MeshMaterial &);
    std::map<uint32_t, int> count;
    std::set<uint32_t> banned;
} node_material_members[]{
    {
        "type",
        [](const swrModel_MeshMaterial &m) { return m.type; },
    },
    {
        "unk1",
        [](const swrModel_MeshMaterial &m) { return m.material->unk1; },
    },
    {
        "unk2",
        [](const swrModel_MeshMaterial &m) { return (uint32_t) m.material->unk2; },
    },
    {
        "unk5",
        [](const swrModel_MeshMaterial &m) { return (uint32_t) m.material->unk5; },
    },
    {
        "unk6",
        [](const swrModel_MeshMaterial &m) { return m.material->render_mode_1; },
    },
    {
        "unk7",
        [](const swrModel_MeshMaterial &m) { return m.material->render_mode_2; },
    },
};

struct NodeMember {
    const char *name;
    uint32_t (*getter)(const swrModel_Node &);
    std::map<uint32_t, int> count;
    std::set<uint32_t> banned;
} node_members[]{
    {
        "flags_4",
        [](const swrModel_Node &m) { return (uint32_t) m.flags_4; },
    },
    {
        "flags_5",
        [](const swrModel_Node &m) { return m.flags_5; },
    },
};


std::map<tSystemTexture *, GLuint> textures;

extern "C" FILE *hook_log;

void std3D_ClearTexture_Hook(tSystemTexture *pTexture) {
    run_on_gl_thread([&] {
        auto &gl_tex = textures.at(pTexture);
        glDeleteTextures(1, &gl_tex);
        textures.erase(pTexture);
    });
    hook_call_original(std3D_ClearTexture, pTexture);
}

GLuint GL_LoadTexture(tSystemTexture *pTexture) {
    fprintf(hook_log, "GL_LoadTexture(%p)\n", pTexture);
    fflush(hook_log);

    GLuint gl_tex = 0;
    glGenTextures(1, &gl_tex);

    LPDIRECTDRAWSURFACE4 lpDD = nullptr;
    if (pTexture->pD3DSrcTexture->QueryInterface(IID_IDirectDrawSurface4, (void **) &lpDD) != S_OK)
        std::abort();

    DDSURFACEDESC2 surfDesc{};
    surfDesc.dwSize = sizeof(DDSURFACEDESC2);
    if (lpDD->Lock(nullptr, &surfDesc, DDLOCK_WAIT | DDLOCK_READONLY, nullptr) != S_OK)
        std::abort();

    GLenum format = GL_BGRA;
    GLenum type = GL_UNSIGNED_SHORT_4_4_4_4;
    const GLenum internal_format = GL_RGBA8;

    const auto &pf = surfDesc.ddpfPixelFormat;
    const auto r = pf.dwRBitMask;
    const auto g = pf.dwGBitMask;
    const auto b = pf.dwBBitMask;
    const auto a = pf.dwRGBAlphaBitMask;
    if (r == 0xf800 && g == 0x7e0 && b == 0x1f) {
        format = GL_RGB;
        type = GL_UNSIGNED_SHORT_5_6_5;
    } else if (a == 0x8000 && r == 0x7c00 && g == 0x3e0 && b == 0x1f) {
        format = GL_BGRA;
        type = GL_UNSIGNED_SHORT_1_5_5_5_REV;
    } else if (a == 0xF000 && r == 0x0F00 && g == 0x00F0 && b == 0x000F) {
        format = GL_BGRA;
        type = GL_UNSIGNED_SHORT_4_4_4_4_REV;
    } else {
        std::abort();
    }

    glBindTexture(GL_TEXTURE_2D, gl_tex);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, internal_format, surfDesc.dwWidth, surfDesc.dwHeight, 0, format,
                 type, surfDesc.lpSurface);
    glGenerateMipmap(GL_TEXTURE_2D);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY, 8);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
    glBindTexture(GL_TEXTURE_2D, 0);

    if (lpDD->Unlock(nullptr) != S_OK)
        std::abort();

    lpDD->Release();

    return gl_tex;
}

void std3D_AllocSystemTexture_Hook(tSystemTexture *pTexture, tVBuffer **apVBuffers,
                                   unsigned int numMipLevels, StdColorFormatType formatType) {
    hook_call_original(std3D_AllocSystemTexture, pTexture, apVBuffers, numMipLevels, formatType);

    tVBuffer *t = apVBuffers[0];
    const auto &c = t->rasterInfo.colorInfo;
    fprintf(hook_log,
            "texture: %p width=%d height=%d size=%d flags=0x%x r=%d g=%d b=%d a=%d format=%d "
            "loaded=%d\n",
            pTexture, t->rasterInfo.width, t->rasterInfo.height, t->rasterInfo.size,
            pTexture->ddsd.ddpfPixelFormat.dwFlags, c.redBPP, c.greenBPP, c.blueBPP, c.alphaBPP,
            formatType, textures.contains(pTexture));
    fflush(hook_log);

    auto &tex = textures.emplace(pTexture, 0).first->second;
    run_on_gl_thread([&] { tex = GL_LoadTexture(pTexture); });
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

std::vector<uint16_t> parse_index_buffer(const swrModel_Mesh *mesh) {
    const Gfx *command = swrModel_MeshGetDisplayList(mesh);
    std::vector<uint16_t> indices;
    uint16_t index_offset = 0;
    while (command->type != 0xdf) {
        switch (command->type) {
            case 0x1:
                index_offset = command->gSPVertex.vertex_offset - mesh->vertices -
                               (int16_t) mesh->vertex_base_offset;
                break;
            case 0x3:
                break;
            case 0x5:
                indices.push_back(command->gSP1Triangle.index0 / 2 + index_offset);
                indices.push_back(command->gSP1Triangle.index1 / 2 + index_offset);
                indices.push_back(command->gSP1Triangle.index2 / 2 + index_offset);
                break;
            case 0x6:
                indices.push_back(command->gSP2Triangles.index0 / 2 + index_offset);
                indices.push_back(command->gSP2Triangles.index1 / 2 + index_offset);
                indices.push_back(command->gSP2Triangles.index2 / 2 + index_offset);

                indices.push_back(command->gSP2Triangles.index3 / 2 + index_offset);
                indices.push_back(command->gSP2Triangles.index4 / 2 + index_offset);
                indices.push_back(command->gSP2Triangles.index5 / 2 + index_offset);
                break;
            default:
                std::abort();
        }
        command++;
    }

    return indices;
}

void debug_render_mesh(const swrModel_Mesh *mesh) {
    const auto &aabb = mesh->aabb;
    // rendered_anything = true;
    // glDrawAABBLines({ aabb[0], aabb[1], aabb[2] }, { aabb[3], aabb[4], aabb[5] });

    if (!mesh->vertices)
        return;

#if 0
    static int counter = 0;
    if (mesh->vertex_base_offset) {
        uintptr_t (*data)[56] = (uintptr_t(*)[56]) mesh->primitive_indices;
        if (data[0] != 0) {
            counter++;
        }
    }

    if (mesh->vertex_base_offset) {
        rdMatrix44 *matrix = *(rdMatrix44 **) ((uintptr_t) mesh->primitive_indices + 52);
        glPushMatrix();
        glLoadIdentity();

        const auto &frustum = rdCamera_pCurCamera->pClipFrustum;

        float f = frustum->zFar;
        float n = frustum->zNear;
        const float t = 1.0f / tan(0.5 * rdCamera_pCurCamera->fov / 180.0 * M_PI);
        int w = 1280;
        int h = 720;
        float a = float(h) / w;
        rdMatrix44 proj_mat{
            {t, 0, 0, 0},
            {0, -t / a, 0, 0},
            {0, 0, -(f + n) / (f - n), -1},
            {0, 0, -2 * f * n / (f - n), 1},
        };
        glLoadMatrixf(&proj_mat.vA.x);
        // glOrtho(-0.5, w - 0.5, -0.5, h - 0.5, -16000, 16000);
        // glOrtho(-1000, 1000, 1000, -1000, -1000, 1000);

        glRotatef(-90.0, 1, 0, 0);

        rdMatrix44 m44{};
        rdMatrix_Copy44_34(&m44, &rdCamera_pCurCamera->view_matrix);
        glMultMatrixf(&m44.vA.x);

        glMultMatrixf(&matrix->vA.x);
    }
#endif

    rendered_anything = true;

    for (auto &member: node_material_members) {
        const uint32_t value = member.getter(*mesh->mesh_material);
        member.count[value]++;
    }

    for (const auto &member: node_material_members) {
        const uint32_t value = member.getter(*mesh->mesh_material);
        if (member.banned.contains(value))
            return;
    }

    const bool vertices_have_normals = mesh->mesh_material->type & 0x11;

    const auto &n64_material = mesh->mesh_material->material;

    const uint32_t render_mode = n64_material->render_mode_1 | n64_material->render_mode_2;
    set_render_mode(render_mode);

    const auto color_cycle1 = CombineMode(n64_material->color_combine_mode_cycle1, false);
    const auto alpha_cycle1 = CombineMode(n64_material->alpha_combine_mode_cycle1, true);
    const auto color_cycle2 = CombineMode(n64_material->color_combine_mode_cycle2, false);
    const auto alpha_cycle2 = CombineMode(n64_material->alpha_combine_mode_cycle2, true);

    std::vector<Vtx> vertices(mesh->vertices, mesh->vertices + mesh->num_vertices);
    for (auto &v: vertices) {
        v.v.x = SWAP16(v.v.x);
        v.v.y = SWAP16(v.v.y);
        v.v.z = SWAP16(v.v.z);
        v.v.u = SWAP16(v.v.u);
        v.v.v = SWAP16(v.v.v);
    }
    float uv_scale_x = 1.0;
    float uv_scale_y = 1.0;
    float uv_offset_x = 0;
    float uv_offset_y = 0;
    if (mesh->mesh_material->material_texture &&
        mesh->mesh_material->material_texture->loaded_material) {
        const auto &tex = mesh->mesh_material->material_texture;
        auto *sys_tex = (tSystemTexture *) tex->loaded_material->textures_alloc;
        auto &gl_tex = textures.emplace(sys_tex, 0).first->second;
        glEnable(GL_TEXTURE_2D);
        glBindTexture(GL_TEXTURE_2D, gl_tex);

        if (tex->specs[0]) {
            uv_scale_x = tex->specs[0]->flags & 0x10'00'00'00 ? 2.0 : 1.0;
            uv_scale_y = tex->specs[0]->flags & 0x01'00'00'00 ? 2.0 : 1.0;
            if ((tex->specs[0]->flags & 0x22'00'00'00) == 0x22'00'00'00) {
                uv_offset_x += 1;
                uv_offset_y += 1;
            }
        }
        uv_offset_x += 1 - (float) mesh->mesh_material->texture_offset[0] / (float) tex->res[0];
        uv_offset_x += 1 - (float) mesh->mesh_material->texture_offset[1] / (float) tex->res[1];
    } else {
        glDisable(GL_TEXTURE_2D);
        glBindTexture(GL_TEXTURE_2D, 0);
    }
    // glPolygonMode(GL_FRONT_AND_BACK, GL_LINE);
    glEnableVertexAttribArray(0);
    glEnableVertexAttribArray(1);
    glEnableVertexAttribArray(2);

    const auto shader = get_or_compile_color_combine_shader(
        {color_cycle1, alpha_cycle1, color_cycle2, alpha_cycle2});
    glUseProgram(shader.handle);

    rdMatrix44 mvp_matrix;
    glGetFloatv(GL_MODELVIEW_MATRIX, &mvp_matrix.vA.x);

    glUniformMatrix4fv(shader.mvp_pos, 1, GL_FALSE, &mvp_matrix.vA.x);
    glUniform2f(shader.uv_offset_pos, uv_offset_x, uv_offset_y);
    glUniform2f(shader.uv_scale_pos, uv_scale_x, uv_scale_y);
    const auto &[r, g, b, a] = n64_material->primitive_color;
    glUniform4f(shader.primitive_color_pos, r / 255.0, g / 255.0, b / 255.0, a / 255.0);

    glVertexAttribPointer(0, 3, GL_SHORT, GL_FALSE, sizeof(Vtx), &vertices[0].v.x);
    if (vertices_have_normals) {
        // TODO: shading not supported... setting the color to white.
        glDisableVertexAttribArray(1);
        glVertexAttrib4f(1, 1, 1, 1, 1);
    } else {
        glVertexAttribPointer(1, 4, GL_UNSIGNED_BYTE, GL_TRUE, sizeof(Vtx), &vertices[0].v.r);
    }
    glVertexAttribPointer(2, 2, GL_SHORT, GL_FALSE, sizeof(Vtx), &vertices[0].v.u);

    const auto indices = parse_index_buffer(mesh);
    glDrawElements(GL_TRIANGLES, indices.size(), GL_UNSIGNED_SHORT, indices.data());

    glDisableVertexAttribArray(0);
    glDisableVertexAttribArray(1);
    glDisableVertexAttribArray(2);

    glUseProgram(0);

#if 0
    if (mesh->vertex_base_offset) {
        glPopMatrix();
    }
#endif
}

void debug_render_node(const swrModel_Node *node, uint32_t flags_1_match,
                       uint32_t flags_1_any_match) {
    if (!node)
        return;

    if ((flags_1_match & node->flags_1) != flags_1_match)
        return;

    if ((flags_1_any_match & node->flags_1) == 0)
        return;

    if (node->flags_0 == 0xD066)
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

    /*if (node->flags_4)
        return;*/

    bool matrix_updated = false;
    if (node->flags_0 == 0xD064 || node->flags_0 == 0xD065) {
        // this node has a transform.
        rdMatrix44 mat{};
        swrModel_NodeGetTransform(node, &mat);
        if (node->flags_0 == 0xD065 && (node->flags_3 & 0x10)) {
            // some kind of pivot point: the translation v is removed from the transform and then added untransformed.
            const rdVector3 v = {
                node->node_d065_data.vector[0],
                node->node_d065_data.vector[1],
                node->node_d065_data.vector[2],
            };
            const rdVector3 v_transformed = {
                mat.vA.x * v.x + mat.vB.x * v.y + mat.vC.x * v.z,
                mat.vA.y * v.x + mat.vB.y * v.y + mat.vC.y * v.z,
                mat.vA.z * v.x + mat.vB.z * v.y + mat.vC.z * v.z,
            };
            mat.vD.x += v.x - v_transformed.x;
            mat.vD.y += v.y - v_transformed.y;
            mat.vD.z += v.z - v_transformed.z;
        }

        glPushMatrix();
        glMultMatrixf(&mat.vA.x);
        matrix_updated = true;
    }

    if (node->flags_0 == 0x3064) {
        for (int i = 0; i < node->num_children; i++)
            debug_render_mesh(node->meshes[i]);
    } else if (node->flags_0 == 0x5066) {
        // find correct lod node
        int i = 1;
        for (; i < 8; i++) {
            if (node->node_5066_data.lods_distances[i] == -1 ||
                node->node_5066_data.lods_distances[i] >= 10)
                break;
        }
        if (i - 1 < node->num_children)
            debug_render_node(node->child_nodes[i - 1], flags_1_match, flags_1_any_match);
    } else {
        for (int i = 0; i < node->num_children; i++)
            debug_render_node(node->child_nodes[i], flags_1_match, flags_1_any_match);
    }

    if (matrix_updated)
        glPopMatrix();
}

void sub_483A90_Hook(int x) {
    fprintf(hook_log, "sub_483A90: %d\n", x);
    fflush(hook_log);

    const auto &unk = swrModel_unk_array[x];
    const swrModel_Node *root_node = (const swrModel_Node *) unk.unk168;
    const uint32_t flags_1_match = unk.unk158;
    const uint32_t flags_1_any_match = unk.unk15c;

    run_on_gl_thread([&] {
        int w = 1280;
        int h = 720;

        GLint id;
        glGetIntegerv(GL_CURRENT_PROGRAM, &id);
        glUseProgram(0);

        glEnable(GL_DEPTH_TEST);
        glEnable(GL_BLEND);

        glMatrixMode(GL_PROJECTION);
        glLoadIdentity();

        glMatrixMode(GL_MODELVIEW);
        glLoadIdentity();

        const auto &frustum = rdCamera_pCurCamera->pClipFrustum;

        float f = frustum->zFar;
        float n = frustum->zNear;
        const float t = 1.0f / tan(0.5 * rdCamera_pCurCamera->fov / 180.0 * M_PI);
        float a = float(h) / w;
        rdMatrix44 proj_mat{
            {t, 0, 0, 0},
            {0, -t / a, 0, 0},
            {0, 0, -(f + n) / (f - n), -1},
            {0, 0, -2 * f * n / (f - n), 1},
        };
        glLoadMatrixf(&proj_mat.vA.x);
        // glOrtho(-0.5, w - 0.5, -0.5, h - 0.5, -16000, 16000);
        // glOrtho(-1000, 1000, 1000, -1000, -1000, 1000);

        glRotatef(-90.0, 1, 0, 0);

        rdMatrix44 m44{};
        rdMatrix_Copy44_34(&m44, &rdCamera_pCurCamera->view_matrix);
        glMultMatrixf(&m44.vA.x);

        debug_render_node(root_node, flags_1_match, flags_1_any_match);

        glUseProgram(id);
    });

    hook_call_original(sub_483A90, x);
}

void init_renderer_hooks() {
    // hook_replace(rdCache_SendFaceListToHardware, rdCache_SendFaceListToHardware_Hook);
    hook_replace(std3D_ClearTexture, std3D_ClearTexture_Hook);
    hook_replace(std3D_AllocSystemTexture, std3D_AllocSystemTexture_Hook);
    hook_replace(sub_483A90, sub_483A90_Hook);

    std::thread([] {
        glfwInit();
        // glfwWindowHint(GLFW_DOUBLEBUFFER, GLFW_FALSE);
        glfwWindowHint(GLFW_VISIBLE, GLFW_FALSE);
        int w = 1280;
        int h = 720;
        auto window = glfwCreateWindow(w, h, "OpenGL renderer", nullptr, nullptr);
        glfwMakeContextCurrent(window);
        gladLoadGLLoader(GLADloadproc(glfwGetProcAddress));

        glEnable(GL_DEPTH_TEST);
        glDepthFunc(GL_LESS);
        glClearDepth(1.0);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        glViewport(0, 0, w, h);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

        while (true) {
            std::vector<std::function<void()>> renderer_tasks_;
            {
                std::unique_lock lock(renderer_tasks_mutex);
                renderer_flush_cvar.wait_for(lock, std::chrono::milliseconds(100),
                                             [] { return !renderer_tasks.empty(); });
                renderer_tasks_ = std::move(renderer_tasks);
                renderer_tasks.clear();
            }

            for (const auto &task: renderer_tasks_)
                task();
        }
    }).detach();
}

void opengl_render_imgui() {
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

    ImGui::Text("node props:");
    for (auto &member: node_members) {
        dump_member(member);
    }

    ImGui::Text("mesh material props:");
    for (auto &member: node_material_members) {
        dump_member(member);
    }

    auto dump_mode = [](const char *name, auto &set) {
        ImGui::Text("%s", name);
        for (const auto &m: set)
            ImGui::Text("    %s", m.c_str());

        set.clear();
    };
}

void opengl_renderer_flush(bool blit) {
    fprintf(hook_log, "opengl_renderer_flush\n");
    fflush(hook_log);

    if (!rendered_anything)
        return;

    rendered_anything = false;

    if (blit) {
        IDirectDrawSurface4 *surf = (IDirectDrawSurface4 *) stdDisplay_g_backBuffer.ddraw_surface;
        DDSURFACEDESC2 desc{};
        desc.dwSize = sizeof(DDSURFACEDESC2);
        if (surf->Lock(nullptr, &desc, DDLOCK_WAIT, nullptr) != S_OK)
            std::abort();

        // the game seems to use 16 bit colors (at least on my end)
        if (desc.ddpfPixelFormat.dwRGBBitCount != 16)
            std::abort();

        run_on_gl_thread([&] {
            // finish frame and copy it
            glFinish();
            glReadPixels(0, 0, 1280, 720, GL_RGB, GL_UNSIGNED_SHORT_5_6_5, desc.lpSurface);
        });

        if (surf->Unlock(nullptr) != S_OK)
            std::abort();
    }

    run_on_gl_thread([] {
        // start a new frame
        glEnable(GL_DEPTH_TEST);
        glDepthMask(GL_TRUE);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    });
}