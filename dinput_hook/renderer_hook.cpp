//
// Created by tly on 10.03.2024.
//
#include "renderer_hook.h"
#include "hook_helper.h"

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <glad/glad.h>

#include <cmath>
#include <mutex>
#include <functional>
#include <thread>
#include <vector>
#include <condition_variable>
#include <globals.h>
#include <imgui.h>
#include <optional>
#include <set>
#include <future>
#include <format>

extern "C"
{
#include <Primitives/rdMatrix.h>
#include <Raster/rdCache.h>
#include <Platform/std3D.h>
}

std::mutex renderer_tasks_mutex;
std::vector<std::function<void()>> renderer_tasks;
std::condition_variable renderer_flush_cvar;
bool rendered_anything = false;

template <typename F>
void run_on_gl_thread(F&& f)
{
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

GLuint program;
GLuint rdflags_pos;
GLuint proj_pos;
GLuint near_plane_pos;
GLuint uv_offset_pos;

std::set<Std3DRenderState> render_states;
std::set<Std3DRenderState> banned_render_states;

std::map<tSystemTexture*, GLuint> textures;

void compileAndEnableShader()
{
    const char* vertex_shader_source = R"(
#version 330 core
layout(location = 0) in vec3 position;
layout(location = 1) in vec4 color;
layout(location = 2) in vec2 uv;

out vec4 passColor;
out vec2 passUV;

uniform float nearPlane;
uniform mat4 projectionMatrix;
uniform vec2 uvOffset;

void main() {
    // the game uses a weird projection method, im not sure how to put that into matrix form.
    vec4 xyzw = vec4(position.x * position.z, position.y * position.z, position.z - nearPlane, position.z);
    gl_Position = projectionMatrix *  xyzw;
    passColor = color;
    passUV = uv + uvOffset;
}
)";

    const char* fragment_shader_source = R"(
#version 330 core
in vec4 passColor;
in vec2 passUV;

uniform sampler2D diffuseTex;
uniform uint rdFlags;

out vec4 color;
void main() {
    color = vec4(passColor.xyz, 1);
    if ((rdFlags & 0x400u) != 0u) {
        color *= texture(diffuseTex, passUV);
    }
    if ((rdFlags & 0x200u) != 0u) {
        color.w *= passColor.w;
    }
    if (color.w == 0)
        discard;
}
)";

    program = glCreateProgram();

    GLuint vertex_shader = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(vertex_shader, 1, &vertex_shader_source, nullptr);
    glCompileShader(vertex_shader);
    GLint status = 0;
    glGetShaderiv(vertex_shader, GL_COMPILE_STATUS, &status);
    if (status != GL_TRUE)
        std::abort();

    GLuint fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(fragment_shader, 1, &fragment_shader_source, nullptr);
    glCompileShader(fragment_shader);
    glGetShaderiv(fragment_shader, GL_COMPILE_STATUS, &status);
    if (status != GL_TRUE)
        std::abort();

    glAttachShader(program, vertex_shader);
    glAttachShader(program, fragment_shader);
    glLinkProgram(program);

    glGetProgramiv(program, GL_LINK_STATUS, &status);
    if (status != GL_TRUE)
        std::abort();

    glUseProgram(program);

    rdflags_pos = glGetUniformLocation(program, "rdFlags");
    proj_pos = glGetUniformLocation(program, "projectionMatrix");
    near_plane_pos = glGetUniformLocation(program, "nearPlane");
    uv_offset_pos = glGetUniformLocation(program, "uvOffset");
}

int GL_renderState = 0;

void GL_SetRenderState(Std3DRenderState rdflags)
{
    glUniform1ui(rdflags_pos, rdflags);

    if (rdflags & (STD3D_RS_UNKNOWN_200 | STD3D_RS_UNKNOWN_400))
    {
        glEnable(GL_BLEND);
    }
    else
    {
        glDisable(GL_BLEND);
    }

    glDepthMask((rdflags & STD3D_RS_ZWRITE_DISABLED) == 0);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, rdflags & STD3D_RS_TEX_CPAMP_U ? GL_CLAMP_TO_EDGE : GL_REPEAT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, rdflags & STD3D_RS_TEX_CPAMP_V ? GL_CLAMP_TO_EDGE : GL_REPEAT);

    GL_renderState = rdflags;
}

extern "C" FILE* hook_log;

void std3D_ClearTexture_Hook(tSystemTexture* pTexture)
{
    run_on_gl_thread([&] {
        auto& gl_tex = textures.at(pTexture);
        glDeleteTextures(1, &gl_tex);
        textures.erase(pTexture);
    });
    hook_call_original(std3D_ClearTexture, pTexture);
}

GLuint GL_LoadTexture(tSystemTexture* pTexture)
{
    fprintf(hook_log, "GL_LoadTexture(%p)\n", pTexture);
    fflush(hook_log);

    GLuint gl_tex = 0;
    glGenTextures(1, &gl_tex);

    LPDIRECTDRAWSURFACE4 lpDD = nullptr;
    if (pTexture->pD3DSrcTexture->QueryInterface(IID_IDirectDrawSurface4, (void**)&lpDD) != S_OK)
        std::abort();

    DDSURFACEDESC2 surfDesc{};
    surfDesc.dwSize = sizeof(DDSURFACEDESC2);
    if (lpDD->Lock(nullptr, &surfDesc, DDLOCK_WAIT | DDLOCK_READONLY, nullptr) != S_OK)
        std::abort();

    GLenum format = GL_BGRA;
    GLenum type = GL_UNSIGNED_SHORT_4_4_4_4;
    const GLenum internal_format = GL_RGBA8;

    const auto& pf = surfDesc.ddpfPixelFormat;
    const auto r = pf.dwRBitMask;
    const auto g = pf.dwGBitMask;
    const auto b = pf.dwBBitMask;
    const auto a = pf.dwRGBAlphaBitMask;
    if (r == 0xf800 && g == 0x7e0 && b == 0x1f)
    {
        format = GL_RGB;
        type = GL_UNSIGNED_SHORT_5_6_5;
    }
    else if (a == 0x8000 && r == 0x7c00 && g == 0x3e0 && b == 0x1f)
    {
        format = GL_BGRA;
        type = GL_UNSIGNED_SHORT_1_5_5_5_REV;
    }
    else if (a == 0xF000 && r == 0x0F00 && g == 0x00F0 && b == 0x000F)
    {
        format = GL_BGRA;
        type = GL_UNSIGNED_SHORT_4_4_4_4_REV;
    }
    else
    {
        std::abort();
    }

    glBindTexture(GL_TEXTURE_2D, gl_tex);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, internal_format, surfDesc.dwWidth, surfDesc.dwHeight, 0, format, type, surfDesc.lpSurface);
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

void std3D_AllocSystemTexture_Hook(tSystemTexture* pTexture, tVBuffer** apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType)
{
    hook_call_original(std3D_AllocSystemTexture, pTexture, apVBuffers, numMipLevels, formatType);

    tVBuffer* t = apVBuffers[0];
    const auto& c = t->rasterInfo.colorInfo;
    fprintf(hook_log, "texture: %p width=%d height=%d size=%d flags=0x%x r=%d g=%d b=%d a=%d format=%d loaded=%d\n", pTexture, t->rasterInfo.width, t->rasterInfo.height, t->rasterInfo.size, pTexture->ddsd.ddpfPixelFormat.dwFlags, c.redBPP, c.greenBPP, c.blueBPP, c.alphaBPP, formatType, textures.contains(pTexture));
    fflush(hook_log);

    textures.emplace(pTexture, 0);
}

void rdCache_SendFaceListToHardware_Hook(size_t numPolys, RdCacheProcEntry* aPolys)
{
    hook_call_original(rdCache_SendFaceListToHardware, numPolys, aPolys);

    run_on_gl_thread([&] {
        float w = 1280;
        float h = 720;
        rdMatrix44 proj_mat{
            { 2.0f / w, 0, 0, 0 },
            { 0, 2.0f / h, 0, 0 },
            { 0, 0, 1, 0 },
            { -1 + 1.0f / w, -1 + 1.0f / h, 0, 1 },
        };
        glUniformMatrix4fv(proj_pos, 1, GL_FALSE, &proj_mat.vA.x);
        glUniform1f(near_plane_pos, rdCamera_pCurCamera->pClipFrustum->zNear);

        glEnableVertexAttribArray(0);
        glEnableVertexAttribArray(1);
        glEnableVertexAttribArray(2);

        glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, sizeof(rdVector3), rdCache_aVertices);
        glVertexAttribPointer(1, 4, GL_FLOAT, GL_FALSE, sizeof(rdVector4), rdCache_aVertIntensities);
        glVertexAttribPointer(2, 2, GL_FLOAT, GL_FALSE, sizeof(rdVector2), rdCache_aTexVertices);

        int prev_rdflags = 0;
        GLuint prev_texture = 0;

        GL_SetRenderState((Std3DRenderState)0);
        glBindTexture(GL_TEXTURE_2D, 0);

        for (int i = 0; i < numPolys; i++)
        {
            auto& entry = aPolys[i];
            rendered_anything = true;

            int rdflags = STD3D_RS_UNKNOWN_10 | STD3D_RS_UNKNOWN_2 | STD3D_RS_UNKNOWN_1;
            if (entry.flags & RD_FF_TEX_TRANSLUCENT)
                rdflags |= STD3D_RS_UNKNOWN_200;
            if (entry.flags & RD_FF_TEX_CLAMP_X)
                rdflags |= STD3D_RS_TEX_CPAMP_U;
            if (entry.flags & RD_FF_TEX_CLAMP_Y)
                rdflags |= STD3D_RS_TEX_CPAMP_V;
            if (!(entry.flags & STD3D_RS_UNKNOWN_10))
                rdflags |= STD3D_RS_TEX_MAGFILTER_LINEAR;
            if (entry.flags & 0x20)
                rdflags |= STD3D_RS_ZWRITE_DISABLED;
            if (entry.flags & RD_FF_FOG_ENABLED)
                rdflags |= STD3D_RS_FOG_ENABLED;
            if (entry.pMaterial && entry.pMaterial->width)
                rdflags |= STD3D_RS_UNKNOWN_400;

            GLuint tex = 0;
            if (entry.pMaterial)
            {
                auto& gl_texture = textures.emplace(entry.pMaterial->aTextures, 0).first->second;
                if (gl_texture == 0)
                    gl_texture = GL_LoadTexture(entry.pMaterial->aTextures);

                tex = gl_texture;
            }
            else
            {
                tex = 0;
            }

            if (prev_texture != tex)
                glBindTexture(GL_TEXTURE_2D, tex);
            if (prev_rdflags != rdflags || prev_texture != tex)
            {
                // render state also sets texture clamp parameters, this is why its also called if the texture changed.
                GL_SetRenderState(static_cast<Std3DRenderState>(rdflags));
            }

            glUniform2f(uv_offset_pos, entry.uv_offset.x, entry.uv_offset.y);
            glDrawArrays(GL_TRIANGLE_FAN, entry.aVertices - rdCache_aVertices, entry.numVertices);

            prev_texture = tex;
            prev_rdflags = rdflags;
        }

        glDisableVertexAttribArray(0);
        glDisableVertexAttribArray(1);
        glDisableVertexAttribArray(2);
    });
}

void init_renderer_hooks()
{
    hook_replace(rdCache_SendFaceListToHardware, rdCache_SendFaceListToHardware_Hook);
    hook_replace(std3D_ClearTexture, std3D_ClearTexture_Hook);
    hook_replace(std3D_AllocSystemTexture, std3D_AllocSystemTexture_Hook);

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

        compileAndEnableShader();

        while (true)
        {
            std::vector<std::function<void()>> renderer_tasks_;
            {
                std::unique_lock lock(renderer_tasks_mutex);
                renderer_flush_cvar.wait_for(lock, std::chrono::milliseconds(100), [] { return !renderer_tasks.empty(); });
                renderer_tasks_ = std::move(renderer_tasks);
                renderer_tasks.clear();
            }

            for (const auto& task : renderer_tasks_)
                task();
        }
    }).detach();
}

void opengl_render_imgui()
{
    /*ImGui::Text("banned render states:");
    for (const auto& state : render_states)
    {
        std::string s = "";
        for (int i = 0; i < 32; i++)
        {
            if (state & (1 << i))
            {
                if (!s.empty())
                    s += "|";

                s += std::format("0x{:x}", (1 << i));
            }
        }
        bool ban = banned_render_states.contains(state);
        ImGui::Checkbox(s.c_str(), &ban);
        if (ban)
        {
            banned_render_states.insert(state);
        }
        else
        {
            banned_render_states.erase(state);
        }
    }*/
}

void opengl_renderer_flush(bool blit)
{
    if (!rendered_anything)
        return;

    rendered_anything = false;

    if (blit)
    {
        IDirectDrawSurface4* surf = (IDirectDrawSurface4*)stdDisplay_g_backBuffer.ddraw_surface;
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
        GL_SetRenderState((Std3DRenderState)0);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    });
}