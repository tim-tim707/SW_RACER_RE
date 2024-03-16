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

std::set<Std3DRenderState> render_states;
std::set<Std3DRenderState> banned_render_states;

struct GLTexture
{
    GLuint texture;
    std::optional<GLuint> alpha_keyed_texture;
};
std::map<tSystemTexture*, GLTexture> textures;

void compileAndEnableShader()
{
    const char* vertex_shader_source = R"(
#version 330 core
layout(location = 0) in vec4 position;
layout(location = 1) in vec4 color;
layout(location = 2) in vec4 specular;
layout(location = 3) in vec2 uv;

out vec4 passColor;
out vec2 passUV;

uniform mat4 projectionMatrix;

void main() {
    gl_Position = projectionMatrix * position;
    passColor = color;
    passUV = uv;
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
    color = vec4(passColor.zyx, 1);
    if ((rdFlags & 0x400u) != 0u) {
        vec4 texColor = texture(diffuseTex, passUV);
        color *= texColor;
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
}

int GL_renderState = 0;

void GL_SetRenderState(Std3DRenderState rdflags)
{
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
        glDeleteTextures(1, &gl_tex.texture);
        if (gl_tex.alpha_keyed_texture)
            glDeleteTextures(1, &*gl_tex.alpha_keyed_texture);

        textures.erase(pTexture);
    });
    hook_call_original(std3D_ClearTexture, pTexture);
}

void std3D_AllocSystemTexture_Hook(tSystemTexture* pTexture, tVBuffer** apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType)
{
    hook_call_original(std3D_AllocSystemTexture, pTexture, apVBuffers, numMipLevels, formatType);

    tVBuffer* t = apVBuffers[0];
    const auto& c = t->rasterInfo.colorInfo;
    fprintf(hook_log, "texture: %p width=%d height=%d size=%d flags=0x%x r=%d g=%d b=%d a=%d format=%d loaded=%d\n", pTexture, t->rasterInfo.width, t->rasterInfo.height, t->rasterInfo.size, pTexture->ddsd.ddpfPixelFormat.dwFlags, c.redBPP, c.greenBPP, c.blueBPP, c.alphaBPP, formatType, textures.contains(pTexture));
    fflush(hook_log);

    run_on_gl_thread([&] {
        auto& gl_tex = textures.emplace(pTexture, GLTexture{}).first->second;
        glGenTextures(1, &gl_tex.texture);
        const bool enable_alpha = formatType != STDCOLOR_FORMAT_RGB;

        std::vector<char> pixels(t->pPixels, t->pPixels + t->rasterInfo.size);
        std::vector<char> alpha_keyed_pixels;

        glBindTexture(GL_TEXTURE_2D, gl_tex.texture);
        auto color_info_to_format = [&](const ColorInfo& c) {
            if (c.redBPP == 5 && c.greenBPP == 5 && c.blueBPP == 5 && c.alphaBPP == 1)
            {
                for (int i = 0; i < t->rasterInfo.width * t->rasterInfo.height; i++)
                {
                    auto& pixel = ((uint16_t*)pixels.data())[i];
                    if (pixel != 0)
                        pixel |= 0x8000;
                }
                return std::make_pair(GL_BGRA, GL_UNSIGNED_SHORT_1_5_5_5_REV);
            }

            if (c.redBPP == 5 && c.greenBPP == 6 && c.blueBPP == 5 && c.alphaBPP == 0)
                return std::make_pair(GL_RGB, GL_UNSIGNED_SHORT_5_6_5_REV);

            if (c.redBPP == 4 && c.greenBPP == 4 && c.blueBPP == 4 && c.alphaBPP == 4)
            {
                alpha_keyed_pixels = pixels;
                for (int i = 0; i < t->rasterInfo.width * t->rasterInfo.height; i++)
                {
                    auto& pixel = ((uint16_t*)alpha_keyed_pixels.data())[i];
                    if ((pixel & 0xF000) != 0)
                        pixel |= 0xF000;
                }
                return std::make_pair(GL_BGRA, GL_UNSIGNED_SHORT_4_4_4_4_REV);
            }

            std::abort();
        };
        const auto [format, type] = color_info_to_format(c);
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        glTexImage2D(GL_TEXTURE_2D, 0, enable_alpha ? GL_RGBA8 : GL_RGB8, t->rasterInfo.width, t->rasterInfo.height, 0, format, type, pixels.data());
        glGenerateMipmap(GL_TEXTURE_2D);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY, 8);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
        glBindTexture(GL_TEXTURE_2D, 0);

        if (!alpha_keyed_pixels.empty())
        {
            gl_tex.alpha_keyed_texture.emplace();
            glGenTextures(1, &*gl_tex.alpha_keyed_texture);
            glBindTexture(GL_TEXTURE_2D, *gl_tex.alpha_keyed_texture);

            glTexImage2D(GL_TEXTURE_2D, 0, enable_alpha ? GL_RGBA8 : GL_RGB8, t->rasterInfo.width, t->rasterInfo.height, 0, format, type, alpha_keyed_pixels.data());
            glGenerateMipmap(GL_TEXTURE_2D);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY, 8);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
            glBindTexture(GL_TEXTURE_2D, 0);
        }
    });
}

void std3D_DrawRenderList_Hook(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags, LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices, int indexCount)
{
    hook_call_original(std3D_DrawRenderList, pTex, rdflags, aVerticies, verticesCount, lpwIndices, indexCount);

    rendered_anything = true;

    render_states.insert(rdflags);
    if (banned_render_states.contains(rdflags))
        return;

    for (int i = 0; i < verticesCount; i++)
    {
        auto& v = aVerticies[i];

        // d3d uses "reciprocal of homogenous w" (RHW) and pretransformed vertices (divided by w).
        // opengl needs the original w and vertices that are not divided by w.
        float w = 1.0f / v.rhw;
        v.sx *= w;
        v.sy *= w;
        v.sz *= w;
        v.rhw = w;
    }

    run_on_gl_thread([&] {
        glUniform1ui(rdflags_pos, rdflags);

        if (pTex)
        {
            std::optional<GLuint> gl_tex;
            for (const auto& [sys_tex, tex] : textures)
            {
                if (sys_tex->pD3DCachedTex == pTex)
                {
                    gl_tex = tex.texture;
                    if ((rdflags & STD3D_RS_ZWRITE_DISABLED) == 0)
                    {
                        // if zwrite not enabled, all texture must have binary alpha information to render correctly. otherwise gray texture are semitransparent
                        if (tex.alpha_keyed_texture)
                            gl_tex = *tex.alpha_keyed_texture;
                    }
                    break;
                }
            }
            if (!gl_tex)
                std::abort();
            glBindTexture(GL_TEXTURE_2D, *gl_tex);
        }
        else
        {
            glBindTexture(GL_TEXTURE_2D, 0);
        }

        GL_SetRenderState(rdflags);

        glEnableVertexAttribArray(0);
        glVertexAttribPointer(0, 4, GL_FLOAT, GL_FALSE, sizeof(D3DTLVERTEX), &aVerticies[0].sx);

        glEnableVertexAttribArray(1);
        glVertexAttribPointer(1, 4, GL_UNSIGNED_BYTE, GL_TRUE, sizeof(D3DTLVERTEX), &aVerticies[0].color);

        glEnableVertexAttribArray(2);
        glVertexAttribPointer(2, 4, GL_UNSIGNED_BYTE, GL_TRUE, sizeof(D3DTLVERTEX), &aVerticies[0].specular);

        glEnableVertexAttribArray(3);
        glVertexAttribPointer(3, 2, GL_FLOAT, GL_FALSE, sizeof(D3DTLVERTEX), &aVerticies[0].tu);

        glDrawElements(GL_TRIANGLES, indexCount, GL_UNSIGNED_SHORT, lpwIndices);

        glDisableVertexAttribArray(0);
        glDisableVertexAttribArray(1);
        glDisableVertexAttribArray(2);
        glDisableVertexAttribArray(3);
    });
}

void init_renderer_hooks()
{
    hook_replace(std3D_ClearTexture, std3D_ClearTexture_Hook);
    hook_replace(std3D_DrawRenderList, std3D_DrawRenderList_Hook);
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

        compileAndEnableShader();
        GLint proj_location = glGetUniformLocation(program, "projectionMatrix");
        float proj_mat[16];

        glMatrixMode(GL_PROJECTION);
        glLoadIdentity();
        // the game transforms the vertices into pixel coords. d3d pixels are offset by half a pixel in comparison to opengl.
        glOrtho(-0.5, w - 0.5, -0.5, h - 0.5, 1, -1);
        glGetFloatv(GL_PROJECTION_MATRIX, proj_mat);

        glUniformMatrix4fv(proj_location, 1, GL_FALSE, proj_mat);

        glActiveTexture(GL_TEXTURE0);
        GLint tex_location = glGetUniformLocation(program, "diffuseTex");
        glUniform1i(tex_location, 0);

        GL_SetRenderState((Std3DRenderState)0);
        // glEnable(GL_ALPHA_TEST);
        // glAlphaFunc(GL_GREATER, 0);

        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

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
    ImGui::Text("banned render states:");
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
    }
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
        GL_SetRenderState(static_cast<Std3DRenderState>(0));
        glEnable(GL_DEPTH_TEST);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    });
}