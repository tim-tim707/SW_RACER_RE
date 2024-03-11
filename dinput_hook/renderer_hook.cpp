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
#include <imgui.h>
#include <optional>
#include <set>

extern "C"
{
#include <Platform/std3D.h>
}

std::mutex renderer_tasks_mutex;
std::vector<std::function<void()>> renderer_tasks;
std::condition_variable renderer_flush_cvar;
bool renderer_flush = false;

bool renderer_active = false;
int GL_renderState = 0;

typedef void(APIENTRY* DEBUGPROC)(GLenum source, GLenum type, GLuint id, GLenum severity, GLsizei length, const char* message, const void* userParam);

void (*glDebugMessageCallback)(DEBUGPROC callback, const void* userParam);

void GL_SetRenderState(Std3DRenderState rdflags)
{
    if ((rdflags & STD3D_RS_UNKNOWN_200) == 0)
    {
        glDisable(GL_BLEND);
        glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
    }
    else
    {
        glEnable(GL_BLEND);
        glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
    }

    /*if ((rdflags & STD3D_RS_UNKNOWN_400) != 0)
    {

        // D3DRENDERSTATE_TEXTUREMAPBLEND, D3DTBLEND_MODULATEALPHA
        glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
    }
    else if ((rdflags & STD3D_RS_UNKNOWN_200) != 0)
    {
        glEnable(GL_BLEND);
        // D3DRENDERSTATE_TEXTUREMAPBLEND, D3DTBLEND_MODULATE
        glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
        glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_MODULATE);
        glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_REPLACE);

        glTexEnvi(GL_TEXTURE_ENV, GL_SRC0_RGB, GL_TEXTURE);
        glTexEnvi(GL_TEXTURE_ENV, GL_SRC1_RGB, GL_PRIMARY_COLOR);

        glTexEnvi(GL_TEXTURE_ENV, GL_SRC0_ALPHA, GL_PRIMARY_COLOR);
    }*/
    glDepthMask((rdflags & STD3D_RS_ZWRITE_DISABLED) == 0);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, rdflags & STD3D_RS_TEX_CPAMP_U ? GL_CLAMP_TO_EDGE : GL_REPEAT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, rdflags & STD3D_RS_TEX_CPAMP_V ? GL_CLAMP_TO_EDGE : GL_REPEAT);

    GL_renderState = rdflags;
}

extern "C" FILE* hook_log;

struct GLSourceTexture
{
    StdColorFormatType format;
    tRasterInfo info;
    std::vector<uint8_t> data;
    GLuint gl_texture = 0;
};

std::map<tSystemTexture*, GLSourceTexture> textures;

void std3D_ClearTexture_Hook(tSystemTexture* pTexture)
{
    {
        std::lock_guard lock(renderer_tasks_mutex);
        renderer_tasks.push_back([pTexture, cachedTex = pTexture->pD3DCachedTex] {
            auto& tex = textures.at(pTexture);
            glDeleteTextures(1, &tex.gl_texture);
            textures.erase(pTexture);
        });
    }
    hook_call_original(std3D_ClearTexture, pTexture);
}

void std3D_AllocSystemTexture_Hook(tSystemTexture* pTexture, tVBuffer** apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType)
{
    tVBuffer* t = apVBuffers[0];
    const auto& c = t->rasterInfo.colorInfo;
    fprintf(hook_log, "texture: %p width=%d height=%d size=%d r=%d g=%d b=%d a=%d format=%d loaded=%d\n", pTexture, t->rasterInfo.width, t->rasterInfo.height, t->rasterInfo.size, c.redBPP, c.greenBPP, c.blueBPP, c.alphaBPP, formatType, textures.contains(pTexture));
    fflush(hook_log);

    GLSourceTexture tex_info{};
    tex_info.format = formatType;
    tex_info.info = t->rasterInfo;
    tex_info.data = { t->pPixels, t->pPixels + t->rasterInfo.size };

    {
        std::lock_guard lock(renderer_tasks_mutex);
        renderer_tasks.push_back([pTexture, tex_info = std::move(tex_info)]() mutable {
            auto& info = textures.emplace(pTexture, GLSourceTexture{}).first->second;
            info = std::move(tex_info);

            glGenTextures(1, &info.gl_texture);

            const auto& c = info.info.colorInfo;
            glBindTexture(GL_TEXTURE_2D, info.gl_texture);
            const bool enable_alpha = info.format != STDCOLOR_FORMAT_RGB;
            auto color_info_to_format = [&](const ColorInfo& c) {
                if (c.redBPP == 5 && c.greenBPP == 5 && c.blueBPP == 5 && c.alphaBPP == 1)
                {
                    // for (int i = 0; i < info.info.width * info.info.height; i++)
                    //     ((uint16_t*)info.data.data())[i] |= 0x8000;
                    return std::make_pair(GL_BGRA, GL_UNSIGNED_SHORT_1_5_5_5_REV);
                }

                if (c.redBPP == 5 && c.greenBPP == 6 && c.blueBPP == 5 && c.alphaBPP == 0)
                    return std::make_pair(GL_RGB, GL_UNSIGNED_SHORT_5_6_5_REV);

                if (c.redBPP == 4 && c.greenBPP == 4 && c.blueBPP == 4 && c.alphaBPP == 4)
                    return std::make_pair(GL_BGRA, GL_UNSIGNED_SHORT_4_4_4_4_REV);

                std::abort();
            };
            const auto [format, type] = color_info_to_format(c);
            glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
            glTexImage2D(GL_TEXTURE_2D, 0, enable_alpha ? GL_RGBA : GL_RGB, info.info.width, info.info.height, 0, format, type, info.data.data());
            glGenerateMipmap(GL_TEXTURE_2D);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY, 8);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR_MIPMAP_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
            glBindTexture(GL_TEXTURE_2D, 0);
        });
    }

    hook_call_original(std3D_AllocSystemTexture, pTexture, apVBuffers, numMipLevels, formatType);
}

void std3D_DrawRenderList_Hook(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags, LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices, int indexCount)
{
    std::vector<D3DTLVERTEX> vertices(aVerticies, aVerticies + verticesCount);
    for (auto& v : vertices)
    {
        float w = 1.0f / v.rhw;
        v.sx *= w;
        v.sy *= w;
        v.sz *= w;
        v.rhw = w;
    }

    std::vector<WORD> indices(lpwIndices, lpwIndices + indexCount);

    {
        std::lock_guard lock(renderer_tasks_mutex);
        renderer_tasks.push_back([pTex, vertices, indices, rdflags] {
            if (pTex)
            {
                std::optional<GLuint> gl_tex;
                for (const auto& [sys_tex, tex] : textures)
                {
                    if (sys_tex->pD3DCachedTex == pTex)
                    {
                        gl_tex = tex.gl_texture;
                        break;
                    }
                }
                if (!gl_tex)
                    std::abort();
                glBindTexture(GL_TEXTURE_2D, *gl_tex);
                glEnable(GL_TEXTURE_2D);
            }
            else
            {
                glDisable(GL_TEXTURE_2D);
                glBindTexture(GL_TEXTURE_2D, 0);
            }

            GL_SetRenderState(rdflags);

            glEnableClientState(GL_VERTEX_ARRAY);
            glEnableClientState(GL_COLOR_ARRAY);
            glEnableClientState(GL_TEXTURE_COORD_ARRAY);

            glVertexPointer(4, GL_FLOAT, sizeof(D3DTLVERTEX), &vertices[0].sx);
            glColorPointer(GL_BGRA, GL_UNSIGNED_BYTE, sizeof(D3DTLVERTEX), &vertices[0].color);
            glTexCoordPointer(2, GL_FLOAT, sizeof(D3DTLVERTEX), &vertices[0].tu);

            glDrawElements(GL_TRIANGLES, indices.size(), GL_UNSIGNED_SHORT, indices.data());

            glDisableClientState(GL_VERTEX_ARRAY);
            glDisableClientState(GL_COLOR_ARRAY);
            glDisableClientState(GL_TEXTURE_COORD_ARRAY);
        });
    }

    return hook_call_original(std3D_DrawRenderList, pTex, rdflags, aVerticies, verticesCount, lpwIndices, indexCount);
}

void init_renderer_hooks()
{
    hook_replace(std3D_ClearTexture, std3D_ClearTexture_Hook);
    hook_replace(std3D_DrawRenderList, std3D_DrawRenderList_Hook);
    hook_replace(std3D_AllocSystemTexture, std3D_AllocSystemTexture_Hook);

    std::thread([] {
        glfwInit();
        // glfwWindowHint(GLFW_DOUBLEBUFFER, GLFW_FALSE);
        auto window = glfwCreateWindow(640, 480, "OpenGL renderer", nullptr, nullptr);
        glfwMakeContextCurrent(window);
        gladLoadGLLoader(GLADloadproc(glfwGetProcAddress));

        glEnable(GL_DEPTH_TEST);
        glDepthFunc(GL_LESS);
        glClearDepth(1.0);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        // glEnable(GL_ALPHA_TEST);
        // glAlphaFunc(GL_GREATER, 0);

        while (true)
        {
            bool do_flush = false;
            std::vector<std::function<void()>> renderer_tasks_;
            {
                std::unique_lock lock(renderer_tasks_mutex);
                renderer_flush_cvar.wait_for(lock, std::chrono::milliseconds(100), [] { return renderer_flush; });
                if (renderer_flush)
                {
                    renderer_flush = false;
                    renderer_tasks_ = std::move(renderer_tasks);
                    renderer_tasks.clear();
                    do_flush = true;
                }
            }

            if (do_flush)
            {
                int w, h;
                glfwGetFramebufferSize(window, &w, &h);

                GL_SetRenderState((Std3DRenderState)0);

                glViewport(0, 0, w, h);
                glEnable(GL_DEPTH_TEST);
                glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

                w = 1280; // TODO hardcoded viewport size...
                h = 720;

                glMatrixMode(GL_PROJECTION);
                glLoadIdentity();
                glOrtho(0, w, h, 0, 1, -1);

                glMatrixMode(GL_MODELVIEW);
                glLoadIdentity();

                for (const auto& task : renderer_tasks_)
                    task();

                glFinish();
                glfwSwapBuffers(window);
            }

            glfwPollEvents();
        }
    }).detach();
}

void opengl_renderer_flush()
{
    std::unique_lock lock(renderer_tasks_mutex);
    renderer_flush = true;
    renderer_flush_cvar.notify_all();
}