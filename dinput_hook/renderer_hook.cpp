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

int GL_renderState = 0;

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

std::map<tSystemTexture*, GLuint> textures;

void std3D_ClearTexture_Hook(tSystemTexture* pTexture)
{
    run_on_gl_thread([&] {
        GLuint tex = textures.at(pTexture);
        glDeleteTextures(1, &tex);
        textures.erase(pTexture);
    });
    hook_call_original(std3D_ClearTexture, pTexture);
}

void std3D_AllocSystemTexture_Hook(tSystemTexture* pTexture, tVBuffer** apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType)
{
    tVBuffer* t = apVBuffers[0];
    const auto& c = t->rasterInfo.colorInfo;
    fprintf(hook_log, "texture: %p width=%d height=%d size=%d r=%d g=%d b=%d a=%d format=%d loaded=%d\n", pTexture, t->rasterInfo.width, t->rasterInfo.height, t->rasterInfo.size, c.redBPP, c.greenBPP, c.blueBPP, c.alphaBPP, formatType, textures.contains(pTexture));
    fflush(hook_log);

    run_on_gl_thread([&] {
        auto& gl_tex = textures.emplace(pTexture, 0).first->second;
        glGenTextures(1, &gl_tex);

        glBindTexture(GL_TEXTURE_2D, gl_tex);
        const bool enable_alpha = formatType != STDCOLOR_FORMAT_RGB;
        auto color_info_to_format = [](const ColorInfo& c) {
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
        glTexImage2D(GL_TEXTURE_2D, 0, enable_alpha ? GL_RGBA : GL_RGB, t->rasterInfo.width, t->rasterInfo.height, 0, format, type, t->pPixels);
        glGenerateMipmap(GL_TEXTURE_2D);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY, 8);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR_MIPMAP_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
        glBindTexture(GL_TEXTURE_2D, 0);
    });

    hook_call_original(std3D_AllocSystemTexture, pTexture, apVBuffers, numMipLevels, formatType);
}

void std3D_DrawRenderList_Hook(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags, LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices, int indexCount)
{
    hook_call_original(std3D_DrawRenderList, pTex, rdflags, aVerticies, verticesCount, lpwIndices, indexCount);

    rendered_anything = true;

    for (int i = 0; i < verticesCount; i++)
    {
        auto& v = aVerticies[i];

        float w = 1.0f / v.rhw;
        v.sx *= w;
        v.sy *= w;
        v.sz *= w;
        v.rhw = w;
    }

    run_on_gl_thread([&] {
        if (pTex)
        {
            std::optional<GLuint> gl_tex;
            for (const auto& [sys_tex, tex] : textures)
            {
                if (sys_tex->pD3DCachedTex == pTex)
                {
                    gl_tex = tex;
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

        glVertexPointer(4, GL_FLOAT, sizeof(D3DTLVERTEX), &aVerticies[0].sx);
        glColorPointer(GL_BGRA, GL_UNSIGNED_BYTE, sizeof(D3DTLVERTEX), &aVerticies[0].color);
        glTexCoordPointer(2, GL_FLOAT, sizeof(D3DTLVERTEX), &aVerticies[0].tu);

        glDrawElements(GL_TRIANGLES, indexCount, GL_UNSIGNED_SHORT, lpwIndices);

        glDisableClientState(GL_VERTEX_ARRAY);
        glDisableClientState(GL_COLOR_ARRAY);
        glDisableClientState(GL_TEXTURE_COORD_ARRAY);
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

        glMatrixMode(GL_PROJECTION);
        glLoadIdentity();
        glOrtho(-0.5, w - 0.5, -0.5, h - 0.5, 1, -1);

        glMatrixMode(GL_MODELVIEW);
        glLoadIdentity();

        GL_SetRenderState((Std3DRenderState)0);
        // glEnable(GL_ALPHA_TEST);
        // glAlphaFunc(GL_GREATER, 0);

        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

        while (true)
        {
            std::vector<std::function<void()>> renderer_tasks_;
            {
                std::unique_lock lock(renderer_tasks_mutex);
                renderer_flush_cvar.wait_for(lock, std::chrono::milliseconds(100), [] {
                    return !renderer_tasks.empty();
                });
                renderer_tasks_ = std::move(renderer_tasks);
                renderer_tasks.clear();
            }

            for (const auto& task : renderer_tasks_)
                task();
        }
    }).detach();
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