//
// Created by tly on 10.03.2024.
//
#include "renderer_hook.h"
#include "hook_helper.h"

#include <cmath>
#include <GLFW/glfw3.h>
#include <mutex>
#include <functional>
#include <thread>
#include <vector>
#include <condition_variable>
#include <imgui.h>
#include <set>

extern "C"
{
#include <Raster/rdCache.h>
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
    if ((rdflags & STD3D_RS_UNKNOWN_400) != 0)
    {
        glEnable(GL_BLEND);
        // D3DRENDERSTATE_TEXTUREMAPBLEND, D3DTBLEND_MODULATEALPHA
    }
    else if ((rdflags & STD3D_RS_UNKNOWN_200) != 0)
    {
        glEnable(GL_BLEND);
        // D3DRENDERSTATE_TEXTUREMAPBLEND, D3DTBLEND_MODULATE);
    }
    else
    {
        glDisable(GL_BLEND);
    }
    glDepthMask((rdflags & STD3D_RS_ZWRITE_DISABLED) == 0);

    GL_renderState = rdflags;
}

/*void GL_SetRenderState(Std3DRenderState rdflags)
{
    if (GL_renderState == rdflags)
        return;

    if ((GL_renderState ^ rdflags) & (STD3D_RS_UNKNOWN_400 | STD3D_RS_UNKNOWN_200))
    {
        if ((rdflags & STD3D_RS_UNKNOWN_400) != 0)
        {
            glEnable(GL_BLEND);
            // D3DRENDERSTATE_TEXTUREMAPBLEND, D3DTBLEND_MODULATEALPHA
        }
        else if ((rdflags & STD3D_RS_UNKNOWN_200) != 0)
        {
            glEnable(GL_BLEND);
            // D3DRENDERSTATE_TEXTUREMAPBLEND, D3DTBLEND_MODULATE);
        }
        else
        {
            glDisable(GL_BLEND);
        }
    }
    if ((GL_renderState ^ rdflags) & STD3D_RS_ZWRITE_DISABLED)
        glDepthMask((rdflags & STD3D_RS_ZWRITE_DISABLED) == 0);

#if 0
    if ( (((unsigned __int16)std3D_renderState ^ (unsigned __int16)rdflags) & 0x800) != 0 )
    {
      if ( (rdflags & 0x800) != 0 )
        std3D_pD3Device->lpVtbl->SetTextureStageState(std3D_pD3Device, 0, D3DTSS_ADDRESSU, 3);
      else
        std3D_pD3Device->lpVtbl->SetTextureStageState(std3D_pD3Device, 0, D3DTSS_ADDRESSU, 1);
    }
    if ( (((unsigned __int16)std3D_renderState ^ (unsigned __int16)rdflags) & 0x1000) != 0 )
    {
      if ( (rdflags & 0x1000) != 0 )
        std3D_pD3Device->lpVtbl->SetTextureStageState(std3D_pD3Device, 0, D3DTSS_ADDRESSV, 3);
      else
        std3D_pD3Device->lpVtbl->SetTextureStageState(std3D_pD3Device, 0, D3DTSS_ADDRESSV, 1);
    }
    if ( (((unsigned __int16)(std3D_renderState ^ rdflags) >> 8) & 0x80u) != 0 )
    {
      if ( (rdflags & 0x8000) != 0 && d3d_FogEnabled )
        std3D_pD3Device->lpVtbl->SetRenderState(std3D_pD3Device, D3DRENDERSTATE_FOGENABLE, 1);
      else
        std3D_pD3Device->lpVtbl->SetRenderState(std3D_pD3Device, D3DRENDERSTATE_FOGENABLE, 0);
    }
    if ( ((std3D_renderState ^ rdflags) & 0x80u) == 0 || (std3D_renderState = rdflags, !std3D_SetTexFilterMode()) )
#endif

    GL_renderState = rdflags;
}*/

#define GL_BGRA 0x80E1
#define GL_UNSIGNED_SHORT_5_6_5 0x8363
#define GL_UNSIGNED_SHORT_5_6_5_REV 0x8364
#define GL_UNSIGNED_SHORT_4_4_4_4 0x8033
#define GL_UNSIGNED_SHORT_4_4_4_4_REV 0x8365
#define GL_UNSIGNED_SHORT_5_5_5_1 0x8034
#define GL_UNSIGNED_SHORT_1_5_5_5_REV 0x8366
#define GL_UNSIGNED_INT_8_8_8_8 0x8035
#define GL_UNSIGNED_INT_8_8_8_8_REV 0x8367
#define GL_DEBUG_OUTPUT_SYNCHRONOUS 0x8242

extern "C" FILE* hook_log;

void APIENTRY debugCallback(GLenum source, GLenum type, GLuint id, GLenum severity, GLsizei length, const char* message, const void* userParam)
{
    fprintf(hook_log, "[OpenGL debug] %s\n", message);
    fflush(hook_log);
}

struct GLSourceTexture
{
    tRasterInfo info;
    std::vector<uint8_t> data;
    GLuint gl_texture = 0;
};

std::map<tSystemTexture*, GLSourceTexture> textures;

void std3D_ClearTexture_Hook(tSystemTexture* pTexture)
{
    fprintf(hook_log, "clear texture: %p loaded=%d\n", pTexture, textures.contains(pTexture));
    fflush(hook_log);

    std::lock_guard lock(renderer_tasks_mutex);
    renderer_tasks.push_back([pTexture] {
        auto tex_it = textures.find(pTexture);
        if (tex_it != textures.end())
        {
            glDeleteTextures(1, &tex_it->second.gl_texture);
            textures.erase(tex_it);
        }
    });

    hook_call_original(std3D_ClearTexture, pTexture);
}

void std3D_AllocSystemTexture_Hook(tSystemTexture* pTexture, tVBuffer** apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType)
{
    tVBuffer* t = apVBuffers[0];
    const auto& c = t->rasterInfo.colorInfo;
    fprintf(hook_log, "texture: %p width=%d height=%d size=%d r=%d g=%d b=%d a=%d format=%d loaded=%d\n", pTexture, t->rasterInfo.width, t->rasterInfo.height, t->rasterInfo.size, c.redBPP, c.greenBPP, c.blueBPP, c.alphaBPP, formatType, textures.contains(pTexture));
    fflush(hook_log);

    GLSourceTexture texture;
    texture.info = t->rasterInfo;
    texture.data = { t->pPixels, t->pPixels + t->rasterInfo.size };

    std::lock_guard lock(renderer_tasks_mutex);
    renderer_tasks.push_back([pTexture, texture = std::move(texture), formatType] {
        auto& tex = textures.emplace(pTexture, GLSourceTexture{}).first->second;
        tex = std::move(texture);

        glGenTextures(1, &tex.gl_texture);

        const auto& c = tex.info.colorInfo;
        glBindTexture(GL_TEXTURE_2D, tex.gl_texture);
        auto color_info_to_format = [](const ColorInfo& c) {
            if (c.redBPP == 5 && c.greenBPP == 5 && c.blueBPP == 5 && c.alphaBPP == 1)
                return std::make_pair(GL_BGRA, GL_UNSIGNED_SHORT_1_5_5_5_REV);

            if (c.redBPP == 5 && c.greenBPP == 6 && c.blueBPP == 5 && c.alphaBPP == 0)
                return std::make_pair(GL_RGB, GL_UNSIGNED_SHORT_5_6_5_REV);

            if (c.redBPP == 4 && c.greenBPP == 4 && c.blueBPP == 4 && c.alphaBPP == 4)
                return std::make_pair(GL_BGRA, GL_UNSIGNED_SHORT_4_4_4_4_REV);

            std::abort();
        };
        const auto [format, type] = color_info_to_format(c);
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        glTexImage2D(GL_TEXTURE_2D, 0, formatType == STDCOLOR_FORMAT_RGB ? GL_RGB : GL_RGBA, tex.info.width, tex.info.height, 0, format, type, tex.data.data());
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glBindTexture(GL_TEXTURE_2D, 0);
    });

    hook_call_original(std3D_AllocSystemTexture, pTexture, apVBuffers, numMipLevels, formatType);
}

void rdCache_SendFaceListToHardware_Hook(size_t numPolys, RdCacheProcEntry* aPolys)
{
    for (size_t i = 0; i < numPolys; i++)
    {
        const auto& entry = aPolys[i];
        if (!entry.aVertices || !entry.aVertColors || !entry.aUVCoords)
            continue;

        std::vector<rdVector3> vertices{ entry.aVertices, entry.aVertices + entry.numVertices };
        std::vector<rdVector4> colors{ entry.aVertColors, entry.aVertColors + entry.numVertices };
        std::vector<rdVector2> uv_coords{ entry.aUVCoords, entry.aUVCoords + entry.numVertices };

        {
            std::lock_guard lock(renderer_tasks_mutex);
            renderer_tasks.push_back([flags = entry.flags, pTex = entry.pMaterial ? entry.pMaterial->aTextures : nullptr, vertices = std::move(vertices), colors = std::move(colors), uv_coords = std::move(uv_coords)] {
                if (pTex && textures.contains(pTex))
                {
                    GLuint gl_tex = textures.at(pTex).gl_texture;
                    glBindTexture(GL_TEXTURE_2D, gl_tex);
                    glEnable(GL_TEXTURE_2D);
                }
                else
                {
                    glDisable(GL_TEXTURE_2D);
                    glBindTexture(GL_TEXTURE_2D, 0);
                }

                std::vector<uint16_t> indices(vertices.size());
                for (int i = 0; i < vertices.size(); i++)
                {
                    indices[i] = (i / 2) % 2 == 1 ? i : 2 * (i / 2) + (1 - i % 2);
                    if (indices[i] >= vertices.size())
                        indices[i]--;
                }

                std::vector<rdVector4> vertices_(vertices.size());
                for (int i = 0; i < vertices.size(); i++)
                {
                    auto& v_ = vertices_[i];
                    auto& v = vertices[i];
                    v_ = {v.x, v.y, 2.0f * v.z / 16000.0f - 1.0f, 1.0f};
                }

                glDepthMask((flags & RD_FF_ZWRITE_DISABLED) == 0);

                // GL_SetRenderState(rdflags);

                glEnableClientState(GL_VERTEX_ARRAY);
                glEnableClientState(GL_COLOR_ARRAY);
                glEnableClientState(GL_TEXTURE_COORD_ARRAY);

                glVertexPointer(4, GL_FLOAT, sizeof(rdVector4), &vertices_[0].x);
                glColorPointer(4, GL_FLOAT, sizeof(rdVector4), &colors[0].x);
                glTexCoordPointer(2, GL_FLOAT, sizeof(rdVector2), &uv_coords[0].x);

                glPointSize(3);
                glDrawElements(GL_TRIANGLE_STRIP, indices.size(), GL_UNSIGNED_SHORT, indices.data());

                glDisableClientState(GL_VERTEX_ARRAY);
                glDisableClientState(GL_COLOR_ARRAY);
                glDisableClientState(GL_TEXTURE_COORD_ARRAY);
            });
        }
    }

    hook_call_original(rdCache_SendFaceListToHardware, numPolys, aPolys);
}

#if 0
void std3D_DrawRenderList_Hook(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags, LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices, int indexCount)
{
    std::vector<D3DTLVERTEX> vertices(aVerticies, aVerticies + verticesCount);
    std::vector<WORD> indices(lpwIndices, lpwIndices + indexCount);

    {
        std::lock_guard lock(renderer_tasks_mutex);
        renderer_tasks.push_back([pTex, vertices, indices, rdflags] {
            if (pTex)
            {
                GLuint gl_tex = d3d_to_gl_tex.at(pTex);
                glBindTexture(GL_TEXTURE_2D, gl_tex);
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

            glVertexPointer(3, GL_FLOAT, sizeof(D3DTLVERTEX), &vertices[0].sx);
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
#endif

void init_renderer_hooks()
{
    hook_replace(std3D_ClearTexture, std3D_ClearTexture_Hook);
    hook_replace(rdCache_SendFaceListToHardware, rdCache_SendFaceListToHardware_Hook);
    // hook_replace(std3D_DrawRenderList, std3D_DrawRenderList_Hook);
    hook_replace(std3D_AllocSystemTexture, std3D_AllocSystemTexture_Hook);

    std::thread([] {
        glfwInit();
        glfwWindowHint(GLFW_DOUBLEBUFFER, GLFW_FALSE);
        auto window = glfwCreateWindow(640, 480, "OpenGL renderer", nullptr, nullptr);
        glfwMakeContextCurrent(window);

        glDebugMessageCallback = (decltype(glDebugMessageCallback))glfwGetProcAddress("glDebugMessageCallback");
        glDebugMessageCallback(debugCallback, nullptr);
        glEnable(GL_DEBUG_OUTPUT_SYNCHRONOUS);

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

                // glfwSwapBuffers(window);
                glFinish();
                glFlush();
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