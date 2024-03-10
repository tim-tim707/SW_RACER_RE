//
// Created by tly on 10.03.2024.
//
#include "renderer_hook.h"
#include "hook_helper.h"

#include <GLFW/glfw3.h>
#include <mutex>
#include <functional>
#include <thread>
#include <vector>
#include <condition_variable>

extern "C"
{
#include <Platform/std3D.h>
}

std::mutex renderer_tasks_mutex;
std::vector<std::function<void()>> renderer_tasks;
std::condition_variable renderer_flush_cvar;
bool renderer_flush = false;

bool renderer_active = false;

int std3D_SetProjection_Hook(float fov, float aspectRatio, float nearPlane, float farPlane)
{
    std::lock_guard lock(renderer_tasks_mutex);
    renderer_tasks.push_back([=] {
        glMatrixMode(GL_PROJECTION);
        glOrtho(0, 1280, 0, 720, -10, 10);
        glMatrixMode(GL_MODELVIEW);
        glLoadIdentity();
    });

    return hook_call_original(std3D_SetProjection, fov, aspectRatio, nearPlane, farPlane);
}

void std3D_DrawRenderList_Hook(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags, LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices, int indexCount)
{
    std::vector<D3DTLVERTEX> vertices(aVerticies, aVerticies + verticesCount);
    std::vector<WORD> indices(lpwIndices, lpwIndices + indexCount);

    std::lock_guard lock(renderer_tasks_mutex);
    renderer_tasks.push_back([vertices, indices] {
        glEnableClientState(GL_VERTEX_ARRAY);
        //glEnableClientState(GL_COLOR_ARRAY);

        glColor3f(1,1,1);
        glVertexPointer(3, GL_FLOAT, sizeof(D3DTLVERTEX), &vertices[0].sx);
        //glColorPointer(3, GL_UNSIGNED_BYTE, sizeof(D3DTLVERTEX), &vertices[0].color);

        // glDrawElements(GL_TRIANGLES, indices.size(), GL_UNSIGNED_SHORT, indices.data());
        glPointSize(5);
        glDrawArrays(GL_POINTS, 0, vertices.size());

        glDisableClientState(GL_VERTEX_ARRAY);
        //glDisableClientState(GL_COLOR_ARRAY);
    });

    return hook_call_original(std3D_DrawRenderList, pTex, rdflags, aVerticies, verticesCount, lpwIndices, indexCount);
}

void init_renderer_hooks()
{
    hook_replace(std3D_SetProjection, std3D_SetProjection_Hook);
    hook_replace(std3D_DrawRenderList, std3D_DrawRenderList_Hook);

    std::thread([] {
        glfwInit();
        auto window = glfwCreateWindow(640, 480, "OpenGL renderer", nullptr, nullptr);
        glfwMakeContextCurrent(window);

        renderer_active = true;
        while (!glfwWindowShouldClose(window))
        {
            bool do_flush = false;
            std::vector<std::function<void()>> renderer_tasks_;
            {
                std::unique_lock lock(renderer_tasks_mutex);
                renderer_flush_cvar.wait_for(lock, std::chrono::milliseconds(100), [] { return renderer_flush; });
                if (renderer_flush)
                {
                    renderer_tasks_ = std::move(renderer_tasks);
                    renderer_tasks.clear();
                    renderer_flush = false;
                    do_flush = true;
                }
            }

            if (do_flush)
            {
                int w, h;
                glfwGetFramebufferSize(window, &w, &h);

                glViewport(0, 0, w, h);
                glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

                for (const auto& task : renderer_tasks_)
                    task();

                glfwSwapBuffers(window);
            }

            glfwPollEvents();
        }
        renderer_active = false;
    }).detach();
}

void opengl_renderer_flush()
{
    std::unique_lock lock(renderer_tasks_mutex);
    renderer_flush_cvar.notify_all();
    renderer_flush = true;
}