//
// Created by tly on 27.02.2024.
//
#include <windows.h>
#include <thread>
#include <fstream>
#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_d3d.h"

#include "globals.h"

#define hr_assert(x) assert(SUCCEEDED(x))

#include <d3d.h>
#include <ddraw.h>

#include "detours.h"
#include "hook_helper.h"

#include <optional>

extern "C" {
FILE* hook_log = nullptr;
}

static auto D3DDrawSurfaceToWindow_489AB0 = (int (*)())0x489AB0;
static WNDPROC WndProcOrig;

LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT CALLBACK WndProc(HWND wnd, UINT code, WPARAM wparam, LPARAM lparam)
{
    if (ImGui_ImplWin32_WndProcHandler(wnd, code, wparam, lparam))
        return 1;

    return WndProcOrig(wnd, code, wparam, lparam);
}

static bool imgui_initialized = false;

int D3DDrawSurfaceToWindow()
{
    // fprintf(hook_log, "[D3DDrawSurfaceToWindow].\n");
    fflush(hook_log);

    if (!imgui_initialized && std3D_pD3Device)
    {
        imgui_initialized = true;
        // Setup Dear ImGui context
        IMGUI_CHECKVERSION();
        assert(ImGui::CreateContext());
        ImGuiIO& io = ImGui::GetIO();
        (void)io;
        // io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
        // io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls

        // Setup Dear ImGui style
        ImGui::StyleColorsDark();
        // ImGui::StyleColorsClassic();

        // Setup Platform/Renderer backends
        const auto wnd = GetActiveWindow();
        assert(ImGui_ImplWin32_Init(wnd));
        assert(ImGui_ImplD3D_Init(std3D_pD3Device, stdDisplay_g_backBuffer.surface));

        WndProcOrig = (WNDPROC)SetWindowLongA(wnd, GWL_WNDPROC, (LONG)WndProc);

        fprintf(hook_log, "[D3DDrawSurfaceToWindow] imgui initialized.\n");
    }

    if (imgui_initialized)
    {
        ImGui_ImplD3D_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::Begin("Test");
        ImGui::Text("Num drawn faces: %d", rdCache_drawnFaces);
        ImGui::SliderFloat("FOV", &cameraFOV, 5, 179);
        rdCamera* cam = (rdCamera*)(0x00dfb2e0 - 0x3c);

        ImGui::End();

        // Rendering
        ImGui::EndFrame();

        if (std3D_pD3Device->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplD3D_RenderDrawData(ImGui::GetDrawData());
            std3D_pD3Device->EndScene();
        }

        bool showCursor = ImGui::GetIO().WantCaptureMouse;
        // since ShowCursor has a counter, it has to be called multiple times until it takes effect...
        if (showCursor)
        {
            while (ShowCursor(true) <= 0)
                ;
        }
        else
        {
            while (ShowCursor(false) >= 0)
                ;
        }
    }

    return D3DDrawSurfaceToWindow_489AB0();
}

static POINT virtual_cursor_pos{ -100, -100 };

auto stdConsole_GetCursosPos_Hook = (int (*)(int*, int*))0x004082e0;

// 0x004082e0
int stdConsole_GetCursosPos(int* out_x, int* out_y)
{
    if (!out_x || !out_y)
        return 0;

    const auto& io = ImGui::GetIO();

    if (io.WantCaptureMouse)
    {
        // move mouse pos out of window
        virtual_cursor_pos = { -100, -100 };
    }
    else
    {
        if (io.MouseDelta.x != 0 || io.MouseDelta.y != 0)
        {
            // mouse moved, update virtual mouse position
            virtual_cursor_pos.x = (io.MousePos.x * 640) / io.DisplaySize.x;
            virtual_cursor_pos.y = (io.MousePos.y * 480) / io.DisplaySize.y;
        }
    }

    *out_x = virtual_cursor_pos.x;
    *out_y = virtual_cursor_pos.y;
    return 1;
}

auto stdConsole_SetCursosPos_Hook = (void (*)(int, int))0x00408360;

// 0x00408360
void stdConsole_SetCursosPos(int X, int Y)
{
    virtual_cursor_pos = POINT{ X, Y };
}

extern "C" HRESULT WINAPI DirectDrawCreateHook(GUID* guid, LPDIRECTDRAW* dd, IUnknown* unk);
extern "C" HRESULT (*WINAPI DirectDrawCreatePtr)(GUID* guid, LPDIRECTDRAW* dd, IUnknown* unk);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    hook_log = fopen("hook.log", "wb");

    fprintf(hook_log, "[DllMain]\n");
    fflush(hook_log);

    /*DetourTransactionBegin();
    DetourAttach(&D3DDrawSurfaceToWindow_489AB0, &D3DDrawSurfaceToWindow);
    DetourAttach(&stdConsole_GetCursosPos_Hook, stdConsole_GetCursosPos);
    DetourAttach(&stdConsole_SetCursosPos_Hook, stdConsole_SetCursosPos);
    // DetourAttach(&DirectDrawCreatePtr, &DirectDrawCreateHook);
    DetourTransactionCommit();*/

    hook_all_functions();

    return TRUE;
}