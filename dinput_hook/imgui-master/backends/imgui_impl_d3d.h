// dear imgui: Renderer Backend for DirectX9
// This needs to be used along with a Platform Backend (e.g. Win32)

// Implemented features:
//  [X] Renderer: User texture binding. Use 'LPDIRECT3DTEXTURE9' as ImTextureID. Read the FAQ about ImTextureID!
//  [X] Renderer: Support for large meshes (64k+ vertices) with 16-bit indices.

// You can use unmodified imgui_impl_* files in your project. See examples/ folder for examples of using this. 
// Prefer including the entire imgui/ repository into your project (either as a copy or as a submodule), and only build the backends you need.
// If you are new to Dear ImGui, read documentation from the docs/ folder + read the top of imgui.cpp.
// Read online: https://github.com/ocornut/imgui/tree/master/docs

#pragma once
#include "imgui.h"      // IMGUI_IMPL_API

struct IDirect3DDevice3;
struct IDirectDrawSurface4;

IMGUI_IMPL_API bool     ImGui_ImplD3D_Init(IDirect3DDevice3* device, IDirectDrawSurface4* surface);
IMGUI_IMPL_API void     ImGui_ImplD3D_Shutdown();
IMGUI_IMPL_API void     ImGui_ImplD3D_NewFrame();
IMGUI_IMPL_API void     ImGui_ImplD3D_RenderDrawData(ImDrawData* draw_data);

IMGUI_IMPL_API void     ImGui_ImplD3D_ClearZBuffer();

// Use if you want to reset your rendering device without losing Dear ImGui state.
IMGUI_IMPL_API bool     ImGui_ImplD3D_CreateDeviceObjects();
IMGUI_IMPL_API void     ImGui_ImplD3D_InvalidateDeviceObjects();
