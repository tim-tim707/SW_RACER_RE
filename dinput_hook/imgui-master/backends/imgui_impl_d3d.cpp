// dear imgui: Renderer Backend for DirectX9
// This needs to be used along with a Platform Backend (e.g. Win32)

// Implemented features:
//  [X] Renderer: User texture binding. Use 'LPDIRECT3DTEXTURE9' as ImTextureID. Read the FAQ about ImTextureID!
//  [X] Renderer: Support for large meshes (64k+ vertices) with 16-bit indices.

// You can use unmodified imgui_impl_* files in your project. See examples/ folder for examples of using this.
// Prefer including the entire imgui/ repository into your project (either as a copy or as a submodule), and only build the backends you need.
// If you are new to Dear ImGui, read documentation from the docs/ folder + read the top of imgui.cpp.
// Read online: https://github.com/ocornut/imgui/tree/master/docs

// CHANGELOG
// (minor and older changes stripped away, please see git history for details)
//  2021-06-29: Reorganized backend to pull data from a single structure to facilitate usage with multiple-contexts (all g_XXXX access changed to bd->XXXX).
//  2021-06-25: DirectX9: Explicitly disable texture state stages after >= 1.
//  2021-05-19: DirectX9: Replaced direct access to ImDrawCmd::TextureId with a call to ImDrawCmd::GetTexID(). (will become a requirement)
//  2021-04-23: DirectX9: Explicitly setting up more graphics states to increase compatibility with unusual non-default states.
//  2021-03-18: DirectX9: Calling IDirect3DStateBlock9::Capture() after CreateStateBlock() as a workaround for state restoring issues (see #3857).
//  2021-03-03: DirectX9: Added support for IMGUI_USE_BGRA_PACKED_COLOR in user's imconfig file.
//  2021-02-18: DirectX9: Change blending equation to preserve alpha in output buffer.
//  2019-05-29: DirectX9: Added support for large mesh (64K+ vertices), enable ImGuiBackendFlags_RendererHasVtxOffset flag.
//  2019-04-30: DirectX9: Added support for special ImDrawCallback_ResetRenderState callback to reset render state.
//  2019-03-29: Misc: Fixed erroneous assert in ImGui_ImplD3D_InvalidateDeviceObjects().
//  2019-01-16: Misc: Disabled fog before drawing UI's. Fixes issue #2288.
//  2018-11-30: Misc: Setting up io.BackendRendererName so it can be displayed in the About Window.
//  2018-06-08: Misc: Extracted imgui_impl_D3D.cpp/.h away from the old combined D3D+Win32 example.
//  2018-06-08: DirectX9: Use draw_data->DisplayPos and draw_data->DisplaySize to setup projection matrix and clipping rectangle.
//  2018-05-07: Render: Saving/restoring Transform because they don't seem to be included in the StateBlock. Setting shading mode to Gouraud.
//  2018-02-16: Misc: Obsoleted the io.RenderDrawListsFn callback and exposed ImGui_ImplD3D_RenderDrawData() in the .h file so you can call it yourself.
//  2018-02-06: Misc: Removed call to ImGui::Shutdown() which is not available from 1.60 WIP, user needs to call CreateContext/DestroyContext themselves.

#include "imgui.h"
#include "imgui_impl_d3d.h"
#include <vector>
#include <tuple>

#define hr_assert(x) assert(SUCCEEDED(x))

// DirectX
#include <d3d.h>

// DirectX data
struct ImGui_ImplD3D_Data
{
    LPDIRECTDRAW4 pdd;
    LPDIRECT3D3 pd3d;
    LPDIRECT3DDEVICE3 pd3dDevice;
    LPDIRECT3DVIEWPORT3 pd3dViewport;
    LPDIRECTDRAWSURFACE4 pddSurface;
    LPDIRECT3DTEXTURE2 FontTexture;
};

struct CUSTOMVERTEX
{
    float pos[3];
    D3DCOLOR col;
    float uv[2];
};
#define D3DFVF_CUSTOMVERTEX (D3DFVF_XYZ | D3DFVF_DIFFUSE | D3DFVF_TEX1)

#ifdef IMGUI_USE_BGRA_PACKED_COLOR
#define IMGUI_COL_TO_D3D_ARGB(_COL) (_COL)
#else
#define IMGUI_COL_TO_D3D_ARGB(_COL) (((_COL) & 0xFF00FF00) | (((_COL) & 0xFF0000) >> 16) | (((_COL) & 0xFF) << 16))
#endif

// Backend data stored in io.BackendRendererUserData to allow support for multiple Dear ImGui contexts
// It is STRONGLY preferred that you use docking branch with multi-viewports (== single Dear ImGui context + multiple windows) instead of multiple Dear ImGui contexts.
static ImGui_ImplD3D_Data* ImGui_ImplD3D_GetBackendData()
{
    return ImGui::GetCurrentContext() ? (ImGui_ImplD3D_Data*)ImGui::GetIO().BackendRendererUserData : NULL;
}

struct BackedUpRenderState
{
    IDirect3DViewport3* viewport = nullptr;
    std::vector<std::pair<D3DRENDERSTATETYPE, DWORD>> render_states;
    std::vector<std::tuple<int, D3DTEXTURESTAGESTATETYPE, DWORD>> texture_states;
    std::vector<std::pair<D3DTRANSFORMSTATETYPE, D3DMATRIX>> matrices;
};

// Functions
static BackedUpRenderState ImGui_ImplD3D_SetupRenderState(ImDrawData* draw_data)
{
    ImGui_ImplD3D_Data* bd = ImGui_ImplD3D_GetBackendData();

    BackedUpRenderState backed_up_state;
    bd->pd3dDevice->GetCurrentViewport(&backed_up_state.viewport);

    DDSURFACEDESC2 surf_desc{};
    surf_desc.dwSize = sizeof(DDSURFACEDESC2);
    hr_assert(bd->pddSurface->GetSurfaceDesc(&surf_desc));

    // Setup viewport
    D3DVIEWPORT2 vp{};
    vp.dwSize = sizeof(D3DVIEWPORT2);
    vp.dwX = 0;
    vp.dwY = 0;
    vp.dwWidth = surf_desc.dwWidth;
    vp.dwHeight = surf_desc.dwHeight;
    vp.dvMinZ = 0.0f;
    vp.dvMaxZ = 1.0f;
    vp.dvClipX = -1;
    vp.dvClipY = 1;
    vp.dvClipWidth = 2;
    vp.dvClipHeight = 2;

    bd->pd3dDevice->DeleteViewport(bd->pd3dViewport);

    hr_assert(bd->pd3dDevice->AddViewport(bd->pd3dViewport));
    hr_assert(bd->pd3dViewport->SetViewport2(&vp));
    hr_assert(bd->pd3dDevice->SetCurrentViewport(bd->pd3dViewport));

    auto set_render_state = [&](D3DRENDERSTATETYPE state, DWORD value) {
        DWORD prev_value = 0;
        hr_assert(bd->pd3dDevice->GetRenderState(state, &prev_value));
        if (prev_value == value)
            return;

        hr_assert(bd->pd3dDevice->SetRenderState(state, value));
        backed_up_state.render_states.emplace_back(state, prev_value);
    };

    set_render_state(D3DRENDERSTATE_SHADEMODE, D3DSHADE_GOURAUD);
    set_render_state(D3DRENDERSTATE_ZWRITEENABLE, FALSE);
    set_render_state(D3DRENDERSTATE_ALPHATESTENABLE, FALSE);
    set_render_state(D3DRENDERSTATE_CULLMODE, D3DCULL_NONE);
    set_render_state(D3DRENDERSTATE_ZENABLE, FALSE);
    set_render_state(D3DRENDERSTATE_ALPHABLENDENABLE, TRUE);
    set_render_state(D3DRENDERSTATE_SRCBLEND, D3DBLEND_SRCALPHA);
    set_render_state(D3DRENDERSTATE_DESTBLEND, D3DBLEND_INVSRCALPHA);
    set_render_state(D3DRENDERSTATE_FOGENABLE, FALSE);
    set_render_state(D3DRENDERSTATE_RANGEFOGENABLE, FALSE);
    set_render_state(D3DRENDERSTATE_SPECULARENABLE, FALSE);
    set_render_state(D3DRENDERSTATE_STENCILENABLE, FALSE);

    auto set_texture_stage_state = [&](int stage, D3DTEXTURESTAGESTATETYPE state, DWORD value) {
        DWORD prev_value = 0;
        hr_assert(bd->pd3dDevice->GetTextureStageState(stage, state, &prev_value));
        if (prev_value == value)
            return;

        hr_assert(bd->pd3dDevice->SetTextureStageState(stage, state, value));
        backed_up_state.texture_states.emplace_back(stage, state, prev_value);
    };

    set_texture_stage_state(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
    set_texture_stage_state(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
    set_texture_stage_state(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
    set_texture_stage_state(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
    set_texture_stage_state(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
    set_texture_stage_state(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
    set_texture_stage_state(1, D3DTSS_COLOROP, D3DTOP_DISABLE);
    set_texture_stage_state(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
    set_texture_stage_state(0, D3DTSS_MINFILTER, D3DTFN_LINEAR);
    set_texture_stage_state(0, D3DTSS_MAGFILTER, D3DTFG_LINEAR);

    auto set_transform = [&](D3DTRANSFORMSTATETYPE transform, D3DMATRIX* value) {
        D3DMATRIX prev_value;
        hr_assert(bd->pd3dDevice->GetTransform(transform, &prev_value));
        if (memcmp(&prev_value, value, sizeof(value)) == 0)
            return;

        hr_assert(bd->pd3dDevice->SetTransform(transform, value));
        backed_up_state.matrices.emplace_back(transform, prev_value);
    };

    // Setup orthographic projection matrix
    // Our visible imgui space lies from draw_data->DisplayPos (top left) to draw_data->DisplayPos+data_data->DisplaySize (bottom right). DisplayPos is (0,0) for single viewport apps.
    // Being agnostic of whether <d3D3D.h> or <DirectXMath.h> can be used, we aren't relying on D3DXMatrixIdentity()/D3DXMatrixOrthoOffCenterLH() or DirectX::XMMatrixIdentity()/DirectX::XMMatrixOrthographicOffCenterLH()
    {
        float L = draw_data->DisplayPos.x + 0.5f;
        float R = draw_data->DisplayPos.x + draw_data->DisplaySize.x + 0.5f;
        float T = draw_data->DisplayPos.y + 0.5f;
        float B = draw_data->DisplayPos.y + draw_data->DisplaySize.y + 0.5f;
        D3DMATRIX mat_identity = { 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f };
        D3DMATRIX mat_projection = { 2.0f / (R - L), 0.0f, 0.0f, 0.0f, 0.0f, 2.0f / (T - B), 0.0f, 0.0f, 0.0f, 0.0f, 0.5f, 0.0f, (L + R) / (L - R), (T + B) / (B - T), 0.5f, 1.0f };
        set_transform(D3DTRANSFORMSTATE_WORLD, &mat_identity);
        set_transform(D3DTRANSFORMSTATE_VIEW, &mat_identity);
        set_transform(D3DTRANSFORMSTATE_PROJECTION, &mat_projection);
    }

    return backed_up_state;
}

// Render function.
void ImGui_ImplD3D_RenderDrawData(ImDrawData* draw_data)
{
    // Avoid rendering when minimized
    if (draw_data->DisplaySize.x <= 0.0f || draw_data->DisplaySize.y <= 0.0f)
        return;

    // Create and grow buffers if needed
    ImGui_ImplD3D_Data* bd = ImGui_ImplD3D_GetBackendData();

    // Setup desired DX state
    auto backed_up_state = ImGui_ImplD3D_SetupRenderState(draw_data);

    // Allocate buffers
    ImVector<CUSTOMVERTEX> vertices;
    vertices.resize(draw_data->TotalVtxCount);

    {
        CUSTOMVERTEX* vtx_dst = vertices.begin();
        // Copy and convert all vertices into a single contiguous buffer, convert colors to D3D default format.
        // FIXME-OPT: This is a minor waste of resource, the ideal is to use imconfig.h and
        //  1) to avoid repacking colors:   #define IMGUI_USE_BGRA_PACKED_COLOR
        //  2) to avoid repacking vertices: #define IMGUI_OVERRIDE_DRAWVERT_STRUCT_LAYOUT struct ImDrawVert { ImVec2 pos; float z; ImU32 col; ImVec2 uv; }
        for (int n = 0; n < draw_data->CmdListsCount; n++)
        {
            const ImDrawList* cmd_list = draw_data->CmdLists[n];
            const ImDrawVert* vtx_src = cmd_list->VtxBuffer.Data;
            for (int i = 0; i < cmd_list->VtxBuffer.Size; i++)
            {
                vtx_dst->pos[0] = vtx_src->pos.x;
                vtx_dst->pos[1] = vtx_src->pos.y;
                vtx_dst->pos[2] = 0.0f;
                vtx_dst->col = IMGUI_COL_TO_D3D_ARGB(vtx_src->col);
                vtx_dst->uv[0] = vtx_src->uv.x;
                vtx_dst->uv[1] = vtx_src->uv.y;
                vtx_dst++;
                vtx_src++;
            }
        }
    }

    // hr_assert(bd->pd3dDevice->BeginScene());

    // Render command lists
    // (Because we merged all buffers into a single one, we maintain our own offset into them)
    int global_vtx_offset = 0;
    ImVec2 clip_off = draw_data->DisplayPos;
    for (int n = 0; n < draw_data->CmdListsCount; n++)
    {
        const ImDrawList* cmd_list = draw_data->CmdLists[n];
        for (int cmd_i = 0; cmd_i < cmd_list->CmdBuffer.Size; cmd_i++)
        {
            const ImDrawCmd* pcmd = &cmd_list->CmdBuffer[cmd_i];
            if (pcmd->UserCallback != NULL)
            {
                // User callback, registered via ImDrawList::AddCallback()
                // (ImDrawCallback_ResetRenderState is a special callback value used by the user to request the renderer to reset render state.)
                if (pcmd->UserCallback == ImDrawCallback_ResetRenderState)
                    ImGui_ImplD3D_SetupRenderState(draw_data);
                else
                    pcmd->UserCallback(cmd_list, pcmd);
            }
            else
            {
                // Project scissor/clipping rectangles into framebuffer space
                ImVec2 clip_min(pcmd->ClipRect.x - clip_off.x, pcmd->ClipRect.y - clip_off.y);
                ImVec2 clip_max(pcmd->ClipRect.z - clip_off.x, pcmd->ClipRect.w - clip_off.y);
                if (clip_max.x < clip_min.x || clip_max.y < clip_min.y)
                    continue;

                // Apply Scissor/clipping rectangle, Bind texture, Draw
                const RECT r = { (LONG)clip_min.x, (LONG)clip_min.y, (LONG)clip_max.x, (LONG)clip_max.y };
                const LPDIRECT3DTEXTURE2 texture = (LPDIRECT3DTEXTURE2)pcmd->GetTexID();
                hr_assert(bd->pd3dDevice->SetTexture(0, texture));
                // bd->pd3dDevice->SetScissorRect(&r);
                hr_assert(bd->pd3dDevice->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, D3DFVF_CUSTOMVERTEX, vertices.begin() + pcmd->VtxOffset + global_vtx_offset, (UINT)cmd_list->VtxBuffer.Size, cmd_list->IdxBuffer.Data + pcmd->IdxOffset, pcmd->ElemCount, 0));
            }
        }
        global_vtx_offset += cmd_list->VtxBuffer.Size;
    }

    for (const auto& [state, value] : backed_up_state.render_states)
        hr_assert(bd->pd3dDevice->SetRenderState(state, value));

    for (const auto& [stage, state, value] : backed_up_state.texture_states)
        hr_assert(bd->pd3dDevice->SetTextureStageState(stage, state, value));

    for (auto& [transform, value] : backed_up_state.matrices)
        hr_assert(bd->pd3dDevice->SetTransform(transform, &value));

    hr_assert(bd->pd3dDevice->SetCurrentViewport(backed_up_state.viewport));
}

void ImGui_ImplD3D_ClearZBuffer()
{
    ImGui_ImplD3D_Data* bd = ImGui_ImplD3D_GetBackendData();

    DDSURFACEDESC2 surf_desc{};
    surf_desc.dwSize = sizeof(DDSURFACEDESC2);
    hr_assert(bd->pddSurface->GetSurfaceDesc(&surf_desc));

    D3DRECT rect{};
    rect.x1 = 0;
    rect.y1 = 0;
    rect.x2 = surf_desc.dwWidth;
    rect.y2 = surf_desc.dwHeight;

    bd->pd3dDevice->DeleteViewport(bd->pd3dViewport);
    hr_assert(bd->pd3dDevice->AddViewport(bd->pd3dViewport));
    hr_assert(bd->pd3dViewport->Clear2(1, &rect, D3DCLEAR_ZBUFFER, 0, 1.0f, 0));
}

bool ImGui_ImplD3D_Init(IDirect3DDevice3* device, IDirectDrawSurface4* surface)
{
    ImGuiIO& io = ImGui::GetIO();
    IM_ASSERT(io.BackendRendererUserData == NULL && "Already initialized a renderer backend!");

    // Setup backend capabilities flags
    ImGui_ImplD3D_Data* bd = IM_NEW(ImGui_ImplD3D_Data)();
    io.BackendRendererUserData = (void*)bd;
    io.BackendRendererName = "imgui_impl_D3D";
    io.BackendFlags |= ImGuiBackendFlags_RendererHasVtxOffset; // We can honor the ImDrawCmd::VtxOffset field, allowing for large meshes.

    device->GetDirect3D(&bd->pd3d);
    hr_assert(bd->pd3d->QueryInterface(IID_IDirectDraw4, (void**)&bd->pdd));
    bd->pd3dDevice = device;
    bd->pd3dDevice->AddRef();

    bd->pddSurface = surface;
    bd->pddSurface->AddRef();

    hr_assert(bd->pd3d->CreateViewport(&bd->pd3dViewport, nullptr));

    return true;
}

void ImGui_ImplD3D_Shutdown()
{
    ImGuiIO& io = ImGui::GetIO();
    ImGui_ImplD3D_Data* bd = ImGui_ImplD3D_GetBackendData();

    ImGui_ImplD3D_InvalidateDeviceObjects();
    if (bd->pd3dDevice)
        bd->pd3dDevice->Release();
    if (bd->pdd)
        bd->pdd->Release();
    if (bd->pd3d)
        bd->pd3d->Release();
    if (bd->pd3dViewport)
        bd->pd3dViewport->Release();
    if (bd->pddSurface)
        bd->pddSurface->Release();

    io.BackendRendererName = NULL;
    io.BackendRendererUserData = NULL;
    IM_DELETE(bd);
}

static bool ImGui_ImplD3D_CreateFontsTexture()
{
    // Build texture atlas
    ImGuiIO& io = ImGui::GetIO();
    ImGui_ImplD3D_Data* bd = ImGui_ImplD3D_GetBackendData();
    unsigned char* pixels;
    int width, height, bytes_per_pixel;
    io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height, &bytes_per_pixel);

    // Convert RGBA32 to BGRA32 (because RGBA32 is not well supported by D3D devices)
#ifndef IMGUI_USE_BGRA_PACKED_COLOR
    if (io.Fonts->TexPixelsUseColors)
    {
        ImU32* dst_start = (ImU32*)ImGui::MemAlloc((size_t)width * height * bytes_per_pixel);
        for (ImU32 *src = (ImU32*)pixels, *dst = dst_start, *dst_end = dst_start + (size_t)width * height; dst < dst_end; src++, dst++)
            *dst = IMGUI_COL_TO_D3D_ARGB(*src);
        pixels = (unsigned char*)dst_start;
    }
#endif

    DDPIXELFORMAT pixel_format{};
    pixel_format.dwFlags = DDPF_RGB | DDPF_ALPHAPIXELS;
    pixel_format.dwRGBBitCount = 32;
    pixel_format.dwRBitMask = 0x00'FF'00'00;
    pixel_format.dwGBitMask = 0x00'00'FF'00;
    pixel_format.dwBBitMask = 0x00'00'00'FF;
    pixel_format.dwRGBAlphaBitMask = 0xFF'00'00'00;

    DDSURFACEDESC2 surface_desc{};
    surface_desc.dwSize = sizeof(DDSURFACEDESC2);
    surface_desc.dwFlags = DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT | DDSD_CAPS;
    surface_desc.dwHeight = height;
    surface_desc.dwWidth = width;
    surface_desc.ddpfPixelFormat = pixel_format;
    surface_desc.ddsCaps.dwCaps = DDSCAPS_TEXTURE;

    IDirectDrawSurface4* surf;
    hr_assert(bd->pdd->CreateSurface(&surface_desc, &surf, nullptr));

    hr_assert(surf->Lock(nullptr, &surface_desc, DDLOCK_WAIT, nullptr));

    for (int y = 0; y < height; y++)
        memcpy((unsigned char*)surface_desc.lpSurface + (size_t)surface_desc.lPitch * y, pixels + (size_t)width * bytes_per_pixel * y, (size_t)width * bytes_per_pixel);

    hr_assert(surf->Unlock(nullptr));

    // Upload texture to graphics system
    bd->FontTexture = nullptr;
    hr_assert(surf->QueryInterface(IID_IDirect3DTexture2, (void**)&bd->FontTexture));

    surf->Release();

    // Store our identifier
    io.Fonts->SetTexID((ImTextureID)bd->FontTexture);

#ifndef IMGUI_USE_BGRA_PACKED_COLOR
    if (io.Fonts->TexPixelsUseColors)
        ImGui::MemFree(pixels);
#endif

    return true;
}

bool ImGui_ImplD3D_CreateDeviceObjects()
{
    ImGui_ImplD3D_Data* bd = ImGui_ImplD3D_GetBackendData();
    if (!bd || !bd->pd3dDevice)
        return false;
    if (!ImGui_ImplD3D_CreateFontsTexture())
        return false;
    return true;
}

void ImGui_ImplD3D_InvalidateDeviceObjects()
{
    ImGui_ImplD3D_Data* bd = ImGui_ImplD3D_GetBackendData();
    if (!bd || !bd->pd3dDevice)
        return;
    if (bd->FontTexture)
    {
        bd->FontTexture->Release();
        bd->FontTexture = NULL;
        ImGui::GetIO().Fonts->SetTexID(NULL);
    } // We copied bd->pFontTextureView to io.Fonts->TexID so let's clear that as well.
}

void ImGui_ImplD3D_NewFrame()
{
    ImGui_ImplD3D_Data* bd = ImGui_ImplD3D_GetBackendData();
    IM_ASSERT(bd != NULL && "Did you call ImGui_ImplD3D_Init()?");

    if (!bd->FontTexture)
        ImGui_ImplD3D_CreateDeviceObjects();
}
