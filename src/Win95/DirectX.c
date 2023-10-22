#include "DirectX.h"

#include "globals.h"

// 0x00408620
void DirectDraw_Shutdown(void)
{
    if (iDirectDraw4_error == 0)
    {
        (*directDrawSurface4_ptr2->lpVtbl->Release)(directDrawSurface4_ptr2);
    }
}

// 0x00431cd0
void DirectDraw_UnlockMainSurface(void)
{
    LPDIRECTDRAWSURFACE This = DirectDraw_GetMainSurface();
    (*This->lpVtbl->Unlock)(This, NULL);
}

// 0x00485360
int DirectInput_Initialize(void)
{
    HANG("TODO");
    return 1;
}

// 0x00485f20
void DirectInput_CreateDevices(void)
{
    HANG("TODO");
}

// 0x00486a10
int DirectInput_EnumDevice_Callback(DIDEVICEINSTANCEA* deviceInstance)
{
    HANG("TODO");
    return 1;
}

// 0x00487370
BOOL DirectPlay_EnumConnectionsCallback(GUID* lpguidSP, LPVOID lpConnection, DWORD dwConnectionSize, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext)
{
    HANG("TODO. Argument count doesnt match documentation");
    return 1;
}

// 0x004874a0
int DirectPlay_EnumPlayersCallback(int a, int b, int c)
{
    HANG("TODO");
    return 0;
}

//  0x00487d20
int DirectDraw_Initialize(void)
{
    HANG("TODO");
}

//  0x00488030
void DirectDraw_ReleaseSurfacesAndFont(void)
{
    HANG("TODO");
}

//  0x00488070
int DirectDraw_GetNbDevices(void)
{
    return directDrawNbDevices;
}

//  0x00488080
int DirectDraw_GetDrawDeviceHead(unsigned int index, swrDrawDevice* drawDevice)
{
    // TODO: prettify
    int iVar1;
    swrDrawDevice* psVar2;

    if (index < directDrawNbDevices)
    {
        psVar2 = swrDrawDevices + index;
        for (iVar1 = 0xa9; iVar1 != 0; iVar1 = iVar1 + -1)
        {
            *param_2 = *(undefined4*)psVar2->driver_desc;
            psVar2 = (swrDrawDevice*)(psVar2->driver_desc + 4);
            param_2 = param_2 + 1;
        }
        return 0;
    }
    return 1;
}

// 0x00488850
int DirectDraw_CompareDisplayMode(swrDisplayMode* left, swrDisplayMode* right)
{
    int tmp_left;
    int tmp_right;

    tmp_left = left->pixelFormat;
    tmp_right = right->pixelFormat;
    if (tmp_left == tmp_right)
    {
        tmp_left = left->width;
        tmp_right = right->width;
        if (tmp_left == tmp_right)
        {
            tmp_left = left->height;
            tmp_right = right->height;
        }
    }
    return tmp_left - tmp_right;
}

// 0x00488880
bool DirectDraw_GetAvailableVidMem(LPDWORD total, LPDWORD free)
{
    HRESULT HVar1;
    DDSCAPS2 caps;

    caps.dwCaps2 = 0;
    caps.dwCaps3 = 0;
    caps.dwCaps4 = 0;
    caps.dwCaps = 0x1000;
    HVar1 = (*iDirectDraw4->lpVtbl->GetAvailableVidMem)(iDirectDraw4, &caps, total, free);
    return HVar1 != 0;
}

// 0x00488a80
IDirectDrawSurface* DirectDraw_GetMainSurface(void)
{
    return iDirectDrawSurface_ptr;
}

// 0x00488a90
void DirectDraw_FillMainSurface(void)
{
    HANG("TODO");
}

// 0x00488d10
void DirectDraw_MainSurfaceRelease(void)
{
    IDirectDraw4Vtbl* pIVar1;
    HWND hWnd;
    DWORD dwFlags;

    if (iDirectDraw4 != NULL)
    {
        pIVar1 = iDirectDraw4->lpVtbl;
        dwFlags = 8;
        hWnd = Window_GetHWND();
        (*pIVar1->SetCooperativeLevel)(iDirectDraw4, hWnd, dwFlags);
        (*iDirectDraw4->lpVtbl->RestoreDisplayMode)(iDirectDraw4);
        (*iDirectDraw4->lpVtbl->Release)(iDirectDraw4);
        iDirectDraw4 = NULL;
    }
    DirectDraw_CooperativeLevel = 8;
    directDrawNbDisplayModes = 0;
}

// 0x00488d70
WINBOOL DirectDraw_EnumerateA_Callback(GUID* directDraw_guid, LPSTR driver_name, LPSTR driver_desc, LPVOID swr_unk_struct)
{
    HANG("TODO");
    return 0;
}

// 0x00488f50
HRESULT DirectDraw_EnumDisplayModes_Callback(DDSURFACEDESC* surfaceDesc, void* param_2)
{
    HANG("TODO");
    return 0;
}

// 0x00489260
IDirectDraw* DirectDraw_GetDirectDrawInterface(void)
{
    return iDirectDraw4;
}

//  0x004899a0
void DirectDraw_ReleaseSurfaces(void)
{
    HANG("TODO");
}

// 0x00489d40
int DirectDraw_GetNbDisplayModes(void)
{
    return directDrawNbDisplayModes;
}

// 0x00489d50
int DirectDraw_GetDisplayModeHead(unsigned int index, swrDisplayMode* displayMode)
{
    // TODO: prettify
    int iVar1;
    swrDisplayMode* psVar2;

    if (index < directDrawNbDisplayModes)
    {
        psVar2 = swrDisplayModes + index;
        for (iVar1 = 0x14; iVar1 != 0; iVar1 = iVar1 + -1)
        {
            displayMode->aspectRatio = (psVar2->h).aspectRatio;
            psVar2 = (swrDisplayMode*)&(psVar2->h).width;
            displayMode = (swrDisplayModeHead*)&displayMode->width;
        }
        return 0;
    }
    return 1;
}

// 0x00489eb0
swr3DDevice* Direct3d_GetDevices(void)
{
    return swr3DDevices;
}

// 0x0048a140
int Direct3d_SetFogMode(void)
{
    HRESULT hres;
    unsigned int light_result;
    unsigned int fog_result;

    if ((d3dDeviceDesc.dpcTriCaps.dwRasterCaps & 0x100) != 0)
    {
        hres = (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_FOGTABLEMODE, 3);
        if (hres == 0)
        {
            return 2;
        }
    }
    if ((d3dDeviceDesc.dpcTriCaps.dwRasterCaps & 0x80) != 0)
    {
        light_result = (*iDirect3DDevice3_ptr->lpVtbl->SetLightState)(iDirect3DDevice3_ptr, D3DLIGHTSTATE_FOGMODE, 0);
        fog_result = (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_FOGTABLEMODE, 0);
        if ((light_result | fog_result) == 0)
        {
            return 1;
        }
    }
    return 0;
}

// 0x0048a1a0
int Direct3d_IsLensflareCompatible(void)
{
    return (d3dDeviceDesc.dpcTriCaps.dwTextureBlendCaps & 0xff) >> 3 & 1;
}

// 0x0048a2f0
int Direct3d_GetNbTextureFormats(void)
{
    return Direct3D_NbTextureFormats;
}

// 0x0048a350
void Direct3d_DrawIndexedTriangleList(IDirect3DTexture2* texture, int renderstate, void* vertices, unsigned int NumVertices, WORD* indices, DWORD indexCount)
{
    HRESULT hres;

    if (NumVertices <= d3dMaxVertices)
    {
        Direct3d_SetRenderState(renderstate);
        if (texture != d3dCurrentTexture)
        {
            hres = (*iDirect3DDevice3_ptr->lpVtbl->SetTexture)(iDirect3DDevice3_ptr, 0, texture);
            if (hres == 0)
            {
                d3dCurrentTexture = texture;
            }
        }
        // flags long lost to time pepehands
        (*iDirect3DDevice3_ptr->lpVtbl->DrawIndexedPrimitive)(iDirect3DDevice3_ptr, D3DPT_TRIANGLELIST, 0x1c4, vertices, NumVertices, indices, indexCount, 0x18);
    }
    return;
}

// 0x0048a300
void Direct3d_BeginScene(void)
{
    d3d_CurrentScene = d3d_CurrentScene + 1;
    (*iDirect3DDevice3_ptr->lpVtbl->BeginScene)(iDirect3DDevice3_ptr);
    d3dCurrentTexture = NULL;
}

// 0x0048a330
void Direct3d_EndScene(void)
{
    (*iDirect3DDevice3_ptr->lpVtbl->EndScene)(iDirect3DDevice3_ptr);
    d3dCurrentTexture = NULL;
}

// 0x0048a3c0
void Direct3d_ClearRenderState(void)
{
    HRESULT hres;

    Direct3d_SetRenderState(d3dRenderState & 0xffff79ff);
    hres = (*iDirect3DDevice3_ptr->lpVtbl->SetTexture)(iDirect3DDevice3_ptr, 0, NULL);
    if (hres == NULL)
    {
        d3dCurrentTexture = NULL;
    }

    return;
}

// 0x0048a3f0
void Direct3d_DrawLineStrip(void* vertices, unsigned int vertex_count)
{
    if (vertex_count <= d3dMaxVertices)
    {
        (*iDirect3DDevice3_ptr->lpVtbl->DrawPrimitive)(iDirect3DDevice3_ptr, D3DPT_LINESTRIP, 0x1c4, vertices, vertex_count, 4);
    }
}

// 0x0048a420
void Direct3d_DrawPointList(void* vertices, unsigned int vertex_count)
{
    if (vertex_count <= d3dMaxVertices)
    {
        (*iDirect3DDevice3_ptr->lpVtbl->DrawPrimitive)(iDirect3DDevice3_ptr, D3DPT_POINTLIST, 0x1c4, vertices, vertex_count, 4);
    }
}

// 0x0048a450
void Direct3d_SetRenderState(unsigned int new_renderstate)
{
    unsigned int tmp;

    if (d3dRenderState != new_renderstate)
    {
        if (((new_renderstate ^ d3dRenderState) & 0x600) != 0)
        {
            if ((new_renderstate & 0x400) == 0)
            {
                if ((new_renderstate & 0x200) == 0)
                {
                    (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_ALPHABLENDENABLE, 0);
                }
                else
                {
                    (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_ALPHABLENDENABLE, 1);
                    (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_TEXTUREMAPBLEND, 2);
                }
            }
            else
            {
                (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_ALPHABLENDENABLE, 1);
                (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_TEXTUREMAPBLEND, 4);
            }
        }
        if (((new_renderstate ^ d3dRenderState) & 0x2000) != 0)
        {
            if ((new_renderstate & 0x2000) == 0)
            {
                (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_ZWRITEENABLE, 1);
            }
            else
            {
                (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_ZWRITEENABLE, 0);
            }
        }
        if (((new_renderstate ^ d3dRenderState) & 0x800) != 0)
        {
            if ((new_renderstate & 0x800) == 0)
            {
                (*iDirect3DDevice3_ptr->lpVtbl->SetTextureStageState)(iDirect3DDevice3_ptr, 0, D3DTSS_ADDRESSU, 1);
            }
            else
            {
                (*iDirect3DDevice3_ptr->lpVtbl->SetTextureStageState)(iDirect3DDevice3_ptr, 0, D3DTSS_ADDRESSU, 3);
            }
        }
        if (((new_renderstate ^ d3dRenderState) & 0x1000) != 0)
        {
            if ((new_renderstate & 0x1000) == 0)
            {
                (*iDirect3DDevice3_ptr->lpVtbl->SetTextureStageState)(iDirect3DDevice3_ptr, 0, D3DTSS_ADDRESSV, 1);
            }
            else
            {
                (*iDirect3DDevice3_ptr->lpVtbl->SetTextureStageState)(iDirect3DDevice3_ptr, 0, D3DTSS_ADDRESSV, 3);
            }
        }
        if (((new_renderstate ^ d3dRenderState) & 0x8000) != 0)
        {
            if (((new_renderstate & 0x8000) == 0) || (d3d_FogEnabled == 0))
            {
                (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_FOGENABLE, 0);
            }
            else
            {
                (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_FOGENABLE, 1);
            }
        }
        tmp = new_renderstate ^ d3dRenderState;
        if ((tmp & 0x80) != 0)
        {
            d3dRenderState = new_renderstate;
            Direct3d_SetTextureStageState();
            if (tmp != 0)
            {
                return;
            }
        }
        d3dRenderState = new_renderstate;
    }
    return;
}

// 0x0048aeb0
bool Direct3d_InitRenderState(void)
{
    HANG("TODO");
    return false;
}

// 0x0048b1b0
void Direct3d_SetTextureStageState(void)
{
    HRESULT hres;
    int zero;

    if (((char)d3dRenderState & 0x80) == 0)
    {
        hres = (*iDirect3DDevice3_ptr->lpVtbl->SetTextureStageState)(iDirect3DDevice3_ptr, 0, D3DTSS_MAGFILTER, 1);
        if (hres != 0)
        {
            return;
        }
        zero = 0;
        hres = (*iDirect3DDevice3_ptr->lpVtbl->SetTextureStageState)(iDirect3DDevice3_ptr, 0, D3DTSS_MINFILTER, 1);
        if (hres != 0)
        {
            return;
        }
    }
    else
    {
        hres = (*iDirect3DDevice3_ptr->lpVtbl->SetTextureStageState)(iDirect3DDevice3_ptr, 0, D3DTSS_MAGFILTER, 2);
        if (hres != 0)
        {
            return;
        }
        zero = 0;
        hres = (*iDirect3DDevice3_ptr->lpVtbl->SetTextureStageState)(iDirect3DDevice3_ptr, 0, D3DTSS_MINFILTER, 2);
        if (hres != 0)
        {
            return;
        }
    }
    d3dMipFilter = zero;
    if (d3dMipFilter == 1)
    {
        (*iDirect3DDevice3_ptr->lpVtbl->SetTextureStageState)(iDirect3DDevice3_ptr, 0, D3DTSS_MIPFILTER, 2);
        return;
    }
    if (d3dMipFilter == 2)
    {
        (*iDirect3DDevice3_ptr->lpVtbl->SetRenderState)(iDirect3DDevice3_ptr, D3DRENDERSTATE_TEXTUREMIN, 3);
        return;
    }
    (*iDirect3DDevice3_ptr->lpVtbl->SetTextureStageState)(iDirect3DDevice3_ptr, 0, D3DTSS_MIPFILTER, 1);
    return;
}

// 0x0048b260
HRESULT Direct3d_SetTransformProjection(float fov, float aspect_ratio, float clip_y, float clip_z)
{
    HRESULT hres;
    int iVar1;
    D3DMATRIX* pDVar2;
    float cos_fov;
    float sin_fov;
    D3DMATRIX mat;

    if (fabs(clip_z - clip_y) < 0.01)
    {
        return -0x7ff8ffa9;
    }
    sin_fov = fsin(fov * 0.5);
    if (fabs(sin_fov) < 0.009999999776482582)
    {
        return -0x7ff8ffa9;
    }
    cos_fov = fcos(fov * 0.5);
    pDVar2 = &mat;
    for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1)
    {
        pDVar2->_11 = 0.0;
        pDVar2 = (D3DMATRIX*)&pDVar2->_12;
    }
    mat._33 = clip_z / (clip_z - clip_y);
    mat._11 = aspect_ratio * (cos_fov / sin_fov);
    mat._22 = (cos_fov / sin_fov);
    mat._43 = -(mat._33 * clip_y);
    mat._34 = 1.0;
    hres = (*iDirect3DDevice3_ptr->lpVtbl->SetTransform)(iDirect3DDevice3_ptr, D3DTRANSFORMSTATE_PROJECTION, &mat);
    return hres;
}

// 0x0048b340
void Direct3d_ConfigFog(DWORD renderstate, float p2, float p3, float p4)
{
    HANG("TODO");
}

// 0x0048b3c0
bool Direct3d_CreateAndAttachViewport(void)
{
    HRESULT hres;
    int iVar1;
    D3DVIEWPORT2 viewport_data;

    hres = (*iDirect3D3_ptr->lpVtbl->CreateViewport)(iDirect3D3_ptr, &iDirect3DViewport_ptr, NULL);
    if (hres != 0)
    {
        return false;
    }
    hres = (*iDirect3DDevice3_ptr->lpVtbl->AddViewport)(iDirect3DDevice3_ptr, iDirect3DViewport_ptr);
    if (hres != 0)
    {
        return false;
    }
    memset(&viewport_data, 0, sizeof(viewport_data));

    viewport_data.dwWidth = stdVBuffer_main.format.height;
    viewport_data.dvClipWidth = (D3DVALUE)stdVBuffer_main.format.height;
    viewport_data.dwHeight = stdVBuffer_main.format.texture_size_in_bytes;
    viewport_data.dvClipHeight = (D3DVALUE)stdVBuffer_main.format.texture_size_in_bytes;
    viewport_data.dwSize = 0x2c;
    viewport_data.dwX = 0;
    viewport_data.dwY = 0;
    viewport_data.dvClipX = 0.0;
    viewport_data.dvClipY = 0.0;
    viewport_data.dvMinZ = 0.0;
    viewport_data.dvMaxZ = 1.0;
    hres = (*iDirect3DViewport_ptr->lpVtbl->SetViewport2)(iDirect3DViewport_ptr, &viewport_data);
    if (hres != 0)
    {
        return false;
    }
    hres = (*iDirect3DDevice3_ptr->lpVtbl->SetCurrentViewport)(iDirect3DDevice3_ptr, iDirect3DViewport_ptr);
    return hres == 0;
}

//  0x0048b4b0
void Direct3d_EnumZBufferFormats(void* ctx)
{
    HANG("TODO");
}

// 0x0048db40
void Direct3d_InitializeVertexBuffer(void)
{
    HANG("TODO easy");
}

// 0x0048b500
HRESULT Direct3d_EnumZBufferFormats_Callback(DDPIXELFORMAT* format, void* ctx)
{
    HANG("TODO");
    return 0;
}

// 0x0048b540
HRESULT Direct3d_EnumDevices_Callback(GUID* guid, char* description, char* name, D3DDEVICEDESC* hal_desc, D3DDEVICEDESC* hel_desc, void* ctx)
{
    HANG("TODO");
    return 0;
}

// 0x0048b770
HRESULT Direct3d_EnumTextureFormats_Callback(DDPIXELFORMAT* format, void* ctx)
{
    HANG("TODO");
    return 0;
}
