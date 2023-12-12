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

// 0x004880c0
int DirectDraw_GetSelectedDevice(swrDrawDevice* device)
{
    HANG("TODO");
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

// 0x00489dc0
int Direct3d_GetInterface(void)
{
    HANG("TODO");
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

// 0x0048be20
void DirectDraw_FreeDrawDevices(swrDrawDevices* devices)
{
    HANG("TODO, easy");
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
