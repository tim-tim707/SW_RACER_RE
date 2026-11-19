#include "DirectX.h"

#include "Window.h"
#include "globals.h"
#include "stdDisplay.h"

#include <macros.h>
#include <engine_config.h>

#include <string.h>

extern FILE* hook_log;

// 0x00408510
void DirectDraw_InitProgressBar(void)
{
    HANG("TODO");
}

// 0x00408620
void DirectDraw_Shutdown(void)
{
    if (iDirectDraw4_error == 0)
    {
        (*ddSurfaceForProgressBar->lpVtbl->Release)(ddSurfaceForProgressBar);
    }
}

// 0x00431C40
void DirectDraw_LockZBuffer(uint32_t* bytes_per_depth_value, LONG* pitch, LPVOID* data, float* near_, float* far_)
{
    LPDIRECTDRAWSURFACE4 zBuffer = DirectDraw_GetZBuffer();
    DDSURFACEDESC2 desc;

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    // faithful: the Lock result is not checked
    zBuffer->lpVtbl->Lock(zBuffer, NULL, &desc, DDLOCK_WAIT, NULL);
    *pitch = desc.lPitch;
    *bytes_per_depth_value = desc.ddpfPixelFormat.dwZBufferBitDepth >> 3;
    *data = desc.lpSurface;
    *near_ = rdCamera_pCurCamera->pClipFrustum->zNear;
    *far_ = rdCamera_pCurCamera->pClipFrustum->zFar;
}

// 0x00431cd0
void DirectDraw_UnlockZBuffer(void)
{
    LPDIRECTDRAWSURFACE4 This = DirectDraw_GetZBuffer();
    (*This->lpVtbl->Unlock)(This, NULL);
}

// 0x00486a10
BOOL __stdcall DirectInput_EnumDevice_Callback(LPCDIDEVICEINSTANCEA deviceInstance, LPVOID context)
{
    switch ((uint8_t)deviceInstance->dwDevType) {
    case DIDEVTYPE_MOUSE:
        if ((unsigned int)DirectInputNbMouses < STDCONTROL_MAX_MOUSE_DEVICES) {
            memcpy((char*)&DirectInputMouses + DirectInputNbMouses * STDCONTROL_JOYSTICK_RECORD_SIZE, deviceInstance, sizeof(DIDEVICEINSTANCEA));
            DirectInputNbMouses++;
        }
        break;
    case DIDEVTYPE_KEYBOARD:
        if ((unsigned int)DirectInputNbKeyboard < STDCONTROL_MAX_KEYBOARD_DEVICES) {
            memcpy((char*)&DirectInputKeyboards + DirectInputNbKeyboard * STDCONTROL_JOYSTICK_RECORD_SIZE, deviceInstance, sizeof(DIDEVICEINSTANCEA));
            DirectInputNbKeyboard = 1; // faithful: every keyboard lands in slot 0 or 1
        }
        break;
    case DIDEVTYPE_JOYSTICK:
        if ((unsigned int)stdControl_numJoystickDevices < STDCONTROL_MAX_JOYSTICK_DEVICES) {
            memcpy((char*)&DirectInputJoysticks + stdControl_numJoystickDevices * STDCONTROL_JOYSTICK_RECORD_SIZE, deviceInstance, sizeof(DIDEVICEINSTANCEA));
            stdControl_numJoystickDevices++;
        }
        break;
    }
    return DIENUM_CONTINUE;
}

// 0x00486ad0
BOOL DirectPlay_Startup(void)
{
    IDirectPlay4Vtbl* pIVar1;
    GUID* guid;
    HRESULT HVar2;
    int iVar3;
    StdCommConnection* pSVar4;
    LPVOID null_;
    DWORD zero_;

    CoInitialize(NULL);
    CoCreateInstance((IID*)&DirectPlay_GUID, NULL, 1, &IID_IDirectPlay4_GUID, (void**)&stdComm_pDirectPlay);
    stdComm_numConnections = 0;
    pSVar4 = stdComm_Connections;
    for (iVar3 = 0x460; iVar3 != 0; iVar3 = iVar3 + -1)
    {
        *(uint32_t*)pSVar4->name = 0;
        pSVar4 = (StdCommConnection*)(pSVar4->name + 2);
    }
    stdComm_bGameActive = 0;
    stdComm_bIsServer = 0;
    zero_ = 0;
    null_ = NULL;
    pIVar1 = stdComm_pDirectPlay->lpVtbl;
    guid = Window_GetGUID();
    HVar2 = (*pIVar1->EnumConnections)(stdComm_pDirectPlay, guid, DirectPlay_EnumConnectionsCallback, null_, zero_);
    return HVar2 < 0;
}

// 0x00486b40
void DirectPlay_Destroy(void)
{
    int iVar1;
    void** ppvVar2;
    unsigned int uVar3;
    StdCommConnection* pSVar4;

    if (stdComm_pDirectPlay != NULL)
    {
        (*stdComm_pDirectPlay->lpVtbl->Release)(stdComm_pDirectPlay);
        stdComm_pDirectPlay = NULL;
    }
    uVar3 = 0;
    if (stdComm_numConnections != 0)
    {
        ppvVar2 = &stdComm_Connections[0].lpConnection;
        do
        {
            if (*ppvVar2 != NULL)
            {
                (*stdPlatform_hostServices_ptr->free)(*ppvVar2);
            }
            uVar3 = uVar3 + 1;
            ppvVar2 = ppvVar2 + 0x46;
        } while (uVar3 < (unsigned int)stdComm_numConnections);
    }
    stdComm_numConnections = 0;
    pSVar4 = stdComm_Connections;
    for (iVar1 = 0x460; iVar1 != 0; iVar1 = iVar1 + -1)
    {
        *(uint32_t*)pSVar4->name = 0;
        pSVar4 = (StdCommConnection*)(pSVar4->name + 2);
    }
    stdComm_bGameActive = 0;
    stdComm_bIsServer = 0;
    CoUninitialize();
}

// 0x00487370
BOOL __stdcall DirectPlay_EnumConnectionsCallback(const GUID* lpguidSP, LPVOID lpConnection, DWORD dwConnectionSize, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext)
{
    HANG("TODO. Argument count doesnt match documentation");
    return 1;
}

// 0x004880c0
int DirectDraw_GetSelectedDevice(StdDisplayDevice* device)
{
    if (stdDisplay_numDevices == 0)
        return 1;
    *device = stdDisplay_aDisplayDevices[stdDisplay_curDevice];
    return 0;
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
    HVar1 = (*stdDisplay_lpDD->lpVtbl->GetAvailableVidMem)(stdDisplay_lpDD, &caps, total, free);
    return HVar1 != 0;
}

// 0x00488a80
IDirectDrawSurface4* DirectDraw_GetZBuffer(void)
{
    return stdDisplay_zBuffer.pDDSurf;
}

// 0x00488a90
void DirectDraw_FillMainSurface(void)
{
    DDBLTFX fx;
    HRESULT hr;

    memset(&fx, 0, sizeof(fx));
    fx.dwSize = sizeof(fx);
    fx.dwFillDepth = directDraw_BltFillColor & 0xffff;
    // clears the z-buffer; a lost surface is restored and the fill retried
    do {
        hr = stdDisplay_zBuffer.pDDSurf->lpVtbl->Blt(stdDisplay_zBuffer.pDDSurf, NULL, NULL, NULL, DDBLT_DEPTHFILL | DDBLT_WAIT, &fx);
        if (hr == DD_OK)
            return;
        if (hr == DDERR_SURFACELOST)
            hr = stdDisplay_zBuffer.pDDSurf->lpVtbl->Restore(stdDisplay_zBuffer.pDDSurf);
    } while (hr == DD_OK);
}

// 0x00488d70
BOOL __stdcall DirectDraw_EnumerateA_Callback(GUID* directDraw_guid, LPSTR driver_name, LPSTR driver_desc, LPVOID swr_unk_struct)
{
    HANG("TODO");
    return 0;
}

// 0x00488f50
HRESULT __stdcall DirectDraw_EnumDisplayModes_Callback(DDSURFACEDESC2* surfaceDesc, void* param_2)
{
    HANG("TODO");
    return 0;
}

// 0x0048a140
int Direct3d_SetFogMode(void)
{
    HRESULT hres;
    unsigned int light_result;
    unsigned int fog_result;

    if ((d3dDeviceDesc.dpcTriCaps.dwRasterCaps & 0x100) != 0)
    {
        hres = (*std3D_pD3Device->lpVtbl->SetRenderState)(std3D_pD3Device, D3DRENDERSTATE_FOGTABLEMODE, 3);
        if (hres == 0)
        {
            return 2;
        }
    }
    if ((d3dDeviceDesc.dpcTriCaps.dwRasterCaps & 0x80) != 0)
    {
        light_result = (*std3D_pD3Device->lpVtbl->SetLightState)(std3D_pD3Device, D3DLIGHTSTATE_FOGMODE, 0);
        fog_result = (*std3D_pD3Device->lpVtbl->SetRenderState)(std3D_pD3Device, D3DRENDERSTATE_FOGTABLEMODE, 0);
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
void Direct3d_ConfigFog(float r, float g, float b, float near_, float far_)
{
    // faithful: channels are not clamped, an out-of-range value spills into its neighbours
    DWORD color = (((DWORD)(int)(g * 255.0f) | (((DWORD)(int)(r * 255.0f) | 0xffffff00) << 8)) << 8) | (DWORD)(int)(b * 255.0f);

    if (std3D_pD3Device->lpVtbl->SetRenderState(std3D_pD3Device, D3DRENDERSTATE_FOGCOLOR, color) != D3D_OK)
        return;
    if (std3D_pD3Device->lpVtbl->SetRenderState(std3D_pD3Device, D3DRENDERSTATE_FOGSTART, *(DWORD*)&near_) != D3D_OK)
        return;
    std3D_pD3Device->lpVtbl->SetRenderState(std3D_pD3Device, D3DRENDERSTATE_FOGEND, *(DWORD*)&far_);
}

// 0x0048b3c0
bool Direct3d_CreateAndAttachViewport(void)
{
    HRESULT hres;
    int iVar1;
    D3DVIEWPORT2 viewport_data;

    hres = (*std3D_pDirect3D->lpVtbl->CreateViewport)(std3D_pDirect3D, &std3D_lpD3DViewPort, NULL);
    if (hres != 0)
    {
        return false;
    }
    hres = (*std3D_pD3Device->lpVtbl->AddViewport)(std3D_pD3Device, std3D_lpD3DViewPort);
    if (hres != 0)
    {
        return false;
    }
    memset(&viewport_data, 0, sizeof(viewport_data));

    // TODO: members of stdDisplay_g_backBuffer are offset by 4 bytes?
    viewport_data.dwWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    viewport_data.dvClipWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    viewport_data.dwHeight = stdDisplay_g_backBuffer.rasterInfo.height;
    viewport_data.dvClipHeight = stdDisplay_g_backBuffer.rasterInfo.height;
    viewport_data.dwSize = 0x2c;
    viewport_data.dwX = 0;
    viewport_data.dwY = 0;
    viewport_data.dvClipX = 0.0;
    viewport_data.dvClipY = 0.0;
    viewport_data.dvMinZ = 0.0;
    viewport_data.dvMaxZ = 1.0;
    hres = (*std3D_lpD3DViewPort->lpVtbl->SetViewport2)(std3D_lpD3DViewPort, &viewport_data);
    if (hres != 0)
    {
        return false;
    }
    hres = (*std3D_pD3Device->lpVtbl->SetCurrentViewport)(std3D_pD3Device, std3D_lpD3DViewPort);
    return hres == 0;
}

// 0x0048b540
HRESULT __stdcall Direct3d_EnumDevices_Callback(GUID* guid, char* description, char* name, D3DDEVICEDESC* hal_desc, D3DDEVICEDESC* hel_desc, void* ctx)
{
    HANG("TODO");
    return 0;
}

// 0x0048b770
HRESULT __stdcall Direct3d_EnumTextureFormats_Callback(DDPIXELFORMAT* format, void* ctx)
{
    HANG("TODO");
    return 0;
}

// 0x0049d39c
HRESULT DirectX_DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA* lplpDirectInput, LPUNKNOWN punkOuter)
{
    HANG("TODO");
    return DIERR_GENERIC;
}
