#include "DirectX.h"

#include "Window.h"
#include "globals.h"
#include "stdDisplay.h"
#include "std.h"

#include <macros.h>
#include <engine_config.h>

#include <string.h>

extern FILE* hook_log;

// Inlined in every DirectX pixel-format reader: shift to the mask's low bit, then count its width.
static void DirectX_ChannelFromMask(DWORD mask, int* posShift, int* shr, int* bits)
{
    DWORD m = mask;
    int n = 0;
    while ((m & 1) == 0) {
        m >>= 1;
        n++;
    }
    *posShift = n;
    *shr = stdCalcBitPos(0xff / (mask >> n));
    n = 0;
    while ((m & 1) != 0) {
        m >>= 1;
        n++;
    }
    *bits = n;
}

// 0x00408510
void DirectDraw_InitProgressBar(void)
{
    DDBLTFX bltfx;

    memset(&ddSurfaceDescForProgressBar, 0, sizeof(ddSurfaceDescForProgressBar));
    ddSurfaceDescForProgressBar.dwSize = sizeof(DDSURFACEDESC2);
    ddSurfaceDescForProgressBar.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH;
    ddSurfaceDescForProgressBar.dwWidth = 8;
    ddSurfaceDescForProgressBar.dwHeight = 8;
    ddSurfaceDescForProgressBar.ddsCaps.dwCaps = DDSCAPS_SYSTEMMEMORY;
    if (IDirectDraw4_CreateSurface(std3D_pDirectDraw, &ddSurfaceDescForProgressBar, &ddSurfaceForProgressBar, NULL) != DD_OK) {
        iDirectDraw4_error = 1;
        return;
    }
    swrUI_progressBarX = (int)((float)(unsigned int)stdDisplay_g_frontBuffer.rasterInfo.width * 0.33333334f);
    swrUI_progressBarWidth = swrUI_progressBarX;
    swrUI_progressBarY = stdDisplay_g_frontBuffer.rasterInfo.height - ((unsigned int)stdDisplay_g_frontBuffer.rasterInfo.height >> 3);
    memset(&bltfx, 0, sizeof(bltfx));
    swrUI_progressBarHeight = 10;
    bltfx.dwSize = sizeof(DDBLTFX);
    bltfx.dwFillColor = 0xff;
    IDirectDrawSurface4_Blt(ddSurfaceForProgressBar, NULL, NULL, NULL, DDBLT_COLORFILL | DDBLT_WAIT, &bltfx);
    tagRect.top = 0;
    tagRect.left = 0;
    iDirectDraw4_error = 0;
    tagRect.right = 8;
    tagRect.bottom = 8;
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
    StdCommConnection* connection;

    if (stdComm_numConnections == STDCOMM_MAX_CONNECTIONS)
        return 0;

    connection = &stdComm_Connections[stdComm_numConnections];
    wcsncpy(connection->name, lpName->lpszShortName, 127);
    connection->name[127] = 0;
    connection->guid = *lpguidSP;
    connection->lpConnection = stdPlatform_hostServices_ptr->alloc(dwConnectionSize);
    memcpy(connection->lpConnection, lpConnection, dwConnectionSize);
    connection->lpConnectionSize = dwConnectionSize;
    stdComm_numConnections++;
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
    StdDisplayDevice* device;
    LPDIRECTDRAW directDraw;

    directDraw = NULL;
    if ((unsigned int)stdDisplay_numDevices >= STD_DISPLAY_MAX_DEVICES)
        return 0;

    device = &stdDisplay_aDisplayDevices[stdDisplay_numDevices];
    if (directDraw_guid != NULL) {
        device->guid = *directDraw_guid;
        device->bGuidNotSet = 0;
    } else {
        memset(&device->guid, 0, sizeof(device->guid));
        device->bGuidNotSet = 1;
    }
    strncpy(device->aDriverName, driver_name, sizeof(device->aDriverName) - 1);
    device->aDriverName[sizeof(device->aDriverName) - 1] = '\0';
    strncpy(device->aDeviceName, driver_desc, sizeof(device->aDeviceName) - 1);
    device->aDeviceName[sizeof(device->aDeviceName) - 1] = '\0';
    device->bHasGuid = directDraw_guid != NULL;

    if (DirectX_DirectDrawCreate(directDraw_guid, &directDraw, NULL) != DD_OK) {
        MessageBoxA(NULL, "DirectDraw Failure\n\nCheck the DesktopResolution\n", "Racer Error", MB_OK);
        return 1;
    }
    // faithful: this failure path (and the DDSCL_NORMAL one below) leaks the DirectDraw object
    if (IDirectDraw_SetCooperativeLevel(directDraw, Window_GetHWND(), DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN) != DD_OK)
        return 0;

    memset(&device->ddcaps, 0, sizeof(device->ddcaps));
    device->ddcaps.dwSize = sizeof(device->ddcaps);
    if (IDirectDraw_GetCaps(directDraw, (LPDDCAPS)&device->ddcaps, NULL) != DD_OK) {
        IDirectDraw_Release(directDraw);
        return 1;
    }
    device->bWindowRenderNotSupported = (device->ddcaps.dwCaps2 & DDCAPS2_CANRENDERWINDOWED) == 0;
    device->b3DAccel = (device->ddcaps.dwCaps & DDCAPS_3D) != 0;
    device->totalVideoMemory = device->ddcaps.dwVidMemTotal;
    device->freeVideoMemory = device->ddcaps.dwVidMemFree;
    if (IDirectDraw_SetCooperativeLevel(directDraw, Window_GetHWND(), DDSCL_NORMAL) != DD_OK)
        return 0;
    IDirectDraw_Release(directDraw);
    if (device->b3DAccel == 1)
        stdDisplay_numDevices++;
    return 1;
}

// 0x00488f50
HRESULT __stdcall DirectDraw_EnumDisplayModes_Callback(DDSURFACEDESC2* surfaceDesc, void* param_2)
{
    StdVideoMode* mode;
    ColorInfo* color;
    int pixels;

    if ((unsigned int)stdDisplay_numVideoModes >= STD_DISPLAY_MAX_VIDEO_MODES)
        return DDENUMRET_CANCEL;

    if (directDrawSpecialDeviceId == 1 && !(surfaceDesc->dwWidth == 512 && surfaceDesc->dwHeight == 384) && !(surfaceDesc->dwWidth == 640 && surfaceDesc->dwHeight == 480) && !(surfaceDesc->dwWidth == 800 && surfaceDesc->dwHeight == 600))
        return DDENUMRET_OK;

    mode = &stdDisplay_aVideoModes[stdDisplay_numVideoModes];
    mode->rasterInfo.width = surfaceDesc->dwWidth;
    mode->rasterInfo.height = surfaceDesc->dwHeight;
    mode->rasterInfo.rowSize = surfaceDesc->lPitch;
    if ((mode->rasterInfo.width == 320 && mode->rasterInfo.height == 200) || (mode->rasterInfo.width == 640 && mode->rasterInfo.height == 400)) {
        mode->aspectRatio = 0.75f;
    } else {
        mode->aspectRatio = 1.0f;
    }

    color = &mode->rasterInfo.colorInfo;
    if (surfaceDesc->ddpfPixelFormat.dwFlags & DDPF_PALETTEINDEXED8) {
        color->colorMode = T_STDCOLOR_PAL;
        color->bpp = 8;
        color->redBPP = 0;
        color->greenBPP = 0;
        color->blueBPP = 0;
    } else if (surfaceDesc->ddpfPixelFormat.dwFlags & DDPF_RGB) {
        color->colorMode = T_STDCOLOR_RGB;
        color->bpp = surfaceDesc->ddpfPixelFormat.dwRGBBitCount;
        DirectX_ChannelFromMask(surfaceDesc->ddpfPixelFormat.dwRBitMask, &color->redPosShift, &color->RedShr, &color->redBPP);
        DirectX_ChannelFromMask(surfaceDesc->ddpfPixelFormat.dwGBitMask, &color->greenPosShift, &color->GreenShr, &color->greenBPP);
        DirectX_ChannelFromMask(surfaceDesc->ddpfPixelFormat.dwBBitMask, &color->bluePosShift, &color->BlueShr, &color->blueBPP);
    }

    switch (color->bpp) {
    // faithful: only 16-bit modes are listed (the 8/24/32 row widths are computed and discarded)
    case 8:
    case 24:
    case 32:
        return DDENUMRET_OK;
    case 16:
        mode->rasterInfo.rowWidth = (unsigned int)mode->rasterInfo.rowSize >> 1;
        break;
    }

    pixels = mode->rasterInfo.width * mode->rasterInfo.height;
    mode->rasterInfo.size = ((unsigned int)color->bpp >> 3) * pixels;
    if ((unsigned int)directDrawVidMemTotal >= (unsigned int)((pixels + mode->rasterInfo.size) * 2))
        stdDisplay_numVideoModes++;
    return DDENUMRET_OK;
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
    StdDisplayDevice displayDevice;
    Device3D* device;
    DWORD textureCaps;
    DWORD shadeCaps;

    if (guid == NULL || hal_desc == NULL || hel_desc == NULL)
        return D3DENUMRET_CANCEL;
    if (memcmp(guid, &IID_IDirect3DNullDevice, sizeof(GUID)) == 0)
        return D3DENUMRET_OK;
    if ((unsigned int)std3D_numDevices >= STD3D_MAX_DEVICES)
        return D3DENUMRET_CANCEL;

    device = &std3D_aDevices[std3D_numDevices];
    device->duid = *guid;
    strncpy(device->deviceDescription, description, sizeof(device->deviceDescription) - 1);
    device->deviceDescription[sizeof(device->deviceDescription) - 1] = '\0';
    strncpy(device->deviceName, name, sizeof(device->deviceName) - 1);
    device->deviceName[sizeof(device->deviceName) - 1] = '\0';
    device->caps.bHAL = hal_desc->dwFlags != 0;
    if (!device->caps.bHAL)
        return D3DENUMRET_OK;

    device->d3dDesc = *hal_desc;
    if (DirectDraw_GetSelectedDevice(&displayDevice) != 0)
        return D3DENUMRET_CANCEL;
    if (displayDevice.bWindowRenderNotSupported == 0 && device->caps.bHAL == 0)
        return D3DENUMRET_OK;

    textureCaps = device->d3dDesc.dpcTriCaps.dwTextureCaps;
    device->caps.bTexturePerspectiveSupported = textureCaps & D3DPTEXTURECAPS_PERSPECTIVE;
    device->caps.hasZBuffer = device->d3dDesc.dwDeviceZBufferBitDepth != 0;
    device->caps.bSqareOnlyTexture = (textureCaps & D3DPTEXTURECAPS_SQUAREONLY) != 0;
    device->caps.bAlphaTextureSupported = (textureCaps & D3DPTEXTURECAPS_ALPHA) != 0;
    shadeCaps = device->d3dDesc.dpcTriCaps.dwShadeCaps;
    if ((shadeCaps & D3DPSHADECAPS_ALPHAFLATBLEND) == 0 && (shadeCaps & D3DPSHADECAPS_ALPHAFLATSTIPPLED) != 0) {
        device->caps.bStippledShadeSupported = 1;
    } else {
        device->caps.bStippledShadeSupported = 0;
    }
    if (((device->d3dDesc.dpcTriCaps.dwTextureBlendCaps & D3DPTBLENDCAPS_MODULATE) && (shadeCaps & D3DPSHADECAPS_ALPHAGOURAUDBLEND)) || device->caps.bStippledShadeSupported != 0) {
        device->caps.bAlphaBlendSupported = 1;
    } else {
        device->caps.bAlphaBlendSupported = 0;
    }
    device->caps.bColorkeyTextureSupported = (textureCaps & D3DPTEXTURECAPS_TRANSPARENCY) != 0;

    if (device->d3dDesc.dwMinTextureWidth == 0) {
        device->caps.minTexWidth = 16;
        device->caps.minTexHeight = 16;
        device->caps.maxTexWidth = 256;
        device->caps.maxTexHeight = 256;
    } else {
        device->caps.minTexWidth = device->d3dDesc.dwMinTextureWidth;
        device->caps.minTexHeight = device->d3dDesc.dwMinTextureHeight;
        device->caps.maxTexWidth = device->d3dDesc.dwMaxTextureWidth;
        device->caps.maxTexHeight = device->d3dDesc.dwMaxTextureHeight;
    }
    device->caps.maxVertexCount = device->d3dDesc.dwMaxVertexCount;
    std3D_numDevices++;
    return D3DENUMRET_OK;
}

// 0x0048b770
HRESULT __stdcall Direct3d_EnumTextureFormats_Callback(DDPIXELFORMAT* format, void* ctx)
{
    stdTextureFormat* texFormat;
    ColorInfo* color;

    if ((unsigned int)std3D_numTextureFormats >= STD3D_MAX_TEXTURE_FORMATS)
        return D3DENUMRET_CANCEL;

    texFormat = &std3D_aTextureFormats[std3D_numTextureFormats];
    texFormat->pixelFormat = *format;
    if ((format->dwFlags & (DDPF_ALPHA | DDPF_FOURCC | DDPF_PALETTEINDEXED4 | DDPF_PALETTEINDEXED8)) != 0 || (format->dwFlags & (DDPF_PALETTEINDEXED1 | DDPF_PALETTEINDEXED2 | DDPF_LUMINANCE | DDPF_BUMPDUDV)) != 0)
        return D3DENUMRET_OK;

    color = &texFormat->texFormat;
    if (format->dwFlags & DDPF_ALPHAPIXELS) {
        std3D_bHasRGBTextureFormat = 1;
        color->colorMode = T_STDCOLOR_RGBA;
        color->bpp = format->dwRGBBitCount;
        DirectX_ChannelFromMask(format->dwRBitMask, &color->redPosShift, &color->RedShr, &color->redBPP);
        DirectX_ChannelFromMask(format->dwGBitMask, &color->greenPosShift, &color->GreenShr, &color->greenBPP);
        DirectX_ChannelFromMask(format->dwBBitMask, &color->bluePosShift, &color->BlueShr, &color->blueBPP);
        DirectX_ChannelFromMask(format->dwRGBAlphaBitMask, &color->alphaPosShift, &color->AlphaShr, &color->alphaBPP);
    } else {
        if ((format->dwFlags & DDPF_RGB) == 0)
            return D3DENUMRET_OK;
        std3D_bHasRGBTextureFormat = 1;
        color->colorMode = T_STDCOLOR_RGB;
        color->bpp = format->dwRGBBitCount;
        DirectX_ChannelFromMask(format->dwRBitMask, &color->redPosShift, &color->RedShr, &color->redBPP);
        DirectX_ChannelFromMask(format->dwGBitMask, &color->greenPosShift, &color->GreenShr, &color->greenBPP);
        DirectX_ChannelFromMask(format->dwBBitMask, &color->bluePosShift, &color->BlueShr, &color->blueBPP);
        color->alphaPosShift = 0;
        color->AlphaShr = 0;
        color->alphaBPP = 0;
    }
    std3D_numTextureFormats++;
    return D3DENUMRET_OK;
}

// 0x0049d390
HRESULT __stdcall DirectX_DirectDrawEnumerateA(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext)
{
    return DirectDrawEnumerateA(lpCallback, lpContext);
}

// 0x0049d396
HRESULT __stdcall DirectX_DirectDrawCreate(GUID* lpGuid, LPDIRECTDRAW* lplpDD, IUnknown* pUnkOuter)
{
    return DirectDrawCreate(lpGuid, lplpDD, pUnkOuter);
}

// 0x0049d39c
HRESULT DirectX_DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA* lplpDirectInput, LPUNKNOWN punkOuter)
{
    HANG("TODO");
    return DIERR_GENERIC;
}
