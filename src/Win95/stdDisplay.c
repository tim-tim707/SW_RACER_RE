#include "stdDisplay.h"

#include "DirectX.h"
#include "Window.h"
#include "globals.h"

#include <macros.h>
#include <string.h>
#include <stdPlatform.h>
#include <General/stdBmp.h>
#include <General/stdColor.h>
#include "std.h"

// Inlined in every DirectDraw pixel-format reader: shift to the mask's low bit, then count its width.
static void stdDisplay_ChannelFromMask(DWORD mask, int* posShift, int* shr, int* bits)
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

static void stdDisplay_ColorInfoFromRGBMasks(ColorInfo* color, const DDPIXELFORMAT* format)
{
    color->colorMode = T_STDCOLOR_RGB;
    color->bpp = format->dwRGBBitCount;
    stdDisplay_ChannelFromMask(format->dwRBitMask, &color->redPosShift, &color->RedShr, &color->redBPP);
    stdDisplay_ChannelFromMask(format->dwGBitMask, &color->greenPosShift, &color->GreenShr, &color->greenBPP);
    stdDisplay_ChannelFromMask(format->dwBBitMask, &color->bluePosShift, &color->BlueShr, &color->blueBPP);
}

// 0x00487d20
int stdDisplay_Startup(void)
{
    if (stdDisplay_bStartup)
        return 1;

    stdDisplay_g_frontBuffer = (tVBuffer){ 0 };
    stdDisplay_g_backBuffer = (tVBuffer){ 0 };
    stdDisplay_zBuffer = (tVSurface){ 0 };
    stdDisplay_bStartup = 1;
    stdDisplay_numDevices = 0;
    if (DirectDrawEnumerateA(DirectDraw_EnumerateA_Callback, NULL) != S_OK)
        return 0;
    stdDisplay_primaryVideoMode.rasterInfo.width = 640;
    stdDisplay_primaryVideoMode.rasterInfo.height = 480;

    return 1;
}

// 0x00487da0
void stdDisplay_Shutdown(void)
{
    if (stdDisplay_bOpen)
        stdDisplay_Close();

    stdDisplay_numVideoModes = 0;
    memset(stdDisplay_aDisplayDevices, 0, sizeof(stdDisplay_aDisplayDevices));
    memset(&stdDisplay_g_frontBuffer, 0, sizeof(stdDisplay_g_frontBuffer));
    memset(&stdDisplay_g_backBuffer, 0, sizeof(stdDisplay_g_backBuffer));
    memset(&stdDisplay_zBuffer, 0, sizeof(stdDisplay_zBuffer));
    stdDisplay_pCurVideMode = 0;
    stdDisplay_numDevices = 0;
    stdDisplay_bStartup = 0;
}

// 0x00487e00
int stdDisplay_Open(int deviceNum)
{
    if (stdDisplay_bOpen)
        stdDisplay_Close();

    if (deviceNum >= stdDisplay_numDevices)
        return 0;

    stdDisplay_curDevice = deviceNum;
    stdDisplay_pcurDevice = &stdDisplay_aDisplayDevices[deviceNum];
    if (!stdDisplay_InitDirectDraw(Window_GetHWND()))
        return 0;

    qsort(stdDisplay_aVideoModes, stdDisplay_numVideoModes, sizeof(StdVideoMode), (int (*)(const void*, const void*))stdDisplay_VideoModeCompare);
    stdDisplay_bOpen = 1;
    return 1;
}

// 0x00487e80
void stdDisplay_Close(void)
{
    if (!stdDisplay_bStartup || !stdDisplay_bOpen)
        return;

    if (stdDisplay_bModeSet)
        stdDisplay_ClearMode();

    stdDisplay_ReleaseDirectDraw();
    stdDisplay_curDevice = 0;
    memset(&stdDisplay_g_frontBuffer, 0, sizeof(stdDisplay_g_frontBuffer));
    memset(&stdDisplay_g_backBuffer, 0, sizeof(stdDisplay_g_backBuffer));
    memset(&stdDisplay_zBuffer, 0, sizeof(stdDisplay_zBuffer));
    stdDisplay_pcurDevice = 0;
    stdDisplay_FillMainSurface_ptr = (void (*)())stdPlatform_noop;
    stdDisplay_bOpen = 0;
}

// 0x00487f00
int stdDisplay_SetMode(int modeNum, int bFullscreen)
{
    if (bFullscreen && modeNum >= stdDisplay_numVideoModes)
        return 0;

    if (stdDisplay_bModeSet)
        stdDisplay_ClearMode();

    if (bFullscreen) {
        stdDisplay_pCurVideMode = &stdDisplay_aVideoModes[modeNum];
        if (!stdDisplay_SetFullscreenMode(Window_GetHWND(), &stdDisplay_aVideoModes[modeNum]))
            return 0;
    } else {
        stdDisplay_pCurVideMode = &stdDisplay_primaryVideoMode;
        if (!stdDisplay_SetWindowMode(Window_GetHWND(), &stdDisplay_primaryVideoMode))
            return 0;
    }
    stdDisplay_hFont = CreateFontA(stdDisplay_pCurVideMode->rasterInfo.width < 640u ? 12 : 24, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 2u, "Arial");

    // those 2 global vars are only used in this one function.
    // dword_529568 = 0;
    // dword_52956C = 0;
    stdDisplay_backbufWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    stdDisplay_backbufHeight = stdDisplay_g_backBuffer.rasterInfo.height;
    stdDisplay_bModeSet = 1;
    stdDisplay_bFullscreen = bFullscreen;
    stdDisplay_VBufferFill(&stdDisplay_g_backBuffer, 0, 0);
    stdDisplay_Update();
    if (bFullscreen)
        stdDisplay_VBufferFill(&stdDisplay_g_backBuffer, 0, 0);
    return 1;
}

// 0x00488030
void stdDisplay_ClearMode(void)
{
    if (stdDisplay_bModeSet)
        stdDisplay_ReleaseBuffers();
    if (stdDisplay_hFont) {
        DeleteObject(stdDisplay_hFont);
        stdDisplay_hFont = 0;
    }
    stdDisplay_bModeSet = 0;
}

// 0x00488070
int stdDisplay_GetNumDevices(void)
{
    return stdDisplay_numDevices;
}

// 0x00488080
int stdDisplay_GetDevice(unsigned int deviceNum, StdDisplayDevice* pDest)
{
    if (deviceNum >= stdDisplay_numDevices)
        return 1;

    *pDest = stdDisplay_aDisplayDevices[deviceNum];
    return 0;
}

// 0x00488100
void stdDisplay_Refresh(int bReload)
{
    if (!stdDisplay_bOpen || !stdDisplay_bModeSet || !bReload)
        return;

    if (IDirectDraw4_SetCooperativeLevel(stdDisplay_lpDD, Window_GetHWND(), stdDisplay_coopLevelFlags) != S_OK)
        return;

    if (stdDisplay_bFullscreen) {
        if (stdDisplay_lpDD) {
            const tRasterInfo* i = &stdDisplay_pCurVideMode->rasterInfo;
            if (IDirectDraw4_SetDisplayMode(stdDisplay_lpDD, i->width, i->height, i->colorInfo.bpp, 0, 0) != S_OK)
                return;
        }

        if (stdDisplay_g_frontBuffer.pVSurface.pDDSurf) {
            if (IDirectDrawSurface4_Restore(stdDisplay_g_frontBuffer.pVSurface.pDDSurf) != S_OK)
                return;
        }
    } else {
        if (stdDisplay_g_backBuffer.pVSurface.pDDSurf) {
            if (IDirectDrawSurface4_Restore(stdDisplay_g_backBuffer.pVSurface.pDDSurf) != S_OK)
                return;
        }
    }

    if (stdDisplay_zBuffer.pDDSurf)
        IDirectDrawSurface4_Restore(stdDisplay_zBuffer.pDDSurf);
}

// 0x004881c0
tVBuffer* stdDisplay_VBufferNew(tRasterInfo* texFormat, int create_ddraw_surface, int use_video_memory)
{
    tVBuffer* buffer = stdPlatform_hostServices.alloc(sizeof(tVBuffer));
    if (!buffer)
        return NULL;

    *buffer = (tVBuffer){ 0 };
    buffer->rasterInfo = *texFormat;

    int bytes_per_pixel = buffer->rasterInfo.colorInfo.bpp / 8;
    buffer->rasterInfo.rowSize = buffer->rasterInfo.width * bytes_per_pixel;
    buffer->rasterInfo.rowWidth = buffer->rasterInfo.width * bytes_per_pixel / bytes_per_pixel;
    buffer->rasterInfo.size = buffer->rasterInfo.width * buffer->rasterInfo.height * bytes_per_pixel;

    if (create_ddraw_surface && stdDisplay_bOpen) {
        buffer->bVideoMemory = 0;
        buffer->bSurfaceAllocated = 1;

        DDSURFACEDESC2* desc = &buffer->pVSurface.ddSurfDesc;
        desc->dwSize = sizeof(DDSURFACEDESC2);
        desc->dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH;
        desc->ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN;
        if (!use_video_memory)
            desc->ddsCaps.dwCaps |= DDSCAPS_SYSTEMMEMORY;
        desc->dwWidth = buffer->rasterInfo.width;
        desc->dwHeight = buffer->rasterInfo.height;

        if (IDirectDraw4_CreateSurface(stdDisplay_lpDD, desc, &buffer->pVSurface.pDDSurf, 0) != S_OK)
            return NULL;

        if (IDirectDrawSurface4_GetSurfaceDesc(buffer->pVSurface.pDDSurf, desc) != S_OK)
            return NULL;

        if (desc->ddsCaps.dwCaps & DDSCAPS_VIDEOMEMORY)
            buffer->bVideoMemory = 1;

        buffer->rasterInfo.rowSize = desc->dwLinearSize;
        buffer->rasterInfo.rowWidth = desc->dwLinearSize / bytes_per_pixel;
        return buffer;
    }

    buffer->bSurfaceAllocated = 0;
    buffer->bVideoMemory = 0;
    buffer->pPixels = stdPlatform_hostServices_ptr->alloc(buffer->rasterInfo.size);
    if (buffer->pPixels) {
        buffer->lockSurfRefCount = 1;
        return buffer;
    }
    return NULL;
}

// 0x00488310
void stdDisplay_VBufferFree(tVBuffer* vbuffer)
{
    IDirectDrawSurface4* This;

    if (vbuffer->bSurfaceAllocated == 0) {
        if (vbuffer->pPixels != NULL) {
            (*stdPlatform_hostServices_ptr->free)(vbuffer->pPixels);
            vbuffer->pPixels = NULL;
        }
    } else if ((vbuffer->bSurfaceAllocated == 1) && (This = vbuffer->pVSurface.pDDSurf, This != NULL)) {
        (*This->lpVtbl->Release)(This);
        vbuffer->pVSurface.pDDSurf = NULL;
        (*stdPlatform_hostServices_ptr->free)(vbuffer);
        return;
    }

    (*stdPlatform_hostServices_ptr->free)(vbuffer);
}

// 0x00488370
int stdDisplay_VBufferLock(tVBuffer* vbuffer)
{
    char* surface_lock;
    unsigned int caps;

    if (vbuffer->bSurfaceAllocated != 0) {
        if (vbuffer->bSurfaceAllocated != 1) {
            return 1;
        }
        caps = (vbuffer->pVSurface.ddSurfDesc).ddsCaps.dwCaps;
        if (((caps & 0x20) != 0) && ((caps & 0x200000) != 0)) {
            return 0;
        }
        surface_lock = (char*)stdDisplay_LockSurface((tVSurface*)&vbuffer->pVSurface);
        vbuffer->pPixels = surface_lock;
        if (surface_lock == NULL) {
            return 0;
        }
    }
    vbuffer->lockSurfRefCount = vbuffer->lockSurfRefCount + 1;
    return 1;
}

// 0x004883c0
int stdDisplay_VBufferUnlock(tVBuffer* vbuffer)
{
    int res;

    if (vbuffer->bSurfaceAllocated == 0) {
        if (vbuffer->lockSurfRefCount != 0) {
            vbuffer->lockSurfRefCount = vbuffer->lockSurfRefCount - 1;
        }
    } else if (vbuffer->bSurfaceAllocated == 1) {
        if (vbuffer->lockSurfRefCount == 0) {
            return 0;
        }
        res = stdDisplay_UnlockSurface((tVSurface*)&vbuffer->pVSurface);
        if (res != 0) {
            return res;
        }
        vbuffer->lockSurfRefCount = vbuffer->lockSurfRefCount - 1;
        return 0;
    }
    return 1;
}

// 0x00488b00
int stdDisplay_InitDirectDraw(HWND wnd)
{
    LPDIRECTDRAW lpDD = 0;
    if (DirectDrawCreate(stdDisplay_pcurDevice->bGuidNotSet ? NULL : &stdDisplay_pcurDevice->guid, &lpDD, NULL) != S_OK)
        return 0;

    DDCAPS caps = { 0 };
    caps.dwSize = sizeof(DDCAPS);
    if (IDirectDraw_GetCaps(lpDD, &caps, 0) != S_OK)
        return 0;

    directDrawVidMemTotal = caps.dwVidMemTotal;
    if (IDirectDraw_QueryInterface(lpDD, &IID_IDirectDraw4, (void**)&stdDisplay_lpDD) != S_OK)
        return 0;

    DDDEVICEIDENTIFIER did = { 0 };
    if (IDirectDraw4_GetDeviceIdentifier(stdDisplay_lpDD, &did, 1) != S_OK)
        return 0;

    if (did.dwVendorId == 4418 && did.dwDeviceId == 25661 || did.dwVendorId == 4313 && did.dwDeviceId == 34342)
        directDrawSpecialDeviceId = 1;

    if (did.dwVendorId == 4634 && (did.dwDeviceId == 1 || did.dwDeviceId == 2)) {
        DDSCAPS2 caps2 = { 0 };
        caps2.dwCaps = DDSCAPS_TEXTURE;

        DWORD total = 0;
        DWORD free = 0;
        if (IDirectDraw4_GetAvailableVidMem(stdDisplay_lpDD, &caps2, &total, &free) != S_OK)
            return 0;

        directDrawVidMemTotal -= total;
    }

    if (IDirectDraw_Release(lpDD) != S_OK)
        return 0;

    stdDisplay_numVideoModes = 0;
    if (IDirectDraw4_SetCooperativeLevel(stdDisplay_lpDD, wnd, DDSCL_FULLSCREEN | DDSCL_ALLOWREBOOT | DDSCL_NOWINDOWCHANGES | DDSCL_EXCLUSIVE) != S_OK)
        return 0;
    if (IDirectDraw4_EnumDisplayModes(stdDisplay_lpDD, 0, 0, 0, DirectDraw_EnumDisplayModes_Callback) != S_OK)
        return 0;
    if (IDirectDraw4_SetCooperativeLevel(stdDisplay_lpDD, wnd, DDSCL_NORMAL) != S_OK)
        return 0;

    return 1;
}

// 0x00488d10
void stdDisplay_ReleaseDirectDraw(void)
{
    if (stdDisplay_lpDD) {
        IDirectDraw4_SetCooperativeLevel(stdDisplay_lpDD, Window_GetHWND(), DDSCL_NORMAL);
        IDirectDraw4_RestoreDisplayMode(stdDisplay_lpDD);
        IDirectDraw4_Release(stdDisplay_lpDD);
        stdDisplay_lpDD = 0;
    }
    stdDisplay_coopLevelFlags = 8;
    stdDisplay_numVideoModes = 0;
}

// 0x00489260
LPDIRECTDRAW4 stdDisplay_GetDirectDraw(void)
{
    return stdDisplay_lpDD;
}

// 0x00489270
int stdDisplay_SetWindowMode(HWND hWnd, StdVideoMode* pDisplayMode)
{
    int width = pDisplayMode->rasterInfo.width;
    int height = pDisplayMode->rasterInfo.height;
    LPDIRECTDRAWCLIPPER clipper;
    DDPIXELFORMAT* format;
    unsigned int bytesPerPixel;

    stdDisplay_g_frontBuffer.bSurfaceAllocated = 1;
    stdDisplay_g_frontBuffer.lockSurfRefCount = 0;
    stdDisplay_g_frontBuffer.bVideoMemory = 0;
    stdDisplay_g_frontBuffer.pPixels = NULL;
    memset(&stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc, 0, sizeof(DDSURFACEDESC2));
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwSize = sizeof(DDSURFACEDESC2);
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwFlags = DDSD_CAPS;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;
    if (IDirectDraw4_CreateSurface(stdDisplay_lpDD, &stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc, &stdDisplay_g_frontBuffer.pVSurface.pDDSurf, NULL) != DD_OK)
        return 0;
    if (IDirectDraw4_CreateClipper(stdDisplay_lpDD, 0, &clipper, NULL) != DD_OK)
        return 0;
    if (IDirectDrawClipper_SetHWnd(clipper, 0, hWnd) != DD_OK) {
        IDirectDrawClipper_Release(clipper);
        return 0;
    }
    if (IDirectDrawSurface4_SetClipper(stdDisplay_g_frontBuffer.pVSurface.pDDSurf, clipper) != DD_OK) {
        IDirectDrawClipper_Release(clipper);
        return 0;
    }
    IDirectDrawClipper_Release(clipper);
    if (IDirectDrawSurface4_GetSurfaceDesc(stdDisplay_g_frontBuffer.pVSurface.pDDSurf, &stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc) != DD_OK)
        return 0;

    pDisplayMode->rasterInfo.width = stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwWidth;
    pDisplayMode->rasterInfo.height = stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwHeight;
    pDisplayMode->rasterInfo.rowSize = stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.lPitch;
    if ((pDisplayMode->rasterInfo.width == 320 && pDisplayMode->rasterInfo.height == 200) || (pDisplayMode->rasterInfo.width == 640 && pDisplayMode->rasterInfo.height == 400)) {
        pDisplayMode->aspectRatio = 0.75f;
    } else {
        pDisplayMode->aspectRatio = 1.0f;
    }

    format = &stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.ddpfPixelFormat;
    if (format->dwFlags & (DDPF_PALETTEINDEXED4 | DDPF_PALETTEINDEXED8 | DDPF_PALETTEINDEXED1 | DDPF_PALETTEINDEXED2))
        return 0;
    if (format->dwFlags & DDPF_RGB)
        stdDisplay_ColorInfoFromRGBMasks(&pDisplayMode->rasterInfo.colorInfo, format);

    switch (pDisplayMode->rasterInfo.colorInfo.bpp) {
    case 8:
        pDisplayMode->rasterInfo.rowWidth = pDisplayMode->rasterInfo.rowSize;
        break;
    case 16:
        pDisplayMode->rasterInfo.rowWidth = (unsigned int)pDisplayMode->rasterInfo.rowSize >> 1;
        break;
    case 24:
        pDisplayMode->rasterInfo.rowWidth = (unsigned int)pDisplayMode->rasterInfo.rowSize / 3;
        break;
    case 32:
        pDisplayMode->rasterInfo.rowWidth = (unsigned int)pDisplayMode->rasterInfo.rowSize >> 2;
        break;
    }
    bytesPerPixel = (unsigned int)pDisplayMode->rasterInfo.colorInfo.bpp >> 3;
    pDisplayMode->rasterInfo.size = bytesPerPixel * pDisplayMode->rasterInfo.width * pDisplayMode->rasterInfo.height;

    stdDisplay_g_frontBuffer.rasterInfo = pDisplayMode->rasterInfo;
    stdDisplay_g_frontBuffer.rasterInfo.rowSize = stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.lPitch;
    stdDisplay_g_frontBuffer.rasterInfo.rowWidth = (unsigned int)stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.lPitch / bytesPerPixel;
    if (stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.ddsCaps.dwCaps & DDSCAPS_VIDEOMEMORY)
        stdDisplay_g_frontBuffer.bVideoMemory = 1;

    memset(&stdDisplay_g_backBuffer.pVSurface.ddSurfDesc, 0, sizeof(DDSURFACEDESC2));
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwWidth = width;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwSize = sizeof(DDSURFACEDESC2);
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwHeight = height;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_3DDEVICE;
    if (IDirectDraw4_CreateSurface(stdDisplay_lpDD, &stdDisplay_g_backBuffer.pVSurface.ddSurfDesc, &stdDisplay_g_backBuffer.pVSurface.pDDSurf, NULL) != DD_OK)
        return 0;
    stdDisplay_g_backBuffer.bSurfaceAllocated = 1;
    stdDisplay_g_backBuffer.lockSurfRefCount = 0;
    stdDisplay_g_backBuffer.bVideoMemory = 1;
    if (IDirectDrawSurface4_GetSurfaceDesc(stdDisplay_g_backBuffer.pVSurface.pDDSurf, &stdDisplay_g_backBuffer.pVSurface.ddSurfDesc) != DD_OK)
        return 0;

    stdDisplay_g_backBuffer.rasterInfo.height = stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwHeight;
    stdDisplay_g_backBuffer.rasterInfo.width = stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwWidth;
    stdDisplay_g_backBuffer.rasterInfo.rowSize = stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.lPitch;
    format = &stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.ddpfPixelFormat;
    if (format->dwFlags & (DDPF_PALETTEINDEXED4 | DDPF_PALETTEINDEXED8 | DDPF_PALETTEINDEXED1 | DDPF_PALETTEINDEXED2))
        return 0;
    if (format->dwFlags & DDPF_RGB)
        stdDisplay_ColorInfoFromRGBMasks(&stdDisplay_g_backBuffer.rasterInfo.colorInfo, format);
    stdDisplay_g_backBuffer.rasterInfo.rowSize = stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.lPitch;
    stdDisplay_coopLevelFlags = DDSCL_NORMAL;
    // faithful: the back buffer's row width divides by the front mode's bytes per pixel
    stdDisplay_g_backBuffer.rasterInfo.rowWidth = (unsigned int)stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.lPitch / bytesPerPixel;
    return 1;
}

// 0x00489790
int stdDisplay_SetFullscreenMode(HWND hwnd, StdVideoMode* pDisplayMode)
{
    unsigned int bytesPerPixel;

    stdDisplay_coopLevelFlags = DDSCL_FULLSCREEN | DDSCL_EXCLUSIVE;
    if (IDirectDraw4_SetCooperativeLevel(stdDisplay_lpDD, hwnd, DDSCL_FULLSCREEN | DDSCL_EXCLUSIVE) != DD_OK)
        return 0;
    if (IDirectDraw4_SetDisplayMode(stdDisplay_lpDD, pDisplayMode->rasterInfo.width, pDisplayMode->rasterInfo.height, pDisplayMode->rasterInfo.colorInfo.bpp, 0, 0) != DD_OK)
        return 0;

    stdDisplay_g_frontBuffer.lockSurfRefCount = 0;
    stdDisplay_g_frontBuffer.bVideoMemory = 0;
    stdDisplay_g_frontBuffer.bSurfaceAllocated = 1;
    stdDisplay_g_frontBuffer.rasterInfo = pDisplayMode->rasterInfo;
    stdDisplay_g_frontBuffer.pPixels = NULL;
    memset(&stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc, 0, sizeof(DDSURFACEDESC2));
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwSize = sizeof(DDSURFACEDESC2);
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwWidth = pDisplayMode->rasterInfo.width;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwHeight = pDisplayMode->rasterInfo.height;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwBackBufferCount = 1;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwFlags = DDSD_CAPS | DDSD_BACKBUFFERCOUNT;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE | DDSCAPS_FLIP | DDSCAPS_COMPLEX | DDSCAPS_3DDEVICE;
    if (IDirectDraw4_CreateSurface(stdDisplay_lpDD, &stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc, &stdDisplay_g_frontBuffer.pVSurface.pDDSurf, NULL) != DD_OK)
        return 0;
    if (IDirectDrawSurface4_GetSurfaceDesc(stdDisplay_g_frontBuffer.pVSurface.pDDSurf, &stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc) != DD_OK)
        return 0;

    bytesPerPixel = (unsigned int)pDisplayMode->rasterInfo.colorInfo.bpp >> 3;
    stdDisplay_g_frontBuffer.rasterInfo.rowSize = stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.lPitch;
    stdDisplay_g_frontBuffer.rasterInfo.rowWidth = (unsigned int)stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.lPitch / bytesPerPixel;
    if (stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.ddsCaps.dwCaps & DDSCAPS_VIDEOMEMORY)
        stdDisplay_g_frontBuffer.bVideoMemory = 1;

    stdDisplay_g_backBuffer.lockSurfRefCount = 0;
    stdDisplay_g_backBuffer.bVideoMemory = 0;
    stdDisplay_g_backBuffer.bSurfaceAllocated = 1;
    stdDisplay_g_backBuffer.rasterInfo = pDisplayMode->rasterInfo;
    stdDisplay_g_backBuffer.pPixels = NULL;
    memset(&stdDisplay_g_backBuffer.pVSurface.ddSurfDesc, 0, sizeof(DDSURFACEDESC2));
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwSize = sizeof(DDSURFACEDESC2);
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwWidth = pDisplayMode->rasterInfo.width;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwHeight = pDisplayMode->rasterInfo.height;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwFlags = DDSD_CAPS | DDSD_BACKBUFFERCOUNT;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.ddsCaps.dwCaps = DDSCAPS_BACKBUFFER | DDSCAPS_3DDEVICE;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwBackBufferCount = 1;
    if (IDirectDrawSurface4_GetAttachedSurface(stdDisplay_g_frontBuffer.pVSurface.pDDSurf, &stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.ddsCaps, &stdDisplay_g_backBuffer.pVSurface.pDDSurf) != DD_OK)
        return 0;
    if (IDirectDrawSurface4_GetSurfaceDesc(stdDisplay_g_backBuffer.pVSurface.pDDSurf, &stdDisplay_g_backBuffer.pVSurface.ddSurfDesc) != DD_OK)
        return 0;
    if (stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.ddsCaps.dwCaps & DDSCAPS_VIDEOMEMORY)
        stdDisplay_g_backBuffer.bVideoMemory = 1;
    stdDisplay_g_backBuffer.rasterInfo.rowSize = stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.lPitch;
    stdDisplay_g_backBuffer.rasterInfo.rowWidth = (unsigned int)stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.lPitch / bytesPerPixel;
    return 1;
}

// 0x00488410
int stdDisplay_VBufferFill(tVBuffer* pVBuffer, DWORD dwFillColor, LECRECT* pRect)
{
    tRasterInfo* raster = &pVBuffer->rasterInfo;
    DWORD caps;
    BYTE* row;
    int y;
    int x;

    if (pVBuffer->bSurfaceAllocated == 1) {
        caps = pVBuffer->pVSurface.ddSurfDesc.ddsCaps.dwCaps;
        if ((caps & DDSCAPS_FRONTBUFFER) && (caps & DDSCAPS_MODEX))
            return 0;
        return stdDisplay_ColorFillSurface(&pVBuffer->pVSurface, dwFillColor, pRect) == 0;
    }
    if (pVBuffer->bSurfaceAllocated != 0)
        return 1;

    // the rect is {left, top, width, height}
    if (raster->colorInfo.bpp == 8) {
        if (pRect == NULL) {
            memset(pVBuffer->pPixels, (BYTE)dwFillColor, raster->size);
            return 1;
        }
        row = pVBuffer->pPixels + pRect->left + raster->rowWidth * pRect->top;
        for (y = 0; y < pRect->bottom; y++) {
            memset(row, (BYTE)dwFillColor, pRect->right);
            row += raster->rowSize;
        }
    } else if (raster->colorInfo.bpp == 16) {
        // even pixel counts are filled two pixels at a time
        DWORD pair = (WORD)dwFillColor | ((DWORD)(WORD)dwFillColor << 16);
        if (pRect == NULL) {
            unsigned int pixels = (unsigned int)raster->size >> 1;
            if ((pixels & 1) == 0) {
                for (x = 0; x < (int)((unsigned int)raster->size >> 2); x++)
                    ((DWORD*)pVBuffer->pPixels)[x] = pair;
            } else {
                for (x = 0; x < (int)pixels; x++)
                    ((WORD*)pVBuffer->pPixels)[x] = (WORD)dwFillColor;
            }
            return 1;
        }
        row = pVBuffer->pPixels + (raster->rowWidth * pRect->top + pRect->left) * 2;
        for (y = 0; y < pRect->bottom; y++) {
            if ((pRect->right & 1) == 0) {
                for (x = 0; x < (int)((unsigned int)pRect->right >> 1); x++)
                    ((DWORD*)row)[x] = pair;
            } else {
                for (x = 0; x < pRect->right; x++)
                    ((WORD*)row)[x] = (WORD)dwFillColor;
            }
            row += raster->rowSize;
        }
    } else if (raster->colorInfo.bpp == 32) {
        if (pRect == NULL) {
            for (x = 0; x < (int)((unsigned int)raster->size >> 2); x++)
                ((DWORD*)pVBuffer->pPixels)[x] = dwFillColor;
            return 1;
        }
        row = pVBuffer->pPixels + (raster->rowWidth * pRect->top + pRect->left) * 4;
        for (y = 0; y < pRect->bottom; y++) {
            for (x = 0; x < pRect->right; x++)
                ((DWORD*)row)[x] = dwFillColor;
            row += raster->rowSize;
        }
    }
    return 1;
}

// tVBuffer *__cdecl stdDisplay_VBufferConvertColorFormat(ColorInfo *pDesiredColorFormat, tVBuffer *pSrc, int bColorKey, LPDDCOLORKEY pColorKey)
// 0x00488670
tVBuffer* stdDisplay_VBufferConvertColorFormat(ColorInfo* texFormat, tVBuffer* src, int colorKey, void* PcolorKey)
{
    tVBuffer* dst;
    tRasterInfo rasterInfo;
    int row;

    if (memcmp(texFormat, &src->rasterInfo.colorInfo, sizeof(ColorInfo)) == 0)
        return src;
    if (src->rasterInfo.colorInfo.colorMode == T_STDCOLOR_PAL && texFormat->colorMode == T_STDCOLOR_PAL)
        return src;

    dst = src;
    if (src->rasterInfo.colorInfo.bpp != texFormat->bpp) {
        rasterInfo = src->rasterInfo;
        rasterInfo.colorInfo = *texFormat;
        dst = stdDisplay_VBufferNew(&rasterInfo, 0, 0);
        if (dst == NULL) {
            stdPlatform_DebugLog(stdPlatform_hostServices_ptr->errorPrint, "D:\\devel.QA5\\pc_gnome\\SpecPlat\\rdroid_gnome\\Jones3D\\Libs\\Std\\Win95\\stdDisplay.c", 1146, "Unable to allocate memory for new tVBuffer", 0, 0, 0, 0);
            return NULL;
        }
    }

    stdDisplay_VBufferLock(src);
    stdDisplay_VBufferLock(dst);
    for (row = 0; row < dst->rasterInfo.height; row++) {
        stdColor_ColorConvertOneRow((char*)(dst->pPixels + row * dst->rasterInfo.rowSize), texFormat, (char*)(src->pPixels + row * src->rasterInfo.rowSize), &src->rasterInfo.colorInfo, dst->rasterInfo.width, colorKey, PcolorKey);
    }
    stdDisplay_VBufferUnlock(src);
    stdDisplay_VBufferUnlock(dst);
    dst->rasterInfo.colorInfo = *texFormat;
    if (dst != src)
        stdDisplay_VBufferFree(src);
    return dst;
}

// 0x004887c0
int stdDisplay_FlushText(char* output_buffer, int x, int y)
{
    HDC hdc;
    HRESULT hres = (*(stdDisplay_g_backBuffer.pVSurface.pDDSurf)->lpVtbl->GetDC)(stdDisplay_g_backBuffer.pVSurface.pDDSurf, &hdc);
    if (hres != 0) {
        return 0;
    }
    SetBkMode(hdc, 1);
    SelectObject(hdc, stdDisplay_hFont);
    SetTextColor(hdc, 0xffff);
    TextOutA(hdc, x, y, output_buffer, strlen(output_buffer));
    (*(stdDisplay_g_backBuffer.pVSurface.pDDSurf)->lpVtbl->ReleaseDC)(stdDisplay_g_backBuffer.pVSurface.pDDSurf, hdc);
    return 1;
}

// 0x00488850
int stdDisplay_VideoModeCompare(const StdVideoMode* pMode1, const StdVideoMode* pMode2)
{
    int iVar1;
    int iVar2;

    iVar1 = (pMode1->rasterInfo).colorInfo.bpp;
    iVar2 = (pMode2->rasterInfo).colorInfo.bpp;
    if (iVar1 == iVar2) {
        iVar1 = (pMode1->rasterInfo).width;
        iVar2 = (pMode2->rasterInfo).width;
        if (iVar1 == iVar2) {
            iVar1 = (pMode1->rasterInfo).height;
            iVar2 = (pMode2->rasterInfo).height;
        }
    }
    return iVar1 - iVar2;
}

// 0x004888d0
int stdDisplay_CreateZBuffer(LPDDPIXELFORMAT pPixelFormat, int bSystemMemory, int zBufferlessHSR)
{
    DDSURFACEDESC2 lockDesc;

    memset(&stdDisplay_zBuffer.ddSurfDesc, 0, sizeof(DDSURFACEDESC2));
    stdDisplay_zBuffer.ddSurfDesc.dwHeight = stdDisplay_g_backBuffer.rasterInfo.height;
    stdDisplay_zBuffer.ddSurfDesc.dwWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    stdDisplay_zBuffer.ddSurfDesc.dwSize = sizeof(DDSURFACEDESC2);
    stdDisplay_zBuffer.ddSurfDesc.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PIXELFORMAT;
    stdDisplay_zBuffer.ddSurfDesc.ddsCaps.dwCaps = bSystemMemory ? (DDSCAPS_ZBUFFER | DDSCAPS_SYSTEMMEMORY) : (DDSCAPS_ZBUFFER | DDSCAPS_VIDEOMEMORY);
    stdDisplay_zBuffer.ddSurfDesc.ddpfPixelFormat = *pPixelFormat;
    if (IDirectDraw4_CreateSurface(stdDisplay_lpDD, &stdDisplay_zBuffer.ddSurfDesc, &stdDisplay_zBuffer.pDDSurf, NULL) != DD_OK)
        return 1;

    if (!bSystemMemory) {
        memset(&lockDesc, 0, sizeof(lockDesc));
        lockDesc.dwSize = sizeof(DDSURFACEDESC2);
        if (IDirectDrawSurface4_Lock(stdDisplay_zBuffer.pDDSurf, NULL, &lockDesc, DDLOCK_WAIT, NULL) == DD_OK) {
            IDirectDrawSurface4_Unlock(stdDisplay_zBuffer.pDDSurf, NULL);
        } else {
            // the video-memory z-buffer can't be locked: retry in system memory, without HSR attachment
            stdDisplay_zBuffer.ddSurfDesc.ddsCaps.dwCaps = DDSCAPS_SYSTEMMEMORY;
            *(uint16_t*)&directDraw_BltFillColor = 0;
            zBufferlessHSR = 1;
            if (IDirectDraw4_CreateSurface(stdDisplay_lpDD, &stdDisplay_zBuffer.ddSurfDesc, &stdDisplay_zBuffer.pDDSurf, NULL) != DD_OK)
                return 1;
        }
    }

    if (zBufferlessHSR != 1 && IDirectDrawSurface4_AddAttachedSurface(stdDisplay_g_backBuffer.pVSurface.pDDSurf, stdDisplay_zBuffer.pDDSurf) != DD_OK)
        return 1;
    if (IDirectDrawSurface4_GetSurfaceDesc(stdDisplay_zBuffer.pDDSurf, &stdDisplay_zBuffer.ddSurfDesc) != DD_OK)
        return 1;

    // 0x10000000: undocumented DDCAPS2 bit of the selected device
    if ((stdDisplay_pcurDevice->ddcaps.dwCaps2 & 0x10000000) != 0 && zBufferlessHSR != 1) {
        stdDisplay_FillMainSurface_ptr = DirectDraw_FillMainSurface;
    } else {
        stdDisplay_FillMainSurface_ptr = (void (*)())stdPlatform_noop;
    }
    DirectDraw_FillMainSurface();
    return 0;
}

// 0x004899a0
void stdDisplay_ReleaseBuffers(void)
{
    if (stdDisplay_zBuffer.pDDSurf != NULL) {
        stdDisplay_g_backBuffer.pVSurface.pDDSurf->lpVtbl->DeleteAttachedSurface(stdDisplay_g_backBuffer.pVSurface.pDDSurf, 0, stdDisplay_zBuffer.pDDSurf);
        stdDisplay_zBuffer.pDDSurf->lpVtbl->Release(stdDisplay_zBuffer.pDDSurf);
    }
    // the back buffer is attached to the front (flip chain), so releasing the front frees both
    if (stdDisplay_g_frontBuffer.pVSurface.pDDSurf != NULL)
        stdDisplay_g_frontBuffer.pVSurface.pDDSurf->lpVtbl->Release(stdDisplay_g_frontBuffer.pVSurface.pDDSurf);
    memset(&stdDisplay_zBuffer, 0, sizeof(stdDisplay_zBuffer));
    memset(&stdDisplay_g_backBuffer, 0, sizeof(stdDisplay_g_backBuffer));
    memset(&stdDisplay_g_frontBuffer, 0, sizeof(stdDisplay_g_frontBuffer));
}

// 0x00489a00
BYTE* stdDisplay_LockSurface(tVSurface* pVSurf)
{
    HRESULT res;

    do {
        res = IDirectDrawSurface4_Lock(pVSurf->pDDSurf, NULL, &pVSurf->ddSurfDesc, DDLOCK_WAIT, NULL);
        if (res == DD_OK) {
            return (BYTE*)pVSurf->ddSurfDesc.lpSurface;
        }
        if (res == DDERR_SURFACELOST) {
            if ((pVSurf->ddSurfDesc.ddsCaps.dwCaps & DDSCAPS_BACKBUFFER) == 0) {
                res = IDirectDrawSurface4_Restore(pVSurf->pDDSurf);
            } else {
                res = IDirectDrawSurface4_Restore(stdDisplay_g_frontBuffer.pVSurface.pDDSurf);
            }
        }
    } while (res == DD_OK);
    return NULL;
}

// 0x00489a60
int stdDisplay_UnlockSurface(tVSurface* pSurf)
{
    HRESULT res;

    do {
        res = IDirectDrawSurface4_Unlock(pSurf->pDDSurf, NULL);
        if (res == DD_OK) {
            return 0;
        }
        if (res == DDERR_SURFACELOST) {
            if ((pSurf->ddSurfDesc.ddsCaps.dwCaps & DDSCAPS_BACKBUFFER) == 0) {
                res = IDirectDrawSurface4_Restore(pSurf->pDDSurf);
            } else {
                res = IDirectDrawSurface4_Restore(stdDisplay_g_frontBuffer.pVSurface.pDDSurf);
            }
        }
    } while (res == DD_OK);
    return 1;
}

// 0x00489ab0
int stdDisplay_Update(void)
{
    HRESULT res;
    POINT origin;
    RECT srcRect;
    RECT dstRect;

    if (swrDisplay_SkipNextFrameUpdate == 1) {
        swrDisplay_SkipNextFrameUpdate = 0;
        return 0;
    }

    for (;;) {
        if (stdDisplay_bFullscreen) {
            res = IDirectDrawSurface4_Flip(stdDisplay_g_frontBuffer.pVSurface.pDDSurf, NULL, 0);
        } else {
            origin.x = 0;
            origin.y = 0;
            ClientToScreen(Window_GetHWND(), &origin);
            dstRect.left = origin.x;
            dstRect.top = origin.y;
            dstRect.right = origin.x + stdDisplay_g_backBuffer.rasterInfo.width;
            dstRect.bottom = origin.y + stdDisplay_g_backBuffer.rasterInfo.height;
            srcRect.left = 0;
            srcRect.top = 0;
            srcRect.right = stdDisplay_g_backBuffer.rasterInfo.width;
            srcRect.bottom = stdDisplay_g_backBuffer.rasterInfo.height;
            res = IDirectDrawSurface4_Blt(stdDisplay_g_frontBuffer.pVSurface.pDDSurf, &dstRect, stdDisplay_g_backBuffer.pVSurface.pDDSurf, &srcRect, DDBLT_WAIT, NULL);
        }
        if (res == DD_OK)
            return 0;
        if (res == DDERR_SURFACELOST) {
            if (IDirectDrawSurface4_Restore(stdDisplay_g_frontBuffer.pVSurface.pDDSurf) != DD_OK)
                return 1;
            res = DD_OK;
            if (!stdDisplay_bFullscreen) {
                res = IDirectDrawSurface4_Restore(stdDisplay_g_backBuffer.pVSurface.pDDSurf);
                if (res != DD_OK)
                    return 1;
            }
        }
        if (res != DDERR_WASSTILLDRAWING && res != DD_OK)
            return 1;
    }
}

// 0x00489bc0
void stdDisplay_FillMainSurface(void)
{
    if (stdDisplay_FillMainSurface_ptr != NULL)
        stdDisplay_FillMainSurface_ptr();
}

// 0x00489bd0
int stdDisplay_ColorFillSurface(tVSurface* pSurf, DWORD dwFillColor, LECRECT* lpRect)
{
    DDBLTFX bltFx;
    RECT rect;
    HRESULT res;

    memset(&bltFx, 0, sizeof(bltFx));
    bltFx.dwSize = sizeof(bltFx);
    bltFx.dwFillColor = dwFillColor;
    if (lpRect == NULL) {
        rect.right = pSurf->ddSurfDesc.dwWidth;
        rect.bottom = pSurf->ddSurfDesc.dwHeight;
        rect.left = 0;
        rect.top = 0;
    } else {
        // LECRECT right/bottom hold width/height here
        if (lpRect->right == 0) {
            return 1;
        }
        if (lpRect->bottom == 0) {
            return 1;
        }
        rect.left = lpRect->left;
        rect.top = lpRect->top;
        rect.right = rect.left + lpRect->right;
        rect.bottom = rect.top + lpRect->bottom;
    }
    do {
        res = IDirectDrawSurface4_Blt(pSurf->pDDSurf, &rect, NULL, NULL, DDBLT_COLORFILL | DDBLT_WAIT, &bltFx);
        if (res == DD_OK) {
            return 0;
        }
        if (res == DDERR_SURFACELOST) {
            if ((pSurf->ddSurfDesc.ddsCaps.dwCaps & DDSCAPS_BACKBUFFER) == 0) {
                res = IDirectDrawSurface4_Restore(pSurf->pDDSurf);
            } else {
                res = IDirectDrawSurface4_Restore(stdDisplay_g_frontBuffer.pVSurface.pDDSurf);
            }
        }
    } while (res == DD_OK);
    return 1;
}

// 0x00489cd0
int stdDisplay_BackBufferFill(uint8_t r, uint8_t b, uint8_t g, LECRECT* lpRect)
{
    return stdDisplay_ColorFillSurface(&stdDisplay_g_backBuffer.pVSurface, (g >> 3) | (8 * (b & 0xFC | (32 * (r & 0xF8)))), lpRect);
}

// 0x00489d20
int stdDisplay_SaveScreen(char* pFilename)
{
    return stdBmp_VBufferToBmp(pFilename, &stdDisplay_g_backBuffer);
}

// 0x00489d40
int stdDisplay_GetNumVideoModes(void)
{
    return stdDisplay_numVideoModes;
}

// 0x00489d50
int stdDisplay_CopyVideoMode(size_t modeNum, StdVideoMode* pDestMode)
{
    if (modeNum >= stdDisplay_numVideoModes)
        return 1;

    *pDestMode = stdDisplay_aVideoModes[modeNum];
    return 0;
}

// 0x00489d90
int stdDisplay_CopyCurrentVideoMode(StdVideoMode* pDisplayMode)
{
    if (!stdDisplay_pCurVideMode)
        return 1;

    *pDisplayMode = *stdDisplay_pCurVideMode;
    return 0;
}
