#include "stdDisplay.h"

#include "DirectX.h"
#include "Window.h"
#include "globals.h"

#include <macros.h>
#include <stdPlatform.h>
#include <General/stdBmp.h>

// 0x00487d20 HOOK
int stdDisplay_Startup(void)
{
    if (stdDisplay_bStartup)
        return 1;

    stdDisplay_g_frontBuffer = (tVBuffer){};
    stdDisplay_g_backBuffer = (tVBuffer){};
    stdDisplay_zBuffer = (tVSurface){};
    stdDisplay_bStartup = 1;
    stdDisplay_numDevices = 0;

    if (DirectDrawEnumerateA(DirectDraw_EnumerateA_Callback, NULL) != S_OK)
        return 0;

    stdDisplay_primaryVideoMode.rasterInfo.width = 640;
    stdDisplay_primaryVideoMode.rasterInfo.height = 480;

    return 1;
}

// 0x00487da0 HOOK
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

// 0x00487e00 HOOK
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

// 0x00487e80 HOOK
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
    stdDisplay_FillMainSurface_ptr = stdPlatform_noop;
    stdDisplay_bOpen = 0;
}

// 0x00487f00 HOOK
int stdDisplay_SetMode(int modeNum, int bFullscreen)
{
    if (bFullscreen && modeNum >= stdDisplay_numVideoModes)
        return 0;

    if (stdDisplay_bModeSet)
        stdDisplay_ClearMode();

    if (bFullscreen)
    {
        stdDisplay_pCurVideMode = &stdDisplay_aVideoModes[modeNum];
        if (!stdDisplay_SetFullscreenMode(Window_GetHWND(), &stdDisplay_aVideoModes[modeNum]))
            return 0;
    }
    else
    {
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

// 0x00488030 HOOK
void stdDisplay_ClearMode(void)
{
    if (stdDisplay_bModeSet)
        stdDisplay_ReleaseBuffers();
    if (stdDisplay_hFont)
    {
        DeleteObject(stdDisplay_hFont);
        stdDisplay_hFont = 0;
    }
    stdDisplay_bModeSet = 0;
}

// 0x00488070 HOOK
int stdDisplay_GetNumDevices(void)
{
    return stdDisplay_numDevices;
}

// 0x00488080 HOOK
int stdDisplay_GetDevice(unsigned int deviceNum, StdDisplayDevice* pDest)
{
    if (deviceNum >= stdDisplay_numDevices)
        return 1;

    *pDest = stdDisplay_aDisplayDevices[deviceNum];
    return 0;
}

// 0x00488100 HOOK
void stdDisplay_Refresh(int bReload)
{
    if (!stdDisplay_bOpen || !stdDisplay_bModeSet || !bReload)
        return;

    if (IDirectDraw4_SetCooperativeLevel(stdDisplay_lpDD, Window_GetHWND(), stdDisplay_coopLevelFlags) != S_OK)
        return;

    if (stdDisplay_bFullscreen)
    {
        if (stdDisplay_lpDD)
        {
            const tRasterInfo* i = &stdDisplay_pCurVideMode->rasterInfo;
            if (IDirectDraw4_SetDisplayMode(stdDisplay_lpDD, i->width, i->height, i->colorInfo.bpp, 0, 0) != S_OK)
                return;
        }

        if (stdDisplay_g_frontBuffer.pVSurface.pDDSurf)
        {
            if (IDirectDrawSurface4_Restore(stdDisplay_g_frontBuffer.pVSurface.pDDSurf) != S_OK)
                return;
        }
    }
    else
    {
        if (stdDisplay_g_backBuffer.pVSurface.pDDSurf)
        {
            if (IDirectDrawSurface4_Restore(stdDisplay_g_backBuffer.pVSurface.pDDSurf) != S_OK)
                return;
        }
    }

    if (stdDisplay_zBuffer.pDDSurf)
        IDirectDrawSurface4_Restore(stdDisplay_zBuffer.pDDSurf);
}

// 0x004881c0 HOOK
tVBuffer* stdDisplay_VBufferNew(tRasterInfo* texFormat, int create_ddraw_surface, int use_video_memory)
{
    tVBuffer* buffer = stdPlatform_hostServices.alloc(sizeof(tVBuffer));
    if (!buffer)
        return NULL;

    *buffer = (tVBuffer){};
    buffer->rasterInfo = *texFormat;

    int bytes_per_pixel = buffer->rasterInfo.colorInfo.bpp / 8;
    buffer->rasterInfo.rowSize = buffer->rasterInfo.width * bytes_per_pixel;
    buffer->rasterInfo.rowWidth = buffer->rasterInfo.width * bytes_per_pixel / bytes_per_pixel;
    buffer->rasterInfo.size = buffer->rasterInfo.width * buffer->rasterInfo.height * bytes_per_pixel;

    if (create_ddraw_surface && stdDisplay_bOpen)
    {
#if GLFW_BACKEND
        abort();
#else
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
#endif
    }

    buffer->bSurfaceAllocated = 0;
    buffer->bVideoMemory = 0;
    buffer->pPixels = stdPlatform_hostServices_ptr->alloc(buffer->rasterInfo.size);
    if (buffer->pPixels)
    {
        buffer->lockSurfRefCount = 1;
        return buffer;
    }
    return NULL;
}

// 0x00488310 HOOK
void stdDisplay_VBufferFree(tVBuffer* vbuffer)
{
    IDirectDrawSurface4* This;

    if (vbuffer->bSurfaceAllocated == 0)
    {
        if (vbuffer->pPixels != NULL)
        {
            (*stdPlatform_hostServices_ptr->free)(vbuffer->pPixels);
            vbuffer->pPixels = NULL;
        }
    }
    else if ((vbuffer->bSurfaceAllocated == 1) && (This = vbuffer->pVSurface.pDDSurf, This != NULL))
    {
        (*This->lpVtbl->Release)(This);
        vbuffer->pVSurface.pDDSurf = NULL;
        (*stdPlatform_hostServices_ptr->free)(vbuffer);
        return;
    }

    (*stdPlatform_hostServices_ptr->free)(vbuffer);
}

// 0x00488370 HOOK
int stdDisplay_VBufferLock(tVBuffer* vbuffer)
{
    char* surface_lock;
    unsigned int caps;

    if (vbuffer->bSurfaceAllocated != 0)
    {
        if (vbuffer->bSurfaceAllocated != 1)
        {
            return 1;
        }
        caps = (vbuffer->pVSurface.ddSurfDesc).ddsCaps.dwCaps;
        if (((caps & 0x20) != 0) && ((caps & 0x200000) != 0))
        {
            return 0;
        }
        surface_lock = (char*)stdDisplay_LockSurface((tVSurface*)&vbuffer->pVSurface);
        vbuffer->pPixels = surface_lock;
        if (surface_lock == NULL)
        {
            return 0;
        }
    }
    vbuffer->lockSurfRefCount = vbuffer->lockSurfRefCount + 1;
    return 1;
}

// 0x004883c0 HOOK
int stdDisplay_VBufferUnlock(tVBuffer* vbuffer)
{
    int res;

    if (vbuffer->bSurfaceAllocated == 0)
    {
        if (vbuffer->lockSurfRefCount != 0)
        {
            vbuffer->lockSurfRefCount = vbuffer->lockSurfRefCount - 1;
        }
    }
    else if (vbuffer->bSurfaceAllocated == 1)
    {
        if (vbuffer->lockSurfRefCount == 0)
        {
            return 0;
        }
        res = stdDisplay_UnlockSurface((tVSurface*)&vbuffer->pVSurface);
        if (res != 0)
        {
            return res;
        }
        vbuffer->lockSurfRefCount = vbuffer->lockSurfRefCount - 1;
        return 0;
    }
    return 1;
}

// 0x00488b00 HOOK
int stdDisplay_InitDirectDraw(HWND wnd)
{
    LPDIRECTDRAW lpDD = 0;
    if (DirectDrawCreate(stdDisplay_pcurDevice->bGuidNotSet ? NULL : &stdDisplay_pcurDevice->guid, &lpDD, NULL) != S_OK)
        return 0;

    DDCAPS caps = {};
    caps.dwSize = sizeof(DDCAPS);
    if (IDirectDraw_GetCaps(lpDD, &caps, 0) != S_OK)
        return 0;

    directDrawVidMemTotal = caps.dwVidMemTotal;
    if (IDirectDraw_QueryInterface(lpDD, &IID_IDirectDraw4, (void**)&stdDisplay_lpDD) != S_OK)
        return 0;

    DDDEVICEIDENTIFIER did = {};
    if (IDirectDraw4_GetDeviceIdentifier(stdDisplay_lpDD, &did, 1) != S_OK)
        return 0;

    if (did.dwVendorId == 4418 && did.dwDeviceId == 25661 || did.dwVendorId == 4313 && did.dwDeviceId == 34342)
        directDrawSpecialDeviceId = 1;

    if (did.dwVendorId == 4634 && (did.dwDeviceId == 1 || did.dwDeviceId == 2))
    {
        DDSCAPS2 caps2 = {};
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

// 0x00488d10 HOOK
void stdDisplay_ReleaseDirectDraw(void)
{
    if (stdDisplay_lpDD)
    {
        IDirectDraw4_SetCooperativeLevel(stdDisplay_lpDD, Window_GetHWND(), DDSCL_NORMAL);
        IDirectDraw4_RestoreDisplayMode(stdDisplay_lpDD);
        IDirectDraw4_Release(stdDisplay_lpDD);
        stdDisplay_lpDD = 0;
    }
    stdDisplay_coopLevelFlags = 8;
    stdDisplay_numVideoModes = 0;
}

// 0x00489260 HOOK
LPDIRECTDRAW4 stdDisplay_GetDirectDraw(void)
{
    return stdDisplay_lpDD;
}

// 0x00489270
int stdDisplay_SetWindowMode(HWND hWnd, StdVideoMode* pDisplayMode)
{
    HANG("TODO");
}

// 0x00489790
int stdDisplay_SetFullscreenMode(HWND hwnd, StdVideoMode* pDisplayMode)
{
    HANG("TODO");
}

// 0x00488410
int stdDisplay_VBufferFill(tVBuffer* pVBuffer, DWORD dwFillColor, LECRECT* pRect)
{
    HANG("TODO");
}

// tVBuffer *__cdecl stdDisplay_VBufferConvertColorFormat(ColorInfo *pDesiredColorFormat, tVBuffer *pSrc, int bColorKey, LPDDCOLORKEY pColorKey)
// 0x00488670
tVBuffer* stdDisplay_VBufferConvertColorFormat(ColorInfo* texFormat, tVBuffer* src, int colorKey, void* PcolorKey)
{
    HANG("TODO, easy");
}

// 0x004887c0 HOOK
int stdDisplay_FlushText(char* output_buffer, int x, int y)
{
    HDC hdc;
    HRESULT hres = (*(stdDisplay_g_backBuffer.pVSurface.pDDSurf)->lpVtbl->GetDC)(stdDisplay_g_backBuffer.pVSurface.pDDSurf, &hdc);
    if (hres != 0)
    {
        return 0;
    }
    SetBkMode(hdc, 1);
    SelectObject(hdc, stdDisplay_hFont);
    SetTextColor(hdc, 0xffff);
    TextOutA(hdc, x, y, output_buffer, strlen(output_buffer));
    (*(stdDisplay_g_backBuffer.pVSurface.pDDSurf)->lpVtbl->ReleaseDC)(stdDisplay_g_backBuffer.pVSurface.pDDSurf, hdc);
    return 1;
}

// 0x00488850 HOOK
int stdDisplay_VideoModeCompare(const StdVideoMode* pMode1, const StdVideoMode* pMode2)
{
    int iVar1;
    int iVar2;

    iVar1 = (pMode1->rasterInfo).colorInfo.bpp;
    iVar2 = (pMode2->rasterInfo).colorInfo.bpp;
    if (iVar1 == iVar2)
    {
        iVar1 = (pMode1->rasterInfo).width;
        iVar2 = (pMode2->rasterInfo).width;
        if (iVar1 == iVar2)
        {
            iVar1 = (pMode1->rasterInfo).height;
            iVar2 = (pMode2->rasterInfo).height;
        }
    }
    return iVar1 - iVar2;
}

// 0x004888d0
int stdDisplay_CreateZBuffer(LPDDPIXELFORMAT pPixelFormat, int bSystemMemory, int zBufferlessHSR)
{
    HANG("TODO");
}

// 0x004899a0
void stdDisplay_ReleaseBuffers(void)
{
    HANG("TODO");
}

// 0x00489a00
BYTE* stdDisplay_LockSurface(tVSurface* pVSurf)
{
    HANG("TODO");
    return 0;
}

// 0x00489a60
int stdDisplay_UnlockSurface(tVSurface* pSurf)
{
    HANG("TODO");
    return 0;
}

// 0x00489ab0
int stdDisplay_Update(void)
{
    HANG("TODO");
}

// 0x00489bc0 HOOK
void stdDisplay_FillMainSurface(void)
{
    if (stdDisplay_FillMainSurface_ptr != NULL)
        stdDisplay_FillMainSurface_ptr();
}

// 0x00489bd0
int stdDisplay_ColorFillSurface(tVSurface* pSurf, DWORD dwFillColor, LECRECT* lpRect)
{
    HANG("TODO");
}

// 0x00489cd0 HOOK
int stdDisplay_BackBufferFill(uint8_t r, uint8_t b, uint8_t g, LECRECT* lpRect)
{
    return stdDisplay_ColorFillSurface(&stdDisplay_g_backBuffer.pVSurface, (g >> 3) | (8 * (b & 0xFC | (32 * (r & 0xF8)))), lpRect);
}

// 0x00489d20 HOOK
int stdDisplay_SaveScreen(char* pFilename)
{
    return stdBmp_VBufferToBmp(pFilename, &stdDisplay_g_backBuffer);
}

// 0x00489d40 HOOK
int stdDisplay_GetNumVideoModes(void)
{
    return stdDisplay_numVideoModes;
}

// 0x00489d50 HOOK
int stdDisplay_CopyVideoMode(size_t modeNum, StdVideoMode* pDestMode)
{
    if (modeNum >= stdDisplay_numVideoModes)
        return 1;

    *pDestMode = stdDisplay_aVideoModes[modeNum];
    return 0;
}

// 0x00489d90 HOOK
int stdDisplay_CopyCurrentVideoMode(StdVideoMode* pDisplayMode)
{
    if (!stdDisplay_pCurVideMode)
        return 1;

    *pDisplayMode = *stdDisplay_pCurVideMode;
    return 0;
}
