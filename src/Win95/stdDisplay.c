#include "stdDisplay.h"

#include "DirectX.h"
#include "Window.h"
#include "globals.h"

#include <macros.h>
#include <stdPlatform.h>
#include <General/stdBmp.h>

#if GLFW_BACKEND
#include <glad/glad.h>
#include <GLFW/glfw3.h>
#endif

// 0x00487d20 HOOK
int stdDisplay_Startup(void)
{
    if (stdDisplay_bStartup)
        return 1;

    stdDisplay_g_frontBuffer = (tVBuffer){ 0 };
    stdDisplay_g_backBuffer = (tVBuffer){ 0 };
    stdDisplay_zBuffer = (tVSurface){ 0 };
    stdDisplay_bStartup = 1;
    stdDisplay_numDevices = 0;
#if GLFW_BACKEND
    stdDisplay_numDevices = 1;
    StdDisplayDevice* device = &stdDisplay_aDisplayDevices[0];
    snprintf(device->aDeviceName, 128, "OpenGL");
    snprintf(device->aDriverName, 128, "OpenGL");
    device->bHAL = true;
    device->bGuidNotSet = true;
    device->bWindowRenderNotSupported = false;
    device->totalVideoMemory = 1024 * 1024 * 1024;
    device->freeVideoMemory = 1024 * 1024 * 1024;
#else
    if (DirectDrawEnumerateA(DirectDraw_EnumerateA_Callback, NULL) != S_OK)
        return 0;
#endif
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

// 0x00487e00 HOOK
int stdDisplay_Open(int deviceNum)
{
    if (stdDisplay_bOpen)
        stdDisplay_Close();

    if (deviceNum >= stdDisplay_numDevices)
        return 0;

    stdDisplay_curDevice = deviceNum;
    stdDisplay_pcurDevice = &stdDisplay_aDisplayDevices[deviceNum];
#if GLFW_BACKEND
    glfwSwapInterval(1);
    gladLoadGLLoader((GLADloadproc)glfwGetProcAddress);

    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);

    stdDisplay_numVideoModes = 1;
    stdDisplay_aVideoModes[0] = (StdVideoMode){
        .aspectRatio = 1.0,
        .rasterInfo = {
            .width = w,
            .height = h,
            .size = w * h * 4,
            .rowSize = w * 4,
            .rowWidth = w,
            .colorInfo = {
                .colorMode = T_STDCOLOR_RGBA,
                .bpp = 32,
                .redBPP = 8,
                .greenBPP = 8,
                .blueBPP = 8,
                .redPosShift = 0,
                .greenPosShift = 8,
                .bluePosShift = 16,
                .RedShr = 0,
                .GreenShr = 0,
                .BlueShr = 0,
                .alphaBPP = 8,
                .alphaPosShift = 24,
                .AlphaShr = 0,
            },
        },
    };
#else
    if (!stdDisplay_InitDirectDraw(Window_GetHWND()))
        return 0;
#endif

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

#if GLFW_BACKEND

#else
    stdDisplay_ReleaseDirectDraw();
#endif
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
#if GLFW_BACKEND
    stdDisplay_g_frontBuffer.rasterInfo = stdDisplay_aVideoModes[0].rasterInfo;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwWidth = stdDisplay_g_frontBuffer.rasterInfo.width;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwHeight = stdDisplay_g_frontBuffer.rasterInfo.height;

    stdDisplay_g_backBuffer.rasterInfo = stdDisplay_aVideoModes[0].rasterInfo;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwHeight = stdDisplay_g_backBuffer.rasterInfo.height;

    stdDisplay_pCurVideMode = &stdDisplay_aVideoModes[0];
    stdDisplay_backbufWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    stdDisplay_backbufHeight = stdDisplay_g_backBuffer.rasterInfo.height;
    stdDisplay_bModeSet = 1;
    stdDisplay_bFullscreen = bFullscreen;
    return 1;
#else
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
#endif
}

// 0x00488030
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

// 0x00488100 HOOK
void stdDisplay_Refresh(int bReload)
{
#if GLFW_BACKEND
    return;
#else
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
#endif
}

// 0x004881c0 HOOK
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

// 0x00488310
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

// 0x00488370
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

// 0x004883c0
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

    if (did.dwVendorId == 4634 && (did.dwDeviceId == 1 || did.dwDeviceId == 2))
    {
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

// 0x00489260
LPDIRECTDRAW4 stdDisplay_GetDirectDraw(void)
{
    return stdDisplay_lpDD;
}

// 0x00489270 HOOK
int stdDisplay_SetWindowMode(HWND hWnd, StdVideoMode* pDisplayMode)
{
#if GLFW_BACKEND

#else
    HANG("TODO");
#endif
}

// 0x00489790 HOOK
int stdDisplay_SetFullscreenMode(HWND hwnd, StdVideoMode* pDisplayMode)
{
#if GLFW_BACKEND

#else
    HANG("TODO");
#endif
}

// 0x00488410 HOOK
int stdDisplay_VBufferFill(tVBuffer* pVBuffer, DWORD dwFillColor, LECRECT* pRect)
{
#if GLFW_BACKEND
    return stdDisplay_ColorFillSurface(&pVBuffer->pVSurface, dwFillColor, pRect);
#else
    HANG("TODO");
#endif
}

// tVBuffer *__cdecl stdDisplay_VBufferConvertColorFormat(ColorInfo *pDesiredColorFormat, tVBuffer *pSrc, int bColorKey, LPDDCOLORKEY pColorKey)
// 0x00488670
tVBuffer* stdDisplay_VBufferConvertColorFormat(ColorInfo* texFormat, tVBuffer* src, int colorKey, void* PcolorKey)
{
    HANG("TODO, easy");
}

// 0x004887c0
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

// 0x00488850
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

// 0x00489ab0 HOOK
int stdDisplay_Update(void)
{
    if (swrDisplay_SkipNextFrameUpdate == 1)
    {
        swrDisplay_SkipNextFrameUpdate = 0;
        return 0;
    }

#if GLFW_BACKEND
    glFinish();
    glfwSwapBuffers(glfwGetCurrentContext());
#else
    HANG("TODO");
#endif
    return 0;
}

// 0x00489bc0 HOOK
void stdDisplay_FillMainSurface(void)
{
#if GLFW_BACKEND
    glDepthMask(GL_TRUE);
    glClear(GL_DEPTH_BUFFER_BIT);
#else
    if (stdDisplay_FillMainSurface_ptr != NULL)
        stdDisplay_FillMainSurface_ptr();
#endif
}

// 0x00489bd0 HOOK
int stdDisplay_ColorFillSurface(tVSurface* pSurf, DWORD dwFillColor, LECRECT* lpRect)
{
#if GLFW_BACKEND
    if (pSurf == &stdDisplay_g_backBuffer.pVSurface && lpRect == NULL)
    {
        uint8_t b = ((dwFillColor >> 0) & 0b11111) << 3;
        uint8_t g = ((dwFillColor >> 5) & 0b111111) << 2;
        uint8_t r = ((dwFillColor >> 11) & 0b11111) << 3;
        glClearColor(r / 255.0, g / 255.0, b / 255.0, 255.0);
        glClear(GL_COLOR_BUFFER_BIT);
    }
#else
    HANG("TODO");
#endif
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
