#include "stdDisplay.h"

#include "globals.h"

#include <macros.h>

// 0x00487d20
int stdDisplay_Startup(void)
{
    HANG("TODO");
}

// 0x00487da0
void stdDisplay_Shutdown(void)
{
    HANG("TODO");
}

// 0x00487e00
int stdDisplay_Open(int deviceNum)
{
    HANG("TODO");
}

// 0x00487e80
void stdDisplay_Close(void)
{
    HANG("TODO");
}

// 0x00487f00
int stdDisplay_SetMode(int modeNum, int bFullscreen)
{
    HANG("TODO");
}

// 0x00488030
void stdDisplay_ClearMode(void)
{
    HANG("TODO");
}

// 0x00488070
int stdDisplay_GetNumDevices(void)
{
    HANG("TODO");
}

// 0x00488080
int stdDisplay_GetDevice(unsigned int deviceNum, StdDisplayDevice* pDest)
{
    HANG("TODO");
}

// 0x004881c0
stdVBuffer* stdDisplay_VBufferNew(stdVBufferTexFmt* texFormat, int create_ddraw_surface, int param_3)
{
    HANG("TODO");
    return NULL;
}

// 0x00488310
void stdDisplay_VBufferFree(stdVBuffer* vbuffer)
{
    IDirectDrawSurface4* This;

    if (vbuffer->bSurfaceLocked == 0)
    {
        if (vbuffer->surface_lock_alloc != NULL)
        {
            (*stdPlatform_hostServices_ptr->free)(vbuffer->surface_lock_alloc);
            vbuffer->surface_lock_alloc = NULL;
        }
    }
    else if ((vbuffer->bSurfaceLocked == 1) && (This = (IDirectDrawSurface4*)vbuffer->ddraw_surface, This != NULL))
    {
        (*This->lpVtbl->Release)(This);
        vbuffer->ddraw_surface = NULL;
        (*stdPlatform_hostServices_ptr->free)(vbuffer);
        return;
    }

    (*stdPlatform_hostServices_ptr->free)(vbuffer);
}

// 0x00488370
int stdDisplay_VBufferLock(stdVBuffer* vbuffer)
{
    char* surface_lock;
    unsigned int caps;

    if (vbuffer->bSurfaceLocked != 0)
    {
        if (vbuffer->bSurfaceLocked != 1)
        {
            return 1;
        }
        caps = (vbuffer->desc).ddsCaps.dwCaps;
        if (((caps & 0x20) != 0) && ((caps & 0x200000) != 0))
        {
            return 0;
        }
        surface_lock = (char*)stdDisplay_LockSurface((tVSurface*)&vbuffer->ddraw_surface);
        vbuffer->surface_lock_alloc = surface_lock;
        if (surface_lock == NULL)
        {
            return 0;
        }
    }
    vbuffer->lock_cnt = vbuffer->lock_cnt + 1;
    return 1;
}

// 0x004883c0
int stdDisplay_VBufferUnlock(stdVBuffer* vbuffer)
{
    int res;

    if (vbuffer->bSurfaceLocked == 0)
    {
        if (vbuffer->lock_cnt != 0)
        {
            vbuffer->lock_cnt = vbuffer->lock_cnt - 1;
        }
    }
    else if (vbuffer->bSurfaceLocked == 1)
    {
        if (vbuffer->lock_cnt == 0)
        {
            return 0;
        }
        res = stdDisplay_UnlockSurface((tVSurface*)&vbuffer->ddraw_surface);
        if (res != 0)
        {
            return res;
        }
        vbuffer->lock_cnt = vbuffer->lock_cnt - 1;
        return 0;
    }
    return 1;
}

// 0x00488b00
int stdDisplay_InitDirectDraw(void)
{
    HANG("TODO");
}

// 0x00488d10
void stdDisplay_ReleaseDirectDraw(void)
{
    HANG("TODO");
}

// 0x00489260
LPDIRECTDRAW4 stdDisplay_GetDirectDraw(void)
{
    HANG("TODO");
}

// 0x00489270
int stdDisplay_SetWindowMode(HWND hWnd, StdVideoMode* pDisplayMode)
{
    HANG("TODO");
}

// 0x00489790
int stdDisplay_SetFullscreenMode(HWND hwnd)
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
stdVBuffer* stdDisplay_VBufferConvertColorFormat(rdTexFormat* texFormat, stdVBuffer* src, int colorKey, void* PcolorKey)
{
    HANG("TODO, easy");
}

// 0x004887c0
int stdDisplay_FlushText(char* output_buffer)
{
    int* piVar1;
    HRESULT hres;
    unsigned int uVar2;
    HDC pHVar3;
    HDC hdc;
    int x;

    // Added, may be used uninitialized
    x = 0;

    hres = (*(stdDisplay_g_backBuffer.ddraw_surface)->vtable->GetDC)((IDirectDrawSurface4*)stdDisplay_g_backBuffer.ddraw_surface, &hdc);
    if (hres != 0)
    {
        return 0;
    }
    SetBkMode(hdc, 1);
    SelectObject(hdc, stdDisplay_hFont);
    SetTextColor(hdc, 0xffff);
    uVar2 = 0xffffffff;
    pHVar3 = hdc;
    do
    {
        if (uVar2 == 0)
            break;
        uVar2 = uVar2 - 1;
        piVar1 = &pHVar3->unused;
        pHVar3 = (HDC)((int)&pHVar3->unused + 1);
    } while (*(char*)piVar1 != '\0');
    TextOutA(hdc, x, (int)output_buffer, (LPCSTR)hdc, ~uVar2 - 1);
    (*(stdDisplay_g_backBuffer.ddraw_surface)->vtable->ReleaseDC)((IDirectDrawSurface4*)stdDisplay_g_backBuffer.ddraw_surface, hdc);
    return 1;
}

// 0x00488850
int stdDisplay_VideoModeCompare(StdVideoMode* pMode1, StdVideoMode* pMode2)
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

// 0x00489bc0
void stdDisplay_FillMainSurface(void)
{
    if (stdDisplay_FillMainSurface_ptr != NULL)
    {
        // TODO: support function pointer in GenerateGlobalHeaderFromSymbols.py
        (stdDisplay_FillMainSurface_ptr)();
        return;
    }
    return;
}

// 0x00489bd0
int stdDisplay_ColorFillSurface(tVSurface* pSurf, DWORD dwFillColor, LECRECT* lpRect)
{
    HANG("TODO");
}

// 0x00489cd0
int stdDisplay_BackBufferFill(unsigned int r, unsigned int b, unsigned int g, LECRECT* lpRect)
{
    HANG("TODO");
}

// 0x00489d20
int stdDisplay_SaveScreen(char* pFilename)
{
    HANG("TODO");
}

// 0x00489d40
int stdDisplay_GetNumVideoModes(void)
{
    HANG("TODO");
}

// 0x00489d50
int stdDisplay_CopyVideoMode(size_t modeNum, StdVideoMode* pDestMode)
{
    HANG("TODO");
}

// 0x00489d90
int stdDisplay_CopyCurrentVideoMode(StdVideoMode* pDisplayMode)
{
    HANG("TODO");
}
