#include "stdDisplay.h"

#include "globals.h"

// 0x004881c0
stdVBuffer* stdDisplay_VBufferNew(stdVBufferTexFmt* texFormat, int create_ddraw_surface, int param_3)
{
    HANG("TODO");
    return NULL;
}

// 0x00488310
void stdDisplay_VBufferFree(stdVBuffer* vbuffer)
{
    rdDDrawSurface* This;

    if (vbuffer->bSurfaceLocked == 0)
    {
        if (vbuffer->surface_lock_alloc != NULL)
        {
            (*stdPlatform_hostServices_ptr->free)(vbuffer->surface_lock_alloc);
            vbuffer->surface_lock_alloc = NULL;
        }
    }
    else if ((vbuffer->bSurfaceLocked == 1) && (This = vbuffer->ddraw_surface, This != NULL))
    {
        (*This->lpVtbl->Release)((IDirectDrawSurface4*)This);
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
        surface_lock = stdDisplay_VBufferLock_(&vbuffer->ddraw_surface);
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
        res = stdDisplay_VBufferUnlock_(&vbuffer->ddraw_surface);
        if (res != 0)
        {
            return res;
        }
        vbuffer->lock_cnt = vbuffer->lock_cnt - 1;
        return 0;
    }
    return 1;
}

// tVBuffer *__cdecl stdDisplay_VBufferConvertColorFormat(ColorInfo *pDesiredColorFormat, tVBuffer *pSrc, int bColorKey, LPDDCOLORKEY pColorKey)
// 0x00488670
stdVBuffer* stdDisplay_VBufferConvertColorFormat(rdTexFormat* texFormat, stdVBuffer* src, int colorKey, void* PcolorKey)
{
    HANG("TODO, easy");
}

// 0x00489a00
char* stdDisplay_VBufferLock_(rdDDrawSurface** rdsurface)
{
    HANG("TODO");
    return 0;
}

// 0x00489a60
int stdDisplay_VBufferUnlock_(rdDDrawSurface** rdsurface)
{
    HANG("TODO");
    return 0;
}
