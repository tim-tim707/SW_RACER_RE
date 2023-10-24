#include "rdCanvas.h"

#include "types.h"
#include "globals.h"

// 0x00490a50
rdCanvas* rdCanvas_New(uint32_t bIdk, stdVBuffer* vbuf, uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    rdCanvas* canvas = (*rdroid_hostServices_ptr->alloc)(sizeof(canvas));
    if (canvas == NULL)
    {
        return NULL;
    }

    rdCanvas_NewEntry(canvas, bIdk, vbuf, x, y, width, height);
    return canvas;
}

// 0x00490aa0
int rdCanvas_NewEntry(rdCanvas* canvas, uint32_t bIdk, stdVBuffer* vbuf, uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    canvas->bIdk = bIdk;
    canvas->vbuffer = vbuf;
    if ((bIdk & 1) == 0)
    {
        canvas->xStart = 0;
        canvas->yStart = 0;
        canvas->widthMinusOne = (vbuf->format).width + -1;
        canvas->heightMinusOne = (vbuf->format).height + -1;
    }
    else
    {
        canvas->xStart = x;
        canvas->yStart = y;
        canvas->widthMinusOne = width;
        canvas->heightMinusOne = height;
    }

    canvas->screen_height_half = (float)canvas->xStart + (float)((canvas->widthMinusOne - canvas->xStart) + 1) * 0.5;
    canvas->screen_width_half = (float)canvas->yStart + (float)((canvas->heightMinusOne - canvas->yStart) + 1) * 0.5;
    return 1;
}

// 0x00490b50
void rdCanvas_Free(rdCanvas* canvas)
{
    if (canvas != NULL)
    {
        rdCanvas_FreeEntry();
        rdroid_hostServices_ptr->free(canvas);
    }
}

// 0x00494c20
rdCanvas_CLIP rdCanvas_CheckBounds(rdCanvas* canvas, int x, int y)
{
    rdCanvas_CLIP res;

    res = 0;
    if (x < canvas->xStart)
    {
        res = rdCanvas_CLIP_XUNDER;
    }
    else if (canvas->widthMinusOne < x)
    {
        res = rdCanvas_CLIP_XOVER;
    }
    if (y < canvas->yStart)
    {
        return res | rdCanvas_CLIP_YUNDER;
    }
    if (canvas->heightMinusOne < y)
    {
        res = res | rdCanvas_CLIP_YOVER;
    }
    return res;
}
