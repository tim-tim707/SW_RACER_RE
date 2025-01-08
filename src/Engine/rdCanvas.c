#include "rdCanvas.h"

#include "types.h"
#include "globals.h"

#include <swr.h>

// 0x00490a50 TODO: Crashes when enabled
rdCanvas* rdCanvas_New(uint32_t bIdk, tVBuffer* vbuf, uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    rdCanvas* canvas = (*rdroid_hostServices_ptr->alloc)(sizeof(canvas));
    if (canvas == NULL)
    {
        return NULL;
    }

    rdCanvas_NewEntry(canvas, bIdk, vbuf, x, y, width, height);
    return canvas;
}

// 0x00490aa0 TODO: Creates a black screen when entering pod select menu
int rdCanvas_NewEntry(rdCanvas* canvas, uint32_t bIdk, tVBuffer* vbuf, uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    canvas->bIdk = bIdk;
    canvas->vbuffer = vbuf;
    if ((bIdk & 1) == 0)
    {
        canvas->xStart = 0;
        canvas->yStart = 0;
        canvas->widthMinusOne = (vbuf->rasterInfo).width + -1;
        canvas->heightMinusOne = (vbuf->rasterInfo).height + -1;
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
        swr_noop2();
        rdroid_hostServices_ptr->free(canvas);
    }
}
