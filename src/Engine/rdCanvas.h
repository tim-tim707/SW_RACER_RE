#ifndef RDCANVAS_H
#define RDCANVAS_H

#include "types.h"

#define rdCanvas_New_ADDR (0x00490a50)
#define rdCanvas_NewEntry_ADDR (0x00490aa0)
#define rdCanvas_Free_ADDR (0x00490b50)

#define rdCanvas_CheckClipping_ADDR (0x00494c20)

rdCanvas* rdCanvas_New(uint32_t bIdk, stdVBuffer* vbuf, uint32_t x, uint32_t y, uint32_t width, uint32_t height);
int rdCanvas_NewEntry(rdCanvas* canvas, uint32_t bIdk, stdVBuffer* vbuf, uint32_t x, uint32_t y, uint32_t width, uint32_t height);
void rdCanvas_Free(rdCanvas* canvas);

rdCanvas_CLIP rdCanvas_CheckClipping(rdCanvas* canvas, int x, int y);

#endif // RDCANVAS_H
