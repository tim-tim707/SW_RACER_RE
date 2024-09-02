#ifndef RDCANVAS_H
#define RDCANVAS_H

#include "types.h"

#define rdCanvas_New_ADDR (0x00490a50)
#define rdCanvas_NewEntry_ADDR (0x00490aa0)
#define rdCanvas_Free_ADDR (0x00490b50)

rdCanvas* rdCanvas_New(uint32_t bIdk, tVBuffer* vbuf, uint32_t x, uint32_t y, uint32_t width, uint32_t height);
int rdCanvas_NewEntry(rdCanvas* canvas, uint32_t bIdk, tVBuffer* vbuf, uint32_t x, uint32_t y, uint32_t width, uint32_t height);
void rdCanvas_Free(rdCanvas* canvas);

#endif // RDCANVAS_H
