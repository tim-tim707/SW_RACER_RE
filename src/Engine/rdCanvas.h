#ifndef RDCANVAS_H
#define RDCANVAS_H

#include "types.h"

#define rdCanvas_New_ADDR (0x00490a50)
#define rdCanvas_NewEntry_ADDR (0x00490aa0)
// #define rdCanvas_NewEntry_ADDR (0x0043AC70)
// #define rdCanvas_Free_ADDR (0x0043AD30)
// #define rdCanvas_FreeEntry_ADDR (0x0043AD50)

rdCanvas* rdCanvas_New(uint32_t bIdk, stdVBuffer* vbuf, uint32_t x, uint32_t y, uint32_t width, uint32_t height);
int rdCanvas_NewEntry(rdCanvas* canvas, uint32_t bIdk, stdVBuffer* vbuf, uint32_t x, uint32_t y, uint32_t width, uint32_t height);
// int rdCanvas_NewEntry(rdCanvas *canvas, int bIdk, stdVBuffer *vbuf, stdVBuffer *a4, int x, int y, int width, int height, int a9);
// void rdCanvas_Free(rdCanvas *canvas);
// void rdCanvas_FreeEntry(rdCanvas *canvas);

#endif // RDCANVAS_H
