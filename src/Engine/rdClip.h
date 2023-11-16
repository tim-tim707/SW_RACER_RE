#ifndef RDCLIP_H
#define RDCLIP_H

#include "types.h"

#define rdClip_Line2_ADDR (0x00494980)
#define rdClip_CalcOutcode2_ADDR (0x00494c20)

int rdClip_Line2(rdCanvas* canvas, int* pX1, int* pY1, int* pX2, int* pY2);

int rdClip_CalcOutcode2(rdCanvas* canvas, int x, int y);

#endif // RDCLIP_H
