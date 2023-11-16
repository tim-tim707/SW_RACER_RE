#ifndef RDPRIMIT2_H
#define RDPRIMIT2_H

#include "types.h"

#define rdPrimit2_DrawClippedLine_ADDR (0x00490e10)

int rdPrimit2_DrawClippedLine(rdCanvas* pCanvas, int x1, int y1, int x2, int y2, uint16_t color16, int mask);

#endif // RDPRIMIT2_H
