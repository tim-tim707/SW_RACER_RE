#ifndef STDCOLOR_H
#define STDCOLOR_H

#include "types.h"

#define stdColor_ColorConvertOneRow_ADDR (0x0048d1c0)

// void __cdecl stdColor_ColorConvertOneRow(BYTE *pDestRow, ColorInfo *pDestInfo, BYTE *pSrcRow, ColorInfo *pSrcInfo, int width, int bColorKey, LPDDCOLORKEY pColorKey)
void stdColor_ColorConvertOneRow(char* destRow, rdTexFormat* destInfo, char* srcRow, rdTexFormat* srcInfo, int width, int colorKey, void* PcolorKey);

#endif // STDCOLOR_H
