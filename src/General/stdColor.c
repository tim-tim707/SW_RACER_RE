#include "stdColor.h"

#include "types.h"
#include "macros.h"

// 0x0048d1c0
// void __cdecl stdColor_ColorConvertOneRow(BYTE *pDestRow, ColorInfo *pDestInfo, BYTE *pSrcRow, ColorInfo *pSrcInfo, int width, int bColorKey, LPDDCOLORKEY pColorKey)
void stdColor_ColorConvertOneRow(char* destRow, ColorInfo* destInfo, char* srcRow, ColorInfo* srcInfo, int width, int colorKey, void* PcolorKey)
{
    HANG("TODO");
}
