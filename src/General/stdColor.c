#include "stdColor.h"

#include "globals.h"
#include "types.h"
#include "macros.h"

// void __cdecl stdColor_ColorConvertOneRow(BYTE *pDestRow, ColorInfo *pDestInfo, BYTE *pSrcRow, ColorInfo *pSrcInfo, int width, int bColorKey, LPDDCOLORKEY pColorKey)
// 0x0048d1c0
void stdColor_ColorConvertOneRow(char* destRow, ColorInfo* destInfo, char* srcRow, ColorInfo* srcInfo, int width, int colorKey, void* PcolorKey)
{
    int srcRedBPP = srcInfo->redBPP;
    int srcGreenBPP = srcInfo->greenBPP;
    char srcBlueBPP = (char)srcInfo->blueBPP;
    int srcAlphaBPP = srcInfo->alphaBPP;
    unsigned int alphaMask = 0;
    int alphaKeyThreshold = 0;

    if (srcAlphaBPP != 0) {
        alphaMask = 0xffffffff >> (0x20 - srcAlphaBPP);
        unsigned int alphaMax = 0xff >> srcInfo->AlphaShr;
        if ((int)(alphaMax & 0xfffffffe) < 3) {
            alphaKeyThreshold = 1;
        } else {
            alphaKeyThreshold = (int)alphaMax >> 1;
        }
    }

    int redShift = srcRedBPP - destInfo->redBPP;
    int greenShift = srcGreenBPP - destInfo->greenBPP;
    unsigned char blueShift = srcBlueBPP - (char)destInfo->blueBPP;
    int alphaShift = 0;
    if (srcAlphaBPP != 0) {
        alphaShift = srcAlphaBPP - destInfo->alphaBPP;
    }

    while (0 < width) {
        unsigned int pixel = 0;
        switch (srcInfo->bpp) {
        case 8:
            pixel = (unsigned char)*srcRow;
            break;
        case 0x10:
            pixel = *(unsigned short*)srcRow;
            break;
        case 0x18:
            pixel = ((unsigned char)srcRow[0] << 0x10) | ((unsigned char)srcRow[1] << 8) | (unsigned char)srcRow[2];
            break;
        case 0x20:
            pixel = *(unsigned int*)srcRow;
            break;
        default:
            (*stdPlatform_hostServices_ptr->assert)("Unsupported pixel depth.  Only 8, 16, 24, & 32 bits per pixel supported at the moment.", "D:\\devel.QA5\\pc_gnome\\SpecPlat\\rdroid_gnome\\Jones3D\\Libs\\Std\\General\\stdColor.c", 0x108);
            break;
        }

        unsigned int r = (pixel >> srcInfo->redPosShift) & (0xffffffff >> (0x20 - srcRedBPP));
        unsigned int g = (pixel >> srcInfo->greenPosShift) & (0xffffffff >> (0x20 - srcGreenBPP));
        unsigned int b = (pixel >> srcInfo->bluePosShift) & (0xffffffff >> (0x20 - srcBlueBPP));
        unsigned int a = 0;
        if (srcInfo->alphaBPP != 0) {
            a = (pixel >> srcInfo->alphaPosShift) & alphaMask;
        }

        if (redShift < 1) {
            r = r << ((-redShift) & 0x1f);
        } else {
            r = r >> (redShift & 0x1f);
        }
        if (greenShift < 1) {
            g = g << ((-greenShift) & 0x1f);
        } else {
            g = g >> (greenShift & 0x1f);
        }
        // Faithful quirk: the original gates the blue channel's shift *direction*
        // on redShift (not blueShift), while still shifting by the blue amount.
        if (redShift < 1) {
            b = b << ((-blueShift) & 0x1f);
        } else {
            b = b >> (blueShift & 0x1f);
        }

        unsigned int outPixel = (g << destInfo->greenPosShift) | (b << destInfo->bluePosShift) | (r << destInfo->redPosShift);
        if (srcInfo->alphaBPP != 0) {
            if (colorKey == 0) {
                if (alphaShift < 1) {
                    a = a << ((-alphaShift) & 0x1f);
                } else {
                    a = a >> (alphaShift & 0x1f);
                }
                outPixel = outPixel | (a << destInfo->alphaPosShift);
            } else if (a < (unsigned int)alphaKeyThreshold) {
                outPixel = (unsigned int)PcolorKey;
            }
        }

        switch (destInfo->bpp) {
        case 8:
            *destRow = (char)outPixel;
            break;
        case 0x10:
            *(short*)destRow = (short)outPixel;
            break;
        case 0x18:
            destRow[0] = (char)(outPixel >> 0x10);
            destRow[1] = (char)(outPixel >> 8);
            destRow[2] = (char)outPixel;
            break;
        case 0x20:
            *(unsigned int*)destRow = outPixel;
            break;
        }

        srcRow = srcRow + ((unsigned int)srcInfo->bpp >> 3);
        destRow = destRow + ((unsigned int)destInfo->bpp >> 3);
        width = width - 1;
    }
}
