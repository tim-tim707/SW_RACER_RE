#include "stdBmp.h"

#include <macros.h>
#include <string.h>

#include "globals.h"
#include "stdColor.h"
#include <stdPlatform.h>
#include <Win95/stdDisplay.h>

// 0x0048d4a0
int stdBmp_VBufferToBmp(char* filename, tVBuffer* vbuffer)
{
    static char sourceFile[] = "D:\\devel.QA5\\pc_gnome\\SpecPlat\\rdroid_gnome\\Jones3D\\Libs\\Std\\General\\stdBmp.c";
    BITMAPFILEHEADER fileHeader;
    BITMAPINFOHEADER infoHeader;
    ColorInfo rgb24;
    stdFile_t file;
    unsigned int imageSize;
    unsigned int rowBytes;
    char* row;
    int y;

    if (vbuffer->rasterInfo.colorInfo.colorMode == T_STDCOLOR_PAL)
        return 1;

    // faithful: biSizeImage/bfSize use the source bpp although rows are written as 24-bit
    imageSize = (unsigned int)(vbuffer->rasterInfo.colorInfo.bpp * vbuffer->rasterInfo.height * vbuffer->rasterInfo.width) >> 3;
    fileHeader.bfType = 0x4d42; // "BM"
    fileHeader.bfSize = imageSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    fileHeader.bfReserved1 = 0;
    fileHeader.bfReserved2 = 0;
    fileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    memset(&infoHeader, 0, sizeof(infoHeader));
    infoHeader.biSize = sizeof(BITMAPINFOHEADER);
    infoHeader.biWidth = vbuffer->rasterInfo.width;
    infoHeader.biHeight = vbuffer->rasterInfo.height;
    infoHeader.biPlanes = 1;
    infoHeader.biBitCount = 24;
    infoHeader.biCompression = BI_RGB;
    infoHeader.biSizeImage = imageSize;
    infoHeader.biXPelsPerMeter = 2834; // 72 dpi
    infoHeader.biYPelsPerMeter = 2834;

    file = stdPlatform_hostServices_ptr->fileOpen(filename, "wb");
    if (file == 0) {
        stdPlatform_DebugLog(stdPlatform_hostServices_ptr->errorPrint, sourceFile, 506, "Unable to open file '%s' for writing.\n", filename, 0, 0, 0);
        return 1;
    }
    if (stdPlatform_hostServices_ptr->fileWrite(file, &fileHeader, sizeof(BITMAPFILEHEADER)) != sizeof(BITMAPFILEHEADER)) {
        stdPlatform_DebugLog(stdPlatform_hostServices_ptr->errorPrint, sourceFile, 515, "Error attempting to write %d bytes to file '%s'.\n", sizeof(BITMAPFILEHEADER), filename, 0, 0);
        stdPlatform_hostServices_ptr->fileClose(file);
        return 1;
    }
    if (stdPlatform_hostServices_ptr->fileWrite(file, &infoHeader, sizeof(BITMAPINFOHEADER)) != sizeof(BITMAPINFOHEADER)) {
        stdPlatform_DebugLog(stdPlatform_hostServices_ptr->errorPrint, sourceFile, 525, "Error attempting to write %d bytes to file '%s'.\n", sizeof(BITMAPINFOHEADER), filename, 0, 0);
        stdPlatform_hostServices_ptr->fileClose(file);
        return 1;
    }

    rowBytes = vbuffer->rasterInfo.width * 3;
    row = stdPlatform_hostServices_ptr->alloc(rowBytes);
    if (row == NULL) {
        stdPlatform_hostServices_ptr->fileClose(file);
        return 1;
    }
    memset(row, 0, rowBytes);

    // the EXE leaves the Shr/alpha fields as stack garbage; zero is what an 8:8:8 target needs
    memset(&rgb24, 0, sizeof(rgb24));
    rgb24.colorMode = T_STDCOLOR_RGB;
    rgb24.bpp = 24;
    rgb24.redBPP = 8;
    rgb24.greenBPP = 8;
    rgb24.blueBPP = 8;
    rgb24.redPosShift = 0;
    rgb24.greenPosShift = 8;
    rgb24.bluePosShift = 16;
    stdDisplay_VBufferLock(vbuffer);
    for (y = vbuffer->rasterInfo.height - 1; y >= 0; y--) {
        stdColor_ColorConvertOneRow(row, &rgb24, (char*)(vbuffer->pPixels + y * vbuffer->rasterInfo.rowSize), &vbuffer->rasterInfo.colorInfo, vbuffer->rasterInfo.width, 0, NULL);
        if (stdPlatform_hostServices_ptr->fileWrite(file, row, rowBytes) != (size_t)(vbuffer->rasterInfo.width * 3)) {
            stdPlatform_DebugLog(stdPlatform_hostServices_ptr->errorPrint, sourceFile, 560, "Error attempting to write %d bytes to file '%s'.\n", rowBytes, filename, 0, 0);
            stdPlatform_hostServices_ptr->free(row);
            stdPlatform_hostServices_ptr->fileClose(file);
            return 1;
        }
    }
    stdPlatform_hostServices_ptr->free(row);
    stdDisplay_VBufferUnlock(vbuffer);
    stdPlatform_hostServices_ptr->fileClose(file);
    return 0;
}
