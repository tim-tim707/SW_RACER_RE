#include "sithRender.h"

#include <stdio.h>

#include "globals.h"

// 0x00410480
void sithRender_MakeScreenShot(char* snap__)
{
    FILE* stream;
    char filename[80];
    int index;

    do
    {
        index = stdDisplay_ScreenshotIndex;
        stdDisplay_ScreenshotIndex = stdDisplay_ScreenshotIndex + 1;
        stdlib__sprintf(filename, "%s%03d.bmp", snap__, index);
        stream = stdlib__fopen(filename, "rb");
        if (stream == NULL)
            break;
        stdlib__fclose(stream);
    } while (stream != NULL);

    return stdDisplay_SaveScreen(filename);
}
