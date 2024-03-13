#include "sithRender.h"

#include <stdio.h>

#include "globals.h"

#include <Win95/stdDisplay.h>

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
        sprintf(filename, "%s%03d.bmp", snap__, index);
        stream = fopen(filename, "rb");
        if (stream == NULL)
            break;
        fclose(stream);
    } while (stream != NULL);

    stdDisplay_SaveScreen(filename);
}
