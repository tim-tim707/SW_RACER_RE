#include "rdFont.h"

#include "globals.h"

#include <macros.h>

// 0x00493df0
void rdFont_Startup(void)
{
    if (rdFont_bStartup != 0) {
        return;
    }
    rdFont_bStartup = 1;
}

// 0x00493e10
void rdFont_Shutdown(void)
{
    if (rdFont_bOpen != 0) {
        rdFont_Close();
    }
    if (rdFont_bStartup != 0) {
        rdFont_bStartup = 0;
    }
}

// 0x00493e40
int rdFont_Open(void)
{
    if (rdFont_bOpen != 0) {
        return -2;
    }
    rdFont_bOpen = 1;
    return 0;
}

// 0x00493e60
void rdFont_Close(void)
{
    if (rdFont_bOpen != 0) {
        rdFont_bOpen = 0;
    }
}
