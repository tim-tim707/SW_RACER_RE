#include "rdroid.h"

#include "types.h"
#include "globals.h"

#include <macros.h>

// 0x00490950
int rdStartup(HostServices* p_hs)
{
    if (bRDroidStartup)
    {
        return 1;
    }

    rdroid_hostServices_ptr = p_hs;

    HANG("TODO: analyse the two functions between rdCache, rdActive, rdRaster startup");

    bRDroidStartup = 1;
    return 1;
}

// 0x00490990
void rdShutdown(void)
{
    HANG("TODO");
}

// 0x004909b0
int rdOpen(void)
{
    HANG("TODO");
}

// 0x00490a00
void rdClose(void)
{
    HANG("TODO");
}

// 0x00490a20
void rdSetRenderOptions(RdDroidFlags options)
{
    rdroid_g_curRenderOptions = options;
}

// 0x00490a30
void rdSetGeometryMode(RdGeometryMode mode)
{
    rdroid_g_curGeometryMode = mode;
}

// 0x00490a40
void rdSetLightingMode(RdLightMode mode)
{
    rdroid_g_curLightingMode = mode;
}
