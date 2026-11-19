#include "rdroid.h"

#include "types.h"
#include "globals.h"

#include <Engine/rdFont.h>
#include <Raster/rdCache.h>

#include <macros.h>

// 0x00490950
int rdStartup(HostServices* p_hs)
{
    if (bRDroidStartup) {
        return 1;
    }

    rdroid_hostServices_ptr = p_hs;
    rdCache_Startup();
    if (rdFont_Startup() != 0) {
        return 0;
    }

    bRDroidStartup = 1;
    return 1;
}

// 0x00490990
void rdShutdown(void)
{
    if (bRDroidStartup == 1) {
        rdFont_Shutdown();
        bRDroidStartup = 0;
    }
}

// 0x004909b0
int rdOpen(void)
{
    if (!bRDroidStartup) {
        return 0;
    }
    if (rdroid_bRDroidOpen) {
        return 1;
    }
    if (rdFont_Open() != 0) {
        return 0;
    }

    rdroid_g_curGeometryMode = RD_GEOMETRY_FULL;
    rdroid_g_curLightingMode = RD_LIGHTING_GOURAUD;
    rdroid_g_curRenderOptions = RDROID_BACKFACE_CULLING_ENABLED;
    rdroid_bRDroidOpen = 1;
    return 1;
}

// 0x00490a00
void rdClose(void)
{
    if (rdroid_bRDroidOpen) {
        rdFont_Close();
        rdroid_bRDroidOpen = 0;
    }
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
