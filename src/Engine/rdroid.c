#include "rdroid.h"

#include "types.h"
#include "globals.h"

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
