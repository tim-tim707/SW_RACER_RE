#include "swrDisplay.h"

#include "globals.h"

#include <macros.h>
#include <Engine/rdThing.h>
#include <Engine/rdroid.h>
#include <Platform/std3D.h>
#include <Primitives/rdModel.h>
#include <Win95/Window.h>
#include <Win95/stdDisplay.h>

// 0x00409B10
BOOL swrDisplay_Open(swrMainDisplaySettings* a1)
{
    HANG("TODO");
}

// 0x00409d00
void swrDisplay_Shutdown(void)
{
    HANG("TODO");
    if (swr_rootModel_ptr != NULL)
    {
        swr_rootModel_ptr->aGeos[0].numMeshes = 0;
        swr_rootModel_ptr->numMaterials = 0;
        swr_rootModel_ptr->apMaterials = NULL;
        rdModel3_Free(swr_rootModel_ptr);
    }
    rdThing_Free((RdThing*)swr_rootThing_ptr);
    rdClose();
    std3D_Close();
    stdDisplay_ClearMode();
    stdDisplay_Close();
    std3D_Shutdown();
    stdDisplay_Shutdown();
}

// 0x00424180
int swrDisplay_SetSettingsFromRegistry(StdDisplayEnvironment* a1, swrMainDisplaySettings* a2)
{
    HANG("TODO");
}

// 0x004243C0
int FindMatchingVideoMode(float a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11, int a12, int a13, int a14, int a15, int a16, int a17, int a18, int a19, int a20, swrMainDisplaySettings* a21)
{
    HANG("TODO");
}

// 0x00423840
bool swrDisplay_Resize(swrMainDisplaySettings* displaySettings, int width, int height)
{
    int opened;

    if ((width == stdDisplayWindow_g.rasterInfo.width) && (height == stdDisplayWindow_g.rasterInfo.width))
    {
        return false;
    }
    std3D_Close();
    stdDisplay_ClearMode();
    opened = stdDisplay_SetMode(displaySettings->_3DDeviceIndex, 0);
    if (opened == 0)
    {
        return true;
    }
    opened = std3D_Open(displaySettings->nb3DDevices);
    return opened == 0;
}

// 0x004238a0
int swrDisplay_SetWindowSize(void)
{
    if ((swrMainDisplay_windowed != 0) && (swrMainDisplay_currentDevice != 0))
    {
        Window_SetWindowSize(200, 200);
        return 1;
    }
    return 0;
}
