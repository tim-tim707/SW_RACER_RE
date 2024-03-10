#include "swrDisplay.h"

#include "globals.h"

#include <macros.h>
#include <Engine/rdThing.h>
#include <Engine/rdroid.h>
#include <Platform/std3D.h>
#include <Primitives/rdModel.h>
#include <Win95/Window.h>
#include <Win95/stdDisplay.h>

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

// 0x00423840
bool swrDisplay_Resize(swrMainDisplaySettings* displaySettings, int width, int height)
{
    int opened;

    if ((width == stdDisplayWindow_g.width) && (height == stdDisplayWindow_g.height))
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
int swrDisplay_SetWindowPos(void)
{
    if ((swrMainDisplay_windowed != 0) && (swrMainDisplay_currentDevice != 0))
    {
        Window_SetWindowPos(200, 0x14);
        return 1;
    }
    return 0;
}
