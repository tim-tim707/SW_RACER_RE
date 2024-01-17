#include "swrDisplay.h"

#include "globals.h"

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
    rdThing_Free(swr_rootThing_ptr);
    rdClose();
    std3D_Close();
    stdDisplay_ClearMode();
    stdDisplay_Close();
    std3D_Shutdown();
    stdDisplay_Shutdown();
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
