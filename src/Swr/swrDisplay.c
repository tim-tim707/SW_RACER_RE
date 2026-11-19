#include "swrDisplay.h"

#include "globals.h"
#include "engine_config.h"
#include "swrModel.h"

#include <macros.h>
#include <string.h>
#include <Engine/rdThing.h>
#include <Engine/rdroid.h>
#include <Platform/wuRegistry.h>
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
    for (int slot = SWR_ASSET_BUFFER_MAX_INDEX; slot >= 0; slot--)
        swrModel_FreeSlotMaterials(slot);
    if (swr_rootModel_ptr != NULL)
    {
        swr_rootModel_ptr->aGeos[0].numMeshes = 0;
        swr_rootModel_ptr->numMaterials = 0;
        swr_rootModel_ptr->apMaterials = NULL;
        rdModel3_Free(swr_rootModel_ptr);
    }
    rdThing_Free(swr_rootModelThing_ptr);
    rdClose();
    std3D_Close();
    stdDisplay_ClearMode();
    stdDisplay_Close();
    std3D_Shutdown();
    stdDisplay_Shutdown();
}

// 0x00424180
int swrDisplay_SetSettingsFromRegistry(StdDisplayEnvironment* env, swrMainDisplaySettings* displaySettings)
{
    char name[256] = { wuRegistry_lpClass[0] };
    StdDisplayInfo* info;
    int i;

    Main_drawDevices = env;
    displaySettings->currentDevice = env->numInfos - 1;
    wuRegistry_GetString("Display", name, sizeof(name), wuRegistry_lpClass);
    for (i = 0; (unsigned int)i < (unsigned int)Main_drawDevices->numInfos; i++) {
        if (strcmp(Main_drawDevices->aDisplayInfos[i].displayDevice.aDriverName, name) == 0) {
            displaySettings->currentDevice = i;
            break;
        }
    }

    info = &Main_drawDevices->aDisplayInfos[displaySettings->currentDevice];
    displaySettings->nb3DDevices = info->numDevices - 1;
    wuRegistry_GetString("3D Device", name, sizeof(name), wuRegistry_lpClass);
    for (i = 0; (unsigned int)i < (unsigned int)info->numDevices; i++) {
        if (strcmp(info->aDevices[i].deviceDescription, name) == 0) {
            displaySettings->nb3DDevices = i;
            break;
        }
    }

    swrMainDisplayMode.aspectRatio = 1.0f;
    swrMainDisplayMode.rasterInfo.width = wuRegistry_GetInt("Display Width", SWR_DISPLAY_DEFAULT_WIDTH);
    swrMainDisplayMode.rasterInfo.height = wuRegistry_GetInt("Display Height", SWR_DISPLAY_DEFAULT_HEIGHT);
    swrMainDisplayMode.rasterInfo.colorInfo.bpp = SWR_DISPLAY_BPP;
    swrMainDisplayMode.rasterInfo.colorInfo.colorMode = T_STDCOLOR_RGB;
    displaySettings->_3DDeviceIndex = FindMatchingVideoMode(swrMainDisplayMode, displaySettings);
    swrMainDisplayMode = info->aModes[displaySettings->_3DDeviceIndex];
    displaySettings->geometryMode = RD_GEOMETRY_FULL;
    displaySettings->lightMode = RD_LIGHTING_GOURAUD;
    displaySettings->backbufferFill = 1;
    displaySettings->RegFullScreen = Main_fullscreen_unk == 0;
    displaySettings->RegFixFlicker = 0;
    displaySettings->RegDevMode = Main_devMode;
    displaySettings->RegUseFett = 0;
    return 0;
}

// 0x004243C0
int FindMatchingVideoMode(StdVideoMode mode, swrMainDisplaySettings* displaySettings)
{
    StdDisplayInfo* info = &Main_drawDevices->aDisplayInfos[displaySettings->currentDevice];
    unsigned int i;

    for (i = 0; i < (unsigned int)info->numModes; i++) {
        const tRasterInfo* raster = &info->aModes[i].rasterInfo;
        if (raster->colorInfo.bpp == SWR_DISPLAY_BPP && raster->width == mode.rasterInfo.width && raster->height == mode.rasterInfo.height)
            return i;
    }
    return 0;
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
