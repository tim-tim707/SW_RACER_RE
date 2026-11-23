#include "swrDisplay.h"

#include "globals.h"
#include "engine_config.h"
#include "swrModel.h"

#include <macros.h>
#include <stdio.h>
#include <string.h>
#include <Engine/rdThing.h>
#include <Engine/rdroid.h>
#include <Platform/wuRegistry.h>
#include <Platform/std3D.h>
#include <Primitives/rdModel.h>
#include <Win95/Window.h>
#include <Win95/stdDisplay.h>
#include <Win95/DirectX.h>
#include <Swr/swrConfig.h>

// 0x00409B10
BOOL swrDisplay_Open(swrMainDisplaySettings* a1)
{
    Device3DCaps caps;
    StdVideoMode mode;
    int i;

    if (swrConfig_ReadVideoConfig("current") < 0) {
        swrConfig_SetDefaultVideo();
        swrConfig_WriteVideoConfig("current");
    }
    if (a1->RegFullScreen != 0)
        swrMainDisplay_windowed = 0;

    if (!stdDisplay_Startup())
        return 1;
    if (!stdDisplay_Open(a1->currentDevice))
        return 1;
    swrMainDisplay_currentDevice = a1->currentDevice;
    if (!stdDisplay_SetMode(a1->videoModeIndex, a1->RegFullScreen == 0))
        return 1;
    if (stdDisplay_CopyCurrentVideoMode(&mode) != 0)
        return 1;

    stdDisplayWindow_g.rasterInfo = mode.rasterInfo;
    if (!swrDisplay_SetWindowSize())
        Window_SetWindowSize(stdDisplayWindow_g.rasterInfo.width, stdDisplayWindow_g.rasterInfo.height);

    if (!std3D_Startup()) {
        MessageBoxA(NULL, "Direct3D Failure\n\nNo 3D Hardware Found\n", "Racer Error", 0);
        sprintf(unknownError_buffer, "ERROR: No 3D Hardware Found.\n%s", std_output_buffer);
        return 1;
    }

    for (i = 0; i < (int)(sizeof(swrMaterialSlot_array) / sizeof(swrMaterialSlot_array[0])); i++)
        swrMaterialSlot_array[i] = NULL;

    // only these three fields are set; the rest of caps is uninitialized stack
    caps.hasZBuffer = 1;
    caps.bTexturePerspectiveSupported = 1;
    caps.bHAL = 1;
    if (!std3D_GetDeviceCaps(std3D_FindMatching3DDevice(&caps), &caps) || caps.bHAL == 0) {
        stdDisplay_Close();
        std3D_Shutdown();
        stdDisplay_Shutdown();
        return 1;
    }
    if (!std3D_Open(a1->device3DIndex))
        return 1;

    rdFace_FogFlagsSupportedByHardware = Direct3d_SetFogMode();
    direct3d_LensFlareCompatible = Direct3d_IsLensflareCompatible();
    if (direct3d_LensFlareCompatible == 0) {
        swrConfig_VIDEO_ENGINEEXHAUST = 0;
        swrConfig_VIDEO_LENSFLARE = 0;
    }
    return rdOpen() == 0;
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
    displaySettings->device3DIndex = info->numDevices - 1;
    wuRegistry_GetString("3D Device", name, sizeof(name), wuRegistry_lpClass);
    for (i = 0; (unsigned int)i < (unsigned int)info->numDevices; i++) {
        if (strcmp(info->aDevices[i].deviceDescription, name) == 0) {
            displaySettings->device3DIndex = i;
            break;
        }
    }

    swrMainDisplayMode.aspectRatio = 1.0f;
    swrMainDisplayMode.rasterInfo.width = wuRegistry_GetInt("Display Width", SWR_DISPLAY_DEFAULT_WIDTH);
    swrMainDisplayMode.rasterInfo.height = wuRegistry_GetInt("Display Height", SWR_DISPLAY_DEFAULT_HEIGHT);
    swrMainDisplayMode.rasterInfo.colorInfo.bpp = SWR_DISPLAY_BPP;
    swrMainDisplayMode.rasterInfo.colorInfo.colorMode = T_STDCOLOR_RGB;
    displaySettings->videoModeIndex = swrDisplay_FindMatchingVideoMode(swrMainDisplayMode, displaySettings);
    swrMainDisplayMode = info->aModes[displaySettings->videoModeIndex];
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
int swrDisplay_FindMatchingVideoMode(StdVideoMode mode, swrMainDisplaySettings* displaySettings)
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
int swrDisplay_Resize(swrMainDisplaySettings* displaySettings, int width, int height)
{
    int opened;

    if ((width == stdDisplayWindow_g.rasterInfo.width) && (height == stdDisplayWindow_g.rasterInfo.width))
    {
        return false;
    }
    std3D_Close();
    stdDisplay_ClearMode();
    opened = stdDisplay_SetMode(displaySettings->videoModeIndex, 0);
    if (opened == 0)
    {
        return true;
    }
    opened = std3D_Open(displaySettings->device3DIndex);
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
