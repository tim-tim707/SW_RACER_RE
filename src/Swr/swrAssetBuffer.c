#include "swrAssetBuffer.h"

#include "globals.h"
#include "swr.h"
#include "swrModel.h"
#include "swrRender.h"
#include "swrSprite.h"
#include "engine_config.h"

#include <macros.h>

// 0x00445aa0
void swrAssetBuffer_ResetToIndex(int index)
{
    char* checkpoint;

    assetBufferIndex = index;
    checkpoint = (&assetBuffer)[index - 1];
    (&assetBuffer)[index] = checkpoint;
    swrAssetBuffer_InvalidateTexturesBelow(checkpoint);
    swr_noop2();
    for (int i = SWR_ASSET_BUFFER_MAX_INDEX; i > assetBufferIndex; i--)
        (&assetBuffer)[i] = NULL;
    assetBufferOverflow = 0;
    for (int slot = SWR_ASSET_BUFFER_MAX_INDEX; slot >= assetBufferIndex; slot--)
        swrModel_FreeSlotMaterials(slot);
}

// 0x00445b20
void swrAssetBuffer_SetBuffer(char* ptr)
{
    (&assetBuffer)[assetBufferIndex] = ptr;
}

// 0x00445b40
char* swrAssetBuffer_GetBuffer(void)
{
    return (&assetBuffer)[assetBufferIndex];
}

// 0x00445b50
BOOL swrAssetBuffer_InBounds(char* ptr)
{
    char* buf;

    buf = swrAssetBuffer_GetBuffer();
    return ptr < buf;
}

// 0x00445b60
int swrAssetBuffer_GetNewIndex(unsigned int offset)
{
    int i;
    unsigned int* puVar1;

    i = assetBufferIndex + -1;
    if (0 < i)
    {
        puVar1 = ((unsigned int*)&assetBuffer) + i;
        do
        {
            if (*puVar1 <= offset)
                break;
            i = i + -1;
            puVar1 = puVar1 + -1;
        } while (0 < i);
    }
    return i + 1;
}

// 0x00445b90
void swrAssetBuffer_CheckOverflow(void)
{
    char debugText[64];
    int slot = 1;

    while ((&assetBuffer)[slot] != NULL) {
        if (swrAssetBuffer_debugPrintSlots != 0)
            sprintf(debugText, swrAssetBuffer_slotDebugFormat, slot);
        slot++;
    }
    // the original spins forever once the newest slot reaches the end of the buffer
    if (assetBufferEnd <= (&assetBuffer)[slot - 1]) {
        while (1) {
        }
    }
}

// 0x00445bf0
int swrAssetBuffer_RemainingSize(void)
{
    char* tmp;

    tmp = swrAssetBuffer_GetBuffer();
    return (int)assetBufferEnd - (int)tmp;
}

// 0x00445c00
void ResetModelPreviewState_Maybe(void)
{
    translation_unk.x = 0.0f;
    translation_unk.y = 0.0f;
    translation_unk.z = 0.0f;
    rotation_unk.x = 0.0f;
    rotation_unk.y = 0.0f;
    rotation_unk.z = 0.0f;
    swrViewport_cameraResetWord = 0;
    swrRender_frameClearFlags = swrRender_FRAME_CLEAR_COLOR;
    swrSprite_SetColor(-0x67, 0, 0, 0, 0xff);
    SetFogParameters(996, 1000, 0xff, 0xff, 0xff, 0xff);
}

// 0x00448d40
void swrAssetBuffer_ReserveRegionA_Maybe(void)
{
    char* buffer = swrAssetBuffer_GetBuffer();

    swrAssetBuffer_regionA = (char*)(((uintptr_t)buffer + 0x3f) & ~(uintptr_t)0x3f);
    swrAssetBuffer_SetBuffer(buffer + SWR_ASSET_BUFFER_REGION_A_SIZE + 0x40);
}

// 0x00448d60
void swrAssetBuffer_ReserveRegionB_Maybe(void)
{
    char* buffer = swrAssetBuffer_GetBuffer();

    swrAssetBuffer_regionB = (char*)(((uintptr_t)buffer + 0x3f) & ~(uintptr_t)0x3f);
    swrAssetBuffer_regionBEnd = swrAssetBuffer_regionB + SWR_ASSET_BUFFER_REGION_B_SIZE;
    swrAssetBuffer_SetBuffer(buffer + SWR_ASSET_BUFFER_REGION_B_SIZE + 0x40);
}

// 0x004475d0
void swrAssetBuffer_InvalidateTexturesBelow(char* ptr)
{
    for (int i = 0; i < SWR_TEXTURE_BUFFER_SIZE; i++) {
        if ((char*)texture_buffer[i] > ptr)
            texture_buffer[i] = NULL;
    }
}

// 0x00448d10
void swrAssetBuffer_GetStats(int* out1, int* out2, int* out3)
{
    *out1 = assetBufferUnknownStats1;
    *out3 = assetBufferUnknownStats4;
    *out2 = assetBufferUnknownStats2;
}
