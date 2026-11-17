#include "swrAssetBuffer.h"

#include "globals.h"
#include "swr.h"
#include "swrModel.h"
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

// 0x00445bf0
int swrAssetBuffer_RemainingSize(void)
{
    char* tmp;

    tmp = swrAssetBuffer_GetBuffer();
    return (int)assetBufferEnd - (int)tmp;
}

// 0x004475d0
void swrAssetBuffer_InvalidateTexturesBelow(char* ptr)
{
    HANG("TODO");
}
