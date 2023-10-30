#include "swrAssetBuffer.h"

#include "globals.h"

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
