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

// 0x00445b50
bool swrAssetBuffer_InBounds(char* ptr)
{
    char* buf;

    buf = swrAssetBuffer_GetBuffer();
    return ptr < buf;
}

// 0x00445bf0
int swrAssetBuffer_RemainingSize(void)
{
    char* tmp;

    tmp = swrAssetBuffer_GetBuffer();
    return (int)assetBufferEnd - (int)tmp;
}
