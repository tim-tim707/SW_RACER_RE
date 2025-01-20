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
