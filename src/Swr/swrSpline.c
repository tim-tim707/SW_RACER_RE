#include "swrSpline.h"

#include "swrLoader.h"
#include "macros.h"
#include "swrAssetBuffer.h"

// 0x00446fc0
void swrSpline_LoadSpline(int index, unsigned short** b)
{
    swrLoader_OpenBlock(swrLoader_TYPE_SPLINE_BLOCK);
    int spline_count;
    swrLoader_ReadAt(swrLoader_TYPE_SPLINE_BLOCK, 0, &spline_count, sizeof(int));
    spline_count = SWAP32(spline_count);

    if (index < 0 || index >= spline_count)
    {
        *b = NULL;
        return;
    }

    unsigned int indices_bound[2];
    swrLoader_ReadAt(swrLoader_TYPE_SPLINE_BLOCK, index * 4 + 4, indices_bound, sizeof(indices_bound));
    indices_bound[0] = SWAP32(indices_bound[0]);
    indices_bound[1] = SWAP32(indices_bound[1]);

    void* _DstBuf = swrAssetBuffer_GetBuffer();
    swrLoader_ReadAt(swrLoader_TYPE_SPLINE_BLOCK, indices_bound[0], _DstBuf, indices_bound[1] - indices_bound[0]);
    unsigned short* unk = *b;
    b = NULL;

    HANG("TODO");

    swrLoader_CloseBlock(swrLoader_TYPE_SPLINE_BLOCK);
}

// 0x004472e0
char* swrSpline_LoadSplineById(char* splineBuffer)
{
    swrSpline_LoadSpline((int)splineBuffer, (unsigned short**)&splineBuffer);
    return splineBuffer;
}
