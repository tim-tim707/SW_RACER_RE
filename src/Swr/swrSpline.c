#include "swrSpline.h"

#include "swrLoader.h"
#include "types_enums.h"
#include "macros.h"
#include "swrAssetBuffer.h"
#include "globals.h"

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

    const unsigned int spline_size = indices_bound[1] - indices_bound[0];
    swrSpline* spline = (swrSpline*)swrAssetBuffer_GetBuffer();
    swrLoader_ReadAt(swrLoader_TYPE_SPLINE_BLOCK, indices_bound[0], spline, spline_size);

    *b = (unsigned short*)spline;
    // the on-disk 4-byte slot at offset 0xc is repurposed as the runtime
    // pointer to the control point array, which follows the 0x10 byte header.
    spline->control_points = (swrSplineControlPoint*)((char*)spline + sizeof(swrSpline));

    spline->unk0 = SWAP16(spline->unk0);
    // note: unk1 is intentionally left un-swapped, matching the original
    spline->num_control_points = SWAP32(spline->num_control_points);
    spline->num_segments = SWAP32(spline->num_segments);

    for (int i = 0; i < (int)spline->num_control_points; i++)
    {
        swrSplineControlPoint* cp = &spline->control_points[i];

        cp->next_count = SWAP16(cp->next_count);
        cp->prev_count = SWAP16(cp->prev_count);
        cp->next1 = SWAP16(cp->next1);
        cp->next2 = SWAP16(cp->next2);
        cp->prev1 = SWAP16(cp->prev1);
        cp->prev2 = SWAP16(cp->prev2);
        cp->prev3 = SWAP16(cp->prev3);
        cp->prev4 = SWAP16(cp->prev4);

        for (int j = 0; j < 3; j++)
            FLOAT_SWAP32_INPLACE(&cp->position.x + j);
        for (int j = 0; j < 3; j++)
            FLOAT_SWAP32_INPLACE(&cp->rotation.x + j);
        for (int j = 0; j < 3; j++)
            FLOAT_SWAP32_INPLACE(&cp->handle1.x + j);
        for (int j = 0; j < 3; j++)
            FLOAT_SWAP32_INPLACE(&cp->handle2.x + j);

        cp->progress = SWAP16(cp->progress);
        for (int j = 0; j < 8; j++)
            cp->unk_set[j] = SWAP16(cp->unk_set[j]);
        // note: cp->unk is intentionally left un-swapped, matching the original
    }

    swrAssetBuffer_SetBuffer((char*)spline + spline_size);
    swrLoader_CloseBlock(swrLoader_TYPE_SPLINE_BLOCK);
}

// 0x004472e0
char* swrSpline_LoadSplineById(char* splineBuffer)
{
    swrSpline_LoadSpline((int)splineBuffer, (unsigned short**)&splineBuffer);
    return splineBuffer;
}

// Active track's total spline length, cached by swrSpline_TraceProgress during bake.
// 0x0047e870
float swrSpline_GetTrackLength(void)
{
    return swrSpline_trackLength;
}

// 0x0044eeb0
void swrSpline_EvaluateAtOffset(void* cursor, rdMatrix44* out, float t)
{
    HANG("TODO");
}
