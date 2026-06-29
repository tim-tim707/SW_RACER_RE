#ifndef SWRASSETBUFFER_H
#define SWRASSETBUFFER_H

#include "types.h"

#define swrAssetBuffer_ResetToIndex_ADDR (0x00445aa0)
#define swrAssetBuffer_SetBuffer_ADDR (0x00445b20)
#define swrAssetBuffer_GetBuffer_ADDR (0x00445b40)
#define swrAssetBuffer_InBounds_ADDR (0x00445b50)
#define swrAssetBuffer_GetNewIndex_ADDR (0x00445b60)
#define swrAssetBuffer_CheckOverflow_ADDR (0x00445b90)
#define swrAssetBuffer_RemainingSize_ADDR (0x00445bf0)
#define ResetModelPreviewState_Maybe_ADDR (0x00445c00)
#define swrAssetBuffer_InvalidateTexturesBelow_ADDR (0x004475d0)
#define swrAssetBuffer_GetStats_ADDR (0x00448d10)
#define swrAssetBuffer_ReserveRegionA_Maybe_ADDR (0x00448d40)
#define swrAssetBuffer_ReserveRegionB_Maybe_ADDR (0x00448d60)

void swrAssetBuffer_ResetToIndex(int index);
void swrAssetBuffer_SetBuffer(char* buffer);
char* swrAssetBuffer_GetBuffer(void);
BOOL swrAssetBuffer_InBounds(char* ptr);
int swrAssetBuffer_GetNewIndex(unsigned int offset);
void swrAssetBuffer_CheckOverflow(void);
int swrAssetBuffer_RemainingSize(void);

// Resets the single-model preview scene: zeroes the preview transform, sets the background color, and configures fog (best guess).
void ResetModelPreviewState_Maybe(void);
void swrAssetBuffer_InvalidateTexturesBelow(char* ptr);
void swrAssetBuffer_GetStats(int* out1, int* out2, int* out3);

// Reserves a 64-byte-aligned scratch region from the asset buffer (best guess).
void swrAssetBuffer_ReserveRegionA_Maybe(void);

// Reserves a second 64-byte-aligned scratch region from the asset buffer (best guess).
void swrAssetBuffer_ReserveRegionB_Maybe(void);

#endif // SWRASSETBUFFER_H
