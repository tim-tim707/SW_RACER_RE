#ifndef SWRASSETBUFFER_H
#define SWRASSETBUFFER_H

#include "types.h"

#define swrAssetBuffer_SetBuffer_ADDR (0x00445b20)
#define swrAssetBuffer_GetBuffer_ADDR (0x00445b40)
#define swrAssetBuffer_InBounds_ADDR (0x00445b50)
#define swrAssetBuffer_GetNewIndex_ADDR (0x00445b60)

#define swrAssetBuffer_RemainingSize_ADDR (0x00445bf0)

void swrAssetBuffer_SetBuffer(char* buffer);
char* swrAssetBuffer_GetBuffer(void);
BOOL swrAssetBuffer_InBounds(char* ptr);
int swrAssetBuffer_GetNewIndex(unsigned int offset);

int swrAssetBuffer_RemainingSize(void);

#endif // SWRASSETBUFFER_H
