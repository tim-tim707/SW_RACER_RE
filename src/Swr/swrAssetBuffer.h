#ifndef SWRASSETBUFFER_H
#define SWRASSETBUFFER_H

#include "types.h"

#define swrAssetBuffer_SetBuffer_ADDR (0x00445b20)
#define swrAssetBuffer_GetBuffer_ADDR (0x00445b40)

char* swrAssetBuffer_SetBuffer(char* buffer);
char* swrAssetBuffer_GetBuffer(void);

#endif // SWRASSETBUFFER_H
