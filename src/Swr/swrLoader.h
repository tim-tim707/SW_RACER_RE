#ifndef SWRLOADER_H
#define SWRLOADER_H

#include <stdio.h>
#include "types.h"

#define swrLoader_DecompressData_ADDR (0x0042D520)
#define swrLoader_TypeToFile_ADDR (0x0042d600)
#define swrLoader_ReadAt_ADDR (0x0042d640)
#define swrLoader_OpenBlock_ADDR (0x0042d680)
#define swrLoader_CloseBlock_ADDR (0x0042d6f0)

void swrLoader_DecompressData(char* compressed, char* decompressed);
FILE** swrLoader_TypeToFile(swrLoader_TYPE type);
size_t swrLoader_ReadAt(swrLoader_TYPE type, long _Offset, void* _DstBuf, size_t _ElementSize);
void swrLoader_OpenBlock(swrLoader_TYPE type);
void swrLoader_CloseBlock(swrLoader_TYPE type);

#endif // SWRLOADER_H
