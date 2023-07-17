#ifndef SWRLOADER_H
#define SWRLOADER_H

#include <stdio.h>
#include "types.h"

#define swrLoader_TypeToFile_ADDR (0x0042d600)
#define swrLoader_OpenBlock_ADDR (0x0042d680)
#define swrLoader_CloseBlock_ADDR (0x0042d6f0)

FILE** swrLoader_TypeToFile(swrLoader_TYPE type);
void swrLoader_OpenBlock(swrLoader_TYPE type);
void swrLoader_CloseBlock(swrLoader_TYPE type);

#endif // SWRLOADER_H
