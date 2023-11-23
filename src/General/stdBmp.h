#ifndef STDBMP_H
#define STDBMP_H

#include "types.h"

#define stdBmp_VBufferToBmp_ADDR (0x0048d4a0)

int stdBmp_VBufferToBmp(char* filename, stdVBuffer* vbuffer);

#endif // STDBMP_H
