#ifndef STD_MEMORY_H
#define STD_MEMORY_H

#include "types.h"

#define daAlloc_ADDR (0x0048d7e0)
#define daFree_ADDR (0x0048d9a0)
#define daRealloc_ADDR (0x0048da80)

#define daSmallAlloc_ADDR (0x0048db10)

void* daAlloc(uint32_t size);
void daFree(void* alloc);
void* daRealloc(void* old, uint32_t size);

void* daSmallAlloc(int size);

#endif // STD_MEMORY_H
