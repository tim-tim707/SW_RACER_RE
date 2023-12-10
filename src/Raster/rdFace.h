#ifndef RDFACE_H
#define RDFACE_H

#include "types.h"

#define rdFace_NewEntry_ADDR (0x004923c0)
#define rdFace_FreeEntry_ADDR (0x00492410)

int rdFace_NewEntry(RdFace* pFace);
void rdFace_FreeEntry(RdFace* pFace);

#endif // RDFACE_H
