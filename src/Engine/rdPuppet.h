#ifndef RDPUPPET_H
#define RDPUPPET_H

#include "types.h"

#define rdPuppet_BuildJointMatrices_ADDR (0x00493310)

// void __cdecl rdPuppet_BuildJointMatrices(RdThing* prdThing, const RdMatrix* pPlacement)
void rdPuppet_BuildJointMatrices(void* prdThing, rdMatrix34* pPlacement);

#endif // RDPUPPET_H
