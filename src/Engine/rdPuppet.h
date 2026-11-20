#ifndef RDPUPPET_H
#define RDPUPPET_H

#include "types.h"

#define rdPuppet_BuildJointMatrices_ADDR (0x00493310)
#define rdPrimit3_ClipFace3T_ADDR (0x00493b80)

void rdPuppet_BuildJointMatrices(RdThing* prdThing, rdMatrix34* pPlacement);

// Gathers a face into pDst (vertices, offset UVs, clamped light) and clips it against the frustum.
void rdPrimit3_ClipFace3T(rdClipFrustum* pFrustum, rdMeshinfo* pSrc, rdMeshinfo* pDst, rdVector2* pTexOffset);

#endif // RDPUPPET_H
