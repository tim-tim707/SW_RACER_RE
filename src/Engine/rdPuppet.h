#ifndef RDPUPPET_H
#define RDPUPPET_H

#include "types.h"

#define rdPuppet_BuildJointMatrices_ADDR (0x00493310)
#define rdClip_Face3T_Maybe_ADDR (0x00493b80)

// void __cdecl rdPuppet_BuildJointMatrices(RdThing* prdThing, const RdMatrix* pPlacement)
void rdPuppet_BuildJointMatrices(void* prdThing, rdMatrix34* pPlacement);

// Gathers a face into pDst (vertices, offset UVs, clamped light) and clips it against the frustum.
void rdClip_Face3T_Maybe(rdClipFrustum* pFrustum, rdMeshinfo* pSrc, rdMeshinfo* pDst, rdVector2* pTexOffset);

#endif // RDPUPPET_H
