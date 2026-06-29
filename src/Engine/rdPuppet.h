#ifndef RDPUPPET_H
#define RDPUPPET_H

#include "types.h"

#define rdPuppet_BuildJointMatrices_ADDR (0x00493310)
#define rdClip_Face3T_Maybe_ADDR (0x00493b80)

// void __cdecl rdPuppet_BuildJointMatrices(RdThing* prdThing, const RdMatrix* pPlacement)
void rdPuppet_BuildJointMatrices(void* prdThing, rdMatrix34* pPlacement);

// Clips a perspective textured-gouraud face: copies and offsets verts, then culls and W-clips it (best guess).
void rdClip_Face3T_Maybe(rdClipFrustum* frustum, unsigned int* srcFace, int* dstFace, float* offset);

#endif // RDPUPPET_H
