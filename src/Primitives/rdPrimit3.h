#ifndef RDPRIMIT3_H
#define RDPRIMIT3_H

#include "types.h"

#define rdPrimit3_ClipFace_ADDR (0x004910a0)
#define rdPrimit3_NoClipFace_ADDR (0x00491ac0)

void rdPrimit3_ClipFace(rdClipFrustum* pFrustrum, RdGeometryMode geoMode, RdLightMode lightMode, rdPrimit3* pSrc, rdPrimit3* pDest, rdVector2* pTexVertOffset);
void rdPrimit3_NoClipFace(rdGeoMode_t geoMode, int lightMode, rdMeshinfo* _vertexSrc, rdMeshinfo* _vertexDst, rdVector2* idkIn);

#endif // RDPRIMIT3_H
