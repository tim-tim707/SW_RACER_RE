#ifndef RDLIGHT_H
#define RDLIGHT_H

#include "types.h"

#define rdLight_NewEntry_ADDR (0x00490510)

#define rdLight_CalcVertexIntensities_ADDR (0x00490550)

#define rdLight_CalcFaceIntensity_ADDR (0x00490750)

int rdLight_NewEntry(rdLight* light);

void rdLight_CalcVertexIntensities(RdLight** apLights, rdVector3* aLightPos, int numLights, rdVector3* aVertexNormal, rdVector3* aVertices, rdVector4* aVertexColors, rdVector4* aLightColors, int numVertices);

void rdLight_CalcFaceIntensity(rdLight** meshLights, rdVector3* localLightPoses, int numLights, rdFace* face, rdVector3* faceNormal, rdVector3* vertices, float param_7, void* outInfos);

#endif // RDLIGHT_H
