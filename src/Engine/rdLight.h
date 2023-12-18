#ifndef RDLIGHT_H
#define RDLIGHT_H

#include "types.h"

#define rdLight_NewEntry_ADDR (0x00490510)
#define rdLight_CalcVertexIntensities_ADDR (0x00490550)
#define rdLight_CalcFaceIntensity_ADDR (0x00490750)
#define rdLight_GetIntensity_ADDR (0x00490930)

int rdLight_NewEntry(rdLight* light);
void rdLight_CalcVertexIntensities(RdLight** apLights, rdVector3* aLightPos, int numLights, rdVector3* aVertexNormal, rdVector3* aVertices, rdVector4* aVertexColors, rdVector4* aLightColors, int numVertices);
void rdLight_CalcFaceIntensity(rdLight** meshLights, rdVector3* localLightPoses, int numLights, rdFace* face, rdVector3* faceNormal, rdVector3* vertices, float param_7, void* outInfos);
float rdLight_GetIntensity(const rdVector4* pLight);

#endif // RDLIGHT_H
