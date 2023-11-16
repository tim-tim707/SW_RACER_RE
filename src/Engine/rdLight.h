#ifndef RDLIGHT_H
#define RDLIGHT_H

#include "types.h"

#define rdLight_NewEntry_ADDR (0x00490510)

#define rdLight_CalcFaceIntensity_ADDR (0x00490750)

int rdLight_NewEntry(rdLight* light);

// 0x00490750
void rdLight_CalcFaceIntensity(rdLight** meshLights, rdVector3* localLightPoses, int numLights, rdFace* face, rdVector3* faceNormal, rdVector3* vertices, float param_7, void* outInfos);

#endif // RDLIGHT_H
