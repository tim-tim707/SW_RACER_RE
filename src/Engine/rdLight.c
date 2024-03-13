#include "rdLight.h"

#include <macros.h>

// 0x00490510
int rdLight_NewEntry(rdLight* light)
{
    light->type = 2;
    light->active = 1;
    (light->direction).x = 0.0;
    (light->direction).y = 0.0;
    (light->direction).z = 0.0;
    light->color = (rdVector4){1,1,1,0};
    light->falloffMin = 0.0;
    light->falloffMax = 0.0;
    return 1;
}

// 0x00490550
void rdLight_CalcVertexIntensities(RdLight** apLights, rdVector3* aLightPos, int numLights, rdVector3* aVertexNormal, rdVector3* aVertices, rdVector4* aVertexColors, rdVector4* aLightColors, int numVertices)
{
    HANG("TODO");
}

// 0x00490750
void rdLight_CalcFaceIntensity(rdLight** meshLights, rdVector3* localLightPoses, int numLights, rdFace* face, rdVector3* faceNormal, rdVector3* vertices, float param_7, void* outInfos)
{
    HANG("TODO, easy. Prototype differ from OPENJKDF2 !");
}

// 0x00490930
float rdLight_GetIntensity(const rdVector4* pLight)
{
    return (pLight->y + pLight->z + pLight->x) * 0.3333333;
}
