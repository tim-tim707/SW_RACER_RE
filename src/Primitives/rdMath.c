#include "rdMath.h"

// 0x004314f0
void rdMath_CalcSurfaceNormal(rdVector4* out, rdVector3* edge1, rdVector3* edge2, rdVector3* edge3)
{
    rdVector3 tmp1;
    rdVector3 tmp2;

    tmp1.x = edge2->x - edge1->x;
    tmp2.x = edge3->x - edge2->x;
    tmp2.y = edge3->y - edge2->y;
    tmp2.z = edge3->z - edge2->z;
    tmp1.y = edge2->y - edge1->y;
    tmp1.z = edge2->z - edge1->z;
    rdVector_Cross3((rdVector3*)out, &tmp1, &tmp2);
    rdVector_Normalize3Acc((rdVector3*)out);
    out->w = edge1->x * out->x + out->y * edge1->y + out->z * edge1->z;
    return;
}

// 0x0048ec50
float rdMath_DistancePointToPlane(rdVector3* light, rdVector3* normal, rdVector3* vertex)
{
    return (light->y - vertex->y) * normal->y + (light->z - vertex->z) * normal->z + (light->x - vertex->x) * normal->x;
}
