#include "rdMath.h"

// What is this then ?
// 0x004314f0
// void rdMath_CalcSurfaceNormal(rdVector4* out, rdVector3* edge1, rdVector3* edge2, rdVector3* edge3)
// {
//     rdVector3 tmp1;
//     rdVector3 tmp2;

//     tmp1.x = edge2->x - edge1->x;
//     tmp2.x = edge3->x - edge2->x;
//     tmp2.y = edge3->y - edge2->y;
//     tmp2.z = edge3->z - edge2->z;
//     tmp1.y = edge2->y - edge1->y;
//     tmp1.z = edge2->z - edge1->z;
//     rdVector_Cross3((rdVector3*)out, &tmp1, &tmp2);
//     rdVector_Normalize3Acc((rdVector3*)out);
//     out->w = edge1->x * out->x + out->y * edge1->y + out->z * edge1->z;
//     return;
// }

// 0x0048eb60
void rdMath_CalcSurfaceNormal(rdVector3* out, rdVector3* edge1, rdVector3* edge2, rdVector3* edge3)
{
    rdVector3 a;
    rdVector3 b;

    rdVector_Sub3(&b, edge2, edge1);
    rdVector_Sub3(&a, edge3, edge1);
    rdVector_Normalize3Acc(&b);
    rdVector_Normalize3Acc(&a);
    rdVector_Cross3(out, &b, &a);
    rdVector_Normalize3Acc(out);

    rdMath_ClampVector(out, 0.000001);
}

// 0x0048ec50
float rdMath_DistancePointToPlane(rdVector3* light, rdVector3* normal, rdVector3* vertex)
{
    return (light->y - vertex->y) * normal->y + (light->z - vertex->z) * normal->z + (light->x - vertex->x) * normal->x;
}

// 0x0048ec90
void rdMath_ClampVector(rdVector3* out, float minVal)
{
    float tmp;

    tmp = out->x;
    if (out->x < 0.0)
    {
        tmp = -tmp;
    }
    if (minVal <= tmp)
    {
        tmp = out->x;
    }
    else
    {
        tmp = 0.0;
    }
    out->x = tmp;
    tmp = out->y;
    if (out->y < 0.0)
    {
        tmp = -tmp;
    }
    if (minVal <= tmp)
    {
        tmp = out->y;
    }
    else
    {
        tmp = 0.0;
    }
    out->y = tmp;
    tmp = out->z;
    if (out->z < 0.0)
    {
        tmp = -tmp;
    }
    if (tmp < minVal)
    {
        out->z = 0.0;
        return;
    }
    out->z = out->z;
}

// 0x0048ed20
int rdMath_PointsCollinear(rdVector3* a1, rdVector3* a2, rdVector3* a3)
{
    float tmp;
    rdVector3 v1;
    rdVector3 v2;

    v2.x = a2->x - a1->x;
    v1.x = a3->x - a1->x;
    v2.y = a2->y - a1->y;
    v2.z = a2->z - a1->z;
    v1.y = a3->y - a1->y;
    v1.z = a3->z - a1->z;
    rdVector_Normalize3Acc_2(&v2);
    rdVector_Normalize3Acc_2(&v1);
    tmp = v1.z * v2.z + v1.y * v2.y + v1.x * v2.x;
    if (tmp < 0.0)
    {
        tmp = -tmp;
    }
    if ((0.999 <= tmp) && (tmp <= 1.001))
    {
        return 1;
    }
    return 0;
}
