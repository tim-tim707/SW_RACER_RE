#include "rdVector.h"

#include "types.h"
#include "../General/stdMath.h"

// 0x0042f6e0
rdVector2* rdVector_Add2(rdVector2* v1, const rdVector2* v2, const rdVector2* v3)
{
    v1->x = v2->x + v3->x;
    v1->y = v2->y + v3->y;
    return v1;
}

// 0x0042f700
rdVector2* rdVector_Scale2(rdVector2* v1, float scale, const rdVector2* v2)
{
    v1->x = v2->x * scale;
    v1->y = v2->y * scale;
    return v1;
}

// 0x0042f720
void rdVector_Scale2Add2(rdVector2* v1, rdVector2* v2, float scale, rdVector2* v3)
{
    v1->x = v3->x * scale + v2->x;
    v1->y = v3->y * scale + v2->y;
    return;
}

// 0x0042f750
float rdVector_Len2(const rdVector2* v)
{
    return stdMath_Sqrt(v->x * v->x + v->y * v->y);
}

// 0x0042f780
float rdVector_Normalize2Acc(rdVector2* v1)
{
    float len = rdVector_Len2(v1);
    if (0.0001 <= len)
    {
        v1->x = v1->x / len;
        v1->y = v1->y / len;
    }
    return len;
}

// 0x0042f7b0
rdVector3* rdVector_Set3(rdVector3* v, float x, float y, float z)
{
    v->x = x;
    v->y = y;
    v->z = z;
    return v;
}

// 0x0042f7d0
void rdVector_Copy3(rdVector3* v1, const rdVector3* v2)
{
    v1->x = v2->x;
    v1->y = v2->y;
    v1->z = v2->z;
}

// 0x0042f7f0
bool rdVector_AreSame3(rdVector3* v1, rdVector3* v2)
{
    if (((v1->x == v2->x) && (v1->y == v2->y)) && (v1->z == v2->z))
    {
        return 1;
    }
    return 0;
}

// 0x0042f830
rdVector3* rdVector_Add3(rdVector3* v1, const rdVector3* v2, rdVector3* v3)
{
    v1->x = v2->x + v3->x;
    v1->y = v2->y + v3->y;
    v1->z = v2->z + v3->z;
    return v1;
}

// 0x0042f860
rdVector3* rdVector_Sub3(rdVector3* v1, const rdVector3* v2, const rdVector3* v3)
{
    v1->x = v2->x - v3->x;
    v1->y = v2->y - v3->y;
    v1->z = v2->z - v3->z;
    return v1;
}

// 0x0042f890
float rdVector_Dot3(const rdVector3* v1, const rdVector3* v2)
{
    return (v1->x * v2->x) + (v1->y * v2->y) + (v1->z * v2->z);
}

// 0x0042f8c0
float rdVector_Len3(const rdVector3* v)
{
    return stdMath_Sqrt(rdVector_Dot3(v, v));
}

// 0x0042f910
float rdVector_DistSquared3(const rdVector3* v1, const rdVector3* v2)
{
    return (v1->z - v2->z) * (v1->z - v2->z) + (v1->y - v2->y) * (v1->y - v2->y) + (v1->x - v2->x) * (v1->x - v2->x);
}

// 0x0042f950
float rdVector_Dist3(const rdVector3* v1, const rdVector3* v2)
{
    return stdMath_Sqrt((v2->z - v1->z) * (v2->z - v1->z) + (v2->y - v1->y) * (v2->y - v1->y) + (v2->x - v1->x) * (v2->x - v1->x));
}

// 0x0042f9b0
float rdVector_Normalize3Acc(rdVector3* v1)
{
    float len = rdVector_Len3(v1);
    if (0.0001 <= len)
    {
        v1->x = v1->x / len;
        v1->y = v1->y / len;
        v1->z = v1->z / len;
    }
    return len;
}

// 0x0042f9f0
void rdVector_Cross3(rdVector3* v1, const rdVector3* v2, const rdVector3* v3)
{
    v1->x = (v3->z * v2->y) - (v2->z * v3->y);
    v1->y = (v2->z * v3->x) - (v3->z * v2->x);
    v1->z = (v3->y * v2->x) - (v2->y * v3->x);
}

// 0x0042fa50
rdVector3* rdVector_Scale3(rdVector3* v1, float scale, const rdVector3* v2)
{
    v1->x = v2->x * scale;
    v1->y = v2->y * scale;
    v1->z = v2->z * scale;
    return v1;
}

// 0x0042fa80
void rdVector_Scale3Add3(rdVector3* v1, const rdVector3* v2, float scale, const rdVector3* v3)
{
    v1->x = v3->x * scale + v2->x;
    v1->y = v3->y * scale + v2->y;
    v1->z = v3->z * scale + v2->z;
    return;
}

// 0x0042fac0
void rdVector_Scale3Add3_both(rdVector3* v1, float scale1, const rdVector3* v2, float scale2, const rdVector3* v3)
{
    v1->x = v3->x * scale2 + v2->x * scale1;
    v1->y = v3->y * scale2 + v2->y * scale1;
    v1->z = v3->z * scale2 + v2->z * scale1;
    return;
}

// 0x00430a90
rdVector4* rdVector_Set4(rdVector4* v, float x, float y, float z, float w)
{
    v->x = x;
    v->y = y;
    v->z = z;
    v->w = w;
    return v;
}

// 0x004315a0
void rdVector_Point3ToPerspective3(rdVector4* out, rdVector3* p1, rdVector3* p2)
{
    out->x = p1->x;
    out->y = p1->y;
    out->z = p1->z;
    rdVector_Normalize3Acc((rdVector3*)out);
    out->w = p2->x * out->x + p2->y * out->y + p2->z * out->z;
    return;
}

// 0x00492440
float rdVector_Normalize3Acc_2(rdVector3* v1)
{
    float len = rdVector_Len3(v1);
    if (0.0001 <= len)
    {
        v1->x = v1->x / len;
        v1->y = v1->y / len;
        v1->z = v1->z / len;
    }
    return len;
}
