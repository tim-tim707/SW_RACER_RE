#include "rdMath.h"

#include "rdVector.h"

#include <macros.h>
#include <General/stdMath.h>

// Plane of triangle a,b,c: out->xyz = normalize(cross(b-a, c-b)), out->w = dot(normal, a)
// (the plane offset, since a lies on the plane). Used by the ray-vs-mesh face callbacks.
// 0x004314f0
void rdMath_CalcSurfaceNormal2(rdVector4* out, rdVector3* a, rdVector3* b, rdVector3* c)
{
    rdVector3 ab;
    rdVector3 bc;

    ab.x = b->x - a->x;
    ab.y = b->y - a->y;
    ab.z = b->z - a->z;
    bc.x = c->x - b->x;
    bc.y = c->y - b->y;
    bc.z = c->z - b->z;
    rdVector_Cross3((rdVector3*) out, &ab, &bc);
    rdVector_Normalize3Acc((rdVector3*) out);
    out->w = ((long double)a->y * out->y + (long double)a->z * out->z) + (long double)a->x * out->x; // (y + z) + x
}

// 0x0048eb60
void rdMath_CalcSurfaceNormal(rdVector3* out, rdVector3* edge1, rdVector3* edge2, rdVector3* edge3)
{
    rdVector3 a;
    rdVector3 b;

    rdVector_Sub3(&b, edge2, edge1);
    rdVector_Sub3(&a, edge3, edge1);
    // Retail normalizes with rdVector_Normalize3Acc_2 (0x00492440) all three times.
    rdVector_Normalize3Acc_2(&b);
    rdVector_Normalize3Acc_2(&a);
    rdVector_Cross3(out, &b, &a);
    rdVector_Normalize3Acc_2(out);

    rdMath_ClampVector(out, 0x1.0c6f7a0b5ed8dp-20); // 0.000001
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
    if ((0x1.ff7ced916872bp-1 <= tmp) && (tmp <= 0x1.004189374bc6ap+0)) // 0.999, 1.001
    {
        return 1;
    }
    return 0;
}

// 0x004813A0
void rdMath_SlerpQuaternions(const rdVector4* a, const rdVector4* b, float t, rdVector4* result)
{
    long double d;
    float d32;
    long double angle;
    float angle32;
    float fa32;
    long double fb;
    float sin_angle, cos_angle;
    float sin_a, cos_a;
    float sin_b, cos_b;

    // Retail accumulates the dot product as ((z + y) + w) + x.
    d = (((long double)a->z * b->z + (long double)a->y * b->y) + (long double)a->w * b->w) + (long double)a->x * b->x;
    d32 = d;
    if (d < 0)
    {
        const rdVector4 a_flipped = { -a->x, -a->y, -a->z, -a->w };
        rdMath_SlerpQuaternions(&a_flipped, b, t, result);
        return;
    }

    if (d32 > 1)
        d32 = 1;

    // ArcCos is consumed straight from ST0; only the copy passed on to SinCos is rounded.
    angle = stdMath_ArcCosUnrounded(d32);
    angle32 = angle;
    if (angle > 0x1.4f8b588e368f1p-17) // 0.00001 (double)
    {
        stdMath_SinCos(angle32, &sin_angle, &cos_angle);
        stdMath_SinCos((1 - t) * angle32, &sin_a, &cos_a);
        fa32 = sin_a / sin_angle;
        stdMath_SinCos(angle32 * t, &sin_b, &cos_b);
        fb = (long double)sin_b / sin_angle;
    }
    else
    {
        fa32 = 1 - t;
        fb = t;
    }
    // fa is spilled to float, fb stays at register width.
    result->x = a->x * fa32 + fb * b->x;
    result->y = a->y * fa32 + fb * b->y;
    result->z = a->z * fa32 + fb * b->z;
    result->w = a->w * fa32 + fb * b->w;
}

// 0x00481520
void rdMath_QuaternionToAxisAngle(rdVector4* axis_angle, const rdVector4* q)
{
    // The squared length had `q->y * q->z` where it needs `q->y * q->y` -- that typo was
    // the "somehow broken" this function used to be marked with. Retail is unambiguous:
    // FMUL of q->y by itself, then q->z by itself, then q->x by itself, accumulated as
    // (y*y + z*z) + x*x, which is the order kept below.
    //
    // The thresholds are float32 constants at 0x004adff8 / 0x004adffc (1e-05f, whose value
    // is 9.999999747e-06), not the double 0.0000099999997 that was written here.
    float l = q->y * q->y + q->z * q->z + q->x * q->x;
    if (l >= 0x1.4f8b58p-17f || l <= -0x1.4f8b58p-17f) // 1e-05f
    {
        float angle = stdMath_ArcCos(q->w);
        float sin_angle, cos_angle;
        stdMath_SinCos(angle, &sin_angle, &cos_angle);

        if (sin_angle >= 0x1.4f8b58p-17f || sin_angle <= -0x1.4f8b58p-17f) // 1e-05f
        {
            *axis_angle = (rdVector4){
                q->x / sin_angle,
                q->y / sin_angle,
                q->z / sin_angle,
                2 * angle,
            };
            rdVector_Normalize3Acc((rdVector3*)axis_angle);
            return;
        }
    }

    *axis_angle = (rdVector4){
        0,
        0,
        1,
        0,
    };
}

// 0x00481620
void rdMath_AxisAngleToQuaternion(rdVector4* quaternion, const rdVector4* axis_angle)
{
    float sin_angle, cos_angle;
    stdMath_SinCos(axis_angle->w * 0.5, &sin_angle, &cos_angle);

    quaternion->x = axis_angle->x;
    quaternion->y = axis_angle->y;
    quaternion->z = axis_angle->z;
    rdVector_Normalize3Acc((rdVector3*)quaternion);

    quaternion->x *= sin_angle;
    quaternion->y *= sin_angle;
    quaternion->z *= sin_angle;
    quaternion->w = cos_angle;
}
