#ifndef RD_MATH_H
#define RD_MATH_H

#include "types.h"

// What is this ?
// #define rdMath_CalcSurfaceNormal2_ADDR (0x004314f0)

#define rdMath_CalcSurfaceNormal_ADDR (0x0048eb60)
#define rdMath_DistancePointToPlane_ADDR (0x0048ec50)
#define rdMath_ClampVector_ADDR (0x0048ec90)
#define rdMath_PointsCollinear_ADDR (0x0048ed20)
#define rdMath_SlerpQuaternions_ADDR (0x004813A0)
#define rdMath_QuaternionToAxisAngle_ADDR (0x00481520)
#define rdMath_AxisAngleToQuaternion_ADDR (0x00481620)

// void rdMath_CalcSurfaceNormal2(rdVector4* out, rdVector3* edge1, rdVector3* edge2, rdVector3* edge3);

void rdMath_CalcSurfaceNormal(rdVector3* out, rdVector3* edge1, rdVector3* edge2, rdVector3* edge3);
float rdMath_DistancePointToPlane(rdVector3* light, rdVector3* normal, rdVector3* vertex);
void rdMath_ClampVector(rdVector3* out, float minVal);
int rdMath_PointsCollinear(rdVector3* a1, rdVector3* a2, rdVector3* a3);
void rdMath_SlerpQuaternions(const rdVector4* a, const rdVector4* b, float t, rdVector4* result);
void rdMath_QuaternionToAxisAngle(rdVector4 *axis_angle, const rdVector4* quaternion);
void rdMath_AxisAngleToQuaternion(rdVector4 *quaternion, const rdVector4* axis_angle);

#endif // RD_MATH_H
