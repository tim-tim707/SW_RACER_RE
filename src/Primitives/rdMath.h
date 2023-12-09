#ifndef RD_MATH_H
#define RD_MATH_H

#include "types.h"

// What is this ?
// #define rdMath_CalcSurfaceNormal_ADDR (0x004314f0)

#define rdMath_CalcSurfaceNormal_ADDR (0x0048eb60)
#define rdMath_DistancePointToPlane_ADDR (0x0048ec50)
#define rdMath_ClampVector_ADDR (0x0048ec90)
#define rdMath_PointsCollinear_ADDR (0x0048ed20)

// void rdMath_CalcSurfaceNormal(rdVector4* out, rdVector3* edge1, rdVector3* edge2, rdVector3* edge3);

void rdMath_CalcSurfaceNormal(rdVector3* out, rdVector3* edge1, rdVector3* edge2, rdVector3* edge3);
float rdMath_DistancePointToPlane(rdVector3* light, rdVector3* normal, rdVector3* vertex);
void rdMath_ClampVector(rdVector3* out, float minVal);
int rdMath_PointsCollinear(rdVector3* a1, rdVector3* a2, rdVector3* a3);

#endif // RD_MATH_H
