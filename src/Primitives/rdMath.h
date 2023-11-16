#ifndef RD_MATH_H
#define RD_MATH_H

#include "types.h"

#define rdMath_CalcSurfaceNormal_ADDR (0x004314f0)

#define rdMath_DistancePointToPlane_ADDR (0x0048ec50)

void rdMath_CalcSurfaceNormal(rdVector4* out, rdVector3* edge1, rdVector3* edge2, rdVector3* edge3);

float rdMath_DistancePointToPlane(rdVector3* light, rdVector3* normal, rdVector3* vertex);

#endif // RD_MATH_H
