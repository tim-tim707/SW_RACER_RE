#ifndef RD_MATH_H
#define RD_MATH_H

#include "types.h"

#define rdMath_CalcSurfaceNormal_ADDR (0x004314f0)

void rdMath_CalcSurfaceNormal(rdVector4* out, rdVector3* edge1, rdVector3* edge2, rdVector3* edge3);

#endif // RD_MATH_H
