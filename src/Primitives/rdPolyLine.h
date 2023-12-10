#ifndef RDPOLYLINE_H
#define RDPOLYLINE_H

#include "types.h"

#define rdPolyLine_Draw_ADDR (0x00493e80)
#define rdPolyline_DrawFace_ADDR (0x004941d0)

int rdPolyLine_Draw(RdThing* thing, rdMatrix34* matrix);
void rdPolyline_DrawFace(RdThing* pLine, RdFace* pFace, rdVector3* aVertices, rdVector2* aUVs);

#endif // RDPOLYLINE_H
