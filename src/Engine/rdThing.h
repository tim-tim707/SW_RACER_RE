#ifndef RDTHING_H
#define RDTHING_H

#include "types.h"

#define rdThing_New_ADDR (0x00490b70)
#define rdThing_NewEntry_ADDR (0x00490ba0)
#define rdThing_Free_ADDR (0x00490bf0)
#define rdThing_FreeEntry_ADDR (0x00490c10)
#define rdThing_Draw_ADDR (0x00490c80)
#define rdThing_AccumulateMatrices_ADDR (0x00490d10)

RdThing* rdThing_New(SithThing* pThing);
void rdThing_NewEntry(RdThing* prdThing, SithThing* pThing);
void rdThing_Free(RdThing* pThing);
void rdThing_FreeEntry(RdThing* pThing);
// int __cdecl rdThing_Draw(RdThing* prdThing, const RdMatrix* pOrient)
int rdThing_Draw(swrUI_Unk3* param_1, rdMatrix34* identity, void* param_3, int screen_width);
int rdThing_AccumulateMatrices(RdThing* prdThing, rdModel3HNode* pNode, rdMatrix34* pPlacement);

#endif // RDTHING_H
