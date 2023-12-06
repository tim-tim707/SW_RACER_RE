#ifndef RDTHING_H
#define RDTHING_H

#include "types.h"

#define rdThing_Draw_ADDR (0x00490c80)

// int __cdecl rdThing_Draw(RdThing* prdThing, const RdMatrix* pOrient)
int rdThing_Draw(swrUI_Unk3* param_1, rdMatrix34* identity, void* param_3, int screen_width);

#endif // RDTHING_H
