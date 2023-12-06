#ifndef RDSPRITE_H
#define RDSPRITE_H

#include "types.h"

#define rdSprite_Draw_ADDR (0x004945e0)

// int __cdecl rdSprite_Draw(RdThing* prdThing, const RdMatrix* orient)
int rdSprite_Draw(swrUI_Unk3* param_1, rdMatrix34* orient);

#endif // RDSPRITE_H
