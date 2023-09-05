#ifndef SWRSPRITE_H
#define SWRSPRITE_H

#include "types.h"

#define swrSprite_UpperPowerOfTwo_ADDR (0x00445c90)
#define swrSprite_LoadTexture_ADDR (0x00446ca0)
#define swrSprite_LoadTexture__ADDR (0x00446fb0)

int swrSprite_UpperPowerOfTwo(int x);

swrSpriteTexture* swrSprite_LoadTexture(int index);
swrSpriteTexture* swrSprite_LoadTexture_(int index);

#endif // SWRSPRITE_H
