#ifndef RDPARTICLE_H
#define RDPARTICLE_H

#include "types.h"

#define rdParticle_Draw_ADDR (0x00494330)

int rdParticle_Draw(RdThing* pParticle, rdMatrix34* pOrient);

#endif // RDPARTICLE_H
