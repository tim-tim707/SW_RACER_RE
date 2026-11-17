#include "swrWeather.h"

#include "macros.h"
#include "globals.h"

// 0x0042d3c0
void swrWeather_SetVelocity(float vx, float vy)
{
    HANG("TODO");
}

// 0x0042d410
void swrWeather_SetParticleCap(int max)
{
    HANG("TODO");
}

// 0x0042d430
void swrWeather_SetStretchFactor(float factor)
{
    HANG("TODO");
}

// 0x0042d470
void swrWeather_ResetParticles(void)
{
    int i;

    for (i = 0; i < 80; i++)
        swrWeather_particleStates[i] = 0;
    for (i = 0; i < 80; i++)
        swrWeather_particleSpriteIds[i] = -1;
}
