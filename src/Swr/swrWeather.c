#include "swrWeather.h"

#include "macros.h"
#include "globals.h"
#include "engine_config.h"
#include "swrSprite.h"

// 0x0042d3c0
void swrWeather_SetVelocity(float vx, float vy)
{
    swrWeather_velocityX = vx;
    swrWeather_velocityY = vy;
}

// 0x0042d410
void swrWeather_SetParticleCap(int max)
{
    swrWeather_particleCap = SWRWEATHER_MAX_PARTICLES;
    if (max <= SWRWEATHER_MAX_PARTICLES)
        swrWeather_particleCap = max;
    swrWeather_HideAllParticles();
}

// 0x0042d430
void swrWeather_SetStretchFactor(float factor)
{
    swrWeather_stretchFactor = factor;
}

// 0x0042d440
void swrWeather_Disable(void)
{
    swrWeather_enabled = 0;
    swrWeather_HideAllParticles();
}

// 0x0042d450
void swrWeather_Enable(void)
{
    swrWeather_enabled = 1;
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

// 0x0042d380
void swrWeather_HideAllParticles(void)
{
    for (int i = 0; i < SWRWEATHER_MAX_PARTICLES; i++) {
        if (swrWeather_particleSpriteIds[i] != -1)
            swrSprite_SetVisible(swrWeather_particleSpriteIds[i], 0);
        swrWeather_particleStates[i] = 0;
    }
}
