#include "swrWeather.h"

#include "macros.h"
#include "globals.h"
#include "engine_config.h"
#include "swrSprite.h"
#include "swrObj.h"
#include "swrViewport.h"
#include <General/utils.h>
#include <Win95/DirectX.h>

#include <math.h>

static double swrWeather_RandUnit(void)
{
    return (double)swrUtils_Rand() * SWR_CTL_RAND_NORM;
}

// 0x0042cca0
void swrWeather_RenderParticles(void* viewport)
{
    swrViewport* vp;
    uint32_t bytesPerDepth;
    LONG pitch;
    LPVOID data;
    float nearOut;
    float farOut;
    float depthScale;
    float screenX;
    float screenY;
    float screenZ;
    float depth;
    float size;
    float offset;
    double sample;
    const unsigned char* pixel;
    uint32_t i;
    int particle;
    int endX;
    int endY;
    int dx;
    int dy;
    short spriteId;
    short alpha;
    uint8_t a;
    rdVector3* pos;
    rdVector2* prevScreen;

    vp = (swrViewport*)viewport;
    if (swrWeather_enabled == 0) {
        return;
    }
    DirectDraw_LockZBuffer(&bytesPerDepth, &pitch, &data, &nearOut, &farOut);
    // the original has no default case and leaves the scale uninitialized; cases 3/4 swap slots
    depthScale = 0.0f;
    switch (bytesPerDepth) {
    case 1:
        depthScale = swrPlayerHUD_zBufferDepthScale[0];
        break;
    case 2:
        depthScale = swrPlayerHUD_zBufferDepthScale[1];
        break;
    case 3:
        depthScale = swrPlayerHUD_zBufferDepthScale[3];
        break;
    case 4:
        depthScale = swrPlayerHUD_zBufferDepthScale[2];
        break;
    }

    for (particle = 0; particle < swrWeather_particleCap; particle++) {
        if (swrWeather_particleSpriteIds[particle] == -1) {
            continue;
        }
        spriteId = (short)swrWeather_particleSpriteIds[particle];
        pos = &swrWeather_particlePositions[particle];
        prevScreen = &swrWeather_particleScreenPositions[particle];

        if (swrWeather_particleStates[particle] == 0) {
            swrSprite_SetVisible(spriteId, 0);
            if (swrWeather_RandUnit() > SWRWEATHER_SPAWN_CHANCE) {
                pos->x = rdVector_model_translation.x;
                pos->y = rdVector_model_translation.y;
                swrWeather_particleStates[particle] = 1;
                pos->z = rdVector_model_translation.z;
                // each component draws its own random offset (faithful)
                pos->x += (swrWeather_RandUnit() * SWRWEATHER_SPAWN_SIDE_RANGE - SWRWEATHER_SPAWN_SIDE_HALF) * vp->model_matrix.vA.x;
                pos->y += (swrWeather_RandUnit() * SWRWEATHER_SPAWN_SIDE_RANGE - SWRWEATHER_SPAWN_SIDE_HALF) * vp->model_matrix.vA.y;
                pos->z += (swrWeather_RandUnit() * SWRWEATHER_SPAWN_SIDE_RANGE - SWRWEATHER_SPAWN_SIDE_HALF) * vp->model_matrix.vA.z;
                offset = swrWeather_RandUnit() * SWRWEATHER_SPAWN_FORWARD_RANGE + SWRWEATHER_SPAWN_MIN_DIST;
                pos->x += vp->model_matrix.vB.x * offset;
                pos->y += vp->model_matrix.vB.y * offset;
                pos->z += vp->model_matrix.vB.z * offset;
                pos->x += (swrWeather_RandUnit() * SWRWEATHER_SPAWN_UP_RANGE + SWRWEATHER_SPAWN_MIN_DIST) * vp->model_matrix.vC.x;
                pos->y += (swrWeather_RandUnit() * SWRWEATHER_SPAWN_UP_RANGE + SWRWEATHER_SPAWN_MIN_DIST) * vp->model_matrix.vC.y;
                offset = swrWeather_RandUnit() * SWRWEATHER_SPAWN_UP_RANGE + SWRWEATHER_SPAWN_MIN_DIST;
                prevScreen->x = -1.0f;
                prevScreen->y = -1.0f;
                pos->z += offset * vp->model_matrix.vC.z;
            }
        } else {
            pos->z = pos->z - swrWeather_velocityY * swrRace_deltaTimeSecs;
            pos->x = pos->x - swrWeather_velocityX * swrRace_deltaTimeSecs;
        }

        if (swrWeather_particleStates[particle] == 0) {
            continue;
        }
        if (swrWeather_particleStates[particle] == 2) {
            swrWeather_particleStates[particle] = 0;
        }
        swrViewport_ProjectToScreen(vp, (rdVector4*)pos, &screenX, &screenY, &screenZ, &depth, 0);
        if (screenX > 0.0f && screenY > 0.0f && (float)swrDisplay_screenWidth > screenX && (float)swrDisplay_screenHeight > screenY) {
            // the x offset is not scaled by the depth byte count (faithful)
            pixel = (const unsigned char*)data + (int)screenY * pitch + (int)screenX;
            sample = 0.0;
            for (i = bytesPerDepth; i > 0; i--) {
                sample += (int)((unsigned int)pixel[i - 1] << ((i - 1) * 8));
            }
            if (screenZ > 0.0f && sample * depthScale < screenZ) {
                swrWeather_particleStates[particle] = 2;
            }
        } else if (screenX < (float)-swrDisplay_screenWidth || (float)(swrDisplay_screenWidth * 2) < screenX || (float)(swrDisplay_screenHeight * 2) < screenY) {
            swrWeather_particleStates[particle] = 0;
        }

        size = SWRWEATHER_SIZE_NUMERATOR;
        if (depth > SWRWEATHER_SIZE_MIN) {
            size = SWRWEATHER_SIZE_NUMERATOR / depth;
        }
        if (size < SWRWEATHER_SIZE_MIN) {
            size = SWRWEATHER_SIZE_MIN;
        }
        size = size * SWRWEATHER_SIZE_SCALE;
        if (swrWeather_velocityY > SWRWEATHER_FAST_VELOCITY) {
            if (size > SWRWEATHER_FAST_SIZE_MAX) {
                size = SWRWEATHER_FAST_SIZE_MAX;
            }
        } else if (swrWeather_velocityY > SWRWEATHER_MEDIUM_VELOCITY) {
            if (size > SWRWEATHER_MEDIUM_SIZE_MAX) {
                size = SWRWEATHER_MEDIUM_SIZE_MAX;
            }
        } else if (size > SWRWEATHER_SLOW_SIZE_MAX) {
            size = SWRWEATHER_SLOW_SIZE_MAX;
        }

        alpha = (signed char)swrWeather_particleColor[3];
        swrSprite_SetVisible(spriteId, 1);
        swrSprite_SetPosF(spriteId, (short)(int)screenX, (short)(int)screenY);
        if (prevScreen->x < 0.0f) {
            swrSprite_SetVisible(spriteId, 0);
        } else {
            endX = (int)(swrWeather_stretchFactor * prevScreen->x + screenX * (1.0f - swrWeather_stretchFactor));
            endY = (int)(prevScreen->y * swrWeather_stretchFactor + screenY * (1.0f - swrWeather_stretchFactor));
            dx = (int)fabsf((float)endX - screenX);
            dy = (int)fabsf((float)endY - screenY);
            if (dx < SWRWEATHER_STREAK_MIN_PIXELS && dy < SWRWEATHER_STREAK_MIN_PIXELS) {
                swrSprite_UnsetFlag(spriteId, swrSprite_FLAG_STREAK);
            } else {
                swrSprite_SetStreakEndpoints_Maybe(spriteId, (short)endX, (short)endY);
                swrSprite_SetFlag(spriteId, swrSprite_FLAG_STREAK);
            }
        }
        swrSprite_SetDim(spriteId, size, size);
        if (GetPauseState() != 0) {
            a = (uint8_t)(int)((float)alpha * SWRWEATHER_PAUSED_ALPHA_SCALE);
        } else {
            a = (uint8_t)alpha;
        }
        swrSprite_SetColor(spriteId, swrWeather_particleColor[0], swrWeather_particleColor[1], swrWeather_particleColor[2], a);
        prevScreen->x = screenX;
        prevScreen->y = screenY;
    }
    DirectDraw_UnlockZBuffer();
}

// 0x0042d3c0
void swrWeather_SetVelocity(float vx, float vy)
{
    swrWeather_velocityX = vx;
    swrWeather_velocityY = vy;
}

// 0x0042d3e0
void swrWeather_SetColor(uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    swrWeather_particleColor[0] = r;
    swrWeather_particleColor[1] = g;
    swrWeather_particleColor[2] = b;
    swrWeather_particleColor[3] = a;
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

// 0x0042d460
void swrWeather_SetParticleSpriteId(int slot, int spriteId)
{
    swrWeather_particleSpriteIds[slot] = spriteId;
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

// 0x0042d330
void swrSprite_SetStreakEndpoints_Maybe(short id, short x, short y)
{
    short v;

    // screen pixels -> the 320x240 sprite space
    v = (short)(int)((float)y / (float)swrDisplay_screenHeight * 240.0f);
    swrSprite_SetUVOffset_Maybe(id, (short)(int)((float)x / (float)swrDisplay_screenWidth * 320.0f), v);
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
