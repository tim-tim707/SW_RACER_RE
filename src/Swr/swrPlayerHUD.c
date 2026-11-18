#include "swrPlayerHUD.h"

#include "globals.h"
#include "swrSprite.h"
#include "swrViewport.h"

#include <Primitives/rdVector.h>
#include <engine_config.h>
#include <macros.h>

// 0x0042cb00
void swrPlayerHUD_RenderWorldSprites(void* viewport)
{
    int i;
    short id;
    float screenX;
    float screenY;
    float screenZ;
    float depth;

    for (i = 0; i < swrPlayerHUD_worldSpriteCount; i++) {
        swrPlayerHUD_worldSpritePixelX[i] = -1000;
        swrPlayerHUD_worldSpritePixelY[i] = -1000;
        if (!(rdVector_Dist3(&swrPlayerHUD_worldSpritePositions[i], &rdVector_model_translation) < SWR_HUD_WORLD_SPRITE_MAX_DIST))
            continue;

        swrViewport_ProjectToScreen((swrViewport*)viewport, (rdVector4*)&swrPlayerHUD_worldSpritePositions[i], &screenX, &screenY, &screenZ, &depth, 0);
        if (!(screenX > -4.0f && screenX < (float)swrDisplay_screenWidth && screenY > 0.0f && screenY < (float)swrDisplay_screenHeight))
            continue;

        swrPlayerHUD_worldSpritePixelX[i] = (int)screenX;
        swrPlayerHUD_worldSpritePixelY[i] = (int)screenY;
        if (!(screenZ < 0.0f || screenZ < swrPlayerHUD_worldSpriteDepth[i]))
            continue;
        if (lightStreakSpriteIDs1[i] == -1)
            continue;

        id = (short)lightStreakSpriteIDs1[i];
        swrSprite_SetVisible(id, 1);
        swrSprite_SetPosF(id, (short)(int)screenX, (short)(int)screenY);
        swrSprite_SetRotation(id, 0.0f);
        swrSprite_SetDim(id, 1.0f, 1.0f);
        swrSprite_SetColor(id, 0xff, 0xff, 0xff, 0xff);
    }
}

// 0x0042d500
void swrPlayerHUD_Enable(void)
{
    InRaceSpritesEnabled = 1;
}

// 0x00464630
void swrPlayerHUD_LoadRaceHUD(int hudType, int weatherLevel, int racerData)
{
    HANG("TODO");
}
