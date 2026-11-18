#include "swrPlayerHUD.h"

#include "globals.h"
#include "swrSprite.h"
#include "swrViewport.h"
#include "swrObj.h"

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

// 0x00464010
void swrPlayerHUD_SetupTrackOverlay(int hudType, int weatherLevel)
{
    HANG("TODO");
}

// 0x00464630
void swrPlayerHUD_LoadRaceHUD(int hudType, int weatherLevel, int racerData)
{
    swrObjJdge* judge = (swrObjJdge*)racerData;
    swrSpriteTexture* fade;
    swrSpriteTexture* flash;
    swrSpriteTexture* tex;
    int i;

    swrSprite_ResetAllSprites();
    fade = swrSprite_LoadTexture_(swrSprite_ej_fade1_rgb);
    flash = swrSprite_LoadTexture_(swrSprite_dial_lightflash_rgb);
    if (numLocalPlayers < 2) {
        swrSprite_NewSprite(0, swrSprite_LoadTexture_(swrSprite_dial_lap_pos_rgb));
        swrSprite_NewSprite(1, swrSprite_LoadTexture_(swrSprite_dial_lap_pos_rgb));
        tex = swrSprite_LoadTexture_(swrSprite_dial_speed_edge_blue_rgb);
        swrSprite_NewSprite(3, tex);
        swrSprite_NewSprite(10, tex);
        swrSprite_SetFlag(10, 4);
        swrSprite_NewSprite(2, swrSprite_LoadTexture_(swrSprite_dial_speed_mid_blue_rgb));
        swrSprite_NewSprite(4, swrSprite_LoadTexture_(swrSprite_dial_time_wire_rgb));
        swrSprite_NewSprite(5, NULL);
        swrSprite_NewSprite(6, NULL);
        tex = swrSprite_LoadTexture_(swrSprite_dial_top_h_wire_rgb);
        swrSprite_NewSprite(11, tex);
        swrSprite_NewSprite(12, tex);
        tex = swrSprite_LoadTexture_(swrSprite_dial_trakmid_wire_rgb);
        swrSprite_NewSprite(7, tex);
        swrSprite_NewSprite(8, tex);
        swrSprite_NewSprite(9, swrSprite_LoadTexture_(swrSprite_dial_traktop_wire_rgb));
        swrSprite_NewSprite(13, fade);
        swrSprite_NewSprite(14, swrSprite_LoadTexture_(swrSprite_ctrl_A_rgb));
        for (i = 0; i < 14; i++)
            swrSprite_SetFlag(i, swrSprite_FLAG_UNK_8000);
        tex = swrSprite_LoadTexture_(swrSprite_dial_speed_wire_rgb);
    } else {
        tex = swrSprite_LoadTexture_(swrSprite_dial_meter_only_rgb);
        swrSprite_NewSprite(0x15, tex);
        swrSprite_NewSprite(0x16, flash);
        swrSprite_NewSprite(0x13, swrSprite_LoadTexture_(swrSprite_dial_gradient_rgb));
        swrSprite_NewSprite(0x14, swrSprite_LoadTexture_(swrSprite_dial_gradient_rgb));
        swrSprite_LoadTexture_(swrSprite_dial_time_wire_rgb);
        swrSprite_NewSprite(0x17, NULL);
        for (i = 0x15; i < 0x18; i++)
            swrSprite_SetFlag(i, swrSprite_FLAG_UNK_8000);
    }
    swrSprite_NewSprite(0x11, tex);
    swrSprite_NewSprite(0x12, flash);
    swrSpriteTexture_dial_gradient_rgb = swrSprite_LoadTexture_(swrSprite_dial_gradient_rgb);
    swrSprite_NewSprite(0xf, swrSpriteTexture_dial_gradient_rgb);
    swrSpriteTexture_dial_gradient_rgb2 = swrSprite_LoadTexture_(swrSprite_dial_gradient_rgb);
    swrSprite_NewSprite(0x10, swrSpriteTexture_dial_gradient_rgb2);
    for (i = 0x11; i < 0x13; i++)
        swrSprite_SetFlag(i, swrSprite_FLAG_UNK_8000);

    swrSprite_NewSprite(0x18, flash);
    swrSprite_NewSprite(0x19, fade);
    swrSprite_SetFlag(0x19, 0);
    swrSprite_NewSprite(0x1a, fade);
    swrSprite_SetFlag(0x1a, 0x1800);
    for (i = 0x18; i < 0x1b; i++)
        swrSprite_SetFlag(i, swrSprite_FLAG_UNK_8000);

    swrSprite_NewSprite(0xa1, swrSprite_LoadTexture_(swrSprite_symbol_1_rgb));
    swrSprite_SetFlag(0xa1, 0x9200);
    swrSprite_NewSprite(0xa2, swrSprite_LoadTexture_(swrSprite_symbol_2_rgb));
    swrSprite_SetFlag(0xa2, 0x9200);
    swrSprite_NewSprite(0xa3, swrSprite_LoadTexture_(swrSprite_symbol_3_rgb));
    swrSprite_SetFlag(0xa3, 0x9200);
    // faithful: each award sprite re-flags its symbol (0xa1..0xa3), not itself
    swrSprite_NewSprite(0xa4, swrSprite_LoadTexture_(swrSprite_award_first_rgb));
    swrSprite_SetFlag(0xa1, 0x1200);
    swrSprite_NewSprite(0xa5, swrSprite_LoadTexture_(swrSprite_award_second_rgb));
    swrSprite_SetFlag(0xa2, 0x1200);
    swrSprite_NewSprite(0xa6, swrSprite_LoadTexture_(swrSprite_award_third_rgb));
    swrSprite_SetFlag(0xa3, 0x1200);

    tex = swrSprite_LoadTexture_(swrSprite_engdisp0_rgb);
    swrSprite_NewSprite(0x1b, tex);
    swrSprite_NewSprite(0x1e, tex);
    swrSprite_SetFlag(0x1e, 4);
    if (numLocalPlayers > 1) {
        swrSprite_NewSprite(0x23, tex);
        swrSprite_NewSprite(0x26, tex);
        swrSprite_SetFlag(0x26, 4);
    }
    tex = swrSprite_LoadTexture_(swrSprite_engdisp1_rgb);
    swrSprite_NewSprite(0x1c, tex);
    swrSprite_NewSprite(0x1f, tex);
    swrSprite_SetFlag(0x1f, 4);
    if (numLocalPlayers > 1) {
        swrSprite_NewSprite(0x24, tex);
        swrSprite_NewSprite(0x27, tex);
        swrSprite_SetFlag(0x27, 4);
    }
    tex = swrSprite_LoadTexture_(swrSprite_engdisp2_rgb);
    swrSprite_NewSprite(0x1d, tex);
    swrSprite_NewSprite(0x20, tex);
    swrSprite_SetFlag(0x20, 4);
    if (numLocalPlayers > 1) {
        swrSprite_NewSprite(0x25, tex);
        swrSprite_NewSprite(0x28, tex);
        swrSprite_SetFlag(0x28, 4);
    }
    tex = swrSprite_LoadTexture_(swrSprite_engdisp3_rgb);
    swrSprite_NewSprite(0x21, tex);
    swrSprite_NewSprite(0x22, tex);
    if (numLocalPlayers > 1) {
        swrSprite_NewSprite(0x29, tex);
        swrSprite_NewSprite(0x2a, tex);
    }

    for (i = 0; i < judge->num_players; i++)
        swrSprite_NewSprite(i + 0x2b, swrSprite_LoadTexture_(((swrRacerData*)swrScoresPtr[i].pilotId)->hudSpriteId));
    swrPlayerHUD_SetupTrackOverlay(hudType, weatherLevel);
    SetPlanetIdAndTrackNumber(hudType, weatherLevel);
}
