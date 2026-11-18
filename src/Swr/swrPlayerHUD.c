#include "swrPlayerHUD.h"

#include "globals.h"
#include "swrSprite.h"
#include "swrViewport.h"
#include "swrObj.h"
#include "swrModel.h"
#include "swrWeather.h"

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
void swrPlayerHUD_SetupTrackOverlay(int planetId, int trackNumber)
{
    swrSpriteTexture* tex;
    rdVector3 sunPos;
    float sunScale;
    uint8_t r, g, b;
    uint8_t a;
    int i;

    if (numLocalPlayers > 1) {
        DisableIngameSprites();
        return;
    }

    if (planetId != 7 && planetId != 5) {
        tex = swrSprite_LoadTexture_(swrSprite_lensflare1_rgb);
        swrSprite_NewSprite(0x41, tex);
        if (planetId == 0)
            swrSprite_NewSprite(0x49, tex);
        tex = swrSprite_LoadTexture_(swrSprite_newflare1_rgb);
        for (i = 0x42; i < 0x49; i++)
            swrSprite_NewSprite(i, tex);
        if (planetId == 0) {
            for (i = 0x4a; i < 0x51; i++)
                swrSprite_NewSprite(i, tex);
        }
        tex = swrSprite_LoadTexture_(swrSprite_newsun_rgb);
        swrSprite_NewSprite(0x3f, tex);
        if (planetId == 0)
            swrSprite_NewSprite(0x40, tex);
        swrSprite_SetFlag(0x3f, 0x1e00);
        swrSprite_UnsetFlag(0x3f, 1);
        for (i = 0x41; i < 0x49; i++) {
            swrSprite_SetFlag(i, 0x1e00);
            swrSprite_UnsetFlag(i, 1);
        }
        if (planetId == 0) {
            swrSprite_SetFlag(0x40, 0x1e00);
            swrSprite_UnsetFlag(0x40, 1);
            for (i = 0x49; i < 0x51; i++) {
                swrSprite_SetFlag(i, 0x1e00);
                swrSprite_UnsetFlag(i, 1);
            }
        }

        a = 0xff;
        if (planetId == 0) {
            rdVector_Set3(&sunPos, -360.0f, 512.0f, 200.0f);
            SetSunSprite(1, 0x40, &sunPos.x, 0.90000004f, 0xff, 0xdc, 0xbe, 0xff);
            swrObjJdge_SetupLensFlareSprites(1, 0x49, 0.90000004f);
            rdVector_Set3(&sunPos, -220.0f, 512.0f, 260.0f);
            sunScale = 1.2f;
            r = 0xff;
            g = 0xfd;
            b = 0xe1;
        } else if (planetId == 1) {
            rdVector_Set3(&sunPos, 278.13f, -121.01f, 213.05f);
            sunScale = 0.3f;
            r = 0xcd;
            g = 0xf0;
            b = 0xff;
        } else if (planetId == 2) {
            rdVector_Set3(&sunPos, 0.0f, 512.0f, 230.0f);
            sunScale = 1.2f;
            r = 0xff;
            g = 0xf4;
            b = 0xbe;
        } else if (planetId == 3) {
            rdVector_Set3(&sunPos, 278.13f, -121.01f, 213.05f);
            sunScale = 1.44f;
            r = 0xff;
            g = 0xda;
            b = 0xcc;
        } else if (planetId == 4) {
            rdVector_Set3(&sunPos, -144.9f, 84.0f, 35.0f);
            sunScale = 1.44f;
            r = 0xff;
            g = 0xe6;
            b = 0xb4;
            if (trackNumber != 3) {
                a = 100;
                sunScale = 0.48000002f;
                r = 0x80;
                g = 0x73;
                b = 0x5a;
            }
        } else if (planetId == 6) {
            rdVector_Set3(&sunPos, -145.08f, 69.15f, 126.97f);
            sunScale = 0.24000001f;
            r = 0xf0;
            g = 0xf0;
            b = 0xff;
        } else {
            rdVector_Set3(&sunPos, 0.0f, 512.0f, 230.0f);
            sunScale = 1.2f;
            r = 0xff;
            g = 0xff;
            b = 0xff;
        }
        SetSunSprite(0, 0x3f, &sunPos.x, sunScale, r, g, b, a);
        swrObjJdge_SetupLensFlareSprites(0, 0x41, sunScale);
    }

    if (numLocalPlayers < 2 && (planetId == 1 || planetId == 4) && trackNumber != 3) {
        swrWeather_Enable();
        swrWeather_SetStretchFactor(1.0f);
        swrWeather_SetParticleCap(0);
        tex = swrSprite_LoadTexture_(swrSprite_newflare1_rgb);
        for (i = 0x51; i < 0x8d; i++) {
            swrSprite_NewSprite(i, tex);
            swrSprite_SetFlag(i, 0x1e00);
            swrSprite_UnsetFlag(i, 1);
            swrWeather_SetParticleSpriteId(i - 0x51, i);
        }
        if (planetId == 1) {
            for (i = 0x8d; i < 0xa1; i++) {
                swrSprite_NewSprite(i, tex);
                swrSprite_SetFlag(i, 0x1e00);
                swrSprite_UnsetFlag(i, 1);
                swrWeather_SetParticleSpriteId(i - 0x51, i);
            }
            swrWeather_SetColor(0xe6, 0xe6, 0xff, 200);
            if (trackNumber == 0) {
                swrWeather_SetParticleCap(0);
            } else if (trackNumber == 1) {
                swrWeather_SetVelocity(25.0f, 45.0f);
                swrWeather_SetParticleCap(20);
            } else if (trackNumber == 2) {
                swrWeather_SetVelocity(20.0f, 60.0f);
                swrWeather_SetParticleCap(40);
                SetSunSpriteAlpha_Maybe(0, 0x80);
            }
        } else {
            swrWeather_SetColor(0xff, 0xff, 0xff, 40);
            swrWeather_SetStretchFactor(7.0f);
            if (trackNumber == 0) {
                swrWeather_SetParticleCap(20);
                swrWeather_SetVelocity(10.0f, 300.0f);
            } else {
                swrWeather_SetVelocity(50.0f, 1000.0f);
                swrWeather_SetParticleCap(60);
            }
        }
    } else {
        swrWeather_Disable();
    }

    if (planetId != 1 || trackNumber == 3) {
        swrSpriteTexture* star = swrSprite_LoadTexture_(swrSprite_lightstar_glowstar2_rgb);
        swrSpriteTexture* streak = swrSprite_LoadTexture_(swrSprite_lightstar_glowstreak_rgb);
        for (i = 0; i < 10; i++) {
            swrSprite_NewSprite(0x8d + i, streak);
            swrSprite_SetFlag(0x8d + i, 0x1f00);
            swrSprite_UnsetFlag(0x8d + i, 1);
            swrSprite_NewSprite(0x97 + i, star);
            swrSprite_SetFlag(0x97 + i, 0x1f00);
            swrSprite_UnsetFlag(0x97 + i, 1);
            SetLightStreakSpriteIDs(i, 0x8d + i, 0x97 + i);
        }
    }
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
