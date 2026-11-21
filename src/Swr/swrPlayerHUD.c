#include "swrPlayerHUD.h"

#include "globals.h"
#include "swrSprite.h"
#include "swrViewport.h"
#include "swrObj.h"
#include "swrModel.h"
#include "swrWeather.h"
#include "swrText.h"
#include "swr.h"
#include "swrRender.h"
#include <Win95/DirectX.h>

#include <Primitives/rdVector.h>
#include <engine_config.h>
#include <macros.h>
#include <stdio.h>

// 0x0042c510
void swrPlayerHUD_RenderDistanceText(void* viewport, bool secondaryPass)
{
    rdVector3* worldPos;
    float dist;
    float alpha;
    float screenX;
    float screenY;
    float screenZ;
    float depth;
    int label;
    char text[8];
    char a;
    char b;

    for (int i = 0; i < SWR_MAX_RACERS; i++) {
        worldPos = &player_sprite_positions_on_map[i];
        if (!secondaryPass) {
            player_sprite_pixel_pos_x[i] = -1000;
            player_sprite_pixel_pos_y[i] = -1000;
        } else {
            player_sprite_pixel_pos_x2[i] = -1000;
            player_sprite_pixel_pos_y2[i] = -1000;
        }
        if (player_sprite_unknown_values[i] == SWR_HUD_RACER_LABEL_NONE)
            continue;
        dist = rdVector_Dist3(worldPos, &rdVector_model_translation);
        if (!(dist > SWR_HUD_RACER_LABEL_MIN_DIST) || !(dist < SWR_HUD_WORLD_SPRITE_MAX_DIST))
            continue;
        if (dist < SWR_HUD_RACER_LABEL_FADE_DIST)
            alpha = 255.0f;
        else
            alpha = (SWR_HUD_WORLD_SPRITE_MAX_DIST - dist) * 255.0f * SWR_HUD_RACER_LABEL_FADE_SCALE;
        if (alpha > SWR_HUD_RACER_LABEL_MAX_ALPHA)
            alpha = SWR_HUD_RACER_LABEL_MAX_ALPHA;
        if (GetPauseState() != 0)
            alpha = alpha * 0.5f;

        swrViewport_ProjectToScreen((swrViewport*)viewport, (rdVector4*)worldPos, &screenX, &screenY, &screenZ, &depth, 0);
        if (!(screenX > -4.0f))
            continue;
        label = player_sprite_unknown_values[i];
        if (label >= 0) {
            screenY = screenY - 13.0f;
            screenX = screenX - 4.0f;
        } else {
            screenY = screenY - 20.0f;
            screenX = screenX - 8.0f;
        }
        if (!(screenX < (float)swrDisplay_screenWidth) || !(screenY > 0.0f) || !(screenY < (float)swrDisplay_screenHeight))
            continue;
        if (!secondaryPass) {
            player_sprite_pixel_pos_x[i] = (int)screenX;
            player_sprite_pixel_pos_y[i] = (int)screenY;
        } else {
            player_sprite_pixel_pos_x2[i] = (int)screenX;
            player_sprite_pixel_pos_y2[i] = (int)screenY;
        }
        // drawn when in front of the camera plane or nearer than the sampled z-buffer depth
        if (!(screenZ < 0.0f) && !(screenZ < player_sprite_depth_values[i]))
            continue;
        if (label >= 0) {
            sprintf(text, swrText_Translate("~s%d"), label);
            a = (char)(int)alpha;
            b = -1;
        } else {
            sprintf(text, "~f1~s%d", -label);
            a = (char)((int)alpha + 0x28);
            b = 0;
        }
        swrText_CreateTextEntry2((int16_t)(int)screenX, (int16_t)(int)screenY, -1, -1, b, a, text);
    }
}

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
        tex = swrSprite_LoadTextureById(swrSprite_lensflare1_rgb);
        swrSprite_NewSprite(0x41, tex);
        if (planetId == 0)
            swrSprite_NewSprite(0x49, tex);
        tex = swrSprite_LoadTextureById(swrSprite_newflare1_rgb);
        for (i = 0x42; i < 0x49; i++)
            swrSprite_NewSprite(i, tex);
        if (planetId == 0) {
            for (i = 0x4a; i < 0x51; i++)
                swrSprite_NewSprite(i, tex);
        }
        tex = swrSprite_LoadTextureById(swrSprite_newsun_rgb);
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
        tex = swrSprite_LoadTextureById(swrSprite_newflare1_rgb);
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
                SetSunSpriteAlpha(0, 0x80);
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
        swrSpriteTexture* star = swrSprite_LoadTextureById(swrSprite_lightstar_glowstar2_rgb);
        swrSpriteTexture* streak = swrSprite_LoadTextureById(swrSprite_lightstar_glowstreak_rgb);
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
    fade = swrSprite_LoadTextureById(swrSprite_ej_fade1_rgb);
    flash = swrSprite_LoadTextureById(swrSprite_dial_lightflash_rgb);
    if (numLocalPlayers < 2) {
        swrSprite_NewSprite(0, swrSprite_LoadTextureById(swrSprite_dial_lap_pos_rgb));
        swrSprite_NewSprite(1, swrSprite_LoadTextureById(swrSprite_dial_lap_pos_rgb));
        tex = swrSprite_LoadTextureById(swrSprite_dial_speed_edge_blue_rgb);
        swrSprite_NewSprite(3, tex);
        swrSprite_NewSprite(10, tex);
        swrSprite_SetFlag(10, 4);
        swrSprite_NewSprite(2, swrSprite_LoadTextureById(swrSprite_dial_speed_mid_blue_rgb));
        swrSprite_NewSprite(4, swrSprite_LoadTextureById(swrSprite_dial_time_wire_rgb));
        swrSprite_NewSprite(5, NULL);
        swrSprite_NewSprite(6, NULL);
        tex = swrSprite_LoadTextureById(swrSprite_dial_top_h_wire_rgb);
        swrSprite_NewSprite(11, tex);
        swrSprite_NewSprite(12, tex);
        tex = swrSprite_LoadTextureById(swrSprite_dial_trakmid_wire_rgb);
        swrSprite_NewSprite(7, tex);
        swrSprite_NewSprite(8, tex);
        swrSprite_NewSprite(9, swrSprite_LoadTextureById(swrSprite_dial_traktop_wire_rgb));
        swrSprite_NewSprite(13, fade);
        swrSprite_NewSprite(14, swrSprite_LoadTextureById(swrSprite_ctrl_A_rgb));
        for (i = 0; i < 14; i++)
            swrSprite_SetFlag(i, swrSprite_FLAG_UNK_8000);
        tex = swrSprite_LoadTextureById(swrSprite_dial_speed_wire_rgb);
    } else {
        tex = swrSprite_LoadTextureById(swrSprite_dial_meter_only_rgb);
        swrSprite_NewSprite(0x15, tex);
        swrSprite_NewSprite(0x16, flash);
        swrSprite_NewSprite(0x13, swrSprite_LoadTextureById(swrSprite_dial_gradient_rgb));
        swrSprite_NewSprite(0x14, swrSprite_LoadTextureById(swrSprite_dial_gradient_rgb));
        swrSprite_LoadTextureById(swrSprite_dial_time_wire_rgb);
        swrSprite_NewSprite(0x17, NULL);
        for (i = 0x15; i < 0x18; i++)
            swrSprite_SetFlag(i, swrSprite_FLAG_UNK_8000);
    }
    swrSprite_NewSprite(0x11, tex);
    swrSprite_NewSprite(0x12, flash);
    swrSpriteTexture_dial_gradient_rgb = swrSprite_LoadTextureById(swrSprite_dial_gradient_rgb);
    swrSprite_NewSprite(0xf, swrSpriteTexture_dial_gradient_rgb);
    swrSpriteTexture_dial_gradient_rgb2 = swrSprite_LoadTextureById(swrSprite_dial_gradient_rgb);
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

    swrSprite_NewSprite(0xa1, swrSprite_LoadTextureById(swrSprite_symbol_1_rgb));
    swrSprite_SetFlag(0xa1, 0x9200);
    swrSprite_NewSprite(0xa2, swrSprite_LoadTextureById(swrSprite_symbol_2_rgb));
    swrSprite_SetFlag(0xa2, 0x9200);
    swrSprite_NewSprite(0xa3, swrSprite_LoadTextureById(swrSprite_symbol_3_rgb));
    swrSprite_SetFlag(0xa3, 0x9200);
    // faithful: each award sprite re-flags its symbol (0xa1..0xa3), not itself
    swrSprite_NewSprite(0xa4, swrSprite_LoadTextureById(swrSprite_award_first_rgb));
    swrSprite_SetFlag(0xa1, 0x1200);
    swrSprite_NewSprite(0xa5, swrSprite_LoadTextureById(swrSprite_award_second_rgb));
    swrSprite_SetFlag(0xa2, 0x1200);
    swrSprite_NewSprite(0xa6, swrSprite_LoadTextureById(swrSprite_award_third_rgb));
    swrSprite_SetFlag(0xa3, 0x1200);

    tex = swrSprite_LoadTextureById(swrSprite_engdisp0_rgb);
    swrSprite_NewSprite(0x1b, tex);
    swrSprite_NewSprite(0x1e, tex);
    swrSprite_SetFlag(0x1e, 4);
    if (numLocalPlayers > 1) {
        swrSprite_NewSprite(0x23, tex);
        swrSprite_NewSprite(0x26, tex);
        swrSprite_SetFlag(0x26, 4);
    }
    tex = swrSprite_LoadTextureById(swrSprite_engdisp1_rgb);
    swrSprite_NewSprite(0x1c, tex);
    swrSprite_NewSprite(0x1f, tex);
    swrSprite_SetFlag(0x1f, 4);
    if (numLocalPlayers > 1) {
        swrSprite_NewSprite(0x24, tex);
        swrSprite_NewSprite(0x27, tex);
        swrSprite_SetFlag(0x27, 4);
    }
    tex = swrSprite_LoadTextureById(swrSprite_engdisp2_rgb);
    swrSprite_NewSprite(0x1d, tex);
    swrSprite_NewSprite(0x20, tex);
    swrSprite_SetFlag(0x20, 4);
    if (numLocalPlayers > 1) {
        swrSprite_NewSprite(0x25, tex);
        swrSprite_NewSprite(0x28, tex);
        swrSprite_SetFlag(0x28, 4);
    }
    tex = swrSprite_LoadTextureById(swrSprite_engdisp3_rgb);
    swrSprite_NewSprite(0x21, tex);
    swrSprite_NewSprite(0x22, tex);
    if (numLocalPlayers > 1) {
        swrSprite_NewSprite(0x29, tex);
        swrSprite_NewSprite(0x2a, tex);
    }

    for (i = 0; i < judge->num_players; i++)
        swrSprite_NewSprite(i + 0x2b, swrSprite_LoadTextureById(((swrRacerData*)swrScoresPtr[i].pilotId)->hudSpriteId));
    swrPlayerHUD_SetupTrackOverlay(hudType, weatherLevel);
    SetPlanetIdAndTrackNumber(hudType, weatherLevel);
}

// 0x0042d490
void swrPlayerHUD_RenderViewport(void* viewport, bool secondaryPass)
{
    if (InRaceSpritesEnabled != 0) {
        UpdateSunAndLensFlareSprites((swrViewport*)viewport);
        UpdateLightStreakSprites((swrViewport*)viewport);
        swrPlayerHUD_RenderWorldSprites(viewport);
        swrWeather_RenderParticles(viewport);
        swrPlayerHUD_RenderDistanceText(viewport, secondaryPass);
        return;
    }
    swrPlayerHUD_worldSpriteCount = 0;
    swrPlayerHUD_RenderDistanceText(viewport, secondaryPass);
}

// Little-endian z-buffer value at (x, y), summed byte by byte as signed ints like the x87 FIADD chain.
static float swrPlayerHUD_ReadDepth(const unsigned char* data, LONG pitch, uint32_t bytesPerDepth, int x, int y, float scale)
{
    const unsigned char* pixel;
    double sum;
    uint32_t i;

    pixel = data + y * pitch + x * (int)bytesPerDepth;
    sum = 0.0;
    for (i = bytesPerDepth; i > 0; i--) {
        sum += (int)((unsigned int)pixel[i - 1] << ((i - 1) * 8));
    }
    return (float)(sum * scale);
}

// 0x0042be60
void swrPlayerHUD_SampleOcclusion(void)
{
    uint32_t bytesPerDepth;
    LONG pitch;
    LPVOID data;
    float nearOut;
    float farOut;
    const unsigned char* end;
    const unsigned char* pixel;
    float depthScale;
    int sun;
    int sampleX;
    int sampleY;
    int count;
    int col;
    int row;
    int colMin;
    int colMax;
    int rowMin;
    int rowMax;
    int i;

    DirectDraw_LockZBuffer(&bytesPerDepth, &pitch, &data, &nearOut, &farOut);
    end = (const unsigned char*)data + pitch * swrDisplay_screenHeight;
    for (sun = 0; sun < SWR_SUN_COUNT; sun++) {
        if (sunSpriteIds[sun] < 0) {
            continue;
        }
        sampleX = sun_occlusionSampleX[sun];
        sampleY = sun_occlusionSampleY[sun];
        if (sampleX < SWR_SUN_OFFSCREEN_X) {
            sun_occlusionCoverage[sun] = SWR_SUN_OCCLUDED_COVERAGE;
            continue;
        }
        // pixels of the 8x8 square that fall in the screen margins count as occluded
        count = 0;
        colMin = 12 - sampleX;
        colMax = swrDisplay_screenWidth - 8 - sampleX;
        rowMin = 12 - sampleY;
        rowMax = swrDisplay_screenHeight - 8 - sampleY;
        pixel = (const unsigned char*)data + (sampleY - 4) * pitch + (sampleX - 4) * (int)bytesPerDepth;
        for (row = 0; row < SWR_SUN_OCCLUSION_SAMPLE_SIZE; row++) {
            for (col = 0; col < SWR_SUN_OCCLUSION_SAMPLE_SIZE; col++) {
                if (col < colMin || col >= colMax || row < rowMin || row >= rowMax) {
                    count++;
                } else if (pixel >= (const unsigned char*)data && pixel < end) {
                    // only 8- and 16-bit z-buffers are tested; other depths never count
                    if ((bytesPerDepth == 1 && *pixel != 0xff) || (bytesPerDepth == 2 && *(const unsigned short*)pixel != 0xffff)) {
                        count++;
                    }
                }
                pixel += bytesPerDepth;
            }
            pixel += pitch - (int)bytesPerDepth * SWR_SUN_OCCLUSION_SAMPLE_SIZE;
        }
        sun_occlusionCoverage[sun] = count;
    }

    // cases 3 and 4 read each other's slot, and any other depth reuses the near-plane out value (faithful)
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
    default:
        depthScale = nearOut;
        break;
    }

    for (i = 0; i < SWR_HUD_PLAYER_SPRITE_COUNT; i++) {
        player_sprite_depth_values[i] = SWR_HUD_NO_DEPTH;
        if (player_sprite_pixel_pos_x[i] >= 0) {
            player_sprite_depth_values[i] = swrPlayerHUD_ReadDepth(data, pitch, bytesPerDepth, player_sprite_pixel_pos_x[i], player_sprite_pixel_pos_y[i], depthScale);
        }
    }
    for (i = 0; i < SWR_HUD_LIGHT_STREAK_COUNT; i++) {
        if (light_streak_valid[i] == 0) {
            continue;
        }
        light_streak_depth_values[i] = SWR_HUD_NO_DEPTH;
        if (light_streak_pixel_pos_x[i] >= 0) {
            light_streak_depth_values[i] = swrPlayerHUD_ReadDepth(data, pitch, bytesPerDepth, light_streak_pixel_pos_x[i], light_streak_pixel_pos_y[i], depthScale);
        }
    }
    for (i = 0; i < swrPlayerHUD_worldSpriteCount; i++) {
        swrPlayerHUD_worldSpriteDepth[i] = SWR_HUD_NO_DEPTH;
        if (swrPlayerHUD_worldSpritePixelX[i] >= 0) {
            swrPlayerHUD_worldSpriteDepth[i] = swrPlayerHUD_ReadDepth(data, pitch, bytesPerDepth, swrPlayerHUD_worldSpritePixelX[i], swrPlayerHUD_worldSpritePixelY[i], depthScale);
        }
    }
    DirectDraw_UnlockZBuffer();
}

// 0x00483cb0
void swrPlayerHUD_RenderAllViewports(void)
{
    int first;
    int i;
    int nextFrameBuffer;
    int prevCurrent;
    int prevPrev;
    swrViewport* viewport;
    swrViewportFog* fog;

    first = 1;
    if (assetBufferModelLoaded == 1) {
        swrRace_RebuildViewport1Scene_Maybe();
        assetBufferModelLoaded = 0;
    }
    swr_noop2();

    swrPlayerHUD_frameCounter++;
    prevCurrent = swrPlayerHUD_frameBufferCurrent;
    prevPrev = swrPlayerHUD_frameBufferPrev;
    nextFrameBuffer = swrPlayerHUD_frameBuffers[swrViewport_frameTriple];
    swrPlayerHUD_frameBufferPrev2 = prevPrev;
    swrPlayerHUD_frameBufferPrev = prevCurrent;
    swrPlayerHUD_frameBufferCurrent = nextFrameBuffer;
    if (prevCurrent == 0)
        swrPlayerHUD_frameBufferPrev = nextFrameBuffer;
    if (prevPrev == 0)
        swrPlayerHUD_frameBufferPrev2 = nextFrameBuffer;

    swrRender_cameraCount = 0;
    swrRender_displayListCursor = (Gfx*)(swrRender_displayListArena + swrViewport_frameParity * SWR_RENDER_DISPLAY_LIST_BYTES);
    swrRender_displayListFrameStart = swrRender_displayListCursor;
    swrViewport_Activate(0);

    // swr_noop1 is a stripped sink; the original passes it the split-screen fog colours or the clear flag
    if (swrObjJdge_splitscreenActive != 0 && (swrViewport_array[2].flag & swrViewport_FLAGS_CAMERA_VALID)) {
        swr_noop1();
    } else {
        if (swrRace_blankWorldForMenu != 0) {
            backBufferClearColor[0] = 0;
            backBufferClearColor[1] = 0;
            backBufferClearColor[2] = 0;
        }
        swr_noop1();
    }
    swrSprite_DrawSprites(1);

    for (i = 0; i < SWR_VIEWPORT_COUNT; i++) {
        viewport = &swrViewport_array[i];
        if ((viewport->flag & swrViewport_FLAGS_CAMERA_VALID) == 0)
            continue;
        swrViewport_Activate(i);
        if (swrObjJdge_splitscreenActive != 0 && i >= 1 && (swrViewport_array[2].flag & swrViewport_FLAGS_CAMERA_VALID)) {
            fog = &swrPlayerHUD_viewportFog[i];
            if (fog->enabled != 0) {
                rdModel_SetFogEnabled(1);
                SetFogParameters(fog->start, 1000, fog->r, fog->g, fog->b, 0xff);
            } else {
                rdModel_SetFogEnabled(0);
            }
            if (fog->skyboxVisible != 0) {
                if (swrObjJdge_splitSkyboxNode != NULL)
                    swrModel_NodeModifyFlags(swrObjJdge_splitSkyboxNode, 2, 3, 0x10, 2);
            } else if (swrObjJdge_splitSkyboxNode != NULL) {
                swrModel_NodeModifyFlags(swrObjJdge_splitSkyboxNode, 2, -4, 0x10, 3);
            }
        }
        if (swrRace_blankWorldForMenu == 0) {
            swrPlayerHUD_RenderViewport(viewport, !first);
            swrViewport_Render(i);
        }
        // bounded by 31 although swrRender_cameraPositions holds one entry per viewport
        if (swrRender_cameraCount < SWR_RENDER_MAX_CAMERA_POSITIONS) {
            rdVector_Copy3(&swrRender_cameraPositions[swrRender_cameraCount], (rdVector3*)&unkCameraArray[viewport->unkCameraIndex].transform.vD);
            swrRender_cameraCount++;
        }
        first = 0;
    }

    swrViewport_Activate(0);
    if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_HIDE_OVERLAY_KEYS) == 0 || swrRace_DebugLevel <= 0 || (inRaceLocalPlayerInputBitset3[0] & 0x1100) != 0x1100) {
        swrSprite_DrawSprites(2);
        // the original also passes the size of the last viewport's display list (in Gfx), which the callee ignores
        swrRace_DrawDebugPosition(swrRace_DebugLevel);
        DrawTextEntries();
        swrSprite_DrawSprites(3);
        DrawTextEntries2();
    }
    swrScene_UpdatePaletteScroll();
    swrSprite_ResetDirtyRects();
    swrRace_blankWorldForMenu = 0;
}
