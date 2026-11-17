#include "swrControl.h"

#include "Win95/Window.h"
#include "Platform/cifr.h"
#include "Platform/stdControl.h"
#include "globals.h"
#include "engine_config.h"
#include "Swr/swrModel.h"

#include <stdlib.h>
#include <string.h>

#include "macros.h"

// 0x00402250
int swrControl_MappingsMenu(swrUI_unk* param_1, unsigned int param_2, unsigned int param_3, int param_4)
{
    HANG("TODO");
}

// 0x00404da0
int swrControl_Shutdown(void)
{
    HANG("TODO");
    return 0;
}

// 0x00404dd0
void swrControl_ProcessInputs(void)
{
    HANG("TODO");
}

// 0x00407500
int swrControl_RemoveMapping(void* cid, char* mondo_text, int param_3, int whichone, int bool_unk)
{
    HANG("TODO");
}

// 0x004078e0
int swrControl_AddMapping(void* cid, char* fnStr, int controllerBinding, int bAnalogCapture, int unk, int unk2)
{
    HANG("TODO");
}

// 0x004078a0
void swrControl_ReplaceMapping(void* cid, char* fnStr, int whichOne, int bAnalogCapture, int unk, int controllerBinding)
{
    HANG("TODO");
}

// 0x00423efd
int swrControl_Startup(void)
{
    HANG("TODO");
    Window_set_msg_handler(Window_msg_default_handler);
    HANG("TODO");
    return 0;
}

// 0x00405cf0
void swrControl_ClearDeviceState(int deviceClass)
{
    if (deviceClass < 0) {
        memset(inRaceLocalPlayerInputRecord, 0, sizeof(inRaceLocalPlayerInputRecord));
        memset(swrControl_buttonHeldPrev, 0, sizeof(swrControl_buttonHeldPrev));
        deviceClass = -deviceClass;
    }
    if (deviceClass == swrConfig_DEVICE_JOYSTICK) {
        swrControl_joystickAxes[2] = 0.0f;
        swrControl_joystickAxes[1] = 0.0f;
        swrControl_joystickAxes[0] = 0.0f;
    } else if (deviceClass == swrConfig_DEVICE_MOUSE) {
        swrControl_mouseAxes[2] = 0.0f;
        swrControl_mouseAxes[1] = 0.0f;
        swrControl_mouseAxes[0] = 0.0f;
        swrControl_mouseAxesAccum[2] = 0.0f;
        swrControl_mouseAxesAccum[1] = 0.0f;
        swrControl_mouseAxesAccum[0] = 0.0f;
    } else if (deviceClass == swrConfig_DEVICE_KEYBOARD) {
        swrControl_keyboardAxes[2] = 0.0f;
        swrControl_keyboardAxes[1] = 0.0f;
        swrControl_keyboardAxes[0] = 0.0f;
    }
}

// 0x00409d70
int swrControl_LoadForceEffects(int deviceType)
{
    char projectFile[20];
    const char* bundle;

    if ((swrControl_forceEffectsDeviceType & 0xff) == deviceType) {
        return 1;
    }
    if (deviceType >= SWR_FF_DEVICE_NONE) {
        return 0;
    }
    if ((unsigned char)swrControl_forceEffectsDeviceType < SWR_FF_DEVICE_NONE) {
        cifr_ReinitEffects_Maybe(&swrControl_forceEffects);
    }
    memset(swrControl_forceEffectValue, 0, sizeof(swrControl_forceEffectValue));
    memset(swrControl_forceEffectPlaying, 0, sizeof(swrControl_forceEffectPlaying));
    // the EXE only ever writes the low byte of swrControl_forceEffectsDeviceType
    if (deviceType < 0) {
        *(unsigned char*)&swrControl_forceEffectsDeviceType = SWR_FF_DEVICE_NONE;
        return 1;
    }
    cifr_Init(&swrControl_forceEffects);
    bundle = cifr_deviceIsWheel ? ".\\data\\bundle2.fcr" : ".\\data\\bundle.fcr";
    memcpy(projectFile, bundle, strlen(bundle) + 1);
    if (cifr_LoadProjectFile(&swrControl_forceEffects, projectFile, swrControl_forceEffectSlotLastIds, swrControl_forceEffectNames) < 0) {
        return 0;
    }
    if (cifr_LoadAllEffects(&swrControl_forceEffects) < 0) {
        (*stdPlatform_hostServices_ptr->errorPrint)("BIZARRO ALERT!  cifr_LoadAllEffectsSlots couldn't load any forces!\n");
        return 0;
    }
    *(unsigned char*)&swrControl_forceEffectsDeviceType = (unsigned char)deviceType;
    swrControl_forceEffectsLoaded = 1;
    return 1;
}

// 0x00409ee0
int swrControl_PlayForceEffect(int effectId, int magnitude, int direction, int duration)
{
    int slot;
    int prepared;
    float strength;
    cifr_Effect* effect;
    swrForceEffectSetting* setting;

    slot = swrControl_FindForceEffectSlot(effectId);
    strength = swrControl_forceStrength;
    // slot -1 (unknown id) yields a pointer one slot before the table; faithful
    effect = &swrControl_forceEffects.slots[slot];
    if (swrConfig_FORCE_ENABLED == 0) {
        return 1;
    }
    setting = &swrControl_forceEffectSettings[effectId];
    if (setting->magnitudeScale < 0.0f || setting->gain < 0.0f || setting->unk8 < 0.0f) {
        // a disabled GForce falls back to the auto-center spring
        if (effectId != swrForceEffect_GFORCE) {
            return 1;
        }
        setting = &swrControl_forceEffectSettings[swrForceEffect_AUTO_CENTER];
        if (setting->magnitudeScale < 0.0f || setting->gain < 0.0f || setting->unk8 < 0.0f) {
            return 1;
        }
        effectId = swrForceEffect_AUTO_CENTER;
    }
    prepared = swrControl_PrepareForceEffect(effectId, 0);
    if (swrControl_forceEffectPlaying[effectId] != 0 && cifr_IsPlaying(effect) == 0) {
        cifr_StopEffect(effect);
        swrControl_forceEffectPlaying[effectId] = 0;
        swrControl_forceEffectValue[effectId] = 0;
    }
    if (prepared == 0) {
        return 0;
    }
    if (swrControl_forceEffectSettings[effectId].gain > 0.0f) {
        strength = strength * swrControl_forceEffectSettings[effectId].gain;
    }
    if (magnitude >= 0) {
        cifr_SetMagnitude(effect, (int)((double)magnitude * strength), 0);
    } else if (strength < 1.0f) {
        cifr_SetMagnitude(effect, (int)((double)strength * 100.0f), 0);
    }
    if (direction >= 0) {
        cifr_SetDirection(effect, direction, 1);
    }
    if (duration >= 0) {
        cifr_SetDuration(effect, duration, 0);
    }
    if (cifr_StartEffect(effect, 0) < 0) {
        return 0;
    }
    swrControl_forceEffectPlaying[effectId] = 1;
    return 1;
}

// 0x0040a0b0
int swrControl_StopForceEffect(int effectId)
{
    int slot;
    cifr_Effect* effect;

    slot = swrControl_FindForceEffectSlot(effectId);
    if (swrControl_forceEffectPlaying[effectId] != 0) {
        swrControl_forceEffectPlaying[effectId] = 0;
    }
    effect = &swrControl_forceEffects.slots[slot];
    if (effect != NULL && effect->interfaces != NULL && swrControl_CheckForceEffectType(slot, effectId) == 0) {
        cifr_StopEffect(effect);
        return 1;
    }
    return 0;
}

// 0x0040a120
void swrControl_StopAllForceEffects(int reInit)
{
    int i;

    for (i = 0; i < SWR_FF_EFFECT_SLOTS; i++) {
        swrControl_StopForceEffect(swrControl_forceEffects.slots[i].effectId);
    }
    if (reInit != 0) {
        swrControl_PlayForceEffect(swrForceEffect_AUTO_CENTER, -1, -1, -1);
    }
}

// 0x0040a160
int swrControl_FindForceEffectSlot(unsigned int effectId)
{
    int slot;

    for (slot = 0; slot < SWR_FF_EFFECT_SLOTS; slot++) {
        if (effectId <= swrControl_forceEffects.slots[slot].lastEffectId) {
            break;
        }
    }
    if (slot >= SWR_FF_EFFECT_SLOTS) {
        slot = -1;
    }
    return slot;
}

// 0x0040a190
int swrControl_CheckForceEffectType(int slot, unsigned int type)
{
    unsigned int loaded;

    if (slot < 0) {
        return -1;
    }
    loaded = swrControl_forceEffects.slots[slot].effectId;
    if ((int)loaded < 0) {
        return 2;
    }
    if (loaded == type) {
        return 0;
    }
    if (strcmp(swrControl_forceEffects.slots[slot].name, swrControl_forceEffectNames[type]) == 0) {
        return 1;
    }
    if (loaded < type) {
        return 3;
    }
    return 4;
}

// 0x0040a240
int swrControl_PrepareForceEffect(int effectId, int force)
{
    int slot;
    int check;
    cifr_Effect* effect;
    const char* name;

    slot = swrControl_FindForceEffectSlot(effectId);
    check = swrControl_CheckForceEffectType(slot, effectId);
    if (check < 0) {
        return 0;
    }
    effect = &swrControl_forceEffects.slots[slot];
    if (check > 3 && force == 0 && cifr_IsPlaying(effect) != 0) {
        return 0;
    }
    // an empty slot (effectId -1) clears index -1 of both arrays; faithful
    swrControl_forceEffectPlaying[effect->effectId] = 0;
    swrControl_forceEffectValue[effect->effectId] = 0;
    effect->effectId = effectId;
    swrControl_forceEffectValue[effectId] = 0;
    if (check > 1) {
        name = swrControl_forceEffectNames[effectId];
        memcpy(effect->name, name, strlen(name) + 1);
        if (cifr_CreateEffect(effect, swrControl_forceEffectNames[effectId], swrControl_forceEffects.project) == 0) {
            return 0;
        }
        swrControl_forceEffectPlaying[effectId] = 0;
    }
    return 1;
}

// 0x0040a330
int swrControl_ConfigureForceEffect(int effectId, int value)
{
    int slot;
    int restarted;
    int ok;
    int coeff;
    unsigned int size;
    int* params;
    char state;
    float scale;
    cifr_Effect* effect;
    swrForceEffectSetting* setting;

    slot = swrControl_FindForceEffectSlot(effectId);
    restarted = 0;
    if (slot < 0 || swrControl_forceEffects.slots[slot].effectId != effectId) {
        return 0;
    }
    setting = &swrControl_forceEffectSettings[effectId];
    if (setting->magnitudeScale < 0.0f || setting->gain < 0.0f || setting->unk8 < 0.0f) {
        return 0;
    }
    effect = &swrControl_forceEffects.slots[slot];
    if (effect->interfaces == NULL) {
        return 0;
    }
    if (cifr_IsPlaying(effect) == 0) {
        restarted = 1;
    }
    if (restarted == 0 && swrControl_forceEffectValue[effectId] == value) {
        return 1;
    }
    if (cifr_GetForceFeedbackState_Maybe(effect, &state) == 0) {
        return 0;
    }
    size = effect->params.cbTypeSpecificParams;
    params = (*stdPlatform_hostServices_ptr->alloc)(size);
    memcpy(params, effect->typeSpecificBuffer, size);
    scale = 1.0f;
    if (setting->magnitudeScale != 0.0f) {
        scale = setting->magnitudeScale;
    }
    // DICONDITION pair: [1]/[2] = axis-0 coefficients, [7]/[8] = axis-1 coefficients
    coeff = (int)((double)value * scale);
    params[1] = coeff;
    params[2] = coeff;
    if (cifr_deviceIsWheel == 0) {
        params[7] = (params[7] / coeff) * value;
        params[8] = params[7];
    }
    swrControl_forceEffectValue[effectId] = value;
    ok = cifr_SetCustomForceData_Maybe(effect, size, params, restarted);
    (*stdPlatform_hostServices_ptr->free)(params);
    if (ok != 0 && restarted != 0) {
        swrControl_forceEffectPlaying[effectId] = 1;
    }
    return ok;
}

// 0x0040a500
int swrControl_UpdateForceEffect(int effectId, int period)
{
    int slot;
    int restarted;
    int ok;
    unsigned int size;
    int* params;
    char state;
    cifr_Effect* effect;
    swrForceEffectSetting* setting;

    slot = swrControl_FindForceEffectSlot(effectId);
    restarted = 0;
    if (slot < 0 || swrControl_forceEffects.slots[slot].effectId != effectId) {
        return 0;
    }
    setting = &swrControl_forceEffectSettings[effectId];
    if (setting->magnitudeScale < 0.0f || setting->gain < 0.0f || setting->unk8 < 0.0f) {
        return 0;
    }
    effect = &swrControl_forceEffects.slots[slot];
    if (effect->interfaces == NULL) {
        return 0;
    }
    if (cifr_IsPlaying(effect) == 0) {
        restarted = 1;
    }
    if (restarted == 0 && swrControl_forceEffectValue[effectId] == period) {
        return 1;
    }
    if (cifr_GetForceFeedbackState_Maybe(effect, &state) == 0) {
        return 0;
    }
    size = effect->params.cbTypeSpecificParams;
    params = (*stdPlatform_hostServices_ptr->alloc)(size);
    memcpy(params, effect->typeSpecificBuffer, size);
    params[3] = period; // DIPERIODIC dwPeriod
    swrControl_forceEffectValue[effectId] = period;
    ok = cifr_SetCustomForceData_Maybe(effect, size, params, restarted);
    (*stdPlatform_hostServices_ptr->free)(params);
    if (ok != 0 && restarted != 0) {
        swrControl_forceEffectPlaying[effectId] = 1;
    }
    return ok;
}

// 0x0040b110
void swrControl_SetForceFeedbackPlayer(swrRace* player)
{
    currentPlayer_Test = player;
    swrControl_ffScore = player->score_ptr;
    swrControl_ffMaxSpeed = player->podStats.maxSpeed;
    swrControl_ffRestSpeedRatio = 0.0f;
    swrControl_ffGForceScale = 6500.0f;
    swrControl_ffPrevSpeedRatio = -65535.0f;
}

// 0x0040b150
void swrControl_UpdateForceFeedback(void)
{
    if (swrConfig_FORCE_ENABLED != 0 && swrControl_ffScore != NULL && swrControl_ffScore->obj_test_ptr != NULL && currentPlayer_Test != NULL && swrRace_resultsScreenActive != 0 && (currentPlayer_Test->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) == 0) {
        swrControl_UpdateTractionForceEffect();
        swrControl_UpdateSpeedForceEffect();
        swrControl_UpdateImpactForceEffect();
    }
}

// 0x0040b1c0
void swrControl_UpdateTractionForceEffect(void)
{
    swrRace* player;
    swrModel_Behavior* behavior;
    int period;
    int delta;
    int i;
    int leftCount;
    int rightCount;
    unsigned int status;
    float maxHealth;

    player = currentPlayer_Test;
    maxHealth = -1.0f;
    status = 0;
    rightCount = 0;
    leftCount = 0;
    if ((player->flags1 & swrObjTest_FLAG1_EXPLODING) != 0) {
        swrControl_PlayForceEffect(swrForceEffect_CRASHING, -1, -1, -1);
        swrControl_PlayForceEffect(swrForceEffect_SWAMP_MUCK, -1, -1, -1);
        return;
    }
    if (player->surfaceSpeedFactor < 1.0f) {
        period = (int)(200000.0f - (double)player->surfaceSpeedFactor * 150000.0f);
        delta = period - swrControl_ffLastTractionPeriod;
        if (delta < 0) {
            delta = swrControl_ffLastTractionPeriod - period;
        }
        if (delta >= 20000) {
            swrControl_UpdateForceEffect(swrForceEffect_ENGINE_RUMBLE, period);
            swrControl_ffLastTractionPeriod = period;
        }
        swrControl_ffTractionRumbleActive = 1;
    } else {
        swrControl_UpdateForceEffect(swrForceEffect_ENGINE_RUMBLE, 8000);
        swrControl_ffTractionRumbleActive = 0;
    }
    if ((currentPlayer_Test->flags1 & swrObjTest_FLAG1_ON_SWAMP) != 0) {
        swrControl_PlayForceEffect(swrForceEffect_SWAMP_MUCK, -1, -1, -1);
    } else {
        swrControl_StopForceEffect(swrForceEffect_SWAMP_MUCK);
    }
    if ((currentPlayer_Test->flags1 & swrObjTest_FLAG1_AIRBORNE) != 0) {
        swrControl_PlayForceEffect(swrForceEffect_AIR_SLIDE, -1, -1, -1);
    } else {
        swrControl_StopForceEffect(swrForceEffect_AIR_SLIDE);
        player = currentPlayer_Test;
        if (player->terrainModel != NULL && player->speedValue > 50.0f) {
            behavior = swrModel_MeshGetBehavior((swrModel_Mesh*)player->terrainModel);
            if (behavior != NULL && (behavior->vehicle_reaction & swrVehicleReaction_Slip) != 0) {
                swrControl_PlayForceEffect(swrForceEffect_ICE_SLIDE, -1, -1, -1);
            }
        }
    }
    // only engines that raise the running max are counted (faithful)
    for (i = 0; i < 6; i++) {
        if (maxHealth < currentPlayer_Test->engineHealth[i]) {
            maxHealth = currentPlayer_Test->engineHealth[i];
            status |= currentPlayer_Test->engineStatus[i];
            if (i <= 2) {
                leftCount++;
            } else {
                rightCount++;
            }
        }
    }
    if ((status & swrRace_ENGINESTATUS_ON_FIRE) != 0) {
        swrControl_PlayForceEffect(swrForceEffect_ENGINE_FIRE_LEFT, -1, (rightCount > leftCount) * 180 + 90, -1);
        return;
    }
    swrControl_StopForceEffect(swrForceEffect_ENGINE_FIRE_LEFT);
}

// 0x0040b3d0
void swrControl_UpdateSpeedForceEffect(void)
{
    float ratio;
    float diff;
    double scaled;
    double rounded;
    int coeff;
    int magnitude;
    int delta;

    ratio = currentPlayer_Test->speedValue / swrControl_ffMaxSpeed;
    if ((swrControl_ffPrevSpeedRatio == -65535.0f || swrControl_ffGForceStarted == 0 || swrControl_damageForceEffectPreempted != 0) && swrControl_PlayForceEffect(swrForceEffect_GFORCE, -1, -1, -1) != 0) {
        swrControl_ffGForceStarted = 1;
        swrControl_damageForceEffectPreempted = 0;
    }
    diff = swrControl_ffAppliedSpeedRatio - ratio;
    if (diff < 0.0f) {
        diff = -diff;
    }
    swrControl_ffSpeedEffectDirty = diff > 0.1f;
    if (swrControl_ffSpeedEffectDirty != 0) {
        swrControl_ffSpeedSettled = 0;
    } else if (swrControl_ffSpeedSettled == 0) {
        // compares the ratio against the absolute maxSpeed, not 1.0 (faithful)
        swrControl_ffSpeedEffectDirty = ratio >= swrControl_ffMaxSpeed || ratio == swrControl_ffRestSpeedRatio;
        swrControl_ffSpeedSettled = swrControl_ffSpeedEffectDirty;
    }
    if (swrControl_ffSpeedEffectDirty != 0) {
        // round away from zero, then offset by 500
        scaled = (double)ratio * swrControl_ffGForceScale;
        coeff = (int)scaled;
        rounded = scaled;
        if ((double)coeff != scaled) {
            if (scaled > 0.0) {
                coeff++;
            } else {
                coeff--;
            }
            rounded = coeff;
        }
        coeff = (int)(rounded - -500.0f);
        if ((currentPlayer_Test->flags0 & swrObjTest_FLAG0_BOOSTING) != 0) {
            coeff = 9500;
        } else if ((float)coeff < 500.0f) {
            coeff = 500;
        } else {
            delta = swrControl_ffLastGForceCoeff - coeff;
            if (delta < 0) {
                delta = coeff - swrControl_ffLastGForceCoeff;
            }
            if (delta < 500) {
                coeff = swrControl_ffLastGForceCoeff;
            }
        }
        swrControl_ConfigureForceEffect(swrForceEffect_GFORCE, coeff);
        swrControl_ffLastGForceCoeff = coeff;
        if (swrControl_ffTractionRumbleActive == 0) {
            magnitude = (int)(((double)ratio - -1.0f) * 50.0f);
            delta = swrControl_ffLastRumbleMagnitude - magnitude;
            if (delta < 0) {
                delta = magnitude - swrControl_ffLastRumbleMagnitude;
            }
            if (delta < 10) {
                magnitude = swrControl_ffLastRumbleMagnitude;
            } else {
                swrControl_ffLastRumbleMagnitude = magnitude;
            }
            swrControl_PlayForceEffect(swrForceEffect_ENGINE_RUMBLE, magnitude, -1, -1);
        }
        swrControl_ffAppliedSpeedRatio = ratio;
    }
    swrControl_ffPrevSpeedRatio = ratio;
}

// 0x0040b5e0
void swrControl_UpdateImpactForceEffect(void)
{
    swrRace* player;
    int boosting;

    player = currentPlayer_Test;
    if ((player->flags1 & swrObjTest_FLAG1_BOOST_START) != 0) {
        swrControl_PlayForceEffect(swrForceEffect_TURBO_START, -1, -1, -1);
    } else {
        boosting = player->flags0 & swrObjTest_FLAG0_BOOSTING;
        if (boosting != 0 && swrControl_ffBoostActive == 0) {
            swrControl_PlayForceEffect(swrForceEffect_START_BOOST, -1, -1, -1);
            swrControl_ffBoostActive = 1;
        } else if (boosting == 0 && swrControl_ffBoostActive != 0) {
            swrControl_PlayForceEffect(swrForceEffect_END_BOOST, -1, -1, -1);
            swrControl_ffBoostActive = 0;
        }
    }
    player = currentPlayer_Test;
    if ((player->flags1 & swrObjTest_FLAG1_SLIDING) != 0 && swrControl_slideButton != 0.0f) {
        if ((player->flags1 & swrObjTest_FLAG1_AIRBORNE) == 0) {
            swrControl_PlayForceEffect(swrForceEffect_HEAVY_SLIDE_SLIP, -1, -1, -1);
        }
    } else if (swrControl_StopForceEffect(swrForceEffect_HEAVY_SLIDE_SLIP) != 0) {
        swrControl_ffGForceStarted = 0;
    }
    player = currentPlayer_Test;
    // fires when tilt leaves neutral or its truncated sign flips
    if (player->tiltManualMult != 0.0 && (swrControl_ffPrevTilt == 0.0 || ((int)swrControl_ffPrevTilt ^ (int)player->tiltManualMult) < 0)) {
        swrControl_PlayForceEffect(swrForceEffect_ROLL_LEFT, -1, player->tiltManualMult < 0.0f ? 90 : 270, -1);
    }
    swrControl_ffPrevTilt = currentPlayer_Test->tiltManualMult;
}

// 0x00405ea0
void swrControl_SetDefaultMappings(int device)
{
    int buttonLimit;
    int numPOVs;
    unsigned int axisMask;
    swrControlBinding* bindings;
    swrControlBinding* defaults;

    if (device == swrConfig_DEVICE_JOYSTICK) {
        buttonLimit = swrConfig_joystickNbButtons;
        axisMask = swrControl_joystickAxisMask;
        numPOVs = swrConfig_joystickNbPOVs;
        bindings = swrControl_bindingsJoystick;
        memset(swrControl_bindingsJoystick, 0, sizeof(swrControl_bindingsJoystick));
        Deadzone = swrControl_defaultDeadzone;
        memcpy(swrControl_joystickFlipAxis, swrControl_defaultJoystickFlipAxis, sizeof(swrControl_joystickFlipAxis));
        defaults = swrControl_defaultBindingsJoystick;
        if (numPOVs != 0 && buttonLimit > 4) {
            buttonLimit = SWR_CONTROL_DEFAULT_BUTTONS_WITH_POV;
        }
    } else if (device == swrConfig_DEVICE_MOUSE) {
        numPOVs = 0;
        buttonLimit = swrConfig_mouseNbButtons;
        axisMask = swrControl_mouseAxisMask;
        bindings = swrControl_bindingsMouse;
        memset(swrControl_bindingsMouse, 0, sizeof(swrControl_bindingsMouse));
        flip_x_axis = swrControl_defaultMouseFlipAxis[0];
        flip_y_axis = swrControl_defaultMouseFlipAxis[1];
        flip_z_axis = swrControl_defaultMouseFlipAxis[2];
        defaults = swrControl_defaultBindingsMouse;
    } else if (device == swrConfig_DEVICE_KEYBOARD) {
        numPOVs = 0;
        axisMask = 0;
        bindings = swrControl_bindingsKeyboard;
        defaults = swrControl_defaultBindingsKeyboard;
        buttonLimit = STDCONTROL_NUM_KEYBOARD_KEYS;
        memset(swrControl_bindingsKeyboard, 0, sizeof(swrControl_bindingsKeyboard));
    } else {
        // the EXE walks `device` itself as the default table here and crashes; never reached
        return;
    }
    swrControl_bindingCounts[device] = 0;
    swrControl_axisSensitivity[device] = 1.0f;
    for (; defaults->flags != SWR_CONTROL_BINDING_END; defaults++) {
        if (((defaults->flags & swrControlBinding_FLAG_BUTTON) != 0 && defaults->input < buttonLimit) || ((defaults->flags & swrControlBinding_FLAG_BUTTON) != 0 && defaults->input >= STDCONTROL_JOYSTICK_POV_KEY_BASE && defaults->input <= numPOVs * STDCONTROL_KEYS_PER_POV + (STDCONTROL_JOYSTICK_POV_KEY_BASE - 1)) || ((defaults->flags & swrControlBinding_FLAG_AXIS) != 0 && (axisMask & (1 << defaults->input)) != 0)) {
            bindings[swrControl_bindingCounts[device]] = *defaults;
            swrControl_bindingCounts[device]++;
        }
    }
    bindings[swrControl_bindingCounts[device]].flags = SWR_CONTROL_BINDING_END;
}

// 0x00407800
void swrControl_ClearBindings(int deviceFilter)
{
    swrRace_ThrottleInput = 0.0f;
    swrRace_UnkInput = 0.0f;
    swrRace_SteeringInput = 0.0f;
    memset(&swrControl_viewButton, 0, SWR_CONTROL_NUM_ACTIONS * sizeof(float));
    swrRace_PitchInput = 0.0f;
    memset(&swrControl_viewHoldTime, 0, SWR_CONTROL_NUM_ACTIONS * sizeof(float));
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_JOYSTICK) {
        memset(swrControl_bindingsJoystick, 0, sizeof(swrControl_bindingsJoystick));
    }
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_MOUSE) {
        memset(swrControl_bindingsMouse, 0, sizeof(swrControl_bindingsMouse));
    }
    if (deviceFilter < 0 || deviceFilter == swrConfig_DEVICE_KEYBOARD) {
        memset(swrControl_bindingsKeyboard, 0, sizeof(swrControl_bindingsKeyboard));
    }
    if (deviceFilter < 0) {
        swrControl_bindingCounts[swrConfig_DEVICE_JOYSTICK] = 0;
        swrControl_bindingCounts[swrConfig_DEVICE_MOUSE] = 0;
        swrControl_bindingCounts[swrConfig_DEVICE_KEYBOARD] = 0;
        return;
    }
    swrControl_bindingCounts[deviceFilter] = 0;
}

// 0x00407d90
char* swrControl_FindKeyName(int id, char otherId)
{
    int i;

    for (i = 0; keyMapping2_0[i].id != -1; i++) {
        if (keyMapping2_0[i].id == id && (char)keyMapping2_0[i].otherId == otherId) {
            return keyMapping2_0[i].name;
        }
    }
    return NULL;
}

// 0x00407f80
int swrControl_PollCancel(int excludeDevice)
{
    int joystick;
    int mouse;
    int keyboard;
    float wheelButton;

    if (excludeDevice == swrConfig_DEVICE_JOYSTICK) {
        joystick = 0;
    } else {
        joystick = stdControl_ReadKey(STDCONTROL_JOYSTICK_KEY_BASE + stdControl_joystickDeviceIndex * STDCONTROL_KEYS_PER_JOYSTICK + 1, NULL);
    }
    if (excludeDevice == swrConfig_DEVICE_MOUSE) {
        mouse = 0;
    } else {
        mouse = stdControl_ReadKey(STDCONTROL_MOUSE_KEY_BASE + 1, NULL);
    }
    if (excludeDevice == swrConfig_DEVICE_KEYBOARD) {
        keyboard = 0;
    } else {
        keyboard = stdControl_ReadKey(DIK_ESCAPE, NULL);
    }
    // a wheel's brake button also cancels unless the joystick is excluded
    wheelButton = 0.0f;
    if (cifr_deviceIsWheel != 0 && excludeDevice != swrConfig_DEVICE_JOYSTICK) {
        wheelButton = JoystickButtonPressedInput[SWR_CONTROL_ACTION_BRAKE];
    }
    if (joystick == 0 && mouse == 0 && keyboard == 0 && (int)wheelButton == 0) {
        return 0;
    }
    return 1;
}
