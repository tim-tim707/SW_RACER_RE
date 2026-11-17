#include "cifr.h"

#include "globals.h"

#include "macros.h"

// 0x00403e10
void cifr_Init(void* effects)
{
    HANG("TODO");
}

// 0x00403f00
void cifr_ReinitEffects_Maybe(void* controller)
{
    HANG("TODO");
}

// 0x00403f30
int cifr_LoadProjectFile(void* effects, char* projectFile, void* nameIndices, void* nameTable)
{
    HANG("TODO");
    return 0;
}

// 0x00403fd0
int cifr_LoadAllEffects(void* controller)
{
    HANG("TODO");
    return 0;
}

// 0x004040a0
int cifr_CreateEffect(void* effect, void* params, void* device)
{
    HANG("TODO");
    return 0;
}

// 0x004041c0
int cifr_StartEffect(cifr_Effect* effect, int restart)
{
    int i;
    IDirectInputEffect* iface;

    if (swrConfig_FORCE_ENABLED != 0 && cifr_device != NULL && effect->interfaces != NULL) {
        if (restart == 0 && cifr_IsPlaying(effect) != 0) {
            return 0;
        }
        for (i = 0; i < effect->numInterfaces; i++) {
            iface = effect->interfaces[i];
            if (iface->lpVtbl->Start(iface, 1, 0) < 0) {
                return -1;
            }
        }
        return 1;
    }
    return -1;
}

// 0x00404230
int cifr_StopEffect(cifr_Effect* effect)
{
    int i;
    IDirectInputEffect* iface;

    if (swrConfig_FORCE_ENABLED != 0 && effect != NULL && effect->interfaces != NULL) {
        for (i = 0; i < effect->numInterfaces; i++) {
            iface = effect->interfaces[i];
            if (iface->lpVtbl->Stop(iface) < 0) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

// 0x00404280
int cifr_IsPlaying(cifr_Effect* effect)
{
    int i;
    DWORD status;
    IDirectInputEffect* iface;

    if (swrConfig_FORCE_ENABLED != 0 && cifr_device != NULL && effect->interfaces != NULL) {
        for (i = 0; i < effect->numInterfaces; i++) {
            iface = effect->interfaces[i];
            if (iface->lpVtbl->GetEffectStatus(iface, &status) < 0) {
                return 0;
            }
            if ((status & DIEGES_PLAYING) != 0) {
                return 1;
            }
        }
    }
    return 0;
}

// 0x004042f0
int cifr_GetDirection(cifr_Effect* effect)
{
    if (swrConfig_FORCE_ENABLED == 0) {
        return -1;
    }
    if (effect->interfaces == NULL) {
        return -1;
    }
    return effect->params.rglDirection[0] / 100;
}

// 0x00404330
int cifr_SetDirection(cifr_Effect* effect, int degrees, int start)
{
    int i;
    IDirectInputEffect* iface;

    if (swrConfig_FORCE_ENABLED != 0 && effect->interfaces != NULL && degrees >= 0 && degrees <= 360) {
        if (cifr_GetDirection(effect) == degrees) {
            return 2;
        }
        effect->params.rglDirection[0] = degrees * 100;
        for (i = 0; i < effect->numInterfaces; i++) {
            iface = effect->interfaces[i];
            if (iface->lpVtbl->SetParameters(iface, (LPCDIEFFECT)&effect->params, (start ? DIEP_START : DIEP_NORESTART) | DIEP_DIRECTION) < 0) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

// 0x004043d0
unsigned int cifr_GetMagnitude(cifr_Effect* effect)
{
    if (swrConfig_FORCE_ENABLED == 0) {
        return 0xffffffff;
    }
    if (effect->interfaces == NULL) {
        return 0xffffffff;
    }
    return effect->params.dwGain / 100;
}

// 0x00404400
int cifr_SetMagnitude(cifr_Effect* effect, int percent, int start)
{
    int i;
    IDirectInputEffect* iface;

    if (swrConfig_FORCE_ENABLED != 0 && effect->interfaces != NULL && percent >= 0 && percent <= 100) {
        if (cifr_GetMagnitude(effect) == (unsigned int)percent) {
            return 2;
        }
        effect->params.dwGain = percent * 100;
        for (i = 0; i < effect->numInterfaces; i++) {
            iface = effect->interfaces[i];
            if (iface->lpVtbl->SetParameters(iface, (LPCDIEFFECT)&effect->params, (start ? DIEP_START : DIEP_NORESTART) | DIEP_GAIN) < 0) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

// 0x004044a0
int cifr_GetDuration(cifr_Effect* effect)
{
    if (swrConfig_FORCE_ENABLED == 0) {
        return -1;
    }
    if (effect->interfaces == NULL) {
        return -1;
    }
    if (effect->params.dwDuration == 0xffffffff) {
        return -1;
    }
    return effect->params.dwDuration / 1000;
}

// 0x004044e0
int cifr_SetDuration(cifr_Effect* effect, int durationMs, int start)
{
    int i;
    int durationUs;
    IDirectInputEffect* iface;

    durationUs = durationMs == -1 ? -1 : durationMs * 1000;
    if (swrConfig_FORCE_ENABLED == 0) {
        return 0;
    }
    if (effect->interfaces == NULL) {
        return 0;
    }
    if (cifr_GetDuration(effect) == durationMs) {
        return 2;
    }
    effect->params.dwDuration = durationUs;
    for (i = 0; i < effect->numInterfaces; i++) {
        iface = effect->interfaces[i];
        if (iface->lpVtbl->SetParameters(iface, (LPCDIEFFECT)&effect->params, (start ? DIEP_START : DIEP_NORESTART) | DIEP_DURATION) < 0) {
            return 0;
        }
    }
    return 1;
}

// 0x00404590
int cifr_SetCustomForceData_Maybe(void* effect, unsigned int size, void* data, int deferred)
{
    HANG("TODO");
    return 0;
}

// 0x00404670
int cifr_GetForceFeedbackState_Maybe(void* effect, char* outState)
{
    HANG("TODO");
    return 0;
}
