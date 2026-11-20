#include "cifr.h"

#include "globals.h"
#include "engine_config.h"

#include <string.h>

// 0x00403e10
void cifr_Init(cifr_EffectSet* effects)
{
    int i;
    int device;
    cifr_Effect* effect;

    if (swrConfig_FORCE_ENABLED == 0) {
        return;
    }
    effects->unk0[0] = 0;
    effects->project = NULL;
    effects->unk44 = 0;
    for (i = 0; i < SWR_FF_EFFECT_SLOTS; i++) {
        effect = &effects->slots[i];
        effect->effectId = -1;
        effect->name[0] = '\0';
        effect->lastEffectId = 0xffffffff;
        effect->numInterfaces = 0;
        effect->interfaces = NULL;
        effect->typeSpecificBuffer = NULL;
        cifr_ResetEffectParams(effect);
    }
    device = stdControl_joystickDeviceIndex;
    cifr_device = (&stdControlJoystickDevice)[device * STDCONTROL_JOYSTICK_RECORD_DWORDS];
    // cifr_deviceIsWheel is only ever set, never cleared; faithful
    if ((&stdControlJoystickSubType)[device * STDCONTROL_JOYSTICK_RECORD_SIZE] == DIDEVTYPEJOYSTICK_WHEEL) {
        cifr_deviceIsWheel = 1;
    } else if (strstr(strlwr(stdControlJoystickProductName + device * STDCONTROL_JOYSTICK_RECORD_SIZE), "wheel") != NULL) {
        cifr_deviceIsWheel = 1;
    }
    if (((&stdControlJoystickCapsFlags)[stdControl_joystickDeviceIndex * STDCONTROL_JOYSTICK_RECORD_DWORDS] & DIDC_FORCEFEEDBACK) == 0) {
        swrControl_forceFeedbackAvailable = 0;
        swrConfig_FORCE_ENABLED = 0;
    }
}

// 0x00403f00
void cifr_ReinitEffects(cifr_EffectSet* effects)
{
    if (swrConfig_FORCE_ENABLED == 0) {
        return;
    }
    cifr_ReleaseAllEffects(effects);
    if (effects->project != NULL) {
        cifr_IFReleaseProject(effects->project);
    }
    cifr_Init(effects);
}

// 0x00403f30
int cifr_LoadProjectFile(cifr_EffectSet* effects, char* projectFile, int* slotLastIds, char** names)
{
    int i;
    int effectId;
    char* name;
    cifr_Effect* effect;

    if (swrConfig_FORCE_ENABLED == 0) {
        return 0;
    }
    effects->project = cifr_IFLoadProjectFile(projectFile, (LPDIRECTINPUTDEVICE2A)cifr_device);
    if (effects->project == NULL) {
        return -1;
    }
    for (i = 0; i < SWR_FF_EFFECT_SLOTS; i++) {
        effect = &effects->slots[i];
        effectId = 0;
        if (i > 0) {
            effectId = slotLastIds[i - 1] + 1;
        }
        effect->effectId = effectId;
        name = names[effectId];
        memcpy(effect->name, name, strlen(name) + 1);
        effect->lastEffectId = slotLastIds[i];
    }
    return SWR_FF_EFFECT_SLOTS;
}

// 0x00403fd0
int cifr_LoadAllEffects(cifr_EffectSet* effects)
{
    int i;
    int created;
    cifr_Effect* effect;

    created = 0;
    if (swrConfig_FORCE_ENABLED == 0) {
        return 0;
    }
    if (cifr_device == NULL || effects->project == NULL) {
        return -1;
    }
    for (i = 0; i < SWR_FF_EFFECT_SLOTS; i++) {
        effect = &effects->slots[i];
        if (cifr_CreateEffect(effect, effect->name, effects->project) != 0) {
            created++;
        }
    }
    if (created == 0) {
        return -1;
    }
    return created;
}

// 0x00404040
int cifr_ReleaseAllEffects(cifr_EffectSet* effects)
{
    int i;
    int released;

    released = 0;
    if (swrConfig_FORCE_ENABLED == 0) {
        return 0;
    }
    if (cifr_device == NULL || effects->project == NULL) {
        return -1;
    }
    for (i = 0; i < SWR_FF_EFFECT_SLOTS; i++) {
        if (cifr_ReleaseEffect(&effects->slots[i], effects->project) != 0) {
            released++;
        }
    }
    return released;
}

// 0x004040a0
int cifr_CreateEffect(cifr_Effect* effect, char* name, HIFORCEPROJECT project)
{
    int i;
    DWORD size;
    HRESULT result;
    IDirectInputEffect* iface;

    if (swrConfig_FORCE_ENABLED == 0 || effect == NULL) {
        return 0;
    }
    if (effect->interfaces != NULL) {
        cifr_ReleaseEffect(effect, project);
    }
    effect->interfaces = cifr_IFCreateEffects(project, name, &effect->numInterfaces);
    if (effect->interfaces == NULL) {
        return 0;
    }
    for (i = 0; i < effect->numInterfaces; i++) {
        cifr_ResetEffectParams(effect);
        iface = effect->interfaces[i];
        result = iface->lpVtbl->GetParameters(iface, (LPDIEFFECT)&effect->params, DIEP_ALLPARAMS_DX5);
        if (result == DIERR_MOREDATA) {
            size = effect->params.cbTypeSpecificParams;
            cifr_ResetEffectParams(effect);
            effect->typeSpecificBuffer = (*stdPlatform_hostServices_ptr->alloc)(size);
            effect->params.lpvTypeSpecificParams = effect->typeSpecificBuffer;
            effect->params.cbTypeSpecificParams = size;
            iface = effect->interfaces[i];
            result = iface->lpVtbl->GetParameters(iface, (LPDIEFFECT)&effect->params, DIEP_ALLPARAMS_DX5);
        }
        if (result != 0) {
            cifr_IFReleaseEffects(project, effect->interfaces);
            effect->interfaces = NULL;
            return 0;
        }
    }
    return 1;
}

// 0x00404190
int cifr_ReleaseEffect(cifr_Effect* effect, HIFORCEPROJECT project)
{
    int result;

    if (swrConfig_FORCE_ENABLED == 0) {
        return 0;
    }
    if (effect->interfaces == NULL) {
        return 0;
    }
    result = cifr_IFReleaseEffects(project, effect->interfaces);
    effect->interfaces = NULL;
    return result;
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
int cifr_SetTypeSpecificParams(cifr_Effect* effect, unsigned int size, void* data, int start)
{
    IDirectInputEffect* iface;

    if (swrConfig_FORCE_ENABLED == 0) {
        return 0;
    }
    if (effect->interfaces == NULL) {
        return 0;
    }
    (*stdPlatform_hostServices_ptr->free)(effect->typeSpecificBuffer);
    effect->typeSpecificBuffer = (*stdPlatform_hostServices_ptr->alloc)(size);
    memcpy(effect->typeSpecificBuffer, data, size);
    effect->params.cbTypeSpecificParams = size;
    effect->params.lpvTypeSpecificParams = effect->typeSpecificBuffer;
    // only the first interface is updated; faithful
    iface = effect->interfaces[0];
    return iface->lpVtbl->SetParameters(iface, (LPCDIEFFECT)&effect->params, (start ? DIEP_START : DIEP_NORESTART) | DIEP_TYPESPECIFICPARAMS) >= 0;
}

// 0x00404640
int cifr_GetEffectGuid(cifr_Effect* effect, GUID* outGuid)
{
    IDirectInputEffect* iface;

    if (swrConfig_FORCE_ENABLED == 0) {
        return 0;
    }
    if (effect->interfaces == NULL) {
        return 0;
    }
    iface = effect->interfaces[0];
    return iface->lpVtbl->GetEffectGuid(iface, outGuid) >= 0;
}

// 0x00404670
int cifr_GetEffectType(cifr_Effect* effect, char* outEffType)
{
    GUID guid;
    DIEFFECTINFOA info;
    LPDIRECTINPUTDEVICE2A device;

    if (cifr_GetEffectGuid(effect, &guid) == 0) {
        return 0;
    }
    device = (LPDIRECTINPUTDEVICE2A)cifr_device;
    info.dwSize = sizeof(DIEFFECTINFOA);
    if (device->lpVtbl->GetEffectInfo(device, &info, &guid) < 0) {
        return 0;
    }
    *outEffType = (char)info.dwEffType;
    return 1;
}

// 0x004046e0
void cifr_ResetEffectParams(cifr_Effect* effect)
{
    memset(&effect->params, 0, sizeof(effect->params));
    effect->params.lpEnvelope = &effect->envelope;
    effect->params.rglDirection = effect->directions;
    effect->params.rgdwAxes = effect->axes;
    effect->params.dwSize = sizeof(DIEFFECT_DX5);
    effect->params.dwFlags = DIEFF_SPHERICAL | DIEFF_POLAR | DIEFF_CARTESIAN | DIEFF_OBJECTIDS;
    effect->params.cAxes = sizeof(effect->axes) / sizeof(effect->axes[0]);
    memset(&effect->envelope, 0, sizeof(effect->envelope));
    effect->envelope.dwSize = sizeof(DIENVELOPE);
    if (effect->typeSpecificBuffer != NULL) {
        (*stdPlatform_hostServices_ptr->free)(effect->typeSpecificBuffer);
        effect->typeSpecificBuffer = NULL;
    }
}
