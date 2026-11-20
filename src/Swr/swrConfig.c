#include "swrConfig.h"

#include <General/stdConffile.h>
#include <General/stdFileUtil.h>
#include <General/stdFnames.h>
#include <General/stdString.h>
#include <Main/swrControl.h>
#include <Platform/wuRegistry.h>

#include "globals.h"
#include "macros.h"
#include <engine_config.h>

#include "swrSound.h"

#include <Swr/swrText.h>
#include <Swr/swrUI.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 0x00406080
int swrConfig_WriteMappings(char* dirname)
{
    char path[256];
    char deviceText[32];
    char bindText[32];
    char rangeText[32];
    char functionText[32];
    swrControlBinding* binding;
    int* flipTable;
    char* name;
    unsigned char flags;
    int axisCount;
    int enabled;
    int device;
    int i;

    sprintf(path, "%s%s\\%s_%s", ".\\data\\config\\", dirname, dirname, "control.map");
    if (stdConffile_OpenWrite(path) == 0) {
        stdConffile_CloseWrite();
        return -1;
    }
    flipTable = NULL;
    binding = NULL;
    bindText[0] = '\0';
    for (device = swrConfig_DEVICE_JOYSTICK; device <= swrConfig_DEVICE_KEYBOARD; device++) {
        if (device == swrConfig_DEVICE_JOYSTICK) {
            binding = swrControl_bindingsJoystick;
            axisCount = STDCONTROL_AXES_PER_JOYSTICK;
            flipTable = swrControl_joystickFlipAxis;
            enabled = swrConfig_joystick_enabled;
            sprintf(deviceText, "JOYSTICK");
        } else if (device == swrConfig_DEVICE_MOUSE) {
            binding = swrControl_bindingsMouse;
            axisCount = STDCONTROL_MOUSE_NUM_AXES;
            // flip_x/y/z_axis are consecutive: the mouse flip table
            flipTable = &flip_x_axis;
            enabled = swrConfig_mouse_enabled;
            sprintf(deviceText, "MOUSE");
        } else {
            binding = swrControl_bindingsKeyboard;
            axisCount = 0;
            enabled = swrConfig_keyboard_enabled;
            sprintf(deviceText, "KEYBOARD");
        }
        swrConfig_Printf("\n\n####### %s MAPPINGS\n\n", deviceText);
        // bindText is not reset per binding: a binding with neither BUTTON nor AXIS reuses the previous one
        for (; binding->flags != SWR_CONTROL_BINDING_END; binding++) {
            flags = binding->flags;
            sprintf(rangeText, wuRegistry_lpClass);
            if ((flags & swrControlBinding_FLAG_BUTTON) != 0 && device != swrConfig_DEVICE_KEYBOARD) {
                name = stdString_RemoveTEXTTag(swrConfig_ControlToString(binding->input, keyMapping1));
                sprintf(bindText, "BUTTON=%s", name);
            } else if ((flags & swrControlBinding_FLAG_BUTTON) != 0 && device == swrConfig_DEVICE_KEYBOARD) {
                name = stdString_RemoveTEXTTag(swrConfig_ControlToString(binding->input, keyMapping2));
                sprintf(bindText, "KEY=%s", name);
            } else if ((flags & swrControlBinding_FLAG_AXIS) != 0) {
                name = stdString_RemoveTEXTTag(swrConfig_ControlToString(binding->input, keyMapping0));
                sprintf(bindText, "AXIS=%s", name);
                if ((flags & swrControlBinding_FLAG_POSITIVE) != 0) {
                    sprintf(rangeText, "AXIS_RANGE=POSITIVE");
                } else if ((flags & swrControlBinding_FLAG_NEGATIVE) != 0) {
                    sprintf(rangeText, "AXIS_RANGE=NEGATIVE");
                }
            }
            if ((flags & swrControlBinding_FLAG_BUTTON) == 0) {
                flags &= ~(swrControlBinding_FLAG_POSITIVE | swrControlBinding_FLAG_NEGATIVE);
            }
            flags &= ~(swrControlBinding_FLAG_AXIS | swrControlBinding_FLAG_BUTTON);
            name = stdString_RemoveTEXTTag(swrControl_FindKeyName(binding->action, flags));
            if (name != NULL) {
                sprintf(functionText, "FUNCTION=%s", name);
                if (swrConfig_Printf("%-28s%-28s%-28s%-28s\n", deviceText, bindText, functionText, rangeText) != 0) {
                    stdConffile_CloseWrite();
                    return 0;
                }
            }
        }
        swrConfig_Printf("\n");
        for (i = 0; i < axisCount; i++) {
            if (flipTable[i] != 0) {
                name = stdString_RemoveTEXTTag(swrConfig_ControlToString(i, keyMapping0));
                sprintf(bindText, "AXIS=%s", name);
                swrConfig_Printf("%-28s%-28sFLIP_AXIS\n", deviceText, bindText);
            }
        }
        if (device < swrConfig_DEVICE_KEYBOARD && swrControl_axisSensitivity[device] != 1.0f) {
            sprintf(bindText, "SENSITIVITY=%0.2f", swrControl_axisSensitivity[device]);
            swrConfig_Printf("%-28s%-28s\n", deviceText, bindText);
        }
        if (device == swrConfig_DEVICE_JOYSTICK && Deadzone != swrControl_defaultDeadzone) {
            sprintf(bindText, "DEADZONE=%0.2f", Deadzone);
            swrConfig_Printf("%-28s%-28s\n", deviceText, bindText);
        }
        sprintf(bindText, enabled != 0 ? "ENABLED=TRUE" : "ENABLED=FALSE");
        swrConfig_Printf("%-28s%-28s\n", deviceText, bindText);
    }
    swrConfig_Puts("\nend.\n");
    stdConffile_CloseWrite();
    return 1;
}

// 0x00407b00
char* swrConfig_ControlToString(unsigned int controlId, keyMapping* table)
{
    char* name;
    int i;

    if (table != NULL) {
        for (i = 0; table[i].id != -1; i++) {
            if (table[i].id == (int)controlId) {
                return table[i].name;
            }
        }
        return NULL;
    }

    switch (controlId) {
    case DIK_EQUALS:
        sprintf(swrText_keyNameText, "+");
        return swrText_keyNameText;
    case DIK_LCONTROL:
        name = "/MONDOTEXT_H_0231/LEFT CTRL";
        break;
    case DIK_GRAVE:
        name = "/MONDOTEXT_H_0233/TILDE";
        break;
    case DIK_LSHIFT:
        name = "/MONDOTEXT_H_0232/LEFT SHIFT";
        break;
    case DIK_LMENU:
        name = "/MONDOTEXT_H_0230/LEFT ALT";
        break;
    case DIK_SCROLL:
        name = "/MONDOTEXT_H_0543/SCR-LOCK";
        break;
    // GetKeyNameText swaps these two: Num Lock is extended, Pause is not.
    case DIK_NUMLOCK:
        controlId = DIK_PAUSE;
        // fallthrough
    default:
        GetKeyNameTextA((((controlId & SWR_DIK_EXTENDED_BIT) << 1) | (controlId & SWR_DIK_SCANCODE_MASK)) << 16, swrText_keyNameText, sizeof(swrText_keyNameText));
        return swrText_keyNameText;
    case DIK_PAUSE:
        controlId = DIK_NUMLOCK;
        GetKeyNameTextA((((controlId & SWR_DIK_EXTENDED_BIT) << 1) | (controlId & SWR_DIK_SCANCODE_MASK)) << 16, swrText_keyNameText, sizeof(swrText_keyNameText));
        return swrText_keyNameText;
    }
    sprintf(swrText_keyNameText, swrText_Translate(name));
    return swrText_keyNameText;
}

// 0x00408820
void swrConfig_SetDefaultVideo(void)
{
    // TODO prettify
    int iVar1;
    int* piVar2;
    int* piVar3;
    int lensflare;

    lensflare = swrConfig_defaultVideoConfig[4];
    piVar2 = swrConfig_defaultVideoConfig;
    piVar3 = &swrConfig_VIDEO_REFLECTIONS;
    for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1)
    {
        *piVar3 = *piVar2;
        piVar2 = piVar2 + 1;
        piVar3 = piVar3 + 1;
    }
    if ((lensflare == 0) || (swrConfig_VIDEO_LENSFLARE = 1, direct3d_LensFlareCompatible == 0))
    {
        swrConfig_VIDEO_LENSFLARE = 0;
    }
    if ((swrConfig_VIDEO_ENGINEEXHAUST == 0) || (swrConfig_VIDEO_ENGINEEXHAUST = 1, direct3d_LensFlareCompatible == 0))
    {
        swrConfig_VIDEO_ENGINEEXHAUST = 0;
    }
}

// 0x00408880
int swrConfig_WriteVideoConfig(char* dirname)
{
    int open_status;
    size_t printf_status;
    char* str_bool;
    char config_name[32];
    char prefix[32];
    char pathname[256];

    sprintf(pathname, "%s%s\\%s", ".\\data\\config\\", dirname, "video.cfg");
    open_status = stdConffile_OpenWrite(pathname);
    if (open_status == 0)
    {
        stdConffile_CloseWrite();
        return 0xffffffff;
    }
    sprintf(prefix, "VIDEO");
    printf_status = swrConfig_Printf("\n\n####### %s SETTINGS\n\n", prefix);
    if (printf_status == 0)
    {
        str_bool = "ON";
        if (swrConfig_VIDEO_REFLECTIONS == 0)
        {
            str_bool = "OFF";
        }
        sprintf(config_name, "REFLECTIONS=%s", str_bool);
        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
        if (printf_status == 0)
        {
            str_bool = "ON";
            if (swrConfig_VIDEO_ZEFFECTS == 0)
            {
                str_bool = "OFF";
            }
            sprintf(config_name, "ZEFFECTS=%s", str_bool);
            printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
            if (printf_status == 0)
            {
                str_bool = "ON";
                if (swrConfig_VIDEO_DYNAMIC_LIGHTING == 0)
                {
                    str_bool = "OFF";
                }
                sprintf(config_name, "DYNAMIC_LIGHTING=%s", str_bool);
                printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                if (printf_status == 0)
                {
                    str_bool = "ON";
                    if (swrConfig_VIDEO_VSYNC == 0)
                    {
                        str_bool = "OFF";
                    }
                    sprintf(config_name, "VSYNC=%s", str_bool);
                    printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                    if (printf_status == 0)
                    {
                        str_bool = "ON";
                        if (swrConfig_VIDEO_LENSFLARE == 0)
                        {
                            str_bool = "OFF";
                        }
                        sprintf(config_name, "LENSFLARE=%s", str_bool);
                        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                        if (printf_status == 0)
                        {
                            str_bool = "ON";
                            if (swrConfig_VIDEO_ENGINEEXHAUST == 0)
                            {
                                str_bool = "OFF";
                            }
                            sprintf(config_name, "ENGINEEXHAUST=%s", str_bool);
                            printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                            if (printf_status == 0)
                            {
                                sprintf(config_name, "TEXTURE_RES=%i", swrConfig_VIDEO_TEXTURE_RES);
                                printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                if (printf_status == 0)
                                {
                                    sprintf(config_name, "MODEL_DETAIL=%i", swrConfig_VIDEO_MODEL_DETAIL);
                                    printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                    if (printf_status == 0)
                                    {
                                        sprintf(config_name, "DRAWDISTANCE=%i", swrConfig_VIDEO_DRAWDISTANCE);
                                        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                        if (printf_status == 0)
                                        {
                                            printf_status = swrConfig_Puts("\nend.\n");
                                            if (printf_status == 0)
                                            {
                                                stdConffile_CloseWrite();
                                                return 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    stdConffile_CloseWrite();
    return 0;
}

// 0x00408b60
int swrConfig_ReadVideoConfig(char* config_type)
{
    char pathname[256];

    sprintf(pathname, "%s%s\\%s", ".\\data\\config\\", config_type, "video.cfg");
    if (stdConffile_Open(pathname) == 0) {
        stdConffile_Close();
        return -1;
    }

    while (stdConffile_ReadArgs() != 0) {
        if (strcmp(stdConffile_g_entry.aArgs[0].argName, "end.") == 0)
            break;

        if (strcmpi(stdConffile_g_entry.aArgs[0].argName, "VIDEO") == 0) {
            char* name = stdConffile_g_entry.aArgs[1].argName;
            char* value = stdConffile_g_entry.aArgs[1].argValue;

            if (strcmpi(name, "REFLECTIONS") == 0) {
                swrConfig_VIDEO_REFLECTIONS = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "ZEFFECTS") == 0) {
                swrConfig_VIDEO_ZEFFECTS = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "DYNAMIC_LIGHTING") == 0) {
                swrConfig_VIDEO_DYNAMIC_LIGHTING = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "VSYNC") == 0) {
                swrConfig_VIDEO_VSYNC = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "LENSFLARE") == 0) {
                swrConfig_VIDEO_LENSFLARE = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "ENGINEEXHAUST") == 0) {
                swrConfig_VIDEO_ENGINEEXHAUST = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "TEXTURE_RES") == 0) {
                swrConfig_VIDEO_TEXTURE_RES = atoi(value);
            } else if (strcmpi(name, "MODEL_DETAIL") == 0) {
                swrConfig_VIDEO_MODEL_DETAIL = atoi(value);
            } else if (strcmpi(name, "DRAWDISTANCE") == 0) {
                swrConfig_VIDEO_DRAWDISTANCE = atoi(value);
            } else {
                stdConffile_Close();
                return 0;
            }
        }
    }

    stdConffile_Close();
    return 1;
}

// Force option level -> effect gain (0 = off)
static float forceLevelGain(int level)
{
    if (level == 0) {
        return -1.0f;
    }
    if (level == 1) {
        return 0.6f;
    }
    if (level == 2) {
        return 0.8f;
    }
    return 1.0f;
}

// 0x0040a680
void swrConfig_AssignForceValues(void)
{
    memset(swrControl_forceEffectSettings, 0, sizeof(swrControl_forceEffectSettings));
    swrControl_forceStrength = forceLevelGain(swrConfig_FORCE_STRENGTH);
    swrControl_forceEffectSettings[swrForceEffect_AUTO_CENTER].gain = forceLevelGain(swrConfig_FORCE_AUTOCENTER);
    swrControl_forceEffectSettings[swrForceEffect_GFORCE].gain = swrConfig_FORCE_GFORCES != 0 ? 1.0f : -1.0f;
    swrControl_forceEffectSettings[swrForceEffect_ENGINE_RUMBLE].gain = swrConfig_FORCE_ENGINERUMBLE != 0 ? 1.0f : -1.0f;

    swrControl_forceEffectSettings[swrForceEffect_HARD_LANDING].gain = forceLevelGain(swrConfig_FORCE_COLLISIONS);
    swrControl_forceEffectSettings[swrForceEffect_OBJ_COLLISION].gain = forceLevelGain(swrConfig_FORCE_COLLISIONS);

    swrControl_forceEffectSettings[swrForceEffect_ACCELERATION3].gain = forceLevelGain(swrConfig_FORCE_PODACTIONS);
    swrControl_forceEffectSettings[swrForceEffect_ACCELERATION3_B].gain = forceLevelGain(swrConfig_FORCE_PODACTIONS);
    swrControl_forceEffectSettings[swrForceEffect_START_BOOST].gain = forceLevelGain(swrConfig_FORCE_PODACTIONS);
    swrControl_forceEffectSettings[swrForceEffect_END_BOOST].gain = forceLevelGain(swrConfig_FORCE_PODACTIONS);
    swrControl_forceEffectSettings[swrForceEffect_ROLL_LEFT].gain = forceLevelGain(swrConfig_FORCE_PODACTIONS);
    swrControl_forceEffectSettings[swrForceEffect_REPAIR].gain = forceLevelGain(swrConfig_FORCE_PODACTIONS);
    swrControl_forceEffectSettings[swrForceEffect_HEAVY_SLIDE_SLIP].gain = forceLevelGain(swrConfig_FORCE_PODACTIONS);
    swrControl_forceEffectSettings[swrForceEffect_TURBO_START].gain = forceLevelGain(swrConfig_FORCE_PODACTIONS);

    swrControl_forceEffectSettings[swrForceEffect_SWAMP_MUCK].gain = forceLevelGain(swrConfig_FORCE_TERRAIN);

    swrControl_forceEffectSettings[swrForceEffect_CRASHING].gain = forceLevelGain(swrConfig_FORCE_DAMAGE);
    swrControl_forceEffectSettings[swrForceEffect_EXPLODING].gain = forceLevelGain(swrConfig_FORCE_DAMAGE);
    swrControl_forceEffectSettings[swrForceEffect_ENGINE_PULL_LEFT].gain = forceLevelGain(swrConfig_FORCE_DAMAGE);
    swrControl_forceEffectSettings[swrForceEffect_ENGINE_BLOWOUT_LEFT].gain = forceLevelGain(swrConfig_FORCE_DAMAGE);
    swrControl_forceEffectSettings[swrForceEffect_ENGINE_FIRE_LEFT].gain = forceLevelGain(swrConfig_FORCE_DAMAGE);

    // not tied to any option
    swrControl_forceEffectSettings[swrForceEffect_AIR_SLIDE].gain = 1.0f;
    swrControl_forceEffectSettings[swrForceEffect_ICE_SLIDE].gain = 1.0f;
    swrControl_forceEffectSettings[swrForceEffect_PIT_BOB].gain = 1.0f;
    swrControl_forceEffectSettings[swrForceEffect_ENEMY_FIRE2].gain = 1.0f;
    swrControl_forceEffectSettings[swrForceEffect_POD_WAKE].gain = 1.0f;
    swrControl_forceEffectSettings[swrForceEffect_SHOCKWAVE].gain = 1.0f;
    swrControl_forceEffectSettings[swrForceEffect_SECONDARY_WEAPON].gain = 1.0f;
    swrControl_forceEffectSettings[swrForceEffect_ACTIVATE_TOW].gain = 1.0f;
    swrControl_forceEffectSettings[swrForceEffect_RELEASE_TOW].gain = 1.0f;
}

// 0x0040ab60
void swrConfig_SetDefaultForce(void)
{
    int count;
    int* src;
    int* dst;

    src = swrConfig_defaultForceConfig;
    dst = &swrConfig_FORCE_STRENGTH;
    for (count = 8; count != 0; count--) {
        *dst = *src;
        src++;
        dst++;
    }
    swrConfig_AssignForceValues();
}

// 0x0040ab80
int swrConfig_WriteForceFeedbackConfig(char* filename)
{
    int open_status;
    size_t printf_status;
    char* str_bool;
    char config_name[32];
    char prefix[32];
    char pathname[256];

    sprintf(pathname, "%s%s\\%s", ".\\data\\config\\", filename, "force.cfg");
    open_status = stdConffile_OpenWrite(pathname);
    if (open_status == 0) {
        stdConffile_CloseWrite();
        return 0xffffffff;
    }
    sprintf(prefix, "FORCEFEEDBACK");
    printf_status = swrConfig_Printf("\n\n####### %s SETTINGS\n\n", prefix);
    if (printf_status == 0) {
        sprintf(config_name, "STRENGTH=%i", swrConfig_FORCE_STRENGTH);
        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
        if (printf_status == 0) {
            sprintf(config_name, "AUTOCENTER=%i", swrConfig_FORCE_AUTOCENTER);
            printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
            if (printf_status == 0) {
                sprintf(config_name, "COLLISIONS=%i", swrConfig_FORCE_COLLISIONS);
                printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                if (printf_status == 0) {
                    sprintf(config_name, "DAMAGE=%i", swrConfig_FORCE_DAMAGE);
                    printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                    if (printf_status == 0) {
                        sprintf(config_name, "TERRAIN=%i", swrConfig_FORCE_TERRAIN);
                        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                        if (printf_status == 0) {
                            sprintf(config_name, "PODACTIONS=%i", swrConfig_FORCE_PODACTIONS);
                            printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                            if (printf_status == 0) {
                                str_bool = "ON";
                                if (swrConfig_FORCE_GFORCES == 0) {
                                    str_bool = "OFF";
                                }
                                sprintf(config_name, "GFORCES=%s", str_bool);
                                printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                if (printf_status == 0) {
                                    str_bool = "ON";
                                    if (swrConfig_FORCE_ENGINERUMBLE == 0) {
                                        str_bool = "OFF";
                                    }
                                    sprintf(config_name, "ENGINERUMBLE=%s", str_bool);
                                    printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                    if (printf_status == 0) {
                                        str_bool = "TRUE";
                                        if (swrConfig_FORCE_ENABLED == 0) {
                                            str_bool = "FALSE";
                                        }
                                        sprintf(config_name, "ENABLED=%s", str_bool);
                                        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                        if (printf_status == 0) {
                                            printf_status = swrConfig_Puts("\nend.\n");
                                            if (printf_status == 0) {
                                                stdConffile_CloseWrite();
                                                return 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    stdConffile_CloseWrite();
    return 0;
}

// 0x0040ae40
int swrConfig_ReadForceFeedbackConfig(char* config_type)
{
    char pathname[256];

    sprintf(pathname, "%s%s\\%s", ".\\data\\config\\", config_type, "force.cfg");
    if (stdConffile_Open(pathname) == 0) {
        stdConffile_Close();
        return -1;
    }

    while (stdConffile_ReadArgs() != 0) {
        if (strcmp(stdConffile_g_entry.aArgs[0].argName, "end.") == 0)
            break;

        if (strcmpi(stdConffile_g_entry.aArgs[0].argName, "FORCEFEEDBACK") == 0) {
            char* name = stdConffile_g_entry.aArgs[1].argName;
            char* value = stdConffile_g_entry.aArgs[1].argValue;

            if (strcmpi(name, "STRENGTH") == 0) {
                swrConfig_FORCE_STRENGTH = atoi(value);
            } else if (strcmpi(name, "AUTOCENTER") == 0) {
                swrConfig_FORCE_AUTOCENTER = atoi(value);
            } else if (strcmpi(name, "COLLISIONS") == 0) {
                swrConfig_FORCE_COLLISIONS = atoi(value);
            } else if (strcmpi(name, "DAMAGE") == 0) {
                swrConfig_FORCE_DAMAGE = atoi(value);
            } else if (strcmpi(name, "TERRAIN") == 0) {
                swrConfig_FORCE_TERRAIN = atoi(value);
            } else if (strcmpi(name, "PODACTIONS") == 0) {
                swrConfig_FORCE_PODACTIONS = atoi(value);
            } else if (strcmpi(name, "GFORCES") == 0) {
                swrConfig_FORCE_GFORCES = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "ENGINERUMBLE") == 0) {
                swrConfig_FORCE_ENGINERUMBLE = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "ENABLED") == 0) {
                if (Main_force_feedback != 0 && swrControl_forceFeedbackAvailable != 0 && strcmpi(value, "TRUE") == 0) {
                    swrConfig_FORCE_ENABLED = 1;
                } else {
                    swrConfig_FORCE_ENABLED = 0;
                }
            } else {
                stdConffile_Close();
                return 0;
            }
        }
    }

    stdConffile_Close();
    swrConfig_AssignForceValues();
    return 1;
}

// 0x00422140
int swrConfig_WriteAudioConfig(char* dirname)
{
    int open_status;
    size_t printf_status;
    char* str_bool;
    char config_name[32];
    char prefix[32];
    char pathname[256];

    sprintf(pathname, "%s%s\\%s", ".\\data\\config\\", dirname, "audio.cfg");
    open_status = stdConffile_OpenWrite(pathname);
    if (open_status == 0) {
        stdConffile_CloseWrite();
        return 0xffffffff;
    }
    sprintf(prefix, "AUDIO");
    printf_status = swrConfig_Printf("\n\n####### %s SETTINGS\n\n", prefix);
    if (printf_status == 0) {
        str_bool = "ON";
        if (Main_sound == 0) {
            str_bool = "OFF";
        }
        sprintf(config_name, "SYS=%s", str_bool);
        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
        if (printf_status == 0) {
            str_bool = "ON";
            if (Main_hiRes_sound == 0) {
                str_bool = "OFF";
            }
            sprintf(config_name, "HIRES=%s", str_bool);
            printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
            if (printf_status == 0) {
                str_bool = "ON";
                if (Sound_enabled_3d == 0) {
                    str_bool = "OFF";
                }
                sprintf(config_name, "3D=%s", str_bool);
                printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                if (printf_status == 0) {
                    str_bool = "ON";
                    if (Main_doppler_sound == 0) {
                        str_bool = "OFF";
                    }
                    sprintf(config_name, "DOPPLER=%s", str_bool);
                    printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                    if (printf_status == 0) {
                        str_bool = "ON";
                        if (Main_sound_reflections == 0) {
                            str_bool = "OFF";
                        }
                        sprintf(config_name, "REFLECTIONS=%s", str_bool);
                        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                        if (printf_status == 0) {
                            sprintf(config_name, "GAINMATCH=%0.2f", (double) Main_sound_gain_adjust);
                            printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                            if (printf_status == 0) {
                                str_bool = "ON";
                                if (swrRace_voices_enabled == 0) {
                                    str_bool = "OFF";
                                }
                                sprintf(config_name, "VOICE=%s", str_bool);
                                printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                if (printf_status == 0) {
                                    str_bool = "ON";
                                    if (swrRace_music_enabled == 0) {
                                        str_bool = "OFF";
                                    }
                                    sprintf(config_name, "MUSIC=%s", str_bool);
                                    printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                    if (printf_status == 0) {
                                        str_bool = "ON";
                                        if (Main_sound_reverb == 0) {
                                            str_bool = "OFF";
                                        }
                                        sprintf(config_name, "REVERB=%s", str_bool);
                                        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                        if (printf_status == 0) {
                                            printf_status = swrConfig_Puts("\nend.\n");
                                            if (printf_status == 0) {
                                                stdConffile_CloseWrite();
                                                return 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    stdConffile_CloseWrite();
    return 0;
}

// 0x00422440
int swrConfig_ReadAudioConfig(char* dirname)
{
    char pathname[256];

    if (swrSound_Initted == 0)
        return 1;

    sprintf(pathname, "%s%s\\%s", ".\\data\\config\\", dirname, "audio.cfg");
    if (stdConffile_Open(pathname) == 0) {
        stdConffile_Close();
        return -1;
    }

    while (stdConffile_ReadArgs() != 0) {
        if (strcmp(stdConffile_g_entry.aArgs[0].argName, "end.") == 0)
            break;

        if (strcmpi(stdConffile_g_entry.aArgs[0].argName, "AUDIO") == 0) {
            char* name = stdConffile_g_entry.aArgs[1].argName;
            char* value = stdConffile_g_entry.aArgs[1].argValue;

            if (strcmpi(name, "HIRES") == 0) {
                Main_hiRes_sound = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "SYS") == 0) {
                Main_sound = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "3D") == 0) {
                Sound_enabled_3d = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "DOPPLER") == 0) {
                Main_doppler_sound = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "GAINMATCH") == 0) {
                Main_sound_gain_adjust = (float) atof(value);
                swrSound_SetMainGain(Main_sound_gain_adjust);
            } else if (strcmpi(name, "VOICE") == 0) {
                swrRace_voices_enabled = strcmpi(value, "ON") == 0;
            } else if (strcmpi(name, "MUSIC") == 0) {
                swrRace_music_enabled = strcmpi(value, "ON") == 0;
            }
        }
    }

    stdConffile_Close();
    return 1;
}

// 0x004879a0
size_t swrConfig_Puts(char* string)
{
    size_t written;
    size_t len;

    if (stdConffile_writeFile == NULL || string == NULL)
    {
        return false;
    }

    len = strlen(string);
    written = stdPlatform_hostServices_ptr->fileWrite(stdConffile_writeFile, string, len);

    return len != written;
}

// 0x004879f0
size_t swrConfig_Printf(char* format, ...)
{
    size_t vsnprintf_written;
    size_t fileWrite_written;

    if (stdConffile_writeFile != NULL && format != NULL)
    {
        va_list args;
        va_start(args, format);
        vsnprintf_written = vsnprintf(swrConfig_buffer, sizeof(swrConfig_buffer), format, args);
        va_end(args);

        fileWrite_written = stdPlatform_hostServices_ptr->fileWrite(stdConffile_writeFile, swrConfig_buffer, vsnprintf_written);
        return fileWrite_written != vsnprintf_written;
    }

    return 1;
}

// 0x0040b740
void swrConfig_RefreshMappingMenu(int deviceIndex, swrUI_unk* page)
{
    swrUI_unk* element;
    int* flipAxis;
    int axisCount;
    int buttonCount;
    char text[64];
    int i;

    // ten binding rows, ids 0x27..0x39 step 2 (keyboard adds secondary rows at odd+1 ids)
    for (i = 0; i < 10; i++)
        swrConfig_SetMappingRowText(deviceIndex, page, 0x27 + i * 2, i, 10, 0, 1);

    if (deviceIndex == swrConfig_DEVICE_JOYSTICK && cifr_deviceIsWheel != 0) {
        swrConfig_SetMappingRowText(swrConfig_DEVICE_JOYSTICK, page, 0x40, 3, 9, 0x20, 1);
        swrConfig_SetMappingRowText(swrConfig_DEVICE_JOYSTICK, page, 0x43, 3, 9, 0x10, 1);
    }
    if (deviceIndex == swrConfig_DEVICE_KEYBOARD) {
        for (i = 1; i <= 3; i++) {
            swrConfig_SetMappingRowText(swrConfig_DEVICE_KEYBOARD, page, 0x3f + i, 3, 9, 0x20, i);
            swrConfig_SetMappingRowText(swrConfig_DEVICE_KEYBOARD, page, 0x45 + i, 2, 9, 0x20, i);
            swrConfig_SetMappingRowText(swrConfig_DEVICE_KEYBOARD, page, 0x48 + i, 2, 9, 0x10, i);
            swrConfig_SetMappingRowText(swrConfig_DEVICE_KEYBOARD, page, 0x42 + i, 3, 9, 0x10, i);
        }
        for (i = 0; i < 10; i++)
            swrConfig_SetMappingRowText(swrConfig_DEVICE_KEYBOARD, page, 0x28 + i * 2, i, 10, 0, 2);
        return;
    }

    swrConfig_SetMappingRowText(deviceIndex, page, 0x3d, 0, 5, 0, 1);
    swrConfig_SetMappingRowText(deviceIndex, page, 0x3e, 2, 5, 0, 1);
    swrConfig_SetMappingRowText(deviceIndex, page, 0x3f, 3, 5, 0, 1);
    swrConfig_SetMappingRowText(deviceIndex, page, 0x3c, 6, 6, 0, 1);
    swrConfig_SetMappingRowText(deviceIndex, page, 0x3b, 2, 6, 0, 1);

    flipAxis = deviceIndex != swrConfig_DEVICE_JOYSTICK ? &flip_x_axis : swrControl_joystickFlipAxis;
    swrUI_SetChecked(swrUI_GetById(page, 0x55), flipAxis[0]);
    swrUI_SetChecked(swrUI_GetById(page, 0x56), flipAxis[1]);
    element = swrUI_GetById(page, 0x57);
    if (element != NULL)
        swrUI_SetChecked(element, flipAxis[2]);

    if (deviceIndex == swrConfig_DEVICE_JOYSTICK) {
        element = swrUI_GetById(page, 0x4d);
        if (element != NULL)
            swrUI_BuildSliderSprites(element, element->flags & swrUI_SLIDER_SELECTED);
        element = swrUI_GetById(page, 0x4e);
        if (element != NULL)
            swrUI_BuildSliderSprites(element, element->flags & swrUI_SLIDER_SELECTED);
        swrUI_SetChecked(swrUI_GetById(page, 0x54), swrConfig_joystick_enabled);
        axisCount = swrConfig_joystickNbAxis;
        buttonCount = swrConfig_joystickNbButtons;
    } else {
        element = swrUI_GetById(page, 0x4e);
        if (element != NULL)
            swrUI_BuildSliderSprites(element, element->flags & swrUI_SLIDER_SELECTED);
        swrUI_SetChecked(swrUI_GetById(page, 0x54), swrConfig_mouse_enabled);
        axisCount = swrConfig_mouseNbAxis;
        buttonCount = swrConfig_mouseNbButtons;
    }
    sprintf(text, swrText_Translate("/MONDOTEXT_H_0238/Detected: %i Axes, %i Buttons"), axisCount, buttonCount);
    element = swrUI_GetById(page, 0x58);
    if (element != NULL)
        swrUI_RunCallbacksScreenText(element, text, 0);
}

// 0x0040bbf0
void swrConfig_RefreshVideoMenu(swrUI_unk* page)
{
    swrUI_SetChecked(swrUI_GetById(page, 0x62), swrConfig_VIDEO_REFLECTIONS);
    swrUI_SetChecked(swrUI_GetById(page, 0x273b), swrConfig_VIDEO_LENSFLARE);
    swrUI_SetChecked(swrUI_GetById(page, 0x273c), swrConfig_VIDEO_ENGINEEXHAUST);
    swrUI_SetChecked(swrUI_GetByValue(swrUI_GetById(page, 0x67), swrConfig_VIDEO_MODEL_DETAIL), 1);
}

// 0x0040bc80
void swrConfig_RefreshAudioMenu(swrUI_unk* page)
{
    swrUI_unk* element;
    char* deviceName;
    char text[64];
    unsigned int hardwareFlags;
    int soundOn;

    soundOn = swrSound_Ready != 0 ? Main_sound : 0;
    swrUI_SetChecked(swrUI_GetById(page, 0x2741), soundOn);
    swrUI_SetChecked(swrUI_GetById(page, 0x2744), Main_hiRes_sound);
    swrUI_SetChecked(swrUI_GetById(page, 0x2742), Sound_enabled_3d);
    swrUI_SetChecked(swrUI_GetById(page, 0x2743), Main_doppler_sound);
    swrUI_SetChecked(swrUI_GetById(page, 0x2746), swrRace_voices_enabled);
    swrUI_SetChecked(swrUI_GetById(page, 0x2747), swrRace_music_enabled);

    if (swrSound_Ready == 0) {
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0243/NO SOUND CARD DETECTED."));
    } else {
        hardwareFlags = swrSound_GetHardwareFlags();
        if (Sound_HardwareDetected == 0)
            deviceName = ".";
        else
            deviceName = swrText_Translate((hardwareFlags & swrSound_HARDWARE_A3D) != 0 ? "/MONDOTEXT_H_0241/: A3D." : "/MONDOTEXT_H_0242/: DIRECTSOUND.");
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0239/%sHardware acceleration detected%s"), Sound_HardwareDetected != 0 ? wuRegistry_lpClass : swrText_Translate("/MONDOTEXT_H_0240/NO "), deviceName);
    }
    element = swrUI_GetById(page, 0x58);
    if (element != NULL) {
        swrUI_RunCallbacksScreenText(element, text, element->text_flags);
        swrUI_SetColorUnk(element, 0xff, 0xff, 0, 200);
        swrUI_BuildHighlightSprites(element, 1);
        swrUI_SetSpriteFlag(element, 0, swrSound_Ready == 0);
    }

    swrUI_SetSliderValue(swrUI_GetById(page, 0x273e), sound_sfx_volume * 100 / 255);
    swrUI_SetSliderValue(swrUI_GetById(page, 0x273f), *(uint8_t*)&sound_music_volume * 100 / 255);
    element = swrUI_GetById(page, 0x2740);
    swrUI_SetSliderValue(element, (int)(Main_sound_gain_adjust * 100.0f));
    swrUI_SetNumberValue(element, (int)(Main_sound_gain_adjust * 100.0f));

    // doppler and its gain slider need 3D sound
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x2743), Main_sound != 0 && swrSound_Ready != 0 ? Sound_enabled_3d : 0);
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x2740), Main_sound != 0 && swrSound_Ready != 0 ? Sound_enabled_3d : 0);
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x2712), Main_sound != 0 && swrSound_Ready != 0 ? Sound_enabled_3d : 0);
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x2742), swrSound_Ready != 0 ? Main_sound : 0);
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x2744), swrSound_Ready != 0 ? Main_sound : 0);
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x273e), swrSound_Ready != 0 ? Main_sound : 0);
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x273f), swrSound_Ready != 0 ? Main_sound : 0);
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x2710), swrSound_Ready != 0 ? Main_sound : 0);
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x2711), swrSound_Ready != 0 ? Main_sound : 0);
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x2746), swrSound_Ready != 0 ? Main_sound : 0);
    swrUI_RunCallbacks2(swrUI_GetById(page, 0x2747), swrSound_Ready != 0 ? Main_sound : 0);
}

// 0x0040c100
void swrConfig_RefreshForceFeedbackMenu(swrUI_unk* page)
{
    swrUI_SetChecked(swrUI_GetById(page, 0x59), swrConfig_FORCE_ENABLED != 0 && Main_force_feedback != 0);
    swrUI_SetChecked(swrUI_GetByValue(swrUI_GetById(page, 0x5a), swrConfig_FORCE_STRENGTH), 1);
    swrUI_SetChecked(swrUI_GetByValue(swrUI_GetById(page, 0x5b), swrConfig_FORCE_AUTOCENTER), 1);
    swrUI_SetChecked(swrUI_GetByValue(swrUI_GetById(page, 0x5c), swrConfig_FORCE_COLLISIONS), 1);
    swrUI_SetChecked(swrUI_GetByValue(swrUI_GetById(page, 0x5d), swrConfig_FORCE_DAMAGE), 1);
    swrUI_SetChecked(swrUI_GetByValue(swrUI_GetById(page, 0x5e), swrConfig_FORCE_TERRAIN), 1);
    swrUI_SetChecked(swrUI_GetByValue(swrUI_GetById(page, 0x5f), swrConfig_FORCE_PODACTIONS), 1);
    swrUI_SetChecked(swrUI_GetById(page, 0x60), swrConfig_FORCE_GFORCES);
    swrUI_SetChecked(swrUI_GetById(page, 0x61), swrConfig_FORCE_ENGINERUMBLE);
    swrConfig_AssignForceValues();
}

// 0x0040c260
void swrConfig_RefreshConfigFilesMenu(swrUI_unk* page)
{
    swrUI_unk* list;
    swrUI_unk* item;
    stdFileSearch* search;
    stdFileSearchResult result;
    char path[256];

    list = swrUI_GetById(page, SWR_UI_ID_FILE_LIST);
    if (list == NULL)
        return;
    swrUI_RefreshListSelection(list);

    // saved settings folders, minus the built-in ones
    search = stdFileUtil_NewFind(".\\data\\config\\", 2, wuRegistry_lpClass);
    while (stdFileUtil_FindNext(search, &result)) {
        if (strcmp("default", result.fpath) != 0 && strcmp("current", result.fpath) != 0 && strcmp(".", result.fpath) != 0 && strcmp("..", result.fpath) != 0)
            swrUI_AddListItem(list, result.fpath, 0, SWR_UI_ID_FILE_LIST_ITEM, 0);
    }
    stdFileUtil_DisposeFind(search);

    // stock control maps, drawn in a different colour
    sprintf(path, "%s%s", rootPathName, ".\\data\\config\\default\\");
    search = stdFileUtil_NewFind(path, 3, "map");
    while (stdFileUtil_FindNext(search, &result)) {
        if (result.is_subdirectory == 0 && strcmp("wheel.map", result.fpath) != 0) {
            stdFnames_StripExtAndDot(result.fpath);
            item = swrUI_AddListItem(list, result.fpath, 0, SWR_UI_ID_FILE_LIST_ITEM, 1);
            swrUI_SetColorUnk2(item, 200, 50, 0, 0xff);
        }
    }
    stdFileUtil_DisposeFind(search);
}

// 0x0040c4e0
void swrConfig_RefreshProfileListMenu(swrUI_unk* page)
{
    swrUI_unk* list;
    swrUI_unk* label;
    stdFileSearch* search;
    stdFileSearchResult result;
    char text[128];

    list = swrUI_GetById(page, SWR_UI_ID_FILE_LIST);
    if (list == NULL)
        return;
    swrUI_RefreshListSelection(list);

    search = stdFileUtil_NewFind(".\\data\\player\\", 3, "sav");
    while (stdFileUtil_FindNext(search, &result)) {
        if (result.is_subdirectory == 0) {
            stdFnames_StripExtAndDot(result.fpath);
            swrUI_AddListItem(list, result.fpath, 0, SWR_UI_ID_FILE_LIST_ITEM, 0);
        }
    }
    swrUI_ClearListSelection(list);
    stdFileUtil_DisposeFind(search);

    swrUI_RunCallbacks2(swrUI_GetById(page, SWR_UI_ID_FILE_NAME_ENTRY), 0);
    label = swrUI_GetById(page, SWR_UI_ID_CURRENT_PLAYER_LABEL);
    if (strlen(swrRace_saveData.profiles[0].name) == 0) {
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0002/Current Player:  %s"), swrText_Translate("/MONDOTEXT_H_0246/-none-"));
        swrRace_profileLoaded = -1;
    } else {
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0002/Current Player:  %s"), swrRace_saveData.profiles[0].name);
        swrRace_profileLoaded = 0;
        swrUI_SelectListItem(swrUI_FindChildByText(list, swrRace_saveData.profiles[0].name), 1);
    }
    swrUI_RunCallbacksScreenText(label, text, 0);
}

// 0x0040c670
void swrConfig_SetMappingRowText(int deviceIndex, swrUI_unk* page, int rowId, int control, int param5, int param6, int param7)
{
    char text[64];
    swrUI_unk* row;
    unsigned int boundControl;
    int skipFirst;

    skipFirst = 0;
    row = swrUI_GetById(page, rowId);
    // the EXE reuses the rowId argument slot as the out-param
    swrControl_FormatBinding(deviceIndex, control, param5, (unsigned char)param6, param7, text, &boundControl);
    if (rowId == SWR_CONFIG_MAPPING_ROW_TRIMMED && strlen(text) > 3) {
        skipFirst = 1;
    }
    if (strcmp(text, "~") == 0) {
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0247/tilde"));
    }
    if (strcmp(text, "=") == 0) {
        sprintf(text, "+");
    }
    if (row != NULL) {
        swrUI_SetValueText(row, skipFirst ? text + 1 : text, 0);
    }
}

// One row of LOW/MED/HIGH (optionally led by OFF) radio buttons under a settings group label.
// The OFF button is sized with the LOW text width, as in the EXE.
static void swrConfig_AddLevelRadioRow(swrUI_unk* page, int id, const int* radioX, int y, int height, int withOff)
{
    int i = 0;
    int value = 1;

    if (withOff) {
        swrUI_NewFramedText(page, id, 0, swrText_Translate("/MONDOTEXT_H_0234/OFF"), radioX[i++], y, swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0235/LOW"), 0), height, swrUI_CHECK_CIRCLE_UNK | swrUI_RADIO_GROUP_UNK, swrUI_FRAMED_TEXT_EXPLICIT_VALUE | 0);
        swrUI_NewFramedText(page, id, 0, swrText_Translate("/MONDOTEXT_H_0235/LOW"), radioX[i++], y, swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0235/LOW"), 0), height, swrUI_CHECK_CIRCLE_UNK, swrUI_FRAMED_TEXT_EXPLICIT_VALUE | value++);
    } else {
        swrUI_NewFramedText(page, id, 0, swrText_Translate("/MONDOTEXT_H_0235/LOW"), radioX[i++], y, swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0235/LOW"), 0), height, swrUI_CHECK_CIRCLE_UNK | swrUI_RADIO_GROUP_UNK, swrUI_FRAMED_TEXT_EXPLICIT_VALUE | value++);
    }
    swrUI_NewFramedText(page, id, 0, swrText_Translate("/MONDOTEXT_H_0236/MED"), radioX[i++], y, swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0236/MED"), 0), height, swrUI_CHECK_CIRCLE_UNK, swrUI_FRAMED_TEXT_EXPLICIT_VALUE | value++);
    swrUI_NewFramedText(page, id, 0, swrText_Translate("/MONDOTEXT_H_0237/HIGH"), radioX[i], y, swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0237/HIGH"), 0), height, swrUI_CHECK_CIRCLE_UNK | swrUI_RADIO_GROUP_UNK, swrUI_FRAMED_TEXT_EXPLICIT_VALUE | value);
}

// Group label in font 6 plus its radio-button strip; returns the strip height and advances *y past the label.
static int swrConfig_AddRadioGroupLabel(swrUI_unk* page, char* text, int x, int* y, int count, int* radioX)
{
    swrUI_unk* label;

    label = swrUI_NewLabel(page, 1, 6, swrText_Translate(text), x, *y, 0, 0);
    swrUI_SetColorUnk(label, 0xff, 0x7d, 0, 0xff);
    *y += swrText_GetStringHeight(swrText_Translate(text), swrText_fontsByIndex[6]);
    return swrUI_LayoutRadioGroup(label, *y, swrText_GetStringWidthByFont(swrText_Translate(text), 6), count, radioX);
}

static void swrConfig_AddSettingsPageHeader(swrUI_unk* page, char* titleKey, int x, int y)
{
    swrUI_unk* element;
    char title[256];

    sprintf(title, swrText_Translate(titleKey));
    element = swrUI_New3PatchBox(page, 1, 6, title, x, y, swrText_GetStringWidth(swrText_Translate(titleKey), swrText_fontsByIndex[6]), swrUI_3PATCH_LARGE_TAB, 1, 0, 0);
    swrUI_SetColorUnk(element, 0xff, 0, 0, 0xff);
    swrUI_AddNavButton(page, SWR_UI_ID_BACK_BUTTON, 0, 0x1a4, 1);
    swrUI_AddDefaultButton(page, 0xcd, 0x1a4);
    swrUI_AddRestoreButton(page, 0x163, 0x1a4);
    swrUI_AddOkButton(page, 0x208, 0x17c);
}

// 0x0040e6a0
void swrConfig_BuildVideoMenu(swrUI_unk* page)
{
    int radioX[3];
    unsigned int restoreWidth;
    int checkRowWidth;
    int checkWidth;
    int checkHeight;
    int radioHeight;
    int y;

    restoreWidth = swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0248/~sRestore Previous Settings"), swrText_fontsByIndex[0]);
    swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0248/~sRestore Previous Settings"), swrText_fontsByIndex[0]);
    swrConfig_AddSettingsPageHeader(page, "/MONDOTEXT_H_0292/~sVIDEO SETTINGS", (((restoreWidth >> 1) + restoreWidth) >> 2) + 300, 0xa0);

    checkWidth = swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0294/~sDynamic Lighting Enabled "), 0);
    checkRowWidth = checkWidth + swrText_GetStringWidthByFont(" ", 0) * 10 + swrText_GetStringWidthByFont("  [X]  ", 0);
    checkHeight = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0294/~sDynamic Lighting Enabled "), swrText_fontsByIndex[0]) * 3;
    swrUI_NewFramedText(page, 0x62, 0, swrText_Translate("/MONDOTEXT_H_0297/~sReflections Enabled "), 0x1e, 200, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);
    swrUI_NewFramedText(page, 0x273c, 0, swrText_Translate("/MONDOTEXT_H_0301/~sSmoke And Dust Enabled "), 0x1e, 0xe6, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);
    swrUI_NewFramedText(page, 0x273b, 0, swrText_Translate("/MONDOTEXT_H_0300/~sLens Flare Enabled "), 0x1e, 0x104, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);

    y = 0xaf;
    radioHeight = swrConfig_AddRadioGroupLabel(page, "/MONDOTEXT_H_0303/~sModel Detail ", checkRowWidth / 16 + 0x3c + checkRowWidth, &y, 3, radioX);
    swrConfig_AddLevelRadioRow(page, 0x67, radioX, y + radioHeight, radioHeight, 0);
}

// 0x0040ea70
void swrConfig_BuildAudioMenu(swrUI_unk* page)
{
    swrUI_unk* element;
    int checkWidth;
    int checkHeight;

    swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0252/~sReset Default Settings"), swrText_fontsByIndex[0]);
    swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0252/~sReset Default Settings"), swrText_fontsByIndex[0]);
    swrConfig_AddSettingsPageHeader(page, "/MONDOTEXT_H_0305/~sAUDIO SETTINGS", 500, 0x3c);

    // row width measured but unused (the video/force pages place a second column with it)
    swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0517/~s3D-Spatialized Sound Enabled "), 0);
    swrText_GetStringWidthByFont(" ", 0);
    swrText_GetStringWidthByFont("  [X]  ", 0);
    checkHeight = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0306/~s3D-Spatialized Sound Enabled "), swrText_fontsByIndex[0]) * 3;
    checkWidth = swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0517/~s3D-Spatialized Sound Enabled "), 0);

    element = swrUI_NewFramedText(page, 0x2741, 0, swrText_Translate("/MONDOTEXT_H_0308/~sSound-System Enabled "), 0xf, 0x73, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);
    // sound-card status line, filled in by swrConfig_RefreshAudioMenu
    element = swrUI_NewLabel(page, 0x58, 0, wuRegistry_lpClass, 0xf, ((element->height - element->y) + 1) / 2 + 0x82, 0x100000, 0);
    swrUI_SetColorUnk(element, 0xff, 0xff, 0, 200);
    swrUI_NewFramedText(page, 0x2744, 0, swrText_Translate("/MONDOTEXT_H_0309/~sUse Hi-Res (22K) sounds "), 0xf, 0xac, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);
    swrUI_NewFramedText(page, 0x2746, 0, swrText_Translate("/MONDOTEXT_H_0502/~sIn-Race Voices Enabled "), 0xf, 0xd1, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);

    element = swrUI_NewNumberField(page, 0x273e, 0x13b, 199, 300, swrUI_SLIDER_SHOW_VALUE, 0);
    element = swrUI_NewLabel(page, 10000, 0, swrText_Translate("/MONDOTEXT_H_0310/Sound Effects Volume"), 0x171, ((element->height - element->y) + 1) / 2 + 0xc4, 0x100000, 0);
    swrUI_SetColorUnk(element, 0xff, 0xff, 0, 0xb9);

    swrUI_NewFramedText(page, 0x2747, 0, swrText_Translate("/MONDOTEXT_H_0503/~sIn-Race Music Enabled "), 0xf, 0xf6, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);
    element = swrUI_NewNumberField(page, 0x273f, 0x13b, 0xec, 300, swrUI_SLIDER_SHOW_VALUE, 0);
    element = swrUI_NewLabel(page, 0x2711, 0, swrText_Translate("/MONDOTEXT_H_0311/Music/Cutscene Volume"), 0x16d, ((element->height - element->y) + 1) / 2 + 0xe9, 0x100000, 0);
    swrUI_SetColorUnk(element, 0xff, 0xff, 0, 0xb9);

    swrUI_NewFramedText(page, 0x2742, 0, swrText_Translate("/MONDOTEXT_H_0306/~s3D-Spatialized Sound Enabled "), 0xf, 0x132, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);
    swrUI_NewFramedText(page, 0x2743, 0, swrText_Translate("/MONDOTEXT_H_0312/~sDoppler Effects Enabled "), 0xf, 0x15f, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);
    element = swrUI_NewNumberField(page, 0x2740, 0x13b, 0x155, 300, swrUI_SLIDER_SHOW_NUMBER | swrUI_SLIDER_SHOW_VALUE, 0);
    element = swrUI_NewLabel(page, 0x2712, 0, swrText_Translate("/MONDOTEXT_H_0313/2D/3D Relative Gain Adjustment"), 0x159, 0x169 - ((element->height - element->y) + 1) / 2, 0x100000, 0);
    swrUI_SetColorUnk(element, 0xff, 0xff, 0, 0xb9);
}

// 0x0040ef40
void swrConfig_BuildForceFeedbackMenu(swrUI_unk* page)
{
    int radioX[4];
    int headerHeight;
    int strengthWidth;
    int checkRowWidth;
    int checkWidth;
    int checkHeight;
    int rightCheckX;
    int rightColumnX;
    int radioHeight;
    int leftY;
    int rightY;

    swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0248/~sRestore Previous Settings"), swrText_fontsByIndex[0]);
    swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0248/~sRestore Previous Settings"), swrText_fontsByIndex[0]);
    headerHeight = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0314/~sFORCE FEEDBACK SETTINGS"), swrText_fontsByIndex[6]) * 3;
    swrConfig_AddSettingsPageHeader(page, "/MONDOTEXT_H_0314/~sFORCE FEEDBACK SETTINGS", 0x212, headerHeight + 5);

    checkWidth = swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0518/~sOverall Force Strength "), 0);
    strengthWidth = checkWidth + swrText_GetStringWidthByFont(" ", 0) * 10;
    checkRowWidth = swrText_GetStringWidthByFont("  [X]  ", 0) + strengthWidth;
    checkHeight = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0315/~sOverall Force Strength "), swrText_fontsByIndex[0]) * 3;
    rightCheckX = strengthWidth + 0x46;
    swrUI_NewFramedText(page, 0x60, 0, swrText_Translate("/MONDOTEXT_H_0322/~sEnable G-Forces "), rightCheckX, headerHeight + 0x14, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);
    swrUI_NewFramedText(page, 0x59, 0, swrText_Translate("/MONDOTEXT_H_0316/~sEnable Force Feedback "), 0x1e, headerHeight + 0x2d, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);
    swrUI_NewFramedText(page, 0x61, 0, swrText_Translate("/MONDOTEXT_H_0323/~sEnable Engine Rumble "), rightCheckX, headerHeight + 0x32, checkWidth, checkHeight, swrUI_LEFT_RIGHT_UNK, 0);

    leftY = headerHeight + 0x5a;
    rightY = leftY;
    rightColumnX = checkRowWidth / 16 + 0x1e + checkRowWidth;

    radioHeight = swrConfig_AddRadioGroupLabel(page, "/MONDOTEXT_H_0315/~sOverall Force Strength ", 0x14, &leftY, 3, radioX);
    leftY += radioHeight;
    swrConfig_AddLevelRadioRow(page, 0x5a, radioX, leftY, radioHeight, 0);
    leftY += radioHeight * 2;

    radioHeight = swrConfig_AddRadioGroupLabel(page, "/MONDOTEXT_H_0317/~sAuto-Center Stiffness ", rightColumnX, &rightY, 4, radioX);
    rightY += radioHeight;
    swrConfig_AddLevelRadioRow(page, 0x5b, radioX, rightY, radioHeight, 1);
    rightY += radioHeight * 2;

    radioHeight = swrConfig_AddRadioGroupLabel(page, "/MONDOTEXT_H_0318/~sCollision Effects ", 0x2d, &leftY, 4, radioX);
    leftY += radioHeight;
    swrConfig_AddLevelRadioRow(page, 0x5c, radioX, leftY, radioHeight, 1);
    leftY += radioHeight * 2;

    radioHeight = swrConfig_AddRadioGroupLabel(page, "/MONDOTEXT_H_0319/~sDamage Effects ", rightColumnX + 0x19, &rightY, 4, radioX);
    rightY += radioHeight;
    swrConfig_AddLevelRadioRow(page, 0x5d, radioX, rightY, radioHeight, 1);
    rightY += radioHeight * 2;

    radioHeight = swrConfig_AddRadioGroupLabel(page, "/MONDOTEXT_H_0320/~sTerrain Effects ", 0x2d, &leftY, 4, radioX);
    swrConfig_AddLevelRadioRow(page, 0x5e, radioX, leftY + radioHeight, radioHeight, 1);

    radioHeight = swrConfig_AddRadioGroupLabel(page, "/MONDOTEXT_H_0321/~sPod Action Effects ", rightColumnX + 0xf, &rightY, 4, radioX);
    swrConfig_AddLevelRadioRow(page, 0x5f, radioX, rightY + radioHeight, radioHeight, 1);
}

// Action-name cell of a binding row; the bound control text is drawn right of labelWidth.
static swrUI_unk* swrConfig_NewBindingRow(swrUI_unk* page, int id, char* key, int x, int y, int width, int height, int labelWidth)
{
    return swrUI_NewScreenText(page, id, 0, swrText_Translate(key), (int)wuRegistry_lpClass, x, y, width, height, labelWidth, swrUI_SCREEN_TEXT_INDENT_1, 0);
}

// Keyboard secondary-key cell (no label, value text only).
static void swrConfig_NewKeyCell(swrUI_unk* page, int id, int x, int y, int width, int height, int valueX)
{
    swrUI_NewScreenText(page, id, 0, NULL, (int)wuRegistry_lpClass, x, y, width, height, valueX, swrUI_SCREEN_TEXT_PLAIN, 0);
}

static char* const swrConfig_bindingRowKeys[10] = {
    "/MONDOTEXT_H_0259/~sCycle Camera", "/MONDOTEXT_H_0015/LOOK_BACK", "/MONDOTEXT_H_0016/BRAKE",
    "/MONDOTEXT_H_0017/THRUST", "/MONDOTEXT_H_0018/BOOST", "/MONDOTEXT_H_0019/SLIDE",
    "/MONDOTEXT_H_0020/ROLL_LEFT", "/MONDOTEXT_H_0021/ROLL_RIGHT", "/MONDOTEXT_H_0255/~sTaunt/Flamejet",
    "/MONDOTEXT_H_0023/REPAIR",
};

static char* const swrConfig_axisRowKeys[5] = {
    "/MONDOTEXT_H_0271/~sTurn Left/Right", "/MONDOTEXT_H_0016/BRAKE", "/MONDOTEXT_H_0278/~sNose Up/Down",
    "/MONDOTEXT_H_0280/~sRoll Left/Right", "/MONDOTEXT_H_0225/THROTTLE",
};
static const int swrConfig_axisRowIds[5] = { 0x3e, 0x3b, 0x3f, 0x3c, 0x3d };

// Shared body of the joystick (0x0040c7a0) and mouse (0x0040d2c0) pages.
static void swrConfig_BuildPointerDeviceMenu(swrUI_unk* page, swrConfig_DEVICE device)
{
    swrUI_unk* element;
    swrUI_unk* list;
    char title[256];
    char* key;
    int bbox[4];
    int listRect[4];
    int radioX[3];
    int isJoystick = device == swrConfig_DEVICE_JOYSTICK;
    int enabledHeight;
    int labelWidth;
    int columnWidth;
    int textHeight;
    int frameWidth;
    int rowHeight;
    int listHeight;
    int axisTop;
    int radioHeight;
    int count;
    int x;
    int y;
    int i;

    swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0248/~sRestore Previous Settings"), swrText_fontsByIndex[0]);
    enabledHeight = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0248/~sRestore Previous Settings"), swrText_fontsByIndex[0]) * 3;
    // the joystick page is positioned with the MOUSE title height and draws its title text directly
    y = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0250/~sMOUSE SETTINGS"), swrText_fontsByIndex[6]) * 3 + 5;
    if (isJoystick) {
        sprintf(title, swrText_Translate("/MONDOTEXT_H_0249/~sJOYSTICK SETTINGS"));
        element = swrUI_New3PatchBox(page, 1, 6, swrText_Translate("/MONDOTEXT_H_0249/~sJOYSTICK SETTINGS"), 0x1e5, y, swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0249/~sJOYSTICK SETTINGS"), swrText_fontsByIndex[6]), swrUI_3PATCH_LARGE_TAB, 1, 0, 0);
        swrUI_SetColorUnk(element, 0xff, 0, 0, 0xff);
        swrUI_AddNavButton(page, SWR_UI_ID_BACK_BUTTON, 0, 0x1a9, 1);
        swrUI_AddDefaultButton(page, 0xcd, 0x1a9);
        swrUI_AddRestoreButton(page, 0x163, 0x1a9);
        swrUI_AddOkButton(page, 0x208, 0x181);
    } else {
        sprintf(title, swrText_Translate("/MONDOTEXT_H_0250/~sMOUSE SETTINGS"));
        element = swrUI_New3PatchBox(page, 1, 6, title, 0x1d1, y, swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0250/~sMOUSE SETTINGS"), swrText_fontsByIndex[6]), swrUI_3PATCH_LARGE_TAB, 1, 0, 0);
        swrUI_SetColorUnk(element, 0xff, 0, 0, 0xff);
        swrUI_AddNavButton(page, SWR_UI_ID_BACK_BUTTON, 0, 0x1a4, 1);
        swrUI_AddDefaultButton(page, 0xcd, 0x1a4);
        swrUI_AddRestoreButton(page, 0x163, 0x1a4);
        swrUI_AddOkButton(page, 0x208, 0x17c);
    }

    element = swrUI_NewLabel(page, 1, -1, swrText_Translate("/MONDOTEXT_H_0257/~sButton Settings"), 100, 5, 0, 0);
    swrUI_SetColorUnk(element, 0xe1, 0xe1, 0, 0xff);

    labelWidth = swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0513/~sTaunt/Flamejet"), 0) + swrText_GetStringWidthByFont(" ", 0) * 5;
    columnWidth = swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0514/Numpad Enter"), 0) + labelWidth;
    textHeight = swrText_GetStringHeight(isJoystick ? "/" : swrText_Translate("/MONDOTEXT_H_0259/~sCycle Camera"), swrText_fontsByIndex[0]);
    swrUI_GetFrameTextureDim(swrUI_FRAME_STYLE_EDIT_SEGMENTED, &frameWidth, &rowHeight);
    if (textHeight + 2 >= rowHeight)
        rowHeight = textHeight + 2;
    if (columnWidth < frameWidth)
        columnWidth = frameWidth;

    swrUI_GetListFrameInsets(bbox, 0);
    listHeight = (isJoystick && cifr_deviceIsWheel != 0 ? 13 : 11) * rowHeight;
    listRect[0] = 0xf;
    listRect[1] = 0xf;
    listRect[2] = bbox[0] + 0xe + columnWidth;
    listRect[3] = bbox[1] + 0xe + listHeight;
    list = swrUI_NewList(page, isJoystick ? 0x30d49 : 0x30d4d, listRect, -1, swrUI_LIST_NO_SELECTION_FRAME | swrUI_LIST_NO_SCROLLBAR, 0);
    list->row_spacing = 0;
    x = bbox[0] + 0xf;
    y = 0xf;
    for (i = 0; i < 10; i++) {
        swrUI_AddListElement(list, swrConfig_NewBindingRow(page, 0x27 + i * 2, swrConfig_bindingRowKeys[i], x, y, columnWidth, rowHeight, labelWidth));
        y += rowHeight;
    }
    if (isJoystick && cifr_deviceIsWheel != 0) {
        swrUI_AddListElement(list, swrConfig_NewBindingRow(page, 0x40, "/MONDOTEXT_H_0268/~sNose Up", x, y, columnWidth, rowHeight, labelWidth));
        y += rowHeight;
        swrUI_AddListElement(list, swrConfig_NewBindingRow(page, 0x43, "/MONDOTEXT_H_0269/~sNose Down", x, y, columnWidth, rowHeight, labelWidth));
    }

    y = bbox[1] + 0xf + listHeight;
    element = swrUI_NewLabel(page, 1, -1, swrText_Translate("/MONDOTEXT_H_0270/~sAxis Settings"), 100, y, 0, 0);
    y += 10;
    swrUI_SetColorUnk(element, 0xe1, 0xe1, 0, 0xff);
    listRect[0] = 0xf;
    listRect[1] = y;
    listRect[2] = bbox[0] + 0xe + columnWidth;
    listRect[3] = bbox[1] + rowHeight * 6 - 1 + y;
    list = swrUI_NewList(page, isJoystick ? 0x30d4a : 0x30d4e, listRect, -1, swrUI_LIST_NO_SELECTION_FRAME | swrUI_LIST_NO_SCROLLBAR, 0);
    list->row_spacing = 0;
    axisTop = y;
    for (i = 0; i < 5; i++) {
        swrUI_AddListElement(list, swrConfig_NewBindingRow(page, swrConfig_axisRowIds[i], swrConfig_axisRowKeys[i], x, y, columnWidth, rowHeight, labelWidth));
        y += rowHeight;
    }

    y = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0250/~sMOUSE SETTINGS"), swrText_fontsByIndex[6]);
    // device status line, filled in by swrConfig_RefreshMappingMenu
    element = swrUI_NewLabel(page, 0x58, 0, wuRegistry_lpClass, 0x145, y * 3 + 7, 0, 0);
    swrUI_SetColorUnk(element, 0xff, 0xff, 0, 200);
    y = y * 3 + 0x14;
    if (!isJoystick)
        key = "/MONDOTEXT_H_0286/~sMouse Enabled ";
    else if (cifr_deviceIsWheel == 0)
        key = "/MONDOTEXT_H_0288/~sJoystick Enabled ";
    else
        key = "/MONDOTEXT_H_0287/~sWheel Enabled ";
    swrUI_NewFramedText(page, 0x54, 0, swrText_Translate(key), 0x145, y, swrText_GetStringWidthByFont(swrText_Translate(key), 0), enabledHeight, swrUI_LEFT_RIGHT_UNK, 0);
    y += rowHeight * 2;

    // Z flip only when the device reports a third axis
    count = ((isJoystick ? swrControl_joystickAxisMask : swrControl_mouseAxisMask) & (1u << SWR_CONTROL_AXIS_Z)) != 0 ? 3 : 2;
    radioHeight = swrConfig_AddRadioGroupLabel(page, "/MONDOTEXT_H_0507/~sFlip Axis", 0x16d, &y, count, radioX);
    y += radioHeight;
    swrUI_NewFramedText(page, 0x55, 0, swrText_Translate("/MONDOTEXT_H_0283/~sX"), radioX[0], y, swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0283/~sX"), 0), radioHeight, swrUI_CHECK_CIRCLE_UNK, 0);
    swrUI_NewFramedText(page, 0x56, 0, swrText_Translate("/MONDOTEXT_H_0284/~sY"), radioX[1], y, swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0284/~sY"), 0), radioHeight, swrUI_CHECK_CIRCLE_UNK, 0);
    if (count > 2)
        swrUI_NewFramedText(page, 0x57, 0, swrText_Translate("/MONDOTEXT_H_0285/~sZ"), radioX[2], y, swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0285/~sZ"), 0), radioHeight, swrUI_CHECK_CIRCLE_UNK, 0);

    // bracket sprite joining the axis list to the two sliders; bbox is reused as its rect
    bbox[0] = listRect[2] - 8;
    bbox[1] = axisTop + 0x18;
    bbox[2] = listRect[2] + 0x30;
    bbox[3] = axisTop + 0x77;
    swrUI_NewSpriteElement(page, 1, bbox, swrSprite_branch, 0, NULL, 0);
    swrUI_NewLabel(page, 1, 0, swrText_Translate("/MONDOTEXT_H_0508/~sSensitivity"), bbox[2] + 0x19, axisTop + 8, 0, 0);
    swrUI_NewNumberField(page, 0x4e, bbox[2] - 10, axisTop + 8, 200, swrUI_SLIDER_SHOW_VALUE, 0);
    if (isJoystick) {
        swrUI_NewLabel(page, 1, 0, swrText_Translate("/MONDOTEXT_H_0509/~sDeadzone"), bbox[2] + 0x19, axisTop + 0x5e, 0, 0);
        // 0xc00000: set in the EXE, not read by the slider code
        swrUI_NewNumberField(page, 0x4d, bbox[2] - 10, axisTop + 0x5e, 200, swrUI_SLIDER_THUMB | swrUI_SLIDER_SHOW_VALUE | swrUI_SLIDER_CENTERED | 0xc00000, 0);
    } else {
        swrUI_NewLabel(page, 1, 0, swrText_Translate("/MONDOTEXT_H_0532/Sensitivity Meter"), bbox[2] + 0x19, axisTop + 0x5e, 0, 0);
        swrUI_NewNumberField(page, 0x4d, bbox[2] - 10, axisTop + 0x5e, 200, swrUI_SLIDER_THUMB | swrUI_SLIDER_SHOW_VALUE | swrUI_SLIDER_NO_CAPS, 0);
    }
}

// 0x0040c7a0
void swrConfig_BuildJoystickMenu(swrUI_unk* page)
{
    swrConfig_BuildPointerDeviceMenu(page, swrConfig_DEVICE_JOYSTICK);
}

// 0x0040d2c0
void swrConfig_BuildMouseMenu(swrUI_unk* page)
{
    swrConfig_BuildPointerDeviceMenu(page, swrConfig_DEVICE_MOUSE);
}

// 0x0040dd10
void swrConfig_BuildKeyboardMenu(swrUI_unk* page)
{
    swrUI_unk* element;
    char title[256];
    int bbox[4];
    int panelRect[4];
    unsigned int restoreWidth;
    int labelWidth;
    int columnWidth;
    int textHeight;
    int frameWidth;
    int rowHeight;
    int listHeight;
    int keyWidth;
    int keyValueX;
    int x;
    int x2;
    int x3;
    int y;
    int i;

    restoreWidth = swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0248/~sRestore Previous Settings"), swrText_fontsByIndex[0]);
    element = swrUI_NewButton(page, 0x4c, -1, swrText_Translate("/MONDOTEXT_H_0291/~sShow Reserved Settings"), 400, 0x55, (restoreWidth >> 3) + restoreWidth, 0x14, swrUI_FRAME_STYLE_SMALL_WINDOW, 0);
    swrUI_SetColorUnk2(element, 0xff, 0, 0, 0xff);
    swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0248/~sRestore Previous Settings"), swrText_fontsByIndex[0]);
    swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0248/~sRestore Previous Settings"), swrText_fontsByIndex[0]);
    y = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0251/~sKEYBOARD SETTINGS"), swrText_fontsByIndex[6]);
    sprintf(title, swrText_Translate("/MONDOTEXT_H_0251/~sKEYBOARD SETTINGS"));
    element = swrUI_New3PatchBox(page, 1, 6, title, 0x230, y * 3 + 5, swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0251/~sKEYBOARD SETTINGS"), swrText_fontsByIndex[6]), swrUI_3PATCH_LARGE_TAB, 1, 0, 0);
    swrUI_SetColorUnk(element, 0xff, 0, 0, 0xff);
    swrUI_AddNavButton(page, SWR_UI_ID_BACK_BUTTON, 0, 0x1ae, 1);
    swrUI_AddDefaultButton(page, 0xcd, 0x1ae);
    swrUI_AddRestoreButton(page, 0x163, 0x1ae);
    swrUI_AddOkButton(page, 0x208, 0x17c);

    labelWidth = swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0513/~sTaunt/Flamejet"), 0) + swrText_GetStringWidthByFont(" ", 0) * 5;
    columnWidth = swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0514/Numpad Enter"), 0) + labelWidth;
    textHeight = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0259/~sCycle Camera"), swrText_fontsByIndex[0]);
    swrUI_GetFrameTextureDim(swrUI_FRAME_STYLE_EDIT_SEGMENTED, &frameWidth, &rowHeight);
    if (textHeight + 2 >= rowHeight)
        rowHeight = textHeight + 2;
    if (columnWidth < frameWidth)
        columnWidth = frameWidth;
    keyValueX = swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0283/~sX"), 0) * 2;
    keyWidth = swrText_GetStringWidthByFont(swrText_Translate("/MONDOTEXT_H_0256/Numpad Enter"), 0);

    swrUI_GetListFrameInsets(bbox, 0);
    listHeight = rowHeight * 11;
    panelRect[0] = 0xf;
    panelRect[1] = 0xf;
    panelRect[2] = keyWidth + bbox[0] + 0xe + columnWidth;
    panelRect[3] = bbox[1] + 0xe + listHeight;
    swrUI_NewPanel(page, 1, panelRect, 0);
    x = bbox[0] + 0xf;
    x2 = columnWidth + 0xf;
    y = bbox[1] + 0xf;
    for (i = 0; i < 10; i++) {
        swrConfig_NewBindingRow(page, 0x27 + i * 2, swrConfig_bindingRowKeys[i], x, y, columnWidth, rowHeight, labelWidth);
        swrConfig_NewKeyCell(page, 0x28 + i * 2, x2, y, keyWidth, rowHeight, keyValueX);
        y += rowHeight;
    }

    y = (bbox[1] >> 1) + bbox[1] + 0xf + listHeight;
    panelRect[0] = 0xf;
    panelRect[1] = y;
    panelRect[2] = bbox[0] + 0xe + keyWidth * 2 + columnWidth;
    panelRect[3] = bbox[1] + rowHeight * 5 - 1 + y;
    swrUI_NewPanel(page, 1, panelRect, 0);
    y += bbox[1];
    x3 = keyWidth - 8 + x2;
    swrConfig_NewBindingRow(page, 0x40, "/MONDOTEXT_H_0268/~sNose Up", x, y, columnWidth, rowHeight, labelWidth);
    swrConfig_NewKeyCell(page, 0x41, x2, y, keyWidth, rowHeight, keyValueX);
    swrConfig_NewKeyCell(page, 0x42, x3, y, keyWidth, rowHeight, keyValueX);
    y += rowHeight;
    swrConfig_NewBindingRow(page, 0x46, "/MONDOTEXT_H_0029/TURN_LEFT", x, y, columnWidth, rowHeight, labelWidth);
    swrConfig_NewKeyCell(page, 0x47, x2, y, keyWidth, rowHeight, keyValueX);
    swrConfig_NewKeyCell(page, 0x48, x3, y, keyWidth, rowHeight, keyValueX);
    y += rowHeight;
    swrConfig_NewBindingRow(page, 0x49, "/MONDOTEXT_H_0030/TURN_RIGHT", x, y, columnWidth, rowHeight, labelWidth);
    swrConfig_NewKeyCell(page, 0x4a, x2, y, keyWidth, rowHeight, keyValueX);
    swrConfig_NewKeyCell(page, 0x4b, x3, y, keyWidth, rowHeight, keyValueX);
    y += rowHeight;
    swrConfig_NewBindingRow(page, 0x43, "/MONDOTEXT_H_0269/~sNose Down", x, y, columnWidth, rowHeight, labelWidth);
    swrConfig_NewKeyCell(page, 0x44, x2, y, keyWidth, rowHeight, keyValueX);
    swrConfig_NewKeyCell(page, 0x45, x3, y, keyWidth, rowHeight, keyValueX);
}
