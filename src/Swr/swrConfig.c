#include "swrConfig.h"

#include <General/stdConffile.h>

#include "globals.h"
#include "macros.h"

#include "swrSound.h"

#include <string.h>
#include <stdlib.h>

// 0x00406080
int swrConfig_WriteMappings(char* dirname)
{
    HANG("TODO");
    return 0;
}

// 0x00407b00
void swrConfig_ControlToString(unsigned int controlId, char* pDest)
{
    HANG("TODO");
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

// 0x0040a680
void swrConfig_AssignForceValues(void)
{
    HANG("TODO");
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
