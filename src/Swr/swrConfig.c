#include "swrConfig.h"

#include <General/stdConffile.h>

#include "globals.h"
#include "macros.h"

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
    HANG("TODO");
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
    HANG("TODO");
}

// 0x0040ab80
int swrConfig_WriteForceFeedbackConfig(char* filename)
{
    HANG("TODO");
}

// 0x0040ae40
int swrConfig_ReadForceFeedbackConfig(char* config_type)
{
    HANG("TODO");
    return 1;
}

// 0x00422140
int swrConfig_WriteAudioConfig(char* dirname)
{
    HANG("TODO");
    return -1;
}

// 0x00422440
int swrConfig_ReadAudioConfig(char* dirname)
{
    HANG("TODO");
    return -1;
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
