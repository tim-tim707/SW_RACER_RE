#include "swrConfig.h"

#include "globals.h"
#include "macros.h"

// 0x00477d0
int swrConfig_Open(char* filename)
{
    if (swrConfig_file != NULL)
    {
        return 0;
    }
    swrConfig_file = stdPlatform_hostServices_ptr->fileOpen(filename, "wb");
    if (swrConfig_file == NULL)
    {
        swrConfig_file = NULL;
        return 0;
    }

    strncpy(swrConfig_filename, filename, sizeof(swrConfig_filename) - 1);
    swrConfig_filename[sizeof(swrConfig_filename) - 1] = '\0';
    return 1;
}

// 0x00487960
void swrConfig_Close(void)
{
    if (swrConfig_file != NULL)
    {
        stdPlatform_hostServices_ptr->fileClose(swrConfig_file);
        swrConfig_file = NULL;
        strncpy(swrConfig_filename, "NOT_OPEN", sizeof(swrConfig_filename) - 1);
        swrConfig_filename[sizeof(swrConfig_filename) - 1] = '\0';
    }
}

// 0x004879a0
size_t swrConfig_Puts(char* string)
{
    size_t written;
    size_t len;

    if (swrConfig_file == NULL || string == NULL)
    {
        return false;
    }

    len = strlen(string);
    written = stdPlatform_hostServices_ptr->fileWrite(swrConfig_file, string, len);

    return len != written;
}

// 0x004879f0
size_t swrConfig_Printf(char* format, ...)
{
    size_t vsnprintf_written;
    size_t fileWrite_written;

    if (swrConfig_file != NULL && format != NULL)
    {
        va_list args;
        va_start(args, format);
        vsnprintf_written = vsnprintf(swrConfig_buffer, sizeof(swrConfig_buffer), format, args);
        va_end(args);

        fileWrite_written = stdPlatform_hostServices_ptr->fileWrite(swrConfig_file, swrConfig_buffer, vsnprintf_written);
        return fileWrite_written != vsnprintf_written;
    }

    return 1;
}

// 0x00487a50
size_t swrConfig_Tokenizer(char* line)
{
    hang("TODO");
    return 0;
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

    stdlib__sprintf(pathname, "%s%s\\%s", ".\\data\\config\\", dirname, "video.cfg");
    open_status = swrConfig_Open(pathname);
    if (open_status == 0)
    {
        swrConfig_Close();
        return 0xffffffff;
    }
    stdlib__sprintf(prefix, "VIDEO");
    printf_status = swrConfig_Printf("\n\n####### %s SETTINGS\n\n", prefix);
    if (printf_status == 0)
    {
        str_bool = "ON";
        if (swrConfig_REFLECTIONS == 0)
        {
            str_bool = "OFF";
        }
        stdlib__sprintf(config_name, "REFLECTIONS=%s", str_bool);
        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
        if (printf_status == 0)
        {
            str_bool = "ON";
            if (swrConfig_ZEFFECTS == 0)
            {
                str_bool = "OFF";
            }
            stdlib__sprintf(config_name, "ZEFFECTS=%s", str_bool);
            printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
            if (printf_status == 0)
            {
                str_bool = "ON";
                if (swrConfig_DYNAMIC_LIGHTING == 0)
                {
                    str_bool = "OFF";
                }
                stdlib__sprintf(config_name, "DYNAMIC_LIGHTING=%s", str_bool);
                printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                if (printf_status == 0)
                {
                    str_bool = "ON";
                    if (swrConfig_VSYNC == 0)
                    {
                        str_bool = "OFF";
                    }
                    stdlib__sprintf(config_name, "VSYNC=%s", str_bool);
                    printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                    if (printf_status == 0)
                    {
                        str_bool = "ON";
                        if (swrConfig_LENSFLARE == 0)
                        {
                            str_bool = "OFF";
                        }
                        stdlib__sprintf(config_name, "LENSFLARE=%s", str_bool);
                        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                        if (printf_status == 0)
                        {
                            str_bool = "ON";
                            if (swrConfig_ENGINEEXHAUST == 0)
                            {
                                str_bool = "OFF";
                            }
                            stdlib__sprintf(config_name, "ENGINEEXHAUST=%s", str_bool);
                            printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                            if (printf_status == 0)
                            {
                                stdlib__sprintf(config_name, "TEXTURE_RES=%i", swrConfig_TEXTURE_RES);
                                printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                if (printf_status == 0)
                                {
                                    stdlib__sprintf(config_name, "MODEL_DETAIL=%i", swrConfig_MODEL_DETAIL);
                                    printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                    if (printf_status == 0)
                                    {
                                        stdlib__sprintf(config_name, "DRAWDISTANCE=%i", swrConfig_DRAWDISTANCE);
                                        printf_status = swrConfig_Printf("%-28s%-28s\n", prefix, config_name);
                                        if (printf_status == 0)
                                        {
                                            printf_status = swrConfig_Puts("\nend.\n");
                                            if (printf_status == 0)
                                            {
                                                swrConfig_Close();
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
    swrConfig_Close();
    return 0;
}
