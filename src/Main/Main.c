#include "Main.h"

#include "globals.h"

// 0x004240d0
void Main_Shutdown(void)
{
    // TODO
    (*stdPlatform_hostServices_ptr->debugPrint)("rdShutdown...");
    // TODO
}

// 0x00423cc0
int Main_Startup(char* cmdline)
{
    // TODO
    return 0;
}

// 0x00424430
int Main_ParseCmdLine(char* cmdline)
{
    char* token;
    int cmp_res;
    double atof_res;

    token = stdlib__strtok(cmdline, "\t\n\r");
    if (token == NULL)
    {
        return 0;
    }
    do
    {
        cmp_res = stdlib___strcmpi(token, "-s");
        if (cmp_res == 0)
        {
            token = stdlib__strtok(NULL, "\t\n\r");
            Main_sound = 0;
        }
        else
        {
            cmp_res = stdlib___strcmpi(token, "-p");
            if (cmp_res == 0)
            {
                token = stdlib__strtok(NULL, "\t\n\r");
                Main_sound_unk = 0;
            }
            else
            {
                cmp_res = stdlib___strcmpi(token, "-r");
                if (cmp_res == 0)
                {
                    token = stdlib__strtok(NULL, "\t\n\r");
                    if (token == NULL)
                    {
                        return 1;
                    }
                    atof_res = stdlib__atof(token);
                    Main_sound_rolloff = atof_res;
                    if (Main_sound_rolloff < 0.0)
                    {
                        Main_sound_rolloff = 0.0;
                    }
                }
                else
                {
                    cmp_res = stdlib___strcmpi(token, "-d");
                    if (cmp_res == 0)
                    {
                        token = stdlib__strtok(NULL, "\t\n\r");
                        if (token == NULL)
                        {
                            return 1;
                        }
                        atof_res = stdlib__atof(token);
                        Main_sound_doppler_scale = atof_res;
                        if (Main_sound_doppler_scale < 0.0)
                        {
                            Main_sound_doppler_scale = 0.0;
                        }
                    }
                    else
                    {
                        cmp_res = stdlib___strcmpi(token, "-nut");
                        if (cmp_res != 0)
                        {
                            cmp_res = stdlib___strcmpi(token, "-force");
                            if (cmp_res == 0)
                            {
                                token = stdlib__strtok(NULL, "\t\n\r");
                                Main_force_feedback = 0;
                            }
                            else
                            {
                                cmp_res = stdlib___strcmpi(token, "+3DImpacts");
                                if (cmp_res == 0)
                                {
                                    token = stdlib__strtok(NULL, "\t\n\r");
                                    Main_sound_3dimpact = 0;
                                }
                                else
                                {
                                    cmp_res = stdlib___strcmpi(token, "-v");
                                    if (cmp_res == 0)
                                    {
                                        token = stdlib__strtok(NULL, "\t\n\r");
                                        Main_settings_menu_only = 1;
                                    }
                                    else
                                    {
                                        cmp_res = stdlib___strcmpi(token, "-i");
                                        if (cmp_res == 0)
                                        {
                                            token = stdlib__strtok(NULL, "\t\n\r");
                                            Main_display_intro_scene = 0;
                                        }
                                        else
                                        {
                                            cmp_res = stdlib___strcmpi(token, "-f");
                                            if (cmp_res == 0)
                                            {
                                                token = stdlib__strtok(NULL, "\t\n\r");
                                                Main_fullscreen_unk = 0;
                                            }
                                            else
                                            {
                                                cmp_res = stdlib___strcmpi(token, "-snafu");
                                                if (cmp_res != 0)
                                                    goto next_token;
                                                token = stdlib__strtok(NULL, "\t\n\r");
                                                Main_settings_debug_hud = 1;
                                            }
                                        }
                                    }
                                }
                            }
                            goto end_condition;
                        }
                        token = stdlib__strtok(NULL, "\t\n\r");
                        if (token == NULL)
                        {
                            return 1;
                        }
                        Main_nut_delay_ms = stdlib__atoi(token);
                    }
                }
            next_token:
                token = stdlib__strtok(NULL, "\t\n\r");
            }
        }
    end_condition:
        if (token == NULL)
        {
            return 1;
        }
    } while (true);
}
