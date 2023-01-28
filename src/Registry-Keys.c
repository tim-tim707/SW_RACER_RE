//----- (00424700) --------------------------------------------------------
BOOL __stdcall DialogFunc(HWND hWnd, UINT a2, WPARAM a3, LPARAM dwNewLong)
{
    if (a2 == 272)
    {
        // Some cool debug dialog?
        return sub_424760(hWnd, a3, dwNewLong);
    }

    if (a2 == 273)
    {
        // The Star Wars Racer graphics settings dialog (which lists all devices
        // and resolutions)
        sub_424A90(hWnd, (unsigned __int16)a3, dwNewLong, a3 >> 16);
        return 1;
    }

    return 0;
}

//----- (00423CC0) --------------------------------------------------------
int __usercall load_registry_options @<eax>(int a1 @<esi>, char *a2)
{
    unsigned int *v2; // esi
    int result; // eax
    HWND v4; // eax
    signed int v5; // ST10_4
    signed int v6; // ST10_4
    signed int v7; // ST10_4
    signed int v8; // ST10_4
    signed int v9; // ST10_4
    signed int v10; // ST10_4
    signed int v11; // ST10_4
    signed int v12; // eax
    signed int v13; // [esp+0h] [ebp-10Ch]
    signed int v14; // [esp+0h] [ebp-10Ch]
    signed int v15; // [esp+0h] [ebp-10Ch]
    CHAR PathName; // [esp+Ch] [ebp-100h]

    dword_50B5A0 = 1;
    parse_command_line_args(a2);
    load_platform_abstraction(&unk_E9F280);
    dword_E9F288 = (int)sub_484820;
    dword_E9F290 = (int)sub_484820;
    dword_E9F294 = (int)sub_484820;
    sub_484720((int)&unk_E9F280);
    parse_racer_tab((int)aDataRacerTab);
    sub_4238A0();
    sub_4081C0();
    sub_410FD0(1, a1);
    dword_50B598 = (int)GetModuleHandleA(0);
    sub_49D060(HKEY_LOCAL_MACHINE, SubKey);

    // Load registry values

    *(_DWORD *)&Data = sub_49D230(aFullscreen, *(int *)&Data);
    *(_DWORD *)&dword_50B564 = sub_49D230(aFixFlicker, *(int *)&dword_50B564);
#ifdef DEBUG_BUILD // Assumption
    *(_DWORD *)&dword_50B568 = sub_49D230(aDevmode, *(int *)&dword_50B568);
#else
    *(_DWORD *)&dword_50B568 = 0;
#endif
    *(_DWORD *)&dword_50B56C = sub_49D230(aUsefett, *(int *)&dword_50B56C);

    // ??
    v2 = (unsigned int *)sub_48BC10();
    if (v2)
    {
        sub_4246C0(1);
        sub_4238A0();
        sub_424180(v2, &Data);
        dword_50B58C = 1;

        // Check if some kind of development mode is turned on? (50B5B0 is set
        // to 1 if "-v" was in the command line options)
        if (dword_50B5B0)
        {
            // Create a debug window
            v4 = (HWND)get_hwnd();
            dword_50B58C = sub_4246D0(v4, (LPARAM)&Data);
            result = 0;
        }
        else
        {
            sub_4246C0(0);
            if (!*(_DWORD *)&Data && !*(_DWORD *)&dword_50B568)
                ShowWindow(hWnd, 3);
            dword_50CB68 = *(_DWORD *)&dword_50B568;
            sub_48BE20(v2);
            sub_490950((int)&unk_E9F280);
            hWnd = (HWND)get_hwnd();
            nullsub_2();
            create_dir(aDataConfig);
            sprintf(&PathName, aSS_0, aDataConfig, aCurrent);
            create_dir(&PathName);
            if (sub_409B10(&Data))
            {
                sprintf(aUnknownError, aUnableToOpenDi, OutputString);
                sub_424150();
            }
            sub_4238A0();
            sub_408510();
            sub_408640((int)v2, 0, v13);
            sub_421D90();
            sub_408640((int)v2, 20, v5);
            if (sub_404B10())
            {
                sprintf(aUnknownError, aErrorElfcontro, OutputString);
                sub_424150();
            }
            sub_408640((int)v2, 25, v14);

            // Store the registry keys back
            sub_49D210(aFullscreen, *(int *)&Data);
            sub_49D210(aFixFlicker, *(int *)&dword_50B564);
            sub_49D210(aDevmode, *(int *)&dword_50B568);
            sub_49D210(aUsefett, *(int *)&dword_50B56C);

            sub_409800((int)v2, (int)&Data);
            sub_408640((int)v2, 38, v6);
            sub_49CE90((int)sub_423900);
            sub_408640((int)v2, 40, v7);
            sub_445960();
            sub_408640((int)v2, 45, v8);
            sub_445A50();
            sub_408640((int)v2, 50, v9);
            sub_411950();
            sub_408640((int)v2, 60, v10);
            sub_421810();
            sub_408640((int)v2, 65, v11);
            dword_50B558 = 0;
            if (dword_EC8E5C == 31744 && dword_EC8E60 == 992
                && dword_EC8E64 == 31)
            {
                dword_50B558 = (int)&unk_4EB558;
                v12 = 0xFFFF;
                do
                {
                    v2 = (unsigned int *)dword_50B558;
                    *(_WORD *)(dword_50B558 + 2 * v12) =
                        (v12 >> 1) & 0x7FE0 | v12 & 0x1F;
                    --v12;
                } while (v12 >= 0);
            }
            // buffer of 124 bytes
            memset(&dword_4EB484, 0, 0x7Cu);
            dword_4EB484 = 124;
            dword_4EB488 = 7;
            dword_4EB490 = 640;
            dword_4EB48C = 480;
            dword_4EB4EC = 2048;
            if (!*(_DWORD *)&Data && !*(_DWORD *)&dword_50B568)
                ShowWindow(hWnd, 3);
            sub_408640((int)v2, 90, v15);
            result = 1;
        }
    }
    else
    {
        MessageBoxA(0, Text, Caption, 0x30u);
        result = 0;
    }
    return result;
}
