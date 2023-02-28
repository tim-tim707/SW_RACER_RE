signed int __cdecl sub_406080(int a1)
{
    signed int result; // eax
    signed int v2; // ebx
    char *v3; // esi
    int v4; // ebp
    int v5; // edi
    char v6; // bl
    CHAR *v7; // eax
    char *v8; // eax
    CHAR *v9; // eax
    char *v10; // eax
    CHAR *v11; // eax
    char *v12; // eax
    char *v13; // eax
    char *v14; // eax
    int v15; // esi
    int *v16; // edi
    CHAR *v17; // eax
    char *v18; // eax
    signed int v19; // [esp+1Ch] [ebp-194h]
    char *v20; // [esp+20h] [ebp-190h]
    signed int v21; // [esp+24h] [ebp-18Ch]
    int v22; // [esp+28h] [ebp-188h]
    int *v23; // [esp+2Ch] [ebp-184h]
    char v24; // [esp+30h] [ebp-180h]
    char v25; // [esp+50h] [ebp-160h]
    char v26; // [esp+70h] [ebp-140h]
    char v27; // [esp+90h] [ebp-120h]
    char v28; // [esp+B0h] [ebp-100h]

    sprintf(&v28, aSSSS, aDataConfig, a1, a1, aControlMap);
    if (sub_4877D0(&v28))
    {
        v2 = 0;
        v19 = 0;
        while (1)
        {
            if (v2)
            {
                if (v2 == 1)
                {
                    v20 = byte_4D6518;
                    v21 = 3;
                    v23 = dword_EC8790;
                    v22 = dword_4D6B38;
                    sprintf(&v25, aMouse);
                }
                else if (v2 == 2)
                {
                    v20 = byte_4D6828;
                    v21 = 0;
                    v22 = dword_4B2948;
                    sprintf(&v25, aKeyboard);
                }
            }
            else
            {
                v20 = byte_4D5FC0;
                v21 = 6;
                v23 = dword_EC8880;
                v22 = dword_4B2944;
                sprintf(&v25, aJoystick);
            }
            sub_4879F0(aSMappings, &v25);
            v3 = v20;
            if (*v20 != -1)
                break;
        LABEL_28:
            sub_4879F0(asc_4B3D48);
            v15 = 0;
            if (v21 > 0)
            {
                v16 = v23;
                do
                {
                    if (*v16)
                    {
                        v17 = sub_407B00(v15, &unk_4B2AF0);
                        v18 = sub_421470(v17);
                        sprintf(&v24, aAxisS, v18);
                        sub_4879F0(a28s28sflipAxis, &v25, &v24);
                    }
                    ++v15;
                    ++v16;
                } while (v15 < v21);
            }
            if (v2 < 2 && dword_EC8780[v2] != 1065353216)
            {
                sprintf(&v24, aSensitivity02f, (_QWORD)dword_EC8780[v2]);
                sub_4879F0(a28s28s, &v25, &v24);
            }
            if (!v2 && dword_EC876C != *(float *)&dword_4B297C)
            {
                sprintf(&v24, aDeadzone02f, dword_EC876C);
                sub_4879F0(a28s28s, &v25, &v24);
            }
            if (v22)
                sprintf(&v24, aEnabledTrue);
            else
                sprintf(&v24, aEnabledFalse);
            sub_4879F0(a28s28s, &v25, &v24);
            v19 = ++v2;
            if (v2 >= 3)
            {
                sub_4879A0(aEnd_0);
                sub_487960();
                return 1;
            }
        }
        while (1)
        {
            v4 = *((_DWORD *)v3 + 2);
            v5 = *((_DWORD *)v3 + 1);
            v6 = *v3;
            v3 += 12;
            sprintf(&v26, &Class);
            if (v6 & 8 && v19 != 2)
            {
                v7 = sub_407B00(v5, &unk_4B2B28);
                v8 = sub_421470(v7);
                sprintf(&v24, aButtonS, v8);
            }
            else if (v6 & 8 && v19 == 2)
            {
                v9 = sub_407B00(v5, &unk_4B2BD0);
                v10 = sub_421470(v9);
                sprintf(&v24, aKeyS, v10);
            }
            else if (v6 & 4)
            {
                v11 = sub_407B00(v5, &unk_4B2AF0);
                v12 = sub_421470(v11);
                sprintf(&v24, aAxisS, v12);
                if (v6 & 0x10)
                {
                    sprintf(&v26, aAxisRangePosit);
                }
                else if (v6 & 0x20)
                {
                    sprintf(&v26, aAxisRangeNegat);
                }
            }
            if (!(v6 & 8))
                v6 &= 0xCFu;
            v13 = sub_407D90(v4, v6 & 0xF3);
            v14 = sub_421470(v13);
            if (v14)
            {
                sprintf(&v27, aFunctionS, v14);
                if (sub_4879F0(a28s28s28s28s, &v25, &v24, &v27, &v26))
                    break;
            }
            if (*v3 == -1)
            {
                v2 = v19;
                goto LABEL_28;
            }
        }
        sub_487960();
        result = 0;
    }
    else
    {
        sub_487960();
        result = -1;
    }
    return result;
}
signed int __cdecl sub_406470(int a1, const char *a2, int a3)
{
    signed int v5; // edi
    char *v6; // ebp
    const char **v8; // esi
    const char *v9; // ST10_4
    _DWORD *v13; // esi

    // FIXME: This union might actually be bigger, that would explain why v17 is
    // left unused.
    //        However, it seems to be stored in 12 byte per element array..
    //        soooo.. idk
    union
    {
        typedef struct
        {
            uint32_t flags; // FIXME: There is strong indication that this is
                            // only 8 bit, then 3 byte padding
            uint32_t input; // The button or axis which the user will use
            uint32_t function; // The function the game will map this to
        } InputSetting;

        struct
        {
            int v14; // [esp+10h] [ebp-130h]
            int v15; // [esp+14h] [ebp-12Ch]
            int v16; // [esp+18h] [ebp-128h]
        };
    };
    char *v17; // [esp+1Ch] [ebp-124h]

    char v18[32]; // [esp+20h] [ebp-120h]
    char v24[256]; // [esp+40h] [ebp-100h]

    strcpy(v18, "control.map");

    if (a3)
    {
        if (!strcmp(a2, aWheel))
        {
            sprintf(v18, aWheelMap);
        }
        else if (strlen(a2) != 0)
        {
            sprintf(v18, aS_0, a2);
        }
        sprintf(v24, aSSS_0, &unk_E9F300, aDataConfigDefa, v18);
    }
    else
    {
        sprintf(v24, aSSSS, aDataConfig, a2, a2, aControlMap);
    }

    // Open the config file and tokenize it
    if (!file_access_fopen(v24))
    {
        file_access_close();
        return -1;
    }

    // Clear the first 2 jostick inputs?!
    if (a1 < 0 || a1 == 0)
    {
        memset(dword_EC8880, 0, 0x18u);
    }

    // Clear the first mouse input?!
    if (a1 < 0 || a1 == 1)
    {
        dword_EC8790[0] = 0;
        dword_EC8794 = 0;
        dword_EC8798 = 0;
    }

    // Clear the input.. again?!
    sub_407800(a1);

    // Simulate v5 and v6 containing garbage from stack?!
    v5 = (signed int)v17;
    v6 = v17;

    while (read_line_unk())
    {
        if (!strcmp(config_string_EC8E84, aEnd))
        {
            break;
        }

        // Pointer to tokens
        typedef struct
        {
            const char *key;
            const char *value;
        } KeyValue;
        v8 = (const char **)&config_string_EC8E84;

        // Clear settings for this button config
        LOBYTE(v14) = 0;
        v15 = 0;
        v16 = -1;

        // Loop over each key / column
        for (uint32_t v7 = 0; v7 < dword_EC8E80; v7++)
        {
            if (!_strcmpi(v8[0] aJoystick))
            {
                v5 = 0;
                v6 = byte_4D5FC0;
            }
            elseif(!_strcmpi(v8[0] aMouse))
            {
                v5 = 1;
                v6 = byte_4D6518;
            }
            else if (!_strcmpi(v8[0] aKeyboard))
            {
                v5 = 2;
                v6 = byte_4D6828;
            }
            else if (!_strcmpi(v8[0] aAxis))
            {
                LOBYTE(v14) = v14 | 4;
                v15 = sub_407A90(v8[1], &unk_4B2AF0);
            }
            else if (!_strcmpi(v8[0] aButton))
            {
                v9 = v8[1];
                LOBYTE(v14) = v14 | 8;
                v15 = sub_407A90(v9, &unk_4B2B28);
            }
            else if (!_strcmpi(v8[0] "KEY"))
            {
                LOBYTE(v14) = v14 | 8;
                v15 = sub_407A90(v8[1], &unk_4B2BD0);
            }
            else if (!_strcmpi(v8[0] aFunction))
            {
                if (!sub_407CD0((int)&v14, v8[1], 0))
                {
                    sub_407800(a1);
                    file_access_close();
                    return 0;
                }
            }
            else if (!_strcmpi(v8[0] aAxisRange))
            {
                if (!_strcmpi(v8[1], aPositive))
                {
                    LOBYTE(v14) = v14 | 0x10;
                }
                else if (!_strcmpi(v8[1], aNegative))
                {
                    LOBYTE(v14) = v14 | 0x20;
                }
                else
                {
                    sub_407800(a1);
                    file_access_close();
                    return 0;
                }
            }
            else if ((a1 < 0 || a1 == v5) && !_strcmpi(v8[0] aFlipAxis))
            { // FIXME: Review this condition
                if (v5 == 0)
                {
                    dword_EC8880[v15] = 1;
                }
                else if (v5 == 1)
                {
                    dword_EC8790[v15] = 1;
                }
                else
                {
                    sub_407800(a1);
                    file_access_close();
                    return 0;
                }
            }
            else if (!_strcmpi(v8[0] aSensitivity))
            {
                *(float *)&dword_EC8780[v5] = atof(v8[1]);
            }
            else if (!_strcmpi(v8[0] aDeadzone))
            {
                if (!v5)
                {
                    dword_EC876C = atof(v8[1]);
                }
            }
            else if (!_strcmpi(v8[0] aEnabled))
            {
                BOOL v10 = !_strcmpi(v8[1], aTrue);
                if (v5 == 0)
                {
                    dword_4B2944 = v10 && dword_4B294C;
                }
                else if (v5 == 1)
                {
                    dword_4D6B38 = v10 && dword_4B2950
                }
                // FIXME: You'd expect an error handler here?!
            }

            // Error if the button / axis is not known
            if (v15 < 0)
            {
                sub_407800(a1);
                file_access_close();
                return 0;
            }

            v8 += 2;
        }

        // Store this buttons config
        if ((a1 < 0 || a1 == v5) && v16 > -1)
        {
            uint32_t *v11 = &v6[12 * dword_4D5E20[v5]];
            v11[0] = v14;
            v11[1] = v15;
            v11[2] = v16;
            ++dword_4D5E20[v5];
        }
    }

    // Unknown, but seems to add a special entry for keyboards
    if (a1 < 0 || a1 == 2)
    {
        LOBYTE(v14) = 10;
        dword_4D5E28++;
        v13 = (_DWORD *)(12 * dword_4D5E28 + 0x4D6828);
        v13[0] = v14;
        v13[1] = 1;
        v13[2] = 10;
    }

    // Mark last entry in each device type
    if (a1 < 0 || a1 == 0)
    {
        byte_4D5FC0[12 * dword_4D5E20[0]] = -1;
    }
    if (a1 < 0 || a1 == 1)
    {
        byte_4D6518[12 * dword_4D5E24] = -1;
    }
    if (a1 < 0 || a1 == 2)
    {
        byte_4D6828[12 * dword_4D5E28] = -1;
    }

    file_access_close();
    return 1;
}
