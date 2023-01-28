int __cdecl sub_41DF10(int a1, int a2, signed int a3, int a4, double a5,
                       double a6, int *a7, _DWORD *a8, int a9)
{
    int result; // eax
    char *v10; // edx
    int v11; // ecx
    int v12; // edx
    _DWORD *v13; // eax
    int v14; // esi
    _DWORD *v15; // eax
    int v16; // eax
    int v17; // eax
    void *v18; // ST0C_4
    const char *v19; // eax
    char v20; // [esp+Ch] [ebp-400h]

    result = dword_4D5E00;
    if (dword_4D5E00)
    {
        result = dword_4EB3B4;
        *(_DWORD *)&dword_EC7BC8 = dword_4EB3B4;
        dword_EC7BCC = a3;
        v10 = (char *)&dword_EC7BD0;
        if (a3 > 1668575852)
        {
            if (a3 > 1718378861)
            {
                if (a3 > 1819243380)
                {
                    if (a3 > 1886550137)
                    {
                        if (a3 > 1919249006)
                        {
                            if (a3 == 1952544110)
                            {
                                *(double *)qword_EC7BD4 = a5;
                                *(_DWORD *)&dword_EC7BD0 = a4;
                                v10 = (char *)&dword_EC7BDC;
                            }
                            else
                            {
                                if (a3 != 1953655143)
                                    return result;
                                *(_DWORD *)&dword_EC7BD0 = a4;
                                *(_DWORD *)qword_EC7BD4 = LODWORD(a5);
                                v10 = &qword_EC7BD4[4];
                            }
                        }
                        else if (a3 != 1919249006)
                        {
                            if (a3 != 1903520116)
                                return result;
                            dword_EA04E0[dword_4EB3B4] = 1;
                            v16 = 4 * result;
                            dword_EA05C0[v16] = 666;
                            dword_EA05C4[v16] = 0;
                            dword_EA05C8[v16] = 0;
                            dword_EA05CC[v16] = 0;
                        }
                    }
                    else if (a3 == 1886550137)
                    {
                        v12 = 0;
                        v13 = &unk_E29BC4;
                        do
                        {
                            if (*v13 == 1094797641 || *v13 == 1282368364)
                                ++v12;
                            v13 += 34;
                        } while ((signed int)v13 < (signed int)&unk_E2A664);
                        *(_DWORD *)&dword_EC7BD0 = v12;
                        v10 = qword_EC7BD4;
                        v14 = 0;
                        v15 = &unk_E29BC4;
                        do
                        {
                            if (*v15 == 1094797641 || *v15 == 1282368364)
                            {
                                *(_DWORD *)v10 = v14;
                                v10 += 4;
                            }
                            v15 += 34;
                            ++v14;
                        } while ((signed int)v15 < (signed int)&unk_E2A664);
                    }
                    else
                    {
                        if (a3 != 1886151024)
                            return result;
                        *(_DWORD *)&dword_EC7BD0 = a4;
                        v10 = &qword_EC7BD4[4];
                        *(float *)qword_EC7BD4 = a5;
                    }
                }
                else if (a3 == 1819243380)
                {
                    *(_DWORD *)&dword_EC7BD0 = a4;
                    v10 = qword_EC7BD4;
                }
                else
                {
                    if (a3 != 1751477356)
                        return result;
                    v10 = qword_EC7BD4;
                    *(_DWORD *)&dword_EC7BD0 = a4;
                }
            }
            else if (a3 == 1718378861)
            {
                v10 = qword_EC7BD4;
                *(_DWORD *)&dword_EC7BD0 = a4;
            }
            else
            {
                if (a3 != 1718185577)
                    return result;
                dword_EA02C0[dword_4EB3B4] = 1;
            }
        }
        else if (a3 != 1668575852)
        {
            if (a3 != 1399878251)
                return result;
            *(_DWORD *)&dword_EC7BD0 = a4;
            *(float *)qword_EC7BD4 = a5;
            *(float *)&qword_EC7BD4[4] = a6;
            dword_EC7BDC = *a7;
            dword_EC7BE0 = a7[1];
            dword_EC7BE4 = a7[2];
            *(_DWORD *)&dword_EC7BE8 = *a8;
            dword_EC7BEC = a8[1];
            v11 = a8[2];
            dword_EC7BF4 = a9;
            dword_EC7BF0 = v11;
            v10 = (char *)&unk_EC7BF8;
        }
        dword_EC7BC0 = v10 - (char *)&dword_EC7BC8;
        dword_EC7BA4 = 0;
        word_EC7BC4 = 23;
        result = sub_41B760((int)&unk_EC7BA0, a1, 1, a2);
        if (a3 == 1903520116)
        {
            if (dword_4EB1C8
                || (v17 = dword_4EB3B4, dword_4B6714 == dword_4EB3B4))
            {
                sub_41C8E0();
                v17 = dword_4EB3B4;
            }
            dword_EA04E0[v17] = 1;
            v18 = sub_41BCE0(v17);
            v19 = sub_421360(aMondotextH0500);
            sprintf(&v20, v19, v18);
            result = (int)sub_41C190(&v20);
        }
    }
    return result;
}
signed int __cdecl sub_41E260(_DWORD *a1)
{
    int v1; // edi
    signed int v2; // ebp
    int *v3; // esi
    int v4; // eax
    float v5; // ST28_4
    float v6; // ST2C_4
    float v7; // ST14_4
    int v8; // eax
    float v9; // ecx
    int v10; // eax
    int v11; // eax
    int v12; // ebx
    char *v13; // ST14_4
    void *v14; // ST0C_4
    const char *v15; // eax
    int v16; // edi
    int v17; // eax
    int v18; // eax
    int v20; // eax
    signed int v21; // eax
    int v22; // [esp+18h] [ebp-118h]
    int v23; // [esp+1Ch] [ebp-114h]
    int v24; // [esp+20h] [ebp-110h]
    int v25; // [esp+24h] [ebp-10Ch]
    int v26; // [esp+28h] [ebp-108h]
    int v27; // [esp+2Ch] [ebp-104h]
    char v28; // [esp+30h] [ebp-100h]

    // FIXME: This refactor assumes that dword_4EB1E8 is not manipulated during
    // this function (or any subs)!
    if (dword_4EB1E8 == 0)
    {
        return 1;
    }

    v1 = a1[10];
    v2 = a1[11];
    v3 = a1 + 12;

    if (v2 == 1903520116)
    {
        dword_EA04E0[v1] = 1;
        v18 = 4 * v1;
        dword_EA05C0[v18] = 666;
        dword_EA05C4[v18] = 0;
        dword_EA05C8[v18] = 0;
        dword_EA05CC[v18] = 0;
        if (dword_4EB1C8)
        {
            sub_41C990(v1);
        }
    }
    else if (v2 == 1886550137)
    {
        v3 = a1 + 13;
        dword_4B6714 = dword_4EB3B4;
        v16 = a1[12];
        if (v16 > 0)
        {
            do
            {
                v17 = *v3;
                ++v3;
                sub_41C990(v17);
                --v16;
            } while (v16);
        }
    }
    else if (v2 == 1919249006)
    {
        sub_411120(65, 0);
        dword_4EB1EC = 1;
    }
    else if (v2 == 1952544110)
    {
        v21 = *v3;
        v3 = a1 + 15;
        sub_427410(v21, a1[13], a1[14], 7976 * v1 + 15337296);
    }
    else if (v2 == 1953655143)
    {
        v20 = *v3;
        v3 = a1 + 14;
        sub_47E7E0(v20, a1[13]);
    }
    else if (v2 == 1886151024)
    {
        v12 = *v3;
        v3 = a1 + 14;
        v13 = sub_41BC20(*((float *)a1 + 13));
        v14 = sub_41BCE0(v1);
        v15 = sub_421360(aMondotextH0511);
        sprintf(&v28, v15, v14, v12, v13);
        sub_41C190(&v28);
    }
    else if (v2 == 1819243380)
    {
        v11 = *v3;
        v3 = a1 + 13;
        sub_41C990(v11);
    }
    else if (v2 == 1751477356)
    {
        v8 = *v3;
        v3 = a1 + 13;
        v9 = dword_E29C44[34 * v8];
        if (v9 != 0.0)
        {
            *(_DWORD *)(LODWORD(v9) + 100) |= 0x40000u;
        }
        v10 = 4 * v8;
        dword_EA05C0[v10] = 666;
        dword_EA05C4[v10] = 0;
        dword_EA05C8[v10] = 0;
        dword_EA05CC[v10] = 0;
    }
    else if (v2 == 1718185577)
    {
        *(_DWORD *)(dword_E28960 + 136 * v1 + 8) |= 2u;
        dword_EA02C0[v1] = 1;
    }
    else if (v2 == 1399878251)
    {
        if (dword_4EB1E0)
        {
            v4 = *v3;
            v5 = *((float *)a1 + 13);
            v6 = *((float *)a1 + 14);
            v25 = a1[15];
            v26 = a1[16];
            v27 = a1[17];
            v22 = a1[18];
            v3 = a1 + 22;
            v23 = a1[19];
            v7 = *((float *)a1 + 21);
            v24 = a1[20];
            sub_477850(LODWORD(dword_E29C44[34 * v4]), v5, v6, (int)&v25,
                       (int)&v22, v7);
        }
    }
    else if (v2 == 1668575852)
    {
        dword_4B6714 = -1;
        sub_41C940(dword_4EB1E8);
    }
    else if (v2 == 1718378861)
    {
        sub_46BB50(*v3);
    }
    else
    {
        return 0;
    }
    return 1;
}
signed int __stdcall sub_487450(int a1, int a2, char a3, int a4)
{
    if (a3 & 1)
    {
        return 0;
    }

    if ((unsigned int)dword_513870 < 32)
    {
        sub_4876D0(a1, 0x5117E8 + dword_513870 * 260);
        dword_513870++;
    }
    return 1;
}
int __cdecl sub_4871B0(unsigned int a1)
{
    dword_510250 = 0;
    memset(&word_50FEE0, 0, 0x370u);
    if (dword_51386C)
        return (*(int(__stdcall **)(LPVOID, _DWORD, _DWORD, _DWORD, _DWORD))(
            *(_DWORD *)ppv + 48))(ppv, 0, sub_4874A0, 0, 0);
    if (a1 >= dword_513870)
        return -2147467259;
    return (
        *(int(__stdcall **)(LPVOID, unsigned int, _DWORD, _DWORD, signed int))(
            *(_DWORD *)ppv + 48))(ppv, 260 * a1 + 5314536, sub_4874A0, 0, 128);
}
signed int __stdcall sub_4874A0(int a1, int a2, int a3, int a4, int a5)
{
    void *v5; // edx
    const wchar_t *v6; // eax
    char v9; // [esp+8h] [ebp-400h]

    // Only look at players, not groups
    if (a2 != 1)
    {
        return 1;
    }

    if ((unsigned int)dword_510250 < 20)
    {
        v5 = (void *)(0x50FEE0 + dword_510250 * 44);
        memset(v5, 0, 0x2Cu);

        v6 = *(const wchar_t **)(a3 + 8);
        if (v6)
        {
            wcsncpy((wchar_t *)v5, v6, 0x13u);
            word_50FF06[dword_510250 * 22] = 0;
        }

        sub_48C380(&v9, *(_WORD **)(a3 + 8), 1024);
        dword_50FF08[dword_510250 * 11] = a1;

        dword_510250++;
    }
    return 1;
}
int sub_487340()
{
    return dword_510250;
}
// a1 = playerindex
void *__cdecl sub_41BCE0(int a1)
{
    sub_48C380(&unk_4EAD88, &word_E9F3C4 + 88 * a1, 32);
    return &unk_4EAD88;
}
_DWORD *__cdecl sub_41C190(char *a1)
{
    _DWORD *result; // eax

    if (a1)
    {
        result = 0;
        if (strlen(a1) != 0)
        {
            sub_41D0C0(a1, -1, dword_4EB3B4);
            result = sub_41C130(a1);
        }
    }
    return result;
}
