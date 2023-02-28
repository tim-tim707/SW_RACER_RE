signed int __cdecl sub_401000(_DWORD *a1, unsigned int a2, int a3)
{
    _DWORD *v10; // eax
    signed int result; // eax
    _DWORD *v12; // esi
    _DWORD *v13; // esi
    const char *v14; // eax
    _DWORD *v15; // esi
    _DWORD *v16; // esi
    const char *v17; // eax
    char *v18; // ST14_4
    char *v19; // ST10_4
    char *v20; // eax
    _DWORD *v21; // esi
    char *v22; // ST18_4
    char *v23; // ST14_4
    char *v24; // eax
    uint8_t *byte = (_BYTE *)(dword_50C454 + 81);
    DWORD *ptr;
    ptr = sub_414D90(a1, 12);
    sub_414E60((int)ptr, *byte == 0);
    ptr = sub_414D90(a1, 14);
    sub_414E60((int)ptr, *byte == 0);
    ptr = sub_414D90(a1, 13);
    sub_414E60((int)ptr, *byte == 0);
    ptr = sub_414D90(a1, 15);
    sub_414E60((int)ptr, *byte == 0);
    ptr = sub_414D90(a1, 16);
    sub_414E60((int)ptr, *byte == 0);
    ptr = sub_414D90(a1, 1);
    sub_414E60((int)ptr, *byte == 0);
    for (int v9 = 0; v9 < 26; v9++)
    {
        ptr = sub_414D90(a1, v9 + 10000);
        sub_414E60((int)ptr, *byte);
    }

    // Not 100% sure about RE in what is following

    if (a2 == 19)
    {
        return 1;
    }
    else if (a2 == 14)
    {
        if (a3)
        {
            dword_4B2940 = 0;
            dword_4D6B6C = 0;
            sub_412640(0);
        }
        return 0;
    }
    else if (a2 == 100)
    {
        if (dword_4D5570 == 13)
        {
            dword_4D5570 = 0;
            return 0;
        }
        else if (dword_4D5570 == 16)
        {
            if (!a3)
            {
                sub_4240D0();
                exit_0(0);
            }
            dword_4D5570 = 0;
            return 0;
        }
        else
        {
            return 0;
        }
    }
    else if (a2 == 1000)
    {
        switch (a3)
        {
        case 12:
            v12 = sub_414D90(0, 10038);
            sub_40C4E0(v12);
            v13 = sub_414D90(v12, 1);
            v14 = lookup_translation(
                aMondotextH0000); // "/MONDOTEXT_H_0000/SINGLE-PLAYER
                                  // FREEPLAY ~nRACER ROSTER"
            sub_414B80((int)v13, (int)v14, 0);
            dword_50C450 = 0;
            sub_411820(10038);
            break;
        case 13:
            dword_50C450 = 0;
            if (sub_41E9D0())
            {
                sub_411820(100005);
            }
            else
            {
                v18 = (char *)lookup_translation(
                    aMondotextH0521); // "/MONDOTEXT_H_0521/~sOK"
                v19 = (char *)lookup_translation(
                    aMondotextH0520); // "/MONDOTEXT_H_0520/~sYou must have IPX
                                      // installed to play multiplayer"
                v20 = (char *)lookup_translation(
                    aMondotextH0519); // "/MONDOTEXT_H_0519/~sMultiplayer"
                sub_4145B0((int)a1, -1, -1, v20, v19, v18, 0, 0, 0);
                dword_4D5570 = 13;
            }
            break;
        case 14:
            v15 = sub_414D90(0, 10038);
            sub_40C4E0(v15);
            v16 = sub_414D90(v15, 1);
            v17 = lookup_translation(
                aMondotextH0001); // "/MONDOTEXT_H_0001/SINGLE-PLAYER
                                  // TOURNAMENT ~nRACER ROSTER"
            sub_414B80((int)v16, (int)v17, 0);
            dword_50C450 = 1;
            sub_411820(10038);
            break;
        case 15:
            sub_411820(21);
            break;
        case 16:
            v21 = sub_414D90(0, 11);
            v22 = (char *)lookup_translation(
                aMondotextH0033); // "/MONDOTEXT_H_0033/~sNo"
            v23 = (char *)lookup_translation(
                aMondotextH0032); // "/MONDOTEXT_H_0032/~sYes"
            v24 = (char *)lookup_translation(
                aMondotextH0523); // "/MONDOTEXT_H_0523/Are you sure you want to
                                  // quit the game?"
            sub_4145B0((int)v21, -1, -1, &Class, v24, v23, v22, 0, 0);
            dword_4D5570 = 16;
            break;
        default:
            break;
        }
        return 0;
    }
    else
    {
        return 0;
    }
}
signed int __cdecl sub_401000(_DWORD *a1, unsigned int a2, int a3)
{
    _DWORD *v3; // eax
    _DWORD *v4; // eax
    _DWORD *v5; // eax
    _DWORD *v6; // eax
    _DWORD *v7; // eax
    _DWORD *v8; // eax
    signed int v9; // edi
    _DWORD *v10; // eax
    signed int result; // eax
    _DWORD *v12; // esi
    _DWORD *v13; // esi
    const char *v14; // eax
    _DWORD *v15; // esi
    _DWORD *v16; // esi
    const char *v17; // eax
    const char *v18; // eax
    _DWORD *v19; // esi
    char *v20; // ST18_4
    char *v21; // ST14_4
    char *v22; // eax

    v3 = sub_415A00(a1, 12);
    sub_415AD0((int)v3, *(_BYTE *)(dword_51771C + 81) == 0);
    v4 = sub_415A00(a1, 14);
    sub_415AD0((int)v4, *(_BYTE *)(dword_51771C + 81) == 0);
    v5 = sub_415A00(a1, 13);
    sub_415AD0((int)v5, *(_BYTE *)(dword_51771C + 81) == 0);
    v6 = sub_415A00(a1, 15);
    sub_415AD0((int)v6, *(_BYTE *)(dword_51771C + 81) == 0);
    v7 = sub_415A00(a1, 16);
    sub_415AD0((int)v7, *(_BYTE *)(dword_51771C + 81) == 0);
    v8 = sub_415A00(a1, 1);
    sub_415AD0((int)v8, *(_BYTE *)(dword_51771C + 81) == 0);
    v9 = 0;
    do
    {
        v10 = sub_415A00(a1, v9 + 10000);
        sub_415AD0((int)v10, *(char *)(dword_51771C + 81));
        ++v9;
    } while (v9 < 26);
    if (a2 <= 0x13)
    {
        if (a2 == 19)
            return 1;
        if (a2 == 14 && a3)
        {
            dword_4B7950 = 0;
            dword_4E1E0C = 0;
            sub_413240(0);
            return 0;
        }
        return 0;
    }
    if (a2 == 100)
    {
        if (dword_4E0810 != 13)
        {
            if (dword_4E0810 != 16)
                return 0;
            if (!a3)
            {
                sub_425380();
                exit_0(0);
            }
        }
        dword_4E0810 = 0;
        return 0;
    }
    if (a2 != 1000)
        return 0;
    switch (a3)
    {
    case 12:
        v12 = sub_415A00(0, 10038);
        sub_40C660(v12);
        v13 = sub_415A00(v12, 1);
        v14 = sub_422220(aMondotextH0000);
        sub_4157F0((int)v13, (int)v14, 0);
        dword_517718 = 0;
        sub_412400(10038);
        result = 0;
        break;
    case 13:
        v18 = sub_422220(aMondotextH0616); // "/MONDOTEXT_H_0616/~f4~n~n OPTION
                                           // AVAILABLE IN FULL VERSION ONLY"
        sub_454210((int)v18, 3.0); // Flashes text on bottom of screen
        result = 0;
        break;
    case 14:
        v15 = sub_415A00(0, 10038);
        sub_40C660(v15);
        v16 = sub_415A00(v15, 1);
        v17 = sub_422220(aMondotextH0001);
        sub_4157F0((int)v16, (int)v17, 0);
        dword_517718 = 1;
        sub_412400(10038);
        result = 0;
        break;
    case 15:
        sub_412400(21);
        result = 0;
        break;
    case 16:
        v19 = sub_415A00(0, 11);
        v20 = (char *)sub_422220(aMondotextH0033);
        v21 = (char *)sub_422220(aMondotextH0032);
        v22 = (char *)sub_422220(aMondotextH0523);
        sub_415220((int)v19, -1, -1, &Class, v22, v21, v20, 0, 0);
        dword_4E0810 = 16;
        result = 0;
        break;
    default:
        return 0;
    }
    return result;
}
