char __usercall sub_406CC0
    @<al>(char *a1 @<ebx>, int a2, int a3, int a4, char *a5, int a6)
{
    char *v6; // esi
    signed int v7; // edi
    _DWORD *v8; // eax
    const char *v9; // eax
    double v10; // st7
    int v11; // eax
    int v12; // esi
    int v13; // eax
    char *v14; // eax
    const char *v15; // edi
    CHAR *v16; // eax
    const char *v17; // ST20_4
    const char *v18; // ST1C_4
    CHAR *v19; // eax
    const char *v20; // ST20_4
    const char *v21; // eax
    char *v22; // ST18_4
    char *v23; // ST14_4
    char *v24; // eax
    int v25; // eax
    CHAR *v26; // eax
    const char *v27; // ST20_4
    const char *v28; // ST1C_4
    CHAR *v29; // eax
    const char *v30; // ST20_4
    CHAR *v31; // eax
    const char *v32; // ST20_4
    int v33; // esi
    const char *v34; // eax
    CHAR *v35; // eax
    const char *v36; // ST20_4
    const char *v37; // eax
    int v38; // esi
    int v39; // eax
    int v40; // edi
    char *v41; // eax
    char *v42; // esi
    const char *v43; // eax
    const char *v44; // eax
    const char *v45; // eax
    CHAR *v46; // eax
    const char *v47; // ST20_4
    const char *v48; // eax
    const char *v49; // eax
    const char *v50; // eax
    const char *v51; // eax
    char *v52; // ST18_4
    char *v53; // ST14_4
    char *v54; // eax
    int v55; // eax
    const char *v56; // eax
    int v57; // ST1C_4
    const char *v58; // eax
    const char *v59; // eax
    void *v61; // [esp-4h] [ebp-1B8h]
    float v62; // [esp+10h] [ebp-1A4h]
    int v63; // [esp+14h] [ebp-1A0h]
    int v64; // [esp+18h] [ebp-19Ch]
    int v65; // [esp+1Ch] [ebp-198h]
    int v66; // [esp+20h] [ebp-194h]
    char v67; // [esp+24h] [ebp-190h]
    int v68; // [esp+25h] [ebp-18Fh]
    int v69; // [esp+2Ch] [ebp-188h]
    int v70; // [esp+30h] [ebp-184h]
    char v71; // [esp+34h] [ebp-180h]
    char v72; // [esp+74h] [ebp-140h]
    char v73; // [esp+B4h] [ebp-100h]

    v6 = (char *)a4;
    v7 = 0;
    v66 = 0;
    v63 = -1;
    v67 = Class;
    v68 = 0;
    v62 = 0.0;
    LOBYTE(a1) = 0;
    sub_414AF0(a4, &v72, 64);
    sub_414AB0(a4, asc_4B4270, 0);

    if (a3 == 0)
    {
        v8 = sub_414D90(0, 24);
    }
    else if (a3 == 1)
        v8 = sub_414D90(0, 25);
}
else
{
    v8 = sub_414D90(0, 26);
}

v64 = (int)v8;
v70 = 10;
dword_4D6510 = 0;
while (1)
{
    if (v62 == 0.0f)
    {
        if (a3 == 0)
        {
            v9 = a2 ? lookup_translation(aMondotextH0218)
                    : lookup_translation(aMondotextH0219);
        }
        else if (a3 == 1)
        {
            v9 = a2 ? lookup_translation(aMondotextH0218)
                    : lookup_translation(aMondotextH0220);
        }
        else if (a3 == 2)
        {
            v9 = lookup_translation(aMondotextH0221);
        }
        sub_44FCE0((int)v9, 2.0f);
        v62 = 1.7f;
    }
    else
    {
        v10 = v62 - dbl_E22A40;
        v62 = v10;
        if (v10 < 0.0f)
        {
            v62 = 0.0f;
        }
    }

    sub_48DB60();
    sub_489BC0();
    sub_404DD0(a1, v6);
    sub_445980(0, 2);
    sub_415020(0);
    if (!dword_4D6510)
    {
        dword_4D6510 = dword_4D6B4C;
        goto LABEL_89;
    }

    if (v70)
    {
        v70 = 0;
        goto LABEL_89;
    }

    if (sub_407F80(a3) || dword_4D6B44 && (a2 && !dword_4D55D4 || a3 >= 2))
    {
        sub_414AB0((int)v6, &v72, 0);
        v59 = lookup_translation(aMondotextH0222);
        sub_44FCE0((int)v59, 2.0);
        LOBYTE(a1) = 3;
        v7 = 1;
        goto LABEL_89;
    }

    if (!a2)
    {
        v11 = sub_405DD0(a3, 0);
        v12 = v11;

        if (v11 == 0xFFFF)
        {
            goto LABEL_89;
        }

        if (a3 != 2 && v11 == 1)
        {
            LOBYTE(a1) = 1;
        }

        v13 = sub_4079F0((char *)a3, v11, 0, (char *)&v69);
        if (v13 < 0)
        {
            goto LABEL_45;
        }

        v14 = sub_407D90(v13, v69);
        v15 = lookup_translation(v14);
        if (!_strcmpi(v15, a5))
        {
            sub_414AB0(a4, &v72, 0);
            LOBYTE(a1) = (unsigned __int8)a1 | 2;
            v7 = 1;
            goto LABEL_89;
        }
        if (a3 == 2)
        {
            v19 = sub_407B00(v12, 0);
            v20 = lookup_translation(v19);
            sprintf(&v71, aS_0, v20);
        }
        else
        {
            v16 = sub_407B00(v12, &unk_4B2B28);
            v17 = lookup_translation(v16);
            v18 = lookup_translation(aMondotextH0213);
            sprintf(&v71, v18, v17);
        }
        v21 = lookup_translation(aMondotextH0223);
        sprintf(&v73, v21, &v71, v15, a5);
        v22 = (char *)lookup_translation(aMondotextH0033);
        v23 = (char *)lookup_translation(aMondotextH0032);
        v24 = (char *)lookup_translation(aMondotextH0224);
        v25 = sub_4145B0(v64, -1, -1, v24, &v73, v23, v22, 0, 1);
        if (v25 != 1)
        {
            if (v25 == 0xFFFF)
            {
                sub_414AB0(a4, &v72, 0);
                LOBYTE(a1) = (unsigned __int8)a1 | 2;
                v7 = 1;
                goto LABEL_89;
            }
        LABEL_45:
            if (!sub_4078A0((char *)a3, a5, a6, 0, 0, v12))
                (*(void(__cdecl **)(char *, char *, signed int))(
                    dword_ECC420 + 24))(aElfcontrolRepl, aDDevelQa5PcGno_4,
                                        1784);
            if (a3 == 2)
            {
                v31 = sub_407B00(v12, 0);
                v32 = lookup_translation(v31);
                sprintf(&v73, aS_0, v32);
            }
            else if (v12 >= 16)
            {
                v29 = sub_407B00(v12, &unk_4B2B28);
                v30 = lookup_translation(v29);
                sprintf(&v73, aS_0, v30);
            }
            else
            {
                v26 = sub_407B00(v12, &unk_4B2B28);
                v27 = lookup_translation(v26);
                v28 = lookup_translation(aMondotextH0213);
                sprintf(&v73, v28, v27);
            }
            sub_414AB0(a4, &v73, 0);
            LOBYTE(a1) = (unsigned __int8)a1 | 6;
            v7 = 1;
            goto LABEL_89;
        }
    LABEL_78:
        sub_414AB0(a4, &v72, 0);
        LOBYTE(a1) = (unsigned __int8)a1 | 2;
        v7 = 1;
        goto LABEL_89;
    }
    v33 = sub_407700(a3, &v65);
    if (v33 >= 0)
    {
        v34 = lookup_translation(aMondotextH0016);
        if (!_strcmpi(a5, v34))
        {
            if (v65 <= 0)
            {
                if (v65 < 0)
                    sprintf(&v67, asc_4B3BD8);
            }
            else
            {
                sprintf(&v67, asc_4B3ECC);
            }
            v66 = 1;
        }
        v35 = sub_407B00(v33, &unk_4B2AF0);
        v36 = lookup_translation(v35);
        v37 = lookup_translation(aMondotextH0216);
        sprintf(&v73, v37, &v67, v36);
        sub_414AB0(a4, &v73, 0);
        v63 = v33;
    }

    if (v63 >= 0 && dword_4D6B40)
    {
        v38 = v63;
        v39 = sub_4079F0((char *)a3, v63, 1, (char *)&v69);
        v40 = v39;
        if (v39 >= 0)
        {
            v41 = sub_407D90(v39, v69);
            v42 = (char *)lookup_translation(v41);
            v43 = lookup_translation(aMondotextH0021);
            if (!_strcmpi(v42, v43)
                || (v44 = lookup_translation(aMondotextH0020),
                    !_strcmpi(v42, v44)))
            {
                v45 = lookup_translation(aMondotextH0020);
                sprintf(v42, v45);
            }

            if (!_strcmpi(v42, a5))
            {
                sub_414AB0(a4, &v72, 0);
                LOBYTE(a1) = 2;
                v7 = 1;
                goto LABEL_89;
            }

            v46 = sub_407B00(v63, &unk_4B2AF0);
            v47 = lookup_translation(v46);
            v48 = lookup_translation(aMondotextH0228);
            sprintf(&v71, v48, v47);
            v49 = lookup_translation(aMondotextH0020);
            if (!_strcmpi(a5, v49))
            {
                v61 = (void *)lookup_translation(aMondotextH0280);
                goto LABEL_74;
            }

            if (v40 == 7 || v40 == 6)
            {
                v51 = lookup_translation(aMondotextH0229);
                sprintf(&v73, v51, &v71, a5);
            }
            else
            {
                v61 = a5;
            LABEL_74:
                v50 = lookup_translation(aMondotextH0223);
                sprintf(&v73, v50, &v71, v42, v61);
            }

            v52 = (char *)lookup_translation(aMondotextH0033);
            v53 = (char *)lookup_translation(aMondotextH0032);
            v54 = (char *)lookup_translation(aMondotextH0224);
            v55 = sub_4145B0(v64, -1, -1, v54, &v73, v53, v52, 0, 1);
            if (v55 == 1 || v55 == 0xFFFF)
            {
                goto LABEL_78;
            }
            v38 = v63;
        }

        v56 = lookup_translation(aMondotextH0020);
        if (!_strcmpi(a5, v56))
        {
            v57 = -v65;
            v58 = lookup_translation(aMondotextH0021);
            if (!sub_4078A0((char *)a3, v58, a6, 1, v57, v38))
                (*(void(__cdecl **)(char *, char *, signed int))(
                    dword_ECC420 + 24))(aElfcontrolRepl_0, aDDevelQa5PcGno_4,
                                        1857);
            v66 = 1;
        }

        v65 &= -(v66 != 0);
        if (!sub_4078A0((char *)a3, a5, a6, a2, v65, v38))
            (*(void(__cdecl **)(char *, char *, signed int))(
                dword_ECC420 + 24))(aElfcontrolRepl_1, aDDevelQa5PcGno_4, 1862);
        LOBYTE(a1) = 6;
        v7 = 1;
        goto LABEL_89;
    }
LABEL_89:
    nullsub_3();
    sub_48DCE0();
    sub_48DD80();
    sub_489AB0();
    if (v7)
    {
        return (char)a1;
    }
    v6 = (char *)a4;
}
}
