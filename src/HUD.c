void sub_462CF0()
{
    void *v0 = sub_450B30(0x4A646765, 0); // Looks for object 0 of type 'Jdge'
    sub_426C80(143, 6, 0.25, 0.2, 1);
    sub_45E1A0(v0);
    sub_463580(v0);
}
typedef struct
{
    ... int16_t current_position; // 92, 0 if the first lap hasn't started
    uint16_t unk23b; // 94
  float unk[???]; // 96 Something to do with lap records
  ... float some_position; // 116
  uint32_t current_lap; // 120
  ... Address unk_pointer; // 132
} A1;

typedef struct
{
    // 292, something which controls some text position?!
    ... uint32_t unk; // 428 Something to do with boost
    ... uint32_t racer_count; // 444
    uint32_t unk; // 448 Something to do with boost
    ... uint32_t lap_count; // 456
    ... float unk116; // 464 Something to do with lap records
} A2;

//----- (00460950) --------------------------------------------------------
// a1 = Some struct which has race / position information
// a2 = Some struct which has race / position information
int __cdecl sub_460950(int a1, int a2)
{
    int v2; // ebp
    int v3; // ebx
    int v4; // esi
    BOOL v5; // edi
    char v7; // c0
    int v8; // eax
    unsigned __int64 v9; // st7
    const char *v10; // eax
    int v11; // eax
    signed int v12; // esi
    double v13; // st7
    signed int v14; // ebp
    int v15; // ebx
    const char *v16; // ST1C_4
    const char *v17; // ST1C_4
    const char *v18; // ST1C_4
    double v19; // st7
    double v20; // st7
    signed int v21; // edi
    double v22; // st7
    char v23; // bp
    double v24; // st7
    int v25; // ebx
    double v26; // st7
    const char *v27; // eax
    const char *v28; // ST1C_4
    const char *v29; // ST1C_4
    int v30; // eax
    int v31; // eax
    int v32; // ST1C_4
    int v33; // ST18_4
    const char *v34; // eax
    __int16 v35; // si
    __int16 v36; // di
    __int16 v37; // bx
    const char *v38; // ST1C_4
    __int16 v39; // di
    const char *v40; // ST1C_4
    int v41; // eax
    __int16 v42; // ax
    int v43; // ST1C_4
    int v44; // ST18_4
    const char *v45; // eax
    const char *v46; // eax
    int result; // eax
    float v48; // [esp+18h] [ebp-128h]
    float v49; // [esp+18h] [ebp-128h]
    float v50; // [esp+1Ch] [ebp-124h]
    float v51; // [esp+1Ch] [ebp-124h]
    float v52; // [esp+1Ch] [ebp-124h]
    float v53; // [esp+20h] [ebp-120h]
    signed int v54; // [esp+24h] [ebp-11Ch]
    signed int v55; // [esp+28h] [ebp-118h]
    float v56; // [esp+2Ch] [ebp-114h]
    __int64 v57; // [esp+30h] [ebp-110h]
    signed int v58; // [esp+38h] [ebp-108h]
    int v59; // [esp+3Ch] [ebp-104h]
    char v60; // [esp+40h] [ebp-100h]

    LOWORD(v57) = 164;
    v2 = a1;
    v3 = sub_45D350();
    v4 = *(_DWORD *)(a1 + 132);
    v5 = a1 == dword_E27820;
    v58 = v3;
    HIDWORD(v57) = a1 == dword_E27820;
    v59 = *(_DWORD *)(a1 + 132);

    if (!sub_445690())
    {
        if (v7)
        {
            *(float *)(v4 + 696) = 0.0f;
        }
        else
        {
            *(float *)(v4 + 696) -= dbl_E22A40;
        }
    }

    v8 = *(_DWORD *)(a2 + 292);
    if (v8 == 0)
    {
        sub_4603F0(COERCE_FLOAT(2));
    }
    else if (v8 == 1)
    {
        sub_4603F0(COERCE_FLOAT(5));
    }
    else
    {
        sub_4603F0(0.0);
    }

    v50 = 254.0;
    v48 = 190.0;
    if (v3 == 2)
    {
        v50 = 277.0;
        v48 = (double)(110 * v5 + 96);
    }

    *(double *)&v9 = *(float *)(*(_DWORD *)(a1 + 132) + 416);
    if (*(double *)&v9 <= 0.0)
    {
        *(double *)&v9 = 0.0;
    }

    v10 = sub_421360(aF2CS0f);
    sprintf(&v60, v10, (_DWORD)v9, (_DWORD)(v9 >> 32));
    sub_450530((signed __int64)v50, (signed __int64)v48, 0, -61, -2, -2,
               (int)&v60);
    if (*(_DWORD *)(a2 + 292) == 1)
    {
        v51 = 240.0;
        v49 = 30.0;
    }
    else
    {
        v51 = 160.0;
        v49 = 23.0;
        if (v3 == 2)
        {
            v49 = (double)(110 * v5 + 20);
        }
    }

    v11 = *(_DWORD *)(a1 + 120);
    HIWORD(v12) = 0;
    v55 = 0;
    v54 = 0;
    if (v11 > 0)
    {
        v53 = *(float *)(a1 + 4 * v11 + 92);
        v56 = 1.0 - *(float *)(a1 + 4 * v11 + 96) * 0.25;
        if (v56 <= 0.0 || v56 >= 1.0)
        {
            if (sub_427670(*(char *)(a1 + 16), 0x100000) && !sub_427360(6, 0))
            {
                sub_4276A0(*(char *)(a1 + 16), 0x100000);
            }
        }
        else
        {
            // Generate some color (R=x, G=x, B=x*0.5)
            if (dword_50C5F0)
            {
                v13 = 223.25;
            }
            else
            {
                v13 = (double)sub_4816B0() * 4.6566129e-10 * 127.0 - -128.0;
            }
            v14 = (signed __int64)v13;
            v15 = (signed __int64)((double)v14 * 0.5);

            // Generate alpha?
            v12 = 8 * (unsigned __int64)(signed __int64)(v56 * 255.0);
            if (v12 > 255)
            {
                v12 = 255;
            }

            // Unknown, but probably formats lap time?
            LOWORD(v5) = (signed __int64)v51;
            v16 = sub_421360(aF3CS);
            sub_450670(v5, (signed __int64)v49, v53, v14, v15, 64, v12,
                       (int)v16);

            // Draw text "LAP TIME"
            v17 = sub_421360(aScreentext420C);
            sub_450530(v5, (signed __int64)(v49 - -17.0), v14, v15, 64, v12,
                       (int)v17);

            // Check if this was a new lap record
            if (v53 <= (double)*(float *)(a2 + 464))
            {
                if ((signed __int64)(v56 * 16.0) & 1)
                {
                    // Draw "New Record" Text
                    v18 = sub_421360(aScreentext538S);
                    sub_450530(v5, (signed __int64)(v49 - -25.0), -56, -1, 0,
                               v12, (int)v18);

                    // FIXME: ???
                    HIWORD(v12) = HIWORD(a1);
                    if (!sub_427670(*(char *)(a1 + 16), 0x100000))
                    {
                        sub_427410(6, 0, 39, 0);
                        sub_427690(*(char *)(a1 + 16), 0x100000);
                    }
                }
            }
            v55 = 1;

            if (*(_DWORD *)(a1 + 120) + 1 == *(_DWORD *)(a2 + 456))
            {
                v19 = v56;
                if (dword_50CA18 > 1)
                {
                    if ((signed int)(signed __int64)(v19 * 36.0) % -2)
                    {
                        v54 = 1;
                    }
                }
                else
                {
                    v20 = v19 - 0.5 + v19 - 0.5;
                    if (v20 > 0.0)
                    {
                        // Generate alpha
                        v21 =
                            4 * (unsigned __int64)(signed __int64)(v20 * 255.0);
                        if (v21 > 255)
                        {
                            LOBYTE(v21) = 255;
                        }

                        // Generate random red?
                        if (dword_50C5F0)
                        {
                            v22 = 191.25;
                        }
                        else
                        {
                            v22 = (double)sub_4816B0() * 4.6566129e-10 * 255.0;
                        }
                        v23 = (signed __int64)v22;

                        // Generate random green?
                        if (dword_50C5F0)
                        {
                            v24 = 191.25;
                        }
                        else
                        {
                            v24 = (double)sub_4816B0() * 4.6566129e-10 * 255.0;
                        }
                        v25 = (signed __int64)v24;

                        // Generate random blue?
                        if (dword_50C5F0)
                        {
                            v26 = 191.25;
                        }
                        else
                        {
                            v26 = (double)sub_4816B0() * 4.6566129e-10 * 255.0;
                        }
                        v12 = (signed __int64)v26;

                        // Draw "FINAL LAP" text
                        v27 = sub_421360(aScreentext526F);
                        sub_450530(160, 70, v23, v25, v12, v21, (int)v27);
                    }
                }
            }
            v2 = a1;
        }
    }

    // Draw the lap time
    // FIXME: What are these conditions?
    if (!v55 && v58 < 2)
    {
        dword_50CA5C = 0;
        LOWORD(v12) = (signed __int64)v51;
        v28 = sub_421360(aF3CS);
        sub_450670(v12, (signed __int64)v49, *(float *)(v2 + 116), 0xFF, 0xFF,
                   0xFF, 0xBE, (int)v28);

        // Draw "TIME" text
        v29 = sub_421360(aScreentext422C);
        sub_450530(v12, (signed __int64)(v49 - -17.0), 0xFF, 0xFF, 0xFF, 0xBE,
                   (int)v29);
    }

    // FIXME: ???
    v30 = *(_DWORD *)(a2 + 292);
    if (v30 == 6 || v30 == 7)
    {
        sub_450670(289, (signed __int64)v49, *(float *)(v2 + 116), 0xFF, 0xFF,
                   0xFF, 0xBE, (int)aF3RS);
    }

    v52 = 62.0;
    if (*(_DWORD *)(a2 + 292) != 1)
    {
        v52 = 42.0;
    }

    v31 = *(_DWORD *)(v2 + 120) + 1;
    if (v31 > *(_DWORD *)(a2 + 456))
    {
        v31 = *(_DWORD *)(a2 + 456);
    }

    // Format text for "<lap> / <total_laps>"
    v32 = *(_DWORD *)(a2 + 456);
    v33 = v31;
    v34 = sub_421360(aF3CSDD);
    sprintf(&v60, v34, v33, v32);

    if (dword_50CA18 > 1 && v54)
    {
        // Draw "<lap> / <total_laps>"
        v35 = (signed __int64)v49;
        v36 = (signed __int64)v52;
        sub_450530(v36, v35, -1, 63, 63, -1, (int)&v60);

        // Draw "LAP" text
        v37 = (signed __int64)(v49 - -17.0);
        v38 = sub_421360(aScreentext424C);
        sub_450530(v36, v37, -1, 63, 63, -1, (int)v38);
    }
    else
    {
        // Draw "<lap> / <total_laps>"
        v35 = (signed __int64)v49;
        v39 = (signed __int64)v52;
        sub_450530(v39, v35, -1, -1, -1, -66, (int)&v60);

        // Draw "LAP" text
        v37 = (signed __int64)(v49 - -17.0);
        v40 = sub_421360(aScreentext424C);
        sub_450530(v39, v37, -1, -1, -1, -66, (int)v40);
    }

    v41 = *(_DWORD *)(a2 + 292);
    if (v41 != 1 && v41 != 6 && v41 != 7)
    {
        // Draw the position when we entered the first lap by crossing the
        // starting line
        v42 = *(_WORD *)(v2 + 92);
        if (v42 > 0)
        {
            v43 = *(_DWORD *)(a2 + 444);
            v44 = v42;
            v45 = sub_421360(aF3CSDD);
            sprintf(&v60, v45, v44, v43);
            sub_450530(278, v35, -1, -1, -1, -66, (int)&v60);
        }

        // Draw "POS" text
        v46 = sub_421360(aScreentext426C);
        sub_450530(278, v37, -1, -1, -1, -66, (int)v46);
    }

    if (dword_50CA18 > 1 && !HIDWORD(v57))
    {
        LOWORD(v57) = 54;
    }

    // Draw the boost meter?
    sub_45FE70(a2, v59, 225, v57, SHIDWORD(v57));

    // FIXME: No idea?!
    result = dword_50C040;
    if (dword_50C040)
    {
        result = dword_50C610;
        if (dword_50C610)
        {
            result = sub_450530(160, 20, 0xFF, 0x00, 0x00, 0xFF, (int)aCOzot);
        }
    }

    return result;
}
char __cdecl sub_45FE70(int a1, int a2, __int16 a3, __int16 a4, int a5)
{
    __int16 v5; // bp
    signed int v6; // esi
    unsigned __int8 v8; // c0
    unsigned __int8 v9; // c3
    char v11; // c0
    double v12; // st7
    const char *v13; // eax
    int v14; // ST14_4
    double v15; // st7
    signed int v16; // esi
    const char *v17; // eax
    double v18; // st7
    signed int v19; // esi
    signed int v20; // edi
    int v21; // ST30_4
    char result; // al
    float v23; // [esp+10h] [ebp-11Ch]
    float v24; // [esp+10h] [ebp-11Ch]
    int v25; // [esp+10h] [ebp-11Ch]
    int v26; // [esp+18h] [ebp-114h]
    int v27; // [esp+20h] [ebp-10Ch]
    int v28; // [esp+28h] [ebp-104h]
    char v29; // [esp+2Ch] [ebp-100h]

    v5 = a3;
    v6 = a5 != 0 ? 21 : 17;
    if (dword_50CA18 > 1)
    {
        v5 = a3 + 31;
    }
    sub_4285D0(a5 != 0 ? 21 : 17, 1);
    sub_428660(v6, v5, a4);
    sub_428740(v6, 89, -116, 54, -2);
    if (!sub_445690())
    {
        if (*(_DWORD *)(a2 + 96) & 0x200000)
        {
            *(float *)(a1 + 4 * a5 + 472) -= dbl_E22A40 * -4.0;
            if (!(v8 | v9))
            {
                *(_DWORD *)(a1 + 4 * a5 + 472) = 1.0f;
            }
        }
        else
        {
            *(float *)(a1 + 4 * a5 + 472) -= dbl_E22A40 * 4.0;
            if (v11)
            {
                *(_DWORD *)(a1 + 4 * a5 + 472) = 0;
            }
        }
    }

    v23 = *(float *)(a1 + 4 * a5 + 472);
    if (dword_50C5F0)
    {
        v12 = (v23 - v23 * 0.69999999 * -3.0) * 0.25;
    }
    else
    {
        v12 = (double)sub_4816B0() * 4.6566129e-10 * (v23 * 0.69999999 - v23)
            + v23;
    }
    v24 = v12 * 255.0;

    sub_4285D0(14, 0);
    if ((unsigned int)&unk_800000 & *(_DWORD *)(a2 + 96))
    {
        v25 = (signed __int64)v24;
        LOWORD(v26) = 255;
        BYTE2(v26) = 0;
        LOBYTE(v27) = 0;
        *(_WORD *)((char *)&v27 + 1) = 255;
        HIBYTE(v27) = -26;
        v28 = 1.0f;
    }
    else
    {
        if (a5)
        {
            sub_4285D0(20, 0);
        }
        else
        {
            sub_4285D0(16, 0);
        }
        v25 = (signed __int64)v24;
        sub_46BC50(a2, &v26, &v27, (float *)&v28);
    }

    if (dword_50CA18 > 1)
    {
        v25 = (signed __int64)((double)(signed __int16)v25 * 2.5);
        if ((signed __int16)v25 > 255)
        {
            LOBYTE(v25) = 255;
        }
    }

    // Draw netplay Ctrl+Q to quit message (after hitting Escape)
    if (*(float *)&dword_4C4A58 > 0.0)
    {
        v13 = sub_421360(aMondotextH0522);
        sprintf(&v29, aF4SCS, v13);
        v14 = (signed __int64)(*(float *)&dword_4C4A58 * 255.0);
        v15 = (double)sub_4816B0() * 4.6566129e-10 * 255.0;
        sub_450530(160, 220, (signed __int64)v15, -1, -1, v14, (int)&v29);
        *(float *)&dword_4C4A58 -= dbl_E22A40 * 0.333299994468689;
    }

    v16 = (a5 != 0 ? 22 : 18);
    sub_4285D0(v16, 1);
    sub_428660(v16, a3 + 24, a4 - 7);
    sub_428740(v16, v26, SBYTE1(v26), SBYTE2(v26), v25);

    // Check if boost is charged
    if (dword_50CA18 <= 1 && !*(_DWORD *)(a1 + 428) && !*(_DWORD *)(a1 + 448)
        && (unsigned __int8)v26 > 0x78u && BYTE1(v26) > 0x78u
        && BYTE2(v26) < 0x78u && !sub_445690())
    {
        // Blink the boost text
        if (++dword_50CA58 & 1)
        {
            // Draw "BOOST" text
            v17 = sub_421360(aScreentext380B);
            sprintf(&v29, aF4CS, v17);
            v18 = (double)sub_4816B0() * 4.6566129e-10 * 255.0;
            sub_450530(244, 162, -1, -1, (signed __int64)v18, v25, (int)&v29);
        }
    }
    v19 = a5 != 0 ? 19 : 15;
    sub_4285D0(v19, 1);
    sub_428660(v19, a3 + 34, a4 + 6);
    sub_428740(v19, v27, SBYTE1(v27), SBYTE2(v27), SHIBYTE(v27));
    dword_50CA04 = v28;
    v20 = a5 != 0 ? 20 : 16;
    if (!((unsigned int)&unk_800000 & *(_DWORD *)(a2 + 96)))
    {
        return sub_4285D0(v20, 0);
    }
    *(float *)&v21 = 1.0 - *(float *)(a2 + 536) * 0.0099999998;
    sub_4285D0(v20, 1);
    sub_428660(v20, a3 + 34, a4 + 6);
    result = sub_428740(v20, -1, -1, -1, -1);
    dword_50CA08 = v21;
    return result;
}
