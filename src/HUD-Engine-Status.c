// TODO: Create a global engine struct to encapsulate the following globals:
// flt_4C52A0[a2]
// dword_4C52A8[a2] = 5.0;
// dword_50CA60[a2]
// dword_50CA68[a2]
// flt_50CA70[a2]

//----- (004611F0) --------------------------------------------------------
char __cdecl sub_4611F0(int a1, int a2)
{
    int v2; // edi
    signed int v3; // edx
    double v4; // st7
    int v5; // ebx
    int v6; // eax
    float *v7; // ecx
    signed int v8; // esi
    double v9; // st7
    unsigned __int8 v11; // c0
    unsigned __int8 v12; // c3
    char v14; // c0
    unsigned __int8 v16; // c0
    unsigned __int8 v17; // c3
    unsigned __int8 v19; // c0
    unsigned __int8 v20; // c3
    signed int v21; // esi
    char result; // al
    signed int v23; // esi
    int *v24; // eax
    signed int v25; // ecx
    int v26; // ebp
    double v27; // st7
    double v28; // st7
    int v29; // eax
    _BYTE *v30; // edi
    signed int v31; // esi
    int v32; // eax
    int v33; // eax
    signed int v34; // ebp
    float *v35; // esi
    signed int v36; // edi
    signed int v37; // edx
    float v38; // ecx
    double v39; // st7
    double v40; // st7
    float *v41; // ecx
    signed int v42; // eax
    int v43; // ebp
    int v44; // ebx
    int v45; // edi
    int v46; // esi
    double v47; // st7
    unsigned int *v48; // edx
    float v49; // ecx
    float v50; // eax
    int v51; // edx
    double v52; // st7
    int v53; // esi
    const char *v54; // ST18_4
    signed int v55; // esi
    const char *v56; // ST18_4
    double v57; // st7
    signed __int64 v58; // rax
    double v59; // st7
    char v60; // si
    int v61; // edi
    int v62; // ebx
    int v63; // ebp
    const char *v64; // ST18_4
    double v65; // st7
    double v66; // st7
    const char *v67; // ST18_4
    char v69; // c0
    int v70; // eax
    signed int v71; // edi
    double v72; // st7
    signed int v73; // esi
    bool v74; // zf
    double v75; // st7
    int v76; // eax
    signed int v77; // edi
    int v78; // esi
    double v79; // st6
    double v80; // st6
    double v81; // st7
    __int16 v82; // bx
    double v83; // st7
    bool v84; // sf
    unsigned __int8 v85; // of
    signed int v86; // esi
    signed int v87; // esi
    char v88; // [esp-14h] [ebp-F0h]
    char v89; // [esp-Ch] [ebp-E8h]
    int v90; // [esp-8h] [ebp-E4h]
    const char *v91; // [esp-4h] [ebp-E0h]
    int v92; // [esp+14h] [ebp-C8h]
    float v93; // [esp+14h] [ebp-C8h]
    signed int v94; // [esp+18h] [ebp-C4h]
    float v95; // [esp+18h] [ebp-C4h]
    float v96; // [esp+18h] [ebp-C4h]
    float v97; // [esp+18h] [ebp-C4h]
    signed int v98; // [esp+1Ch] [ebp-C0h]
    int v99; // [esp+1Ch] [ebp-C0h]
    signed int v100; // [esp+20h] [ebp-BCh]
    float v101; // [esp+20h] [ebp-BCh]
    float v102; // [esp+20h] [ebp-BCh]
    float v103; // [esp+24h] [ebp-B8h]
    int v104; // [esp+24h] [ebp-B8h]
    float v105; // [esp+28h] [ebp-B4h]
    float v106; // [esp+28h] [ebp-B4h]
    float *v107; // [esp+2Ch] [ebp-B0h]
    signed int v108; // [esp+2Ch] [ebp-B0h]
    float v109; // [esp+2Ch] [ebp-B0h]
    float v110; // [esp+30h] [ebp-ACh]
    signed int v111; // [esp+34h] [ebp-A8h]
    signed int v112; // [esp+38h] [ebp-A4h]
    float v113; // [esp+38h] [ebp-A4h]
    signed int v114; // [esp+3Ch] [ebp-A0h]
    unsigned int *v115; // [esp+40h] [ebp-9Ch]
    signed int v116; // [esp+44h] [ebp-98h]
    signed int v117; // [esp+48h] [ebp-94h]
    signed int v118; // [esp+4Ch] [ebp-90h]
    char v119; // [esp+50h] [ebp-8Ch]
    char v120; // [esp+54h] [ebp-88h]
    signed int v121; // [esp+58h] [ebp-84h]
    char v122; // [esp+5Ch] [ebp-80h]
    char v123; // [esp+60h] [ebp-7Ch]
    char v124; // [esp+64h] [ebp-78h]
    signed int v125; // [esp+68h] [ebp-74h]
    char v126; // [esp+6Ch] [ebp-70h]
    signed int v127; // [esp+70h] [ebp-6Ch]
    signed int v128; // [esp+74h] [ebp-68h]
    float v129; // [esp+78h] [ebp-64h]
    int v130[6]; // [esp+7Ch] [ebp-60h]
    int v131[6]; // [esp+94h] [ebp-48h]
    int v132[6]; // [esp+ACh] [ebp-30h]
    int v133[6]; // [esp+C4h] [ebp-18h]

    v2 = *(_DWORD *)(a1 + 132);
    v3 = 0;
    v100 = 0;
    v94 = 0;
    v121 = 0;
    v112 = 1048576000;
    v103 = 0.0;
    v92 = *(_DWORD *)(a1 + 132);
    if (a2)
    {
        v4 = 65.0;
    }
    else
    {
        v4 = 175.0;
    }
    v5 = *(_DWORD *)(v2 + 96);
    v105 = v4;
    v129 = v4;
    if (v5 & 0x1000)
    {
        dword_50CA60[a2] = 1.0f;
        dword_50CA68[a2] = 0;
    }
    else if (v5 & 0x4000)
    {
        dword_50CA68[a2] = -1.0f;
    }
    else
    {
        if (v5 & 0x2000)
        {
            v3 = 1;
        }
        v6 = *(_DWORD *)(v2 + 100);
        if (v6 & 0x4000)
        {
            v3 = 1;
        }
        if (*(float *)(v2 + 696) > 0.0)
        {
            v3 = 1;
        }
        if (*(float *)(v2 + 536) < 50.0)
        {
            v3 = 1;
        }
        v7 = (float *)(v2 + 672);

        // Loop over 6 engine parts?
        v8 = 6;
        do
        {
            if (*(v7 - 6) > 0.6)
            {
                v3 = 1;
            }
            if (*(_BYTE *)v7 & 0x1C)
            {
                v3 = 1;
            }
            ++v7;
            --v8;
        } while (v8);

        if (v5 & 0x400)
        {
            v3 = 1;
        }
        if (v3)
        {
            dword_50CA68[a2] = 1082130432;
            dword_4C52A8[a2] = 5.0;
        }
    }

    if (!sub_445690())
    {
        v9 = flt_4C52A0[a2] - dbl_E22A40 * 1.5;
        flt_4C52A0[a2] = v9;
        if (v11 | v12)
            flt_4C52A0[a2] = v9 - -1.0;
        *(float *)(v2 + 696) = *(float *)(v2 + 696) - dbl_E22A40;
        if (v14)
            *(_DWORD *)(v2 + 696) = 0;
        *(float *)&dword_50CA60[a2] = *(float *)&dword_50CA68[a2] * dbl_E22A40
            + *(float *)&dword_50CA60[a2];
        if (!(v16 | v17))
        {
            dword_50CA60[a2] = 1.0f;
            dword_50CA68[a2] = 0;
        }
        if (*(float *)&dword_50CA60[a2] > 0.0)
        {
            dword_4C52A8[a2] = dword_4C52A8[a2] - dbl_E22A40;
            if (v19 | v20)
            {
                dword_50CA68[a2] = -4.0f;
            }
        }
    }
    if (*(float *)&dword_50CA60[a2] <= 0.0)
    {
        dword_50CA60[a2] = 0;
        dword_50CA68[a2] = 0;
        if (a2)
        {
            // Loop over 6 engine parts?
            v23 = 0;
            do
            {
                sprite_display(v23++ + 35, 0);
            } while (v23 < 6);

            sprite_display(41, 0);
            result = sprite_display(42, 0);
        }
        else
        {
            // Loop over 6 engine parts?
            v21 = 0;
            do
                sprite_display(v21++ + 27, 0);
            while (v21 < 6);

            sprite_display(33, 0);
            result = sprite_display(34, 0);
        }
        return result;
    }

    if (!sub_445690())
    {
        v24 = (int *)(v2 + 672);

        // Loop over 6 engine parts?
        v25 = 6;
        do
        {
            v26 = *v24;
            ++v24;
            --v25;
            *(v24 - 1) = v26 ^ 2;
        } while (v25);
    }

    v119 = 0;
    v120 = -1;
    v123 = -1;
    if (dword_50C5F0)
        v27 = 112.0;
    else
        v27 = (double)frand() * 64.0 + 64.0;
    v125 = (signed __int64)v27;
    v126 = 0;
    v122 = -1;
    v124 = -1;
    if (dword_50C5F0)
    {
        v28 = 112.0;
    }
    else
    {
        v28 = (double)frand() * 64.0 + 64.0;
    }
    v127 = (signed __int64)v28;
    v29 = *(_DWORD *)(v2 + 96);
    if (!(v29 & 0x2000))
    {
        if (v29 & 0x5000 || (v33 = *(_DWORD *)(v2 + 100), BYTE1(v33) & 0x40))
        {
            memset32(v131, 255, 6u);
            memset32(v133, 255, 6u);

            // Loop over 6 engine parts?
            v71 = 0;
            do
            {
                if (dword_50C5F0)
                {
                    v72 = 150.0;
                }
                else
                {
                    v72 = (double)frand() * 200.0;
                }
                v73 = (signed __int64)v72;
                v74 = dword_50C5F0 == 0;
                v132[v71] = v73;
                if (v74)
                    v75 = (double)frand() * 4.6566129e-10 * 128.0;
                else
                    v75 = 96.0;
                v130[v71] = (signed __int64)v75;
                if ((signed int)(signed __int64)v75 > v73)
                    v130[v71] = v73;
                ++v71;
            } while (v71 < 6);

            goto LABEL_197;
        }

        // Loop over 6 engine parts?
        v34 = 0;
        v35 = (float *)(v2 + 672);
        v36 = 0;
        v37 = 0;
        v107 = v35;
        do
        {
            v38 = *v35;
            if (*(_DWORD *)v35 & 4)
            {
                if (v37 >= 3)
                    v34 = 1;
                else
                    v36 = 1;
            }
            if (LOBYTE(v38) & 0x10)
                v100 = 1;
            if (*(v35 - 6) >= 1.0)
                v94 = 1;
            if (LOBYTE(v38) & 8)
                v121 = 1;
            ++v37;
            ++v35;
        } while (v37 < 6);

        v116 = v34;
        v111 = v36;
        if (v36)
        {
            v123 = 0;
            v119 = -1;
            v120 = -1;
            if (dword_50C5F0)
                v39 = 223.25;
            else
                v39 = (double)frand() * 127.0 + 128.0;
            v125 = (signed __int64)v39;
        }
        if (v34)
        {
            v124 = 0;
            v126 = -1;
            v122 = -1;
            if (dword_50C5F0)
                v40 = 223.25;
            else
                v40 = (double)frand() * 127.0 + 128.0;
            v127 = (signed __int64)v40;
        }
        v41 = v107;
        v42 = 0;
        do
        {
            v115 = (unsigned int *)v41;
            v108 = v42;
            v98 = 3;
            do
            {
                v43 = 100;
                v128 = 100;
                v110 = *((float *)v115 - 6);
                if (v110 < 0.0)
                    v110 = 0.0;
                if (v110 > 1.0)
                    v110 = 1.0;
                v44 = (signed __int64)(v110 * 510.0);
                v114 = (signed __int64)(v110 * 510.0);
                v45 = (signed __int64)((1.0 - v110 + 1.0 - v110) * 255.0);
                v46 = 0;
                v118 = (signed __int64)((1.0 - v110 + 1.0 - v110) * 255.0);
                v117 = 0;
                if (v110 > 0.8 && (double)frand() > 0.5)
                {
                    v44 = 128;
                    v45 = 0;
                    v114 = 128;
                    v118 = 0;
                    v117 = 0;
                }
                if (v110 >= 1.0)
                {
                    v47 = flt_4C52A0[a2] * 127.0;
                    v44 = (signed __int64)(v47 - -128.0);
                    v114 = (signed __int64)(v47 - -128.0);
                    v45 = (signed __int64)v47;
                    v46 = (signed __int64)v47;
                    v43 = (signed __int64)(v47 - -128.0);
                    v118 = (signed __int64)v47;
                    v117 = (signed __int64)v47;
                    v128 = (signed __int64)(v47 - -128.0);
                }
                v48 = v115;
                v49 = *(float *)v115;
                if (!(*v115 & 8))
                {
                    if (*(float *)(v92 + 696) > 0.0 && LOBYTE(v49) & 1)
                    {
                        if (LOBYTE(v49) & 2)
                        {
                            v44 = 255;
                            v46 = 150;
                            v45 = 255;
                            v43 = 255;
                            v114 = 255;
                            v118 = 255;
                            v117 = 150;
                            v128 = 255;
                        }
                    }
                    else
                    {
                        *v115 = LODWORD(v49) & 0xFFFFFFFE;
                    }
                }
                v50 = *(float *)v115;
                if (*v115 & 4 && LOBYTE(v50) & 2)
                {
                    v44 = 128;
                    v46 = 255;
                    v45 = 128;
                    v43 = 200;
                    v114 = 128;
                    v118 = 128;
                    v117 = 255;
                    v128 = 200;
                }
                if (LOBYTE(v50) & 8)
                {
                    if ((v111 || v116) && LOBYTE(v50) & 2)
                    {
                        v44 = 128;
                        v46 = 255;
                        v45 = 128;
                        v43 = 200;
                    }
                    else
                    {
                        v44 = (signed __int64)((double)(255 - v44)
                                                   * flt_4C52A0[a2]
                                               + (double)v114);
                        v45 = (signed __int64)((double)(128 - v45)
                                                   * flt_4C52A0[a2]
                                               + (double)v118);
                        v46 = (signed __int64)((double)-v46 * flt_4C52A0[a2]
                                               + (double)v117);
                        v48 = v115;
                        v43 = (signed __int64)((double)(200 - v43)
                                                   * flt_4C52A0[a2]
                                               + (double)v128);
                    }
                }

                v44 = clamp(v44, 0x00, 0xFF);
                v45 = clamp(v45, 0x00, 0xFF);
                v46 = clamp(v46, 0x00, 0xFF);
                v43 = clamp(v43, 0x00, 0xFF);

                v51 = (int)(v48 + 1);
                v115 = (unsigned int *)v51;
                *(int *)((char *)v133 + v108) = v44;
                *(int *)((char *)v132 + v108) = v45;
                *(int *)((char *)v130 + v108) = v46;
                *(int *)((char *)v131 + v108) = v43;
                v108 += 4;
                --v98;
            } while (v98);
            v42 = v108;
            v41 = (float *)v51;
        } while (v108 < 24);

        v52 = v105 - 45.0;
        v106 = v52;
        v109 = v52 - -15.0;
        if (v121)
        {
            v53 = (signed __int64)(flt_4C52A0[a2] * 255.0);
            v54 = lookup_translation(aScreentext433C);
            sub_450530(54, (signed __int64)(v109 - -48.0), -1, -128, 0, v53,
                       (int)v54);
        }

        if (*(float *)(v92 + 536) >= 20.0)
        {
            if (*(float *)(v92 + 536) < 50.0)
            {
                v57 = (*(float *)(v92 + 536) - 50.0) * -0.033333335;
                if (v57 < 0.0)
                    v57 = 0.0;
                if (v57 > 1.0)
                    v57 = 1.0;
                v58 = (signed __int64)(v57 * 255.0);
                v59 = 1.0 - v57;
                v60 = v58;
                v61 = (signed __int64)(v59 * 127.0 - -128.0);
                v62 = (signed __int64)(v59 * 255.0);
                v63 = (signed __int64)(flt_4C52A0[a2] * 255.0);
                if ((unsigned int)&unk_800000 & *(_DWORD *)(v92 + 96))
                {
                    v64 = lookup_translation(aScreentext435C);
                    sub_450530(54, (signed __int64)(v109 - -48.0), v60, v61,
                               v62, v63, (int)v64);
                }
                if (dword_50C5F0)
                    v65 = 223.25;
                else
                    v65 = (double)frand() * 127.0 + 128.0;
                v125 = (signed __int64)v65;
                v127 = (signed __int64)v65;
                v119 = v60;
                v120 = v61;
                v123 = v62;
                v126 = v60;
                v122 = v61;
                v124 = v62;
                if ((unsigned int)&unk_800000 & *(_DWORD *)(v92 + 96))
                {
                    v112 = 1045220557;
                    v103 = 0.5;
                }
            }
        }
        else
        {
            v55 = (signed __int64)(flt_4C52A0[a2] * 255.0);
            if (!v121 && (unsigned int)&unk_800000 & *(_DWORD *)(v92 + 96))
            {
                v56 = lookup_translation(aScreentext434C);
                sub_450530(54, (signed __int64)(v109 - -48.0), -1, -128, 0, v55,
                           (int)v56);
            }
            v119 = -1;
            v126 = -1;
            v120 = -128;
            v123 = 0;
            v125 = v55;
            v122 = -128;
            v124 = 0;
            v127 = v55;
            if (*(_DWORD *)(v92 + 96) & (unsigned int)&unk_800000)
            {
                v112 = 1050253722;
                v103 = 0.75;
            }
        }
        if (v94)
        {
            v66 = flt_4C52A0[a2] * 127.0;
            v67 = lookup_translation(aScreentext432C);
            sub_450530(54, (signed __int64)(v106 - -48.0),
                       (signed __int64)(v66 - -128.0), (signed __int64)v66,
                       (signed __int64)v66, (signed __int64)(v66 - -128.0),
                       (int)v67);
            v106 = v106 - 12.0;
        }
        if (*(_DWORD *)(v92 + 96) & 0x400)
        {
            if (v111 || v116 || v100)
            {
                v70 = dword_50C5F0;
                flt_50CA70[a2] = 0.0;
                if (v70)
                    v96 = 223.25;
                else
                    v96 = (double)frand() * 127.0 + 128.0;
                v91 = lookup_translation(aScreentext436C);
                v90 = (signed __int64)v96;
                v89 = -1;
                v88 = -128;
            }
            else
            {
                if (flt_50CA70[a2] <= 0.0)
                    sub_426C80(70, 7, 0.25, 1.0, 0);
                flt_50CA70[a2] = flt_50CA70[a2] + dbl_E22A40;
                if (!v69)
                    goto LABEL_169;
                if (dword_50C5F0)
                    v95 = 223.25;
                else
                    v95 = (double)frand() * 127.0 + 128.0;
                v91 = lookup_translation(aScreentext437C);
                v90 = (signed __int64)v95;
                v89 = 64;
                v88 = 64;
            }
            sub_450530(54, (signed __int64)(v106 - -48.0), v88, -128, v89, v90,
                       (int)v91);
        }
        else
        {
            flt_50CA70[a2] = 0.0;
        }

    LABEL_169:
        if (!sub_445690())
        {
            if (v121)
            {
                if (dbl_E22A38 - 2.0 > flt_50CA78)
                {
                    flt_50CA7C = dbl_E22A38;
                    sub_426C80(135, 7, 0.25, 1.0, 0);
                }
                if (dbl_E22A38 - 1.799999952316284 > flt_50CA7C)
                    sub_426C80(134, 6, 0.25, 1.0, 1);
                flt_50CA78 = dbl_E22A38;
            }
            if (v103 > 0.0)
                sub_426C80(131, 7, *(float *)&v112, v103, 1);
            if (*(_DWORD *)(v92 + 96) & 0x400 && (v111 || v116 || v100))
            {
                if (dbl_E22A38 - 2.0 > flt_50CA80)
                {
                    flt_50CA84 = dbl_E22A38;
                    sub_426C80(133, 7, 0.25, 1.0, 0);
                }
                if (dbl_E22A38 - 1.799999952316284 > flt_50CA84)
                    sub_426C80(117, 6, 0.25, 1.0, 1);
                flt_50CA80 = dbl_E22A38;
            }
        }
        goto LABEL_197;
    }

    // Loop over 6 engine parts?
    v30 = (_BYTE *)(v2 + 672);
    v31 = 0;
    do
    {
        if (*v30 & 2)
        {
            v32 = dword_50C5F0;
            v133[v31] = 100;
            v132[v31] = 100;
            if (v32)
                v130[v31] = (signed __int64)223.25;
            else
                v130[v31] = (signed __int64)((double)frand() * 127.0 + 128.0);
        }
        else
        {
            v133[v31] = 200;
            v132[v31] = 200;
            v130[v31] = 200;
        }
        v131[v31] = 255;
        ++v31;
        v30 += 4;
    } while (v31 < 6);

LABEL_197:

    // This likely draws the engine parts as it loops over 2 colums, with 3 rows
    // each. It also calls what is probably the sprite renderer

    v104 = 0;
    v76 = 0;
    do
    {
        v77 = 0;
        v99 = 3 * v76;
        v113 = (double)(24 * v76) - -30.0 - -4.0;
        do
        {
            v78 = v77 + v99;
            v79 = (1.0 - *(float *)&dword_50CA60[a2]) * 15.0;
            v93 = (double)(14 * v77) + v129 - -2.0;
            v97 = v79;
            if (v77 == 1)
            {
                v79 = v79 * 1.5;
            }

            if (v104)
            {
                v80 = v79 + v113;
            }
            else
            {
                v80 = v113 - v79;
            }
            v101 = v80;

            if (v77 == 0)
            {
                v81 = v93 - v97;
                v93 = v81;
            }
            else if (v77 == 2)
            {
                v81 = v97 + v93;
                v93 = v81;
            }

            v82 = v78 + 27;
            if (a2)
            {
                v82 = v78 + 35;
            }

            // All of the following is probably responsible for setting the
            // sprite color and size, then finally drawing it
            sprite_display(v82, 1);
            v83 = v93;
            if (dword_E996DC & 0x4000)
            {
                sprite_set_pos(v82, (signed __int64)(92.0 - v101),
                               (signed __int64)v83);
            }
            else
            {
                sprite_set_pos(v82, (signed __int64)v101, (signed __int64)v83);
            }
            sprite_scale(v82, 1061158912, 1061158912);
            sprite_set_color(v82, v133[v78], v132[v78], v130[v78],
                             (signed __int64)((double)v131[v78]
                                              * *(float *)&dword_50CA60[a2]));

            ++v77;
        } while (v77 < 3);
        v76 = v104 + 1;
        v85 = __OFSUB__(v104 + 1, 2);
        v84 = v104++ - 1 < 0;
    } while (v84 ^ v85);

    v102 = 12.0;
    if (!(dword_E996DC & 0x4000))
    {
        v102 = -12.0;
    }

    v86 = a2 != 0 ? 41 : 33;
    sprite_display(v86, 1);
    sprite_set_pos(v86, (signed __int64)(v102 - -30.0 - -12.0),
                   (signed __int64)v129);
    sprite_scale(v86, 0.75f, 0.75f);
    sprite_set_color(v86, v119, v120, v123,
                     (signed __int64)((double)v125 * *(float *)&dword_50CA60[a2]
                                      * *(float *)&dword_50CA60[a2]));

    v87 = a2 != 0 ? 42 : 34;
    sprite_display(v87, 1);
    sprite_set_pos(v87, (signed __int64)(42.0 - v102), (signed __int64)v129);
    sprite_scale(v87, 0.75f, 0.75f);
    return sprite_set_color(
        v87, v126, v122, v124,
        (signed __int64)((double)v127 * *(float *)&dword_50CA60[a2]
                         * *(float *)&dword_50CA60[a2]));
}
