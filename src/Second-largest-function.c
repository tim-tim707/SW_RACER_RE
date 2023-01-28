//----- (0049A390) --------------------------------------------------------
signed int __cdecl sub_49A390(int a1, float *a2, float *a3, float *a4, int a5)
{
    float *v5; // edi
    float *v6; // ebx
    int v7; // edx
    int v8; // esi
    float *v9; // ecx
    int v10; // ebp
    double v11; // st6
    double v13; // st7
    char v14; // c0
    float v15; // ST24_4
    double v17; // st6
    char v18; // c3
    double v20; // st5
    char v21; // c0
    double v23; // st4
    char v24; // c0
    double v25; // st5
    int v26; // esi
    int v27; // eax
    _DWORD *v28; // esi
    _DWORD *v29; // eax
    signed int result; // eax
    int v31; // eax
    int v32; // esi
    int v33; // eax
    int v34; // edx
    int v35; // edi
    int v36; // ebp
    int v37; // ebx
    int v38; // ecx
    bool v40; // sf
    float *v41; // ecx
    int v42; // edx
    int v43; // ebp
    double v44; // st6
    double v46; // st7
    unsigned __int8 v47; // c0
    unsigned __int8 v48; // c3
    float v49; // ST24_4
    double v51; // st6
    char v52; // c3
    double v54; // st5
    char v55; // c0
    double v57; // st4
    char v58; // c0
    double v59; // st5
    int v60; // esi
    int v61; // eax
    _DWORD *v62; // esi
    _DWORD *v63; // eax
    int v64; // ebx
    int v65; // eax
    int v66; // esi
    float *v67; // ebx
    int v68; // edi
    int v69; // eax
    int v70; // edx
    float *v71; // edi
    signed int v72; // edx
    int v73; // ecx
    float *v74; // ecx
    int v75; // ebp
    int v76; // et1
    double v78; // st7
    unsigned __int8 v79; // c0
    unsigned __int8 v80; // c3
    double v81; // st2
    float v82; // ST24_4
    double v83; // st6
    double v85; // st5
    char v86; // c0
    double v88; // st4
    char v89; // c0
    double v90; // st5
    int v91; // eax
    _DWORD *v92; // esi
    _DWORD *v93; // eax
    int v94; // edi
    int v95; // eax
    int v96; // ecx
    int v97; // esi
    float *v98; // edi
    int v99; // eax
    int v100; // ebx
    signed int v101; // ebp
    int v102; // ecx
    float *v103; // ebx
    float *v104; // ecx
    int v105; // edx
    int v106; // et1
    double v108; // st7
    char v109; // c0
    double v110; // st2
    float v111; // ST24_4
    double v112; // st6
    double v114; // st5
    char v115; // c0
    double v117; // st4
    char v118; // c0
    double v119; // st5
    int v120; // eax
    _DWORD *v121; // esi
    _DWORD *v122; // eax
    int v123; // eax
    int v124; // ecx
    int v125; // eax
    int v126; // ebx
    int v127; // edi
    int v128; // esi
    int v129; // ecx
    int v130; // edi
    signed int v131; // edx
    float *v132; // ebx
    float *v133; // ebp
    float *v134; // ecx
    int v135; // edi
    double v136; // st7
    int v137; // eax
    _DWORD *v138; // esi
    _DWORD *v139; // eax
    int v140; // ebx
    int v141; // eax
    int v142; // ebx
    int v143; // eax
    signed int v144; // ebp
    int v145; // ecx
    int v146; // eax
    int v147; // edi
    int v148; // ecx
    float *v149; // edi
    float *v150; // ebx
    float *v151; // ecx
    int v152; // ebp
    double v153; // st7
    int v154; // eax
    _DWORD *v155; // esi
    _DWORD *v156; // eax
    float *v157; // [esp+10h] [ebp-1Ch]
    float *v158; // [esp+10h] [ebp-1Ch]
    int v159; // [esp+10h] [ebp-1Ch]
    int v160; // [esp+10h] [ebp-1Ch]
    signed int v161; // [esp+14h] [ebp-18h]
    signed int v162; // [esp+14h] [ebp-18h]
    signed int v163; // [esp+14h] [ebp-18h]
    signed int v164; // [esp+14h] [ebp-18h]
    int v165; // [esp+14h] [ebp-18h]
    int v166; // [esp+14h] [ebp-18h]
    float *v167; // [esp+18h] [ebp-14h]
    float *v168; // [esp+18h] [ebp-14h]
    float *v169; // [esp+18h] [ebp-14h]
    float *v170; // [esp+18h] [ebp-14h]
    float *v171; // [esp+18h] [ebp-14h]
    float *v172; // [esp+18h] [ebp-14h]
    float *v173; // [esp+1Ch] [ebp-10h]
    float *v174; // [esp+1Ch] [ebp-10h]
    float *v175; // [esp+1Ch] [ebp-10h]
    float *v176; // [esp+1Ch] [ebp-10h]
    float *v177; // [esp+1Ch] [ebp-10h]
    float *v178; // [esp+1Ch] [ebp-10h]
    float v179; // [esp+20h] [ebp-Ch]
    float v180; // [esp+20h] [ebp-Ch]
    float v181; // [esp+20h] [ebp-Ch]
    float v182; // [esp+20h] [ebp-Ch]
    float *v183; // [esp+20h] [ebp-Ch]
    float *v184; // [esp+20h] [ebp-Ch]
    float v185; // [esp+24h] [ebp-8h]
    float v186; // [esp+24h] [ebp-8h]
    float v187; // [esp+24h] [ebp-8h]
    float v188; // [esp+24h] [ebp-8h]
    float *v189; // [esp+24h] [ebp-8h]
    float *v190; // [esp+24h] [ebp-8h]
    int v191; // [esp+28h] [ebp-4h]
    signed int v192; // [esp+28h] [ebp-4h]
    signed int v193; // [esp+28h] [ebp-4h]
    signed int v194; // [esp+28h] [ebp-4h]
    float v195; // [esp+40h] [ebp+14h]
    float v196; // [esp+40h] [ebp+14h]
    signed int v197; // [esp+40h] [ebp+14h]
    float v198; // [esp+40h] [ebp+14h]
    float v199; // [esp+40h] [ebp+14h]
    signed int v200; // [esp+40h] [ebp+14h]
    float v201; // [esp+40h] [ebp+14h]
    float v202; // [esp+40h] [ebp+14h]
    int v203; // [esp+40h] [ebp+14h]
    signed int v204; // [esp+40h] [ebp+14h]
    float v205; // [esp+40h] [ebp+14h]
    float v206; // [esp+40h] [ebp+14h]
    int v207; // [esp+40h] [ebp+14h]
    signed int v208; // [esp+40h] [ebp+14h]
    signed int v209; // [esp+40h] [ebp+14h]

    v5 = a3;
    v6 = a4;
    v157 = &a2[3 * a5 - 3];
    v173 = &a3[2 * a5 - 2];
    v7 = 0;
    v8 = (int)&unk_DFA140;
    dword_DFAA04 = 0;
    dword_DFA138 = (int)a2;
    dword_DF9EB4 = (int)&unk_DFA140;
    dword_DF9EA8 = (int)a3;
    dword_DF9EAC = (int)&unk_DF9EB8;
    dword_DFA13C = (int)a4;
    dword_DF9EB0 = (int)&unk_DFA500;
    v161 = 0;
    v9 = &a4[4 * a5 - 4];
    v167 = a2;

    // For loop from 0 to a5 exclusive
    if (a5 > 0)
    {
        v10 = 0;
        v191 = a5;
        do
        {
            v11 = *v157;
            v195 = *(float *)(a1 + 48) * v157[1];
            v13 = *(float *)(a1 + 48) * v167[1];
            if (!v14 || v13 <= *v167)
            {
                if (*v157 != v195 && v13 != *v167
                    && (*v157 < (double)v195 || v13 > *v167))
                {
                    v196 = v167[1] - v157[1];
                    v179 = *v167 - *v157;
                    v17 = v167[1] * *v157 - v157[1] * *v167;
                    if (!v18)
                    {
                        v15 = *(float *)(a1 + 48) * v196 - v179;
                        v17 = v17 / v15;
                    }
                    v185 = *(float *)(a1 + 48) * v17;
                    v20 = v196;
                    if (v21)
                        v20 = -v20;
                    v23 = v179;
                    if (v24)
                        v23 = -v23;
                    if (v20 <= v23)
                        v25 = (v185 - *v157) / v179;
                    else
                        v25 = (v17 - v157[1]) / v196;
                    *(float *)(v8 + v10) = v185;
                    *(float *)(dword_DF9EB4 + v10 + 4) = v17;
                    v26 = 8 * v161;
                    v10 += 12;
                    ++v161;
                    *(float *)(dword_DF9EB4 + v10 - 4) =
                        (v167[2] - v157[2]) * v25 + v157[2];
                    *(float *)(dword_DF9EAC + v26) =
                        (*v5 - *v173) * v25 + *v173;
                    *(float *)(dword_DF9EAC + v26 + 4) =
                        (v5[1] - v173[1]) * v25 + v173[1];
                    *(float *)(dword_DF9EB0 + v7) = (*v6 - *v9) * v25 + *v9;
                    *(float *)(dword_DF9EB0 + v7 + 4) =
                        (v6[1] - v9[1]) * v25 + v9[1];
                    *(float *)(dword_DF9EB0 + v7 + 8) =
                        (v6[2] - v9[2]) * v25 + v9[2];
                    v7 += 16;
                    *(float *)(dword_DF9EB0 + v7 - 4) =
                        (v6[3] - v9[3]) * v25 + v9[3];
                    v27 = dword_DFAA04;
                    v8 = dword_DF9EB4;
                    LOBYTE(v27) = dword_DFAA04 | 0x10;
                    dword_DFAA04 = v27;
                }
                if (v13 <= *v167)
                {
                    v28 = (_DWORD *)(v10 + v8);
                    v10 += 12;
                    *v28 = *(_DWORD *)v167;
                    v28[1] = *((_DWORD *)v167 + 1);
                    v28[2] = *((_DWORD *)v167 + 2);
                    *(float *)(dword_DF9EAC + 8 * v161) = *v5;
                    *(float *)(dword_DF9EAC + 8 * v161 + 4) = v5[1];
                    v29 = (_DWORD *)(v7 + dword_DF9EB0);
                    *v29 = *(_DWORD *)v6;
                    v29[1] = *((_DWORD *)v6 + 1);
                    v29[2] = *((_DWORD *)v6 + 2);
                    v29[3] = *((_DWORD *)v6 + 3);
                    ++v161;
                    v8 = dword_DF9EB4;
                    v7 += 16;
                }
            }
            v173 = v5;
            v157 = v167;
            v167 += 3;
            v9 = v6;
            v5 += 2;
            v6 += 4;
            --v191;
        } while (v191);
    }

    // This looks like an unrolled loop?
    result = v161;
    if (v161 >= 3)
    {
        v31 = v8 ^ dword_DFA138;
        v197 = v161;
        v32 = v8 ^ dword_DFA138 ^ v8;
        v33 = v32 ^ v31;
        v34 = dword_DF9EAC ^ dword_DF9EA8 ^ dword_DF9EAC;
        v35 = v34 ^ dword_DF9EAC ^ dword_DF9EA8;
        v158 = (float *)(v33 + 12 * v161 - 12);
        v36 = dword_DF9EB0 ^ dword_DFA13C ^ dword_DF9EB0;
        dword_DF9EB4 = v32;
        v37 = v36 ^ dword_DF9EB0 ^ dword_DFA13C;
        v174 = (float *)(v35 + 8 * v161 - 8);
        v38 = 16 * v161;
        v40 = v161 < 0;
        dword_DFA138 = v33;
        dword_DF9EAC ^= dword_DF9EA8 ^ dword_DF9EAC;
        dword_DF9EA8 = v35;
        dword_DF9EB0 ^= dword_DFA13C ^ dword_DF9EB0;
        dword_DFA13C = v37;
        v162 = 0;
        v41 = (float *)(v38 + v37 - 16);
        v168 = (float *)v33;
        if (!v40 && (v161 != 0))
        {
            v42 = 0;
            v43 = 0;
            v192 = v197;
            do
            {
                v44 = v158[0];
                v198 = *(float *)(a1 + 40) * v158[1];
                v46 = *(float *)(a1 + 40) * v168[1];
                if (v47 | v48 || v46 >= *v168)
                {
                    if (v158[0] != v198 && v46 != v168[0]
                        && (v158[0] > (double)v198 || v46 < v168[0]))
                    {
                        v199 = v168[1] - v158[1];
                        v180 = v168[0] - v158[0];
                        v51 = v168[1] * v158[0] - v158[1] * v168[0];
                        if (!v52)
                        {
                            v49 = *(float *)(a1 + 40) * v199 - v180;
                            v51 = v51 / v49;
                        }
                        v186 = *(float *)(a1 + 40) * v51;

                        v54 = v55 ? -v54 : v199;
                        v57 = v58 ? -v75 : v180;
                        if (v54 <= v57)
                        {
                            v59 = (v186 - v158[0]) / v180;
                            else
                            {
                                v59 = (v51 - v158[1]) / v199;
                            }
                            *(float *)(v32 + v43) = v186;
                            *(float *)(dword_DF9EB4 + v43 + 4) = v51;
                            v60 = 8 * v162;
                            ++v162;

                            // Copy Z, Y, X
                            *(float *)(dword_DF9EB4 + v43 + 8) =
                                (v168[2] - v158[2]) * v59 + v158[2];
                            *(float *)(dword_DF9EAC + v60 + 0) =
                                (*(float *)(v35 + 0) - v174[0]) * v59 + v174[0];
                            *(float *)(dword_DF9EAC + v60 + 4) =
                                (*(float *)(v35 + 4) - v174[1]) * v59 + v174[1];
                            v43 += 12;

                            // Copy RGBA
                            *(float *)(dword_DF9EB0 + v42 + 0) =
                                (*(float *)(v37 + 0) - v41[0]) * v59 + v41[0];
                            *(float *)(dword_DF9EB0 + v42 + 4) =
                                (*(float *)(v37 + 4) - v41[1]) * v59 + v41[1];
                            *(float *)(dword_DF9EB0 + v42 + 8) =
                                (*(float *)(v37 + 8) - v41[2]) * v59 + v41[2];
                            *(float *)(dword_DF9EB0 + v42 + 12) =
                                (*(float *)(v37 + 12) - v41[3]) * v59 + v41[3];
                            v42 += 16;

                            v61 = dword_DFAA04;
                            v32 = dword_DF9EB4;
                            LOBYTE(v61) = dword_DFAA04 | 0x20;
                            dword_DFAA04 = v61;
                        }

                        if (v46 >= *v168)
                        {
                            // Copy XYZ
                            v62 = (_DWORD *)(v43 + v32);
                            v62[0] = *((_DWORD *)v168 + 0);
                            v62[1] = *((_DWORD *)v168 + 1);
                            v62[2] = *((_DWORD *)v168 + 2);
                            v43 += 12;

                            // Copy UV
                            *(_DWORD *)(dword_DF9EAC + 8 * v162 + 0) =
                                *(_DWORD *)(v35 + 0);
                            *(_DWORD *)(dword_DF9EAC + 8 * v162 + 4) =
                                *(_DWORD *)(v35 + 4);

                            // Copy RGBA
                            v63 = (_DWORD *)(v42 + dword_DF9EB0);
                            v63[0] = *(_DWORD *)(v37 + 0);
                            v63[1] = *(_DWORD *)(v37 + 4);
                            v63[2] = *(_DWORD *)(v37 + 8);
                            v63[3] = *(_DWORD *)(v37 + 12);

                            ++v162;
                            v32 = dword_DF9EB4;
                            v42 += 16;
                        }
                    }
                    v174 = (float *)v35;
                    v158 = v168;
                    v168 += 3;
                    v41 = (float *)v37;
                    v35 += 8;
                    v37 += 16;
                    --v192;
                }
                while (v192)
                    ;
                v33 = dword_DFA138;
                v35 = dword_DF9EA8;
                v34 = dword_DF9EAC;
                v37 = dword_DFA13C;
                v36 = dword_DF9EB0;
            }
            if (v162 >= 3)
            {
                v64 = v36 ^ v37;
                v65 = v32 ^ v33;
                v66 = v65 ^ v32;
                dword_DF9EB0 = v64 ^ v36;
                v67 = (float *)(v64 ^ v36 ^ v64);
                v68 = v34 ^ v35;
                v69 = v66 ^ v65;
                v70 = v68 ^ v34;
                v71 = (float *)(v70 ^ v68);
                dword_DF9EAC = v70;
                v72 = 0;
                dword_DF9EB4 = v66;
                v159 = v69 + 12 * v162 - 12;
                v175 = &v71[2 * v162 - 2];
                v73 = 4 * v162;
                v40 = v162 < 0;
                dword_DFA138 = v69;
                dword_DF9EA8 = (int)v71;
                dword_DFA13C = (int)v67;
                v200 = v162;
                v163 = 0;
                v74 = &v67[v73 - 4];
                if (!v40 && (v162 != 0))
                {
                    v75 = 0;
                    v169 = (float *)(v69 + 8);
                    v193 = v200;
                    do
                    {
                        v76 = *(_DWORD *)(v159 + 8);
                        v201 = *(float *)(a1 + 44) * *(float *)(v159 + 4);
                        v78 = *(v169 - 1) * *(float *)(a1 + 44);
                        if (v79 | v80 || v78 >= *v169)
                        {
                            if (*(float *)(v159 + 8) != v201 && v78 != *v169
                                && (*(float *)(v159 + 8) > (double)v201
                                    || v78 < *v169))
                            {
                                v202 = *(v169 - 1) - *(float *)(v159 + 4);
                                v181 = *v169 - *(float *)(v159 + 8);
                                v81 = *(float *)(a1 + 44) * v202 - v181;
                                v83 = *(v169 - 1) * *(float *)(v159 + 8)
                                    - *v169 * *(float *)(v159 + 4);
                                if (v81 != 0.0)
                                {
                                    v82 = v81;
                                    v83 = v83 / v82;
                                }
                                v187 = *(float *)(a1 + 44) * v83;
                                v85 = v202;
                                if (v86)
                                    v85 = -v85;
                                v88 = v181;
                                if (v89)
                                    v88 = -v88;
                                if (v85 <= v88)
                                    v90 = (v187 - *(float *)(v159 + 8)) / v181;
                                else
                                    v90 = (v83 - *(float *)(v159 + 4)) / v202;
                                v203 = 8 * v163;
                                v75 += 12;
                                ++v163;
                                *(float *)(v66 + v75 - 12) =
                                    (*(v169 - 2) - *(float *)v159) * v90
                                    + *(float *)v159;
                                *(float *)(dword_DF9EB4 + v75 - 8) = v83;
                                *(float *)(dword_DF9EB4 + v75 - 4) = v187;
                                *(float *)(dword_DF9EAC + v203) =
                                    (*v71 - *v175) * v90 + *v175;
                                *(float *)(dword_DF9EAC + v203 + 4) =
                                    (v71[1] - v175[1]) * v90 + v175[1];
                                *(float *)(dword_DF9EB0 + v72) =
                                    (*v67 - *v74) * v90 + *v74;
                                *(float *)(dword_DF9EB0 + v72 + 4) =
                                    (v67[1] - v74[1]) * v90 + v74[1];
                                *(float *)(dword_DF9EB0 + v72 + 8) =
                                    (v67[2] - v74[2]) * v90 + v74[2];
                                v72 += 16;
                                *(float *)(dword_DF9EB0 + v72 - 4) =
                                    (v67[3] - v74[3]) * v90 + v74[3];
                                v91 = dword_DFAA04;
                                v66 = dword_DF9EB4;
                                LOBYTE(v91) = dword_DFAA04 | 4;
                                dword_DFAA04 = v91;
                            }
                            if (v78 >= *v169)
                            {
                                v92 = (_DWORD *)(v75 + v66);
                                v75 += 12;
                                *v92 = *((_DWORD *)v169 - 2);
                                v92[1] = *((_DWORD *)v169 - 1);
                                v92[2] = *(_DWORD *)v169;
                                *(float *)(dword_DF9EAC + 8 * v163) = *v71;
                                *(float *)(dword_DF9EAC + 8 * v163 + 4) =
                                    v71[1];
                                v93 = (_DWORD *)(v72 + dword_DF9EB0);
                                *v93 = *(_DWORD *)v67;
                                v93[1] = *((_DWORD *)v67 + 1);
                                v93[2] = *((_DWORD *)v67 + 2);
                                v93[3] = *((_DWORD *)v67 + 3);
                                ++v163;
                                v66 = dword_DF9EB4;
                                v72 += 16;
                            }
                        }
                        v175 = v71;
                        v71 += 2;
                        v159 = (int)(v169 - 2);
                        v169 += 3;
                        v74 = v67;
                        v67 += 4;
                        --v193;
                    } while (v193);
                    v72 = v163;
                }
                if (v72 >= 3)
                {
                    v94 = dword_DF9EAC ^ dword_DF9EA8;
                    v95 = v66 ^ dword_DFA138;
                    v96 = dword_DF9EAC ^ dword_DF9EA8 ^ dword_DF9EAC;
                    v97 = v66 ^ dword_DFA138 ^ v66;
                    dword_DF9EAC = v96;
                    v98 = (float *)(v96 ^ v94);
                    v99 = v97 ^ v95;
                    v100 = dword_DF9EB0 ^ dword_DFA13C;
                    v101 = 0;
                    v102 = dword_DF9EB0 ^ dword_DFA13C ^ dword_DF9EB0;
                    dword_DF9EB4 = v97;
                    dword_DF9EB0 = v102;
                    v103 = (float *)(v102 ^ v100);
                    dword_DFA138 = v99;
                    dword_DF9EA8 = (int)v98;
                    dword_DFA13C = (int)v103;
                    v204 = v72;
                    v160 = v99 + 12 * v72 - 12;
                    v176 = &v98[2 * v72 - 2];
                    v164 = 0;
                    v104 = &v103[4 * v72 - 4];
                    if (v72 > 0)
                    {
                        v105 = 0;
                        v170 = (float *)(v99 + 8);
                        v194 = v204;
                        do
                        {
                            v106 = *(_DWORD *)(v160 + 8);
                            v205 = *(float *)(a1 + 32) * *(float *)(v160 + 4);
                            v108 = *(v170 - 1) * *(float *)(a1 + 32);
                            if (!v109 || v108 <= *v170)
                            {
                                if (*(float *)(v160 + 8) != v205
                                    && v108 != *v170
                                    && (*(float *)(v160 + 8) < (double)v205
                                        || v108 > *v170))
                                {
                                    v206 = *(v170 - 1) - *(float *)(v160 + 4);
                                    v182 = *v170 - *(float *)(v160 + 8);
                                    v110 = *(float *)(a1 + 32) * v206 - v182;
                                    v112 = *(v170 - 1) * *(float *)(v160 + 8)
                                        - *v170 * *(float *)(v160 + 4);
                                    if (v110 != 0.0)
                                    {
                                        v111 = v110;
                                        v112 = v112 / v111;
                                    }
                                    v188 = *(float *)(a1 + 32) * v112;
                                    v114 = v206;
                                    if (v115)
                                        v114 = -v114;
                                    v117 = v182;
                                    if (v118)
                                        v117 = -v117;
                                    if (v114 <= v117)
                                        v119 = (v188 - *(float *)(v160 + 8))
                                            / v182;
                                    else
                                        v119 = (v112 - *(float *)(v160 + 4))
                                            / v206;
                                    v207 = 8 * v164;
                                    v101 += 12;
                                    ++v164;
                                    *(float *)(v97 + v101 - 12) =
                                        (*(v170 - 2) - *(float *)v160) * v119
                                        + *(float *)v160;
                                    *(float *)(dword_DF9EB4 + v101 - 8) = v112;
                                    *(float *)(dword_DF9EB4 + v101 - 4) = v188;
                                    *(float *)(dword_DF9EAC + v207) =
                                        (*v98 - *v176) * v119 + *v176;
                                    *(float *)(dword_DF9EAC + v207 + 4) =
                                        (v98[1] - v176[1]) * v119 + v176[1];
                                    *(float *)(dword_DF9EB0 + v105) =
                                        (*v103 - *v104) * v119 + *v104;
                                    *(float *)(dword_DF9EB0 + v105 + 4) =
                                        (v103[1] - v104[1]) * v119 + v104[1];
                                    *(float *)(dword_DF9EB0 + v105 + 8) =
                                        (v103[2] - v104[2]) * v119 + v104[2];
                                    v105 += 16;
                                    *(float *)(dword_DF9EB0 + v105 - 4) =
                                        (v103[3] - v104[3]) * v119 + v104[3];
                                    v120 = dword_DFAA04;
                                    v97 = dword_DF9EB4;
                                    LOBYTE(v120) = dword_DFAA04 | 8;
                                    dword_DFAA04 = v120;
                                }
                                if (v108 <= *v170)
                                {
                                    v121 = (_DWORD *)(v101 + v97);
                                    v101 += 12;
                                    *v121 = *((_DWORD *)v170 - 2);
                                    v121[1] = *((_DWORD *)v170 - 1);
                                    v121[2] = *(_DWORD *)v170;
                                    *(float *)(dword_DF9EAC + 8 * v164) = *v98;
                                    *(float *)(dword_DF9EAC + 8 * v164 + 4) =
                                        v98[1];
                                    v122 = (_DWORD *)(v105 + dword_DF9EB0);
                                    *v122 = *(_DWORD *)v103;
                                    v122[1] = *((_DWORD *)v103 + 1);
                                    v122[2] = *((_DWORD *)v103 + 2);
                                    v122[3] = *((_DWORD *)v103 + 3);
                                    ++v164;
                                    v97 = dword_DF9EB4;
                                    v105 += 16;
                                }
                            }
                            v176 = v98;
                            v98 += 2;
                            v160 = (int)(v170 - 2);
                            v170 += 3;
                            v104 = v103;
                            v103 += 4;
                            --v194;
                        } while (v194);
                        v101 = v164;
                    }
                    if (v101 >= 3)
                    {
                        v123 = dword_DF9EAC ^ dword_DF9EA8;
                        v124 = dword_DF9EAC ^ dword_DF9EA8 ^ dword_DF9EAC;
                        dword_DF9EAC = v124;
                        v125 = v124 ^ v123;
                        v126 = v97 ^ dword_DFA138;
                        v127 = dword_DF9EB0 ^ dword_DFA13C;
                        v128 = v97 ^ dword_DFA138 ^ v97;
                        v129 = dword_DF9EB0 ^ dword_DFA13C ^ dword_DF9EB0;
                        dword_DF9EB0 = v129;
                        v130 = v129 ^ v127;
                        dword_DFA138 = v128 ^ v126;
                        v208 = v101;
                        v131 = 0;
                        dword_DF9EB4 = v128;
                        dword_DF9EA8 = v125;
                        dword_DFA13C = v130;
                        v132 = (float *)((v128 ^ v126) + 12 * v101 - 12);
                        v177 = (float *)(v125 + 8 * v101 - 8);
                        v133 = (float *)v130;
                        v189 = (float *)v125;
                        v134 = (float *)(16 * v208 + v130 - 16);
                        v171 = (float *)v130;

                        // For loop from 0 to v208 (exclusive) ???
                        if (v208 > 0)
                        {
                            v135 = 0;
                            v165 = 0;
                            v183 = (float *)(dword_DFA138 + 4);
                            do
                            {
                                if (v132[1] >= (double)*(float *)(a1 + 4)
                                    || *v183 >= (double)*(float *)(a1 + 4))
                                {
                                    if (v132[1] != *(float *)(a1 + 4)
                                        && *v183 != *(float *)(a1 + 4)
                                        && (v132[1] < (double)*(float *)(a1 + 4)
                                            || *v183
                                                < (double)*(float *)(a1 + 4)))
                                    {
                                        v136 = (*(float *)(a1 + 4) - v132[1])
                                            / (*v183 - v132[1]);
                                        *(_DWORD *)(v128 + v165 + 4) =
                                            *(_DWORD *)(a1 + 4);
                                        *(float *)(dword_DF9EB4 + v165 + 8) =
                                            (v183[1] - v132[2]) * v136
                                            + v132[2];
                                        *(float *)(dword_DF9EB4 + v165) =
                                            (*(v183 - 1) - *v132) * v136
                                            + *v132;
                                        *(float *)(dword_DF9EAC + 8 * v131) =
                                            (*v189 - *v177) * v136 + *v177;
                                        v133 = v171;
                                        *(float *)(dword_DF9EAC + 8 * v131
                                                   + 4) =
                                            (v189[1] - v177[1]) * v136
                                            + v177[1];
                                        *(float *)(dword_DF9EB0 + v135) =
                                            (*v171 - *v134) * v136 + *v134;
                                        *(float *)(dword_DF9EB0 + v135 + 4) =
                                            (v171[1] - v134[1]) * v136
                                            + v134[1];
                                        v165 += 12;
                                        ++v131;
                                        v135 += 16;
                                        *(float *)(dword_DF9EB0 + v135 - 8) =
                                            (v171[2] - v134[2]) * v136
                                            + v134[2];
                                        *(float *)(dword_DF9EB0 + v135 - 4) =
                                            (v171[3] - v134[3]) * v136
                                            + v134[3];
                                        v137 = dword_DFAA04;
                                        v128 = dword_DF9EB4;
                                        LOBYTE(v137) = dword_DFAA04 | 1;
                                        dword_DFAA04 = v137;
                                    }
                                    if (*v183 >= (double)*(float *)(a1 + 4))
                                    {
                                        v138 = (_DWORD *)(v165 + v128);
                                        v165 += 12;
                                        *v138 = *((_DWORD *)v183 - 1);
                                        v138[1] = *(_DWORD *)v183;
                                        v138[2] = *((_DWORD *)v183 + 1);
                                        *(float *)(dword_DF9EAC + 8 * v131) =
                                            *v189;
                                        *(float *)(dword_DF9EAC + 8 * v131
                                                   + 4) = v189[1];
                                        v139 = (_DWORD *)(v135 + dword_DF9EB0);
                                        ++v131;
                                        v135 += 16;
                                        *v139 = *(_DWORD *)v133;
                                        v139[1] = *((_DWORD *)v133 + 1);
                                        v139[2] = *((_DWORD *)v133 + 2);
                                        v139[3] = *((_DWORD *)v133 + 3);
                                        v128 = dword_DF9EB4;
                                    }
                                }
                                v134 = v133;
                                v133 += 4;
                                v132 = v183 - 1;
                                v183 += 3;
                                v177 = v189;
                                v189 += 2;
                                v171 = v133;
                                v208--;
                            } while (v208 != 0);

                            v125 = dword_DF9EA8;
                            v130 = dword_DFA13C;
                        }

                        v140 = dword_DFA138;

                        if (v131 >= 3)
                        {
                            if (!*(_DWORD *)a1)
                            {
                                if ((float *)v128 != a2)
                                {
                                    qmemcpy(
                                        a2, (const void *)v128,
                                        4 * ((unsigned int)(12 * v131) >> 2));
                                    qmemcpy(
                                        a3, (const void *)dword_DF9EAC,
                                        4 * ((unsigned int)(8 * v131) >> 2));
                                    qmemcpy(
                                        a4, (const void *)dword_DF9EB0,
                                        4 * ((unsigned int)(16 * v131) >> 2));
                                }
                                return v131;
                            }
                            v142 = v128 ^ v140;
                            v143 = dword_DF9EAC ^ v125;
                            v144 = v131;
                            v145 = v143 ^ dword_DF9EAC;
                            v128 ^= v142;
                            dword_DF9EAC = v145;
                            v146 = v145 ^ v143;
                            v147 = dword_DF9EB0 ^ v130;
                            dword_DFA138 = v128 ^ v142;
                            v148 = v147 ^ dword_DF9EB0;
                            v131 = 0;
                            dword_DF9EB0 = v148;
                            v149 = (float *)(v148 ^ v147);
                            dword_DF9EB4 = v128;
                            dword_DF9EA8 = v146;
                            dword_DFA13C = (int)v149;
                            v150 = (float *)((v128 ^ v142) + 12 * v144 - 12);
                            v178 = (float *)(v146 + 8 * v144 - 8);
                            v209 = v144;
                            v151 = &v149[4 * v144 - 4];
                            v190 = (float *)v146;
                            v172 = v149;

                            // Loop from 0 to ???
                            if (v144 > 0)
                            {
                                v152 = 0;
                                v166 = 0;
                                v184 = (float *)(dword_DFA138 + 4);
                                do
                                {
                                    if (v150[1] <= (double)*(float *)(a1 + 8)
                                        || *v184 <= (double)*(float *)(a1 + 8))
                                    {
                                        if (v150[1] != *(float *)(a1 + 8)
                                            && *v184 != *(float *)(a1 + 8)
                                            && (v150[1]
                                                    > (double)*(float *)(a1 + 8)
                                                || *v184 > (double)*(
                                                       float *)(a1 + 8)))
                                        {
                                            v153 =
                                                (*(float *)(a1 + 8) - v150[1])
                                                / (*v184 - v150[1]);
                                            *(_DWORD *)(v128 + v166 + 4) =
                                                *(_DWORD *)(a1 + 8);
                                            *(float *)(dword_DF9EB4 + v166
                                                       + 8) =
                                                (v184[1] - v150[2]) * v153
                                                + v150[2];
                                            *(float *)(dword_DF9EB4 + v166) =
                                                (*(v184 - 1) - *v150) * v153
                                                + *v150;
                                            *(float *)(dword_DF9EAC
                                                       + 8 * v131) =
                                                (*v190 - *v178) * v153 + *v178;
                                            v149 = v172;
                                            *(float *)(dword_DF9EAC + 8 * v131
                                                       + 4) =
                                                (v190[1] - v178[1]) * v153
                                                + v178[1];
                                            *(float *)(dword_DF9EB0 + v152) =
                                                (*v172 - *v151) * v153 + *v151;
                                            *(float *)(dword_DF9EB0 + v152
                                                       + 4) =
                                                (v172[1] - v151[1]) * v153
                                                + v151[1];
                                            v166 += 12;
                                            ++v131;
                                            v152 += 16;
                                            *(float *)(dword_DF9EB0 + v152
                                                       - 8) =
                                                (v172[2] - v151[2]) * v153
                                                + v151[2];
                                            *(float *)(dword_DF9EB0 + v152
                                                       - 4) =
                                                (v172[3] - v151[3]) * v153
                                                + v151[3];
                                            v154 = dword_DFAA04;
                                            v128 = dword_DF9EB4;
                                            LOBYTE(v154) = dword_DFAA04 | 2;
                                            dword_DFAA04 = v154;
                                        }
                                        if (*v184 <= (double)*(float *)(a1 + 8))
                                        {
                                            v155 = (_DWORD *)(v166 + v128);
                                            v166 += 12;
                                            *v155 = *((_DWORD *)v184 - 1);
                                            v155[1] = *(_DWORD *)v184;
                                            v155[2] = *((_DWORD *)v184 + 1);
                                            *(float *)(dword_DF9EAC
                                                       + 8 * v131) = *v190;
                                            *(float *)(dword_DF9EAC + 8 * v131
                                                       + 4) = v190[1];
                                            v156 =
                                                (_DWORD *)(v152 + dword_DF9EB0);
                                            ++v131;
                                            v152 += 16;
                                            *v156 = *(_DWORD *)v149;
                                            v156[1] = *((_DWORD *)v149 + 1);
                                            v156[2] = *((_DWORD *)v149 + 2);
                                            v156[3] = *((_DWORD *)v149 + 3);
                                            v128 = dword_DF9EB4;
                                        }
                                    }
                                    v151 = v149;
                                    v149 += 4;
                                    v150 = v184 - 1;
                                    v184 += 3;
                                    v178 = v190;
                                    v190 += 2;
                                    v172 = v149;
                                    v209--;
                                } while (v209 != 0);
                            }

                            if (v131 >= 3)
                            {
                                if ((float *)v128 != a2)
                                {
                                    qmemcpy(
                                        a2, (const void *)v128,
                                        4 * ((unsigned int)(12 * v131) >> 2));
                                    qmemcpy(
                                        a3, (const void *)dword_DF9EAC,
                                        4 * ((unsigned int)(8 * v131) >> 2));
                                    qmemcpy(
                                        a4, (const void *)dword_DF9EB0,
                                        4 * ((unsigned int)(16 * v131) >> 2));
                                }
                            }
                            return v131;
                        }
                        else
                        {
                            v141 = dword_DFAA04;
                            LOBYTE(v141) = dword_DFAA04 | 0x40;
                            dword_DFAA04 = v141;
                            return v131;
                        }
                    }
                    else
                    {
                        return v164;
                    }
                }
                else
                {
                    return v163;
                }
            }
            else
            {
                return v162;
            }
        }
        return result;
    }
