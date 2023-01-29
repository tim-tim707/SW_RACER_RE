// 8 (?) elements at dword_E67E40
struct
{
    uint32_t unk0;
    uint32_t unk1; // index to some other object, probably buffer
    uint32_t unk2; // some flag?
    uint32_t unk3;
    uint32_t unk4;
    float unk5;
    float unk6; // volume?
    uint32_t unk7;
    A3dSource *unk8; // not 100% sure
    uint32_t unk9;
    uint32_t unk10; // some flag?
    float unk11; // x
    float unk12; // y
    float unk13; // z
    float unk14; // x
    float unk15; // y
    float unk16; // z
    // 68 bytes
} AudioSource;

//----- (00449EF0) --------------------------------------------------------
int sub_449EF0()
{
    int result; // eax
    unsigned int v1; // ebp
    int *v2; // esi
    float v3; // ST0C_4
    int v4; // eax
    int *v5; // ebx
    int v6; // edi
    float *v7; // eax
    int v10; // ecx
    int v12; // eax
    int *v13; // edi
    int v14; // ebx
    int v15; // eax
    signed int v16; // ebx
    int v17; // eax
    signed __int64 v18; // rax
    float v19; // ST0C_4
    int v20; // ecx
    double v21; // st7
    int v22; // ST0C_4
    __int16 v23; // ax
    float v24; // ST0C_4
    float *v25; // esi
    double v26; // st5
    double v27; // st6
    double v28; // st7
    int v31; // edi
    int v32; // eax
    int v33; // eax
    int v34; // esi
    int v35; // ST08_4
    signed int v36; // eax
    double v37; // st7
    int v38; // ebx
    double v39; // st7
    int v40; // ST0C_4
    double v41; // st7
    signed __int64 v42; // rax
    signed int v43; // ecx
    float v44; // ST0C_4
    __int16 v45; // ax
    float v46; // ST0C_4
    int v47; // ST0C_4
    int v48; // ST08_4
    float *v49; // ecx
    bool v50; // sf
    unsigned __int8 v51; // of
    double v52; // [esp+20h] [ebp-30h]
    int v53; // [esp+28h] [ebp-28h]
    int v54; // [esp+2Ch] [ebp-24h]
    double v55; // [esp+30h] [ebp-20h]
    float v56; // [esp+38h] [ebp-18h]
    float v57; // [esp+3Ch] [ebp-14h]
    float v58; // [esp+40h] [ebp-10h]

    result = dword_4EB450;
    if (!dword_4EB450)
    {
        return result;
    }

    if (dword_50D550)
    {
        dword_50C678 = dword_50C668;
        dword_50C67C = dword_50C66C;
        dword_50C680 = dword_50C670;
        sub_4292B0(&unk_50C638);
    }

    if (byte_50C684 == byte_50C688)
    {
        v53 = 0;
    }
    else
    {
        v53 = 1;
        byte_50C684 = byte_50C688;
    }

    if (dword_4EB454 <= 0)
    {
        dword_4EB454 = 0;
    }
    else
    {
        --dword_4EB454;
    }

    LODWORD(v52) = 0;
    do
    {
        v1 = 68 * LODWORD(v52);
        v2 = &dword_E67E40[17 * LODWORD(v52)];
        if (dword_E67E40[17 * LODWORD(v52)] >= 0 && !dword_E67E68[v1 / 4]
            && dword_4EB454
            && *(_DWORD *)(sub_422A90(dword_E67E44[v1 / 4]) + 72)
                != dword_E67E60[v1 / 4])
        {
            sub_449E00((int)v2);
        }

        if (dword_E67C40[v1 / 4])
        {
            HIDWORD(v52) = (signed __int64)((double)dword_E67C38[v1 / 4]
                                            - dbl_E22A40 * 42666.66666666666);
            dword_E67C38[v1 / 4] = HIDWORD(v52);
            if ((double)SHIDWORD(v52) > 0.0f)
            {
                v3 = (double)SHIDWORD(v52)
                    * (1.0f / (float)0x7FFF); // * 0.000030518509;
                sub_484D90(dword_E67C40[v1 / 4], v3);
            }
            else
            {
                sub_485070(dword_E67C40[v1 / 4]);
                if (dword_E67C44[v1 / 4])
                {
                    sub_4850A0(dword_E67C40[v1 / 4]);
                }
                dword_E67C40[v1 / 4] = 0;
                dword_E67C44[v1 / 4] = 1;
            }
        }

        if (dword_E68068[v1 / 4])
        {
            v4 = dword_E6806C[v1 / 4];
            if (v4 != dword_E22A30 && v4 != dword_E22A30 - 1)
            {
                LODWORD(v55) = (signed __int64)((double)dword_E68078[v1 / 4]
                                                - dbl_E22A40 * 64000.0);
                dword_E68078[v1 / 4] = LODWORD(v55);
                if ((double)SLODWORD(v55) <= 0.0)
                {
                    dword_E68078[v1 / 4] = 0;
                    sub_449E00((int)&dword_E68060[v1 / 4]);
                }
            }
        }

        if (*v2 != -1)
        {
            v5 = (int *)dword_E67E60[v1 / 4];
            if (!sub_4850C0(dword_E67E60[v1 / 4], 0))
            {
                if (dword_E68060[v1 / 4] == *v2)
                {
                    sub_449E00((int)&dword_E68060[v1 / 4]);
                }
                v6 = sub_422A90(dword_E67E44[v1 / 4]);
                if (!(*(_BYTE *)(v6 + 36) & 8))
                {
                    if (dword_E67E68[v1 / 4])
                    {
                        sub_4850A0((int)v5);
                    }

                    if (dword_4B6D2C)
                    {
                        if (*(_DWORD *)(v6 + 40) <= 300000)
                        {
                            sub_449E00((int)v2);
                            goto LABEL_47;
                        }
                    }
                    else if (*(_BYTE *)(v6 + 36) & 6
                             || *(_DWORD *)(v6 + 40) <= 200000)
                    {
                        sub_449E00((int)v2);
                        goto LABEL_47;
                    }
                }
                sub_422D10((_DWORD *)v6);
                sub_449E00((int)v2);
                goto LABEL_47;
            }

            // Update velocity
            if (dword_E67E78[v1 / 4] && !(sub_485040(v5) & 0x20))
            {
                sub_484E10((int)v5, dword_E67E78[v1 / 4]);
                if (dword_4B6D18)
                {
                    v7 = (float *)dword_E67E78[v1 / 4];

                    // Scale some vector between 2 points?
                    v55 = 1.0 / dbl_E22A40;
                    float v59 =
                        v7[0] - *(float *)&dword_E67E6C[17 * LODWORD(v52)];
                    float v60 =
                        v7[1] - *(float *)&dword_E67E70[17 * LODWORD(v52)];
                    float v61 =
                        v7[2] - *(float *)&dword_E67E74[17 * LODWORD(v52)];

                    float v[3];
                    v[0] = v59 * v55;
                    v[1] = v60 * v55;
                    v[2] = v61 * v55;
                    sub_484E40((int)v5, v); // Does SetVelocity3f
                }
                else
                {
                    sub_484E40((int)v5, (float *)&unk_50C690);
                }
                dword_E67E6C[v1 / 4] = *(_DWORD *)(dword_E67E78[v1 / 4] + 0);
                dword_E67E70[v1 / 4] = *(_DWORD *)(dword_E67E78[v1 / 4] + 4);
                dword_E67E74[v1 / 4] = *(_DWORD *)(dword_E67E78[v1 / 4] + 8);

                // Note that this copies the freshly written values, so we just
                // duplicated memory from 0xE67E78
                dword_E6808C[v1 / 4] = dword_E67E6C[v1 / 4];
                dword_E68090[v1 / 4] = dword_E67E70[v1 / 4];
                dword_E68094[v1 / 4] = dword_E67E74[v1 / 4];
            }
        }

    LABEL_47:
        v12 = *v2;
        if (dword_E68060[v1 / 4] == *v2)
        {
            if (v12 < 0)
            {
                goto LABEL_119;
            }

            // Get pointer to source?
            v13 = (int *)dword_E67E60[v1 / 4];

            if (v53)
            {
                if (dword_4EB460)
                {
                    v14 = sub_422A90(dword_E67E44[v1 / 4]);
                    LODWORD(v55) = v14;
                    if (!(*(_BYTE *)(v14 + 36) & 8))
                    {
                        HIDWORD(v52) = (unsigned __int8)byte_50C688 > 0u;
                        v15 = sub_422E30(v14, 0, (_DWORD *)&v52 + 1);
                        if (HIDWORD(v52) == (unsigned __int8)byte_50C688 > 0u)
                        {
                            qmemcpy((char *)&unk_E67C20 + v1, v2, 0x44u);
                            dword_E67C44[v1 / 4] =
                                dword_E67C40[v1 / 4] != *(_DWORD *)(v14 + 72);
                            dword_E68080[v1 / 4] = v15;
                            dword_E68088[v1 / 4] = v15 != *(_DWORD *)(v14 + 72);
                        LABEL_95:
                            v37 = *(float *)&dword_E68074[17 * LODWORD(v52)];
                            v38 = dword_E68080[v1 / 4];
                            qmemcpy(&dword_E67E40[v1 / 4],
                                    &dword_E68060[v1 / 4], 0x44u);
                            if (v37 >= 0.05)
                            {
                                v39 =
                                    *(float *)&dword_E68074[17 * LODWORD(v52)];
                            }
                            else
                            {
                                v39 = 0.05;
                            }
                            *(float *)&v40 = v39 + v39;
                            sub_484DD0(v38, *(_DWORD *)(LODWORD(v55) + 44),
                                       v40);
                            if (dword_E68068[v1 / 4])
                            {
                                v41 =
                                    dbl_E22A40 <= 0.5 ? dbl_E22A40 : dbl_50CB70;
                                v42 = (signed __int64)(v41 * 42666.66666666666);
                                v43 = dword_E68078[v1 / 4];
                                dword_E67E58[v1 / 4] = v42;
                                if ((signed int)v42 > v43)
                                    dword_E67E58[v1 / 4] = v43;
                            }
                            v44 = (double)dword_E67E58[v1 / 4]
                                * (1.0f / (float)0x7FFF) // * 0.000030518509;
                                sub_484D90(v38, v44);
                            v45 = word_E6807C[v1 / 2];
                            if (v45 != -999)
                            {
                                LODWORD(v55) = v45;
                                v46 = ((double)v45 - 64.0) * 0.015625;
                                sub_484C30(v38, v46);
                            }
                            if (word_E6807C[v1 / 2] == -999)
                            {
                                sub_485020(v38, 0);
                                v38->SetTransformMode(0);
                                *(float *)&v47 =
                                    dword_E6809C[17 * LODWORD(v52)] * 3.28;
                                *(float *)&v48 =
                                    dword_E680A0[17 * LODWORD(v52)] * 3.28;
                                sub_484DF0(v38, v48, v47);
                                sub_484E10(v38, (int)&dword_E6808C[v1 / 4]);
                                if (dword_E68068[v1 / 4])
                                {
                                    sub_484E40(v38, (float *)&unk_50C690);
                                }

                                if (dword_E68064[v1 / 4] < dword_E9F360)
                                {
                                    if (dword_E2899C
                                        && ((v49 = *(float **)(dword_E2899C
                                                               + 132),
                                             *(float *)&dword_E6808C[v1 / 4]
                                                 != v49[20])
                                            || *(float *)&dword_E68090
                                                    [17 * LODWORD(v52)]
                                                != v49[21]
                                            || *(float *)&dword_E68094
                                                    [17 * LODWORD(v52)]
                                                != v49[22]))
                                    {
                                        v38->SetDopplerScale(1.0f)
                                    }
                                    else
                                    {
                                        v38->SetDopplerScale(0.0f);
                                    }
                                }
                                else
                                {
                                    v38->SetDopplerScale(0.0f);
                                }
                            }
                            else
                            {
                                sub_485020(v38, 32);
                            }
                            sub_484BE0(v38, dword_E68068[v1 / 4]);
                            goto LABEL_119;
                        }
                        if (v15 != *(_DWORD *)(v14 + 72))
                            sub_4850A0(v15);
                    }
                }
            }

            v16 = dword_E68078[v1 / 4];
            LODWORD(v55) = dword_E67E58[v1 / 4];
            if (LODWORD(v55) != v16)
            {
                if (!dword_E67E48[v1 / 4]
                    || (v17 = dword_E67E4C[v1 / 4], v17 != dword_E22A30)
                        && v17 != dword_E22A30 - 1
                        && (v18 = (signed __int64)((double)SLODWORD(v55)
                                                   - dbl_E22A40
                                                       * -42666.66666666666),
                            dword_E67E58[v1 / 4] = v18, (signed int)v18 > v16))
                {
                    dword_E67E58[v1 / 4] = v16;
                }
                v19 = (double)dword_E67E58[v1 / 4]
                    * (1.0f / (float)0x7FFF) // * 0.000030518509;
                    sub_484D90((int)v13, v19);
            }
            if (*(float *)&dword_E67E54[17 * LODWORD(v52)]
                != *(float *)&dword_E68074[17 * LODWORD(v52)])
            {
                v20 = sub_422A90(dword_E67E44[v1 / 4]);

                if (*(float *)&dword_E68074[17 * LODWORD(v52)] >= 0.05f)
                    v21 = *(float *)&dword_E68074[17 * LODWORD(v52)];
                else
                    v21 = 0.05f;

                *(float *)&v22 = v21 + v21;
                sub_484DD0((int)v13, *(_DWORD *)(v20 + 44), v22);
                dword_E67E54[v1 / 4] = dword_E68074[v1 / 4];
            }
            v23 = word_E6807C[v1 / 2];
            if (word_E67E5C[v1 / 2] != v23)
            {
                if (v23 != -999)
                {
                    LODWORD(v55) = v23;
                    v24 = ((double)v23 - 64.0) * 0.015625;
                    sub_484C30((int)v13, v24);
                    if (!(sub_485040(v13) & 0x20))
                        sub_485020((int)v13, 32);
                }
                v23 = word_E6807C[v1 / 2];
                word_E67E5C[v1 / 2] = v23;
            }
            if (v23 == -999
                && (sub_485040(v13) & 0x20
                    || *(float *)&dword_E67E6C[17 * LODWORD(v52)]
                        != *(float *)&dword_E6808C[17 * LODWORD(v52)]
                    || *(float *)&dword_E67E70[17 * LODWORD(v52)]
                        != *(float *)&dword_E68090[17 * LODWORD(v52)]
                    || *(float *)&dword_E67E74[17 * LODWORD(v52)]
                        != *(float *)&dword_E68094[17 * LODWORD(v52)]))
            {
                sub_485020((int)v13, 0);
                sub_484E10((int)v13, (int)&dword_E6808C[v1 / 4]);
                if (dword_E68068[v1 / 4])
                {
                    if (dword_4B6D18)
                    {
                        v26 = *(float *)&dword_E6808C[v1 / 4]
                            - *(float *)&dword_E67E6C[17 * LODWORD(v52)];
                        v27 = *(float *)&dword_E68090[17 * LODWORD(v52)]
                            - *(float *)&dword_E67E70[17 * LODWORD(v52)];
                        v28 = *(float *)&dword_E68094[17 * LODWORD(v52)]
                            - *(float *)&dword_E67E74[17 * LODWORD(v52)];
                        v55 = 1.0 / dbl_E22A40;
                        v56 = v26 * v55;
                        v57 = v27 * v55;
                        v58 = v28 * v55;
                        sub_484E40((int)v13, &v56);
                    }
                    else
                    {
                        sub_484E40((int)v13, (float *)&unk_50C690);
                    }
                }
                dword_E67E6C[v1 / 4] = dword_E6808C[v1 / 4];
                dword_E67E70[v1 / 4] = dword_E68090[v1 / 4];
                dword_E67E74[v1 / 4] = dword_E68094[v1 / 4];
            }
        }
        else
        {
            if (v12 == -1)
            {
                v33 = dword_E68064[v1 / 4];
                if (v33 == -1)
                {
                    goto LABEL_119;
                }
                dword_E68060[v1 / 4] = v33;
                if (v33 == -1)
                {
                    goto LABEL_119;
                }
                if (!byte_50C688 || (v54 = 1, !dword_4EB460))
                {
                    v54 = 0;
                }
                v34 = sub_422A90(dword_E68064[v1 / 4]);
                v35 = dword_E68068[v1 / 4];
                LODWORD(v55) = v34;
                v36 = sub_422E30(v34, v35, &v54);
                dword_E68080[v1 / 4] = v36;
                dword_E68088[v1 / 4] = v36 != *(_DWORD *)(v34 + 72);
                goto LABEL_95;
            }
            if (dword_E67E50[v1 / 4])
            {
                v31 = dword_E67E60[v1 / 4];
                v32 = sub_422A90(dword_E67E44[v1 / 4]);
                if (!(*(_BYTE *)(v32 + 36) & 8) || sub_423190(v32))
                {
                    sub_485070(v31);
                }
                dword_E67E50[v1 / 4] = 0;
            }
        }
    LABEL_119:
        LODWORD(v52) += 1;
        v51 = __OFSUB__(LODWORD(v52), 8);
        v50 = LODWORD(v52) < 8;
    } while (v50 ^ v51);

    // This block proabbly handles the listener
    if (dword_50D550)
    {
        if (dword_4B6D18)
        {
            v55 = 1.0 / dbl_E22A40;
            v56 = (*(float *)&dword_50C668 - *(float *)&dword_50C678) * v55;
            v57 = (*(float *)&dword_50C66C - *(float *)&dword_50C67C) * v55;
            v58 = (*(float *)&dword_50C670 - *(float *)&dword_50C680) * v55;
            sub_484F10((int)&v56);
        }
        else
        {
            sub_484F10((int)&unk_50C690);
        }
        sub_484F40((int)&dword_50C668, (int)&unk_50C648, (int)&unk_50C658);
    }

    return sub_484FA0();
}

//----- (00449E00) --------------------------------------------------------
uint32_t *__cdecl sub_449E00(uint32_t *a1)
{
    a1[0] = -1;
    a1[1] = -1;
    a1[2] = 0;
    a1[3] = -1;
    a1[4] = 0;
    a1[5] = 1.0f;
    // a1[6] not set
    a1[7] = 64;
    a1[8] = 0;
    // a1[9] not set
    a1[10] = 0;
    return a1;
}

//----- (004292B0) --------------------------------------------------------
// a1 = 4x4 matrix?!
_DWORD *__cdecl sub_4292B0(float *a1)
{
    int32_t v1 = _RTC_NumErrors(); // FIXME: I'm guessing this was misdetected?!
    if (v1 <= 0)
    {
        return set_identity_mat(a1);
    }

    int32_t v3;
    int32_t v2 = 0;
    while (1)
    {
        v3 = sub_4318D0(v2);
        if (v3)
        {
            if (sub_431770(v3) & 1)
            {
                break;
            }
        }

        v2++;
        if (v2 >= v1)
        {
            return set_identity_mat(a1);
        }
    }

    int32_t v6 = sub_4318B0(v3);
    return sub_44BB10(a1, (int)off_4B91C4 + 124 * v6 + 20);
}

//----- (004313D0) --------------------------------------------------------
float *__cdecl set_identity_mat(float *a1)
{
    a1[0] = 1.0f;
    a1[1] = 0.0f;
    a1[2] = 0.0f;
    a1[3] = 0.0f;
    a1[4] = 0.0f;
    a1[5] = 1.0f;
    a1[6] = 0.0f;
    a1[7] = 0.0f;
    a1[8] = 0.0f;
    a1[9] = 0.0f;
    a1[10] = 1.0f;
    a1[11] = 0.0f;
    a1[12] = 0.0f;
    a1[13] = 0.0f;
    a1[14] = 0.0f;
    a1[15] = 1.0f;
    return a1;
}

//----- (004318D0) --------------------------------------------------------
int __cdecl sub_4318D0(int32_t a1)
{
    // Boundary check the argument
    if (a1 < 0 || a1 >= 4)
    {
        return 0;
    }

    return 0xDFB040 + a1 * 364;
}

//----- (00422A90) --------------------------------------------------------
int __cdecl sub_422A90(int32_t a1)
{
    // Boundary check the argument
    if (a1 < 0 || a1 >= *((_DWORD *)off_4B6D34 + 8))
    {
        result = 0;
    }

    return *((_DWORD *)off_4B6D34 + 10) + a1 * 76;
}

//----- (004850A0) --------------------------------------------------------
void __cdecl sub_4850A0(int a1)
{
    if (dword_50D548 == 0)
    {
        return;
    }
    a1->Release();
    return;
}

//----- (004850C0) --------------------------------------------------------
signed int __cdecl sub_4850C0(int a1, int a2)
{
    if (a1 == 0)
    {
        return -1;
    }

    int v2 = a1; // esi

    // GetStatus???
    // FIXME: This looks wrong? Why is it passing a pointer to itself?
    if ((*(int(__stdcall **)(int, int *))(*(_DWORD *)a1 + 224))(a1, &a1) < 0)
    {
        return -1;
    }

    if (!(a1 & 1))
    {
        return 0;
    }

    if (a2)
    {
        // GetWavePosition???
        (*(void(__stdcall **)(int, int))(*(_DWORD *)v2 + 76))(v2, a2);
    }
    return 1;
}
