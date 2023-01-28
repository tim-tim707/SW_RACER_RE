// a1 = &pixelsize_in_bytes
// a2 = &pitch
// a3 = &surface_data_ptr
// a4 = probably some width?
// a5 = probably some height?
// Locks the Z-Buffer
// Probably returns void
uint32_t *__cdecl sub_433CD0(uint32_t *a1, _DWORD *a2, _DWORD *a3, uint32_t *a4,
                             uint32_t *a5)
{
    // Get depth buffer surface
    DirectDrawSurface4 *v5 = sub_48DB40();

    // Lock the surface
    DDSURFACEDESC2 v8; // FIXME: static assert that this is sizeof() == 124 and
                       // use this below
    memset(&v8, 0, 124);
    v8.dwSize = 124;
    v5->Lock(NULL, &v8, 1, 0);

    *a2 = desc->lPitch; // + 0x10
    *a1 = desc->ddpfPixelFormat.dwZBufferBitDepth
        / 8; // +0x54 ; FIXME: Confirm that this is the correct field
    *a3 = desc->lpSurface; // +0x24

    *a4 = *(_DWORD *)(*(_DWORD *)(dword_E03204 + 72) + 4);
    *a5 = *(_DWORD *)(*(_DWORD *)(dword_E03204 + 72) + 8);

    return a5;
}
// Does various tests against the Z-Buffer
int sub_42D440()
{
    int v31; // [esp+10h] [ebp-30h]
    uint8_t *v32; // [esp+14h] [ebp-2Ch] // buffer base?
    int32_t v33; // [esp+18h] [ebp-28h] // pitch
    int32_t v35; // [esp+20h] [ebp-20h] // pixel size in bytes
    int v36; // [esp+24h] [ebp-1Ch]
    int v37; // [esp+28h] [ebp-18h]
    int v38; // [esp+2Ch] [ebp-14h]
    int v39; // [esp+30h] [ebp-10h]
    uint8_t *v40; // [esp+34h] [ebp-Ch]
    uint32_t v41; // [esp+38h] [ebp-8h]
    uint32_t v42; // [esp+3Ch] [ebp-4h]

    // Lock the Z-Buffer
    sub_433CD0(&v35, &v33, &v32, &v42, &v41);

    v40 = v32 + dword_ED38C8 * v33; // buffer end?

    // Presumably handle up to 2 suns
    for (unsigned int v3 = 0; v3 < 2; v3++)
    {
        if (dword_4BEE60[v3] >= 0)
        {
            int32_t v4 = dword_EA5760[v3];
            int32_t v5 = dword_EA5768[v3];
            if (v4 >= -500)
            {
                v36 = 12 - v4;
                v38 = 12 - v5;

                v37 = dword_ED39A4 - v4 - 8;
                v39 = dword_ED38C8 - v5 - 8;

                // Get pixel (v4 - 4, v5 - 4)
                uint8_t *v6 = v32 + v33 * (v5 - 4) + v35 * (v4 - 4);

                // This seems to scan a 8x8 pixel block and counts pixels which
                // were not in depth buffer [= farplane]
                v31 = 0;
                for (int v7 = 0; v7 < 8; v7++)
                {
                    for (int v8 = 0; v8 < 8; v8++)
                    {
                        if (v8 < v36 || v8 >= v37 || v7 < v38 || v7 >= v39
                            || v6 >= v32 && v6 < v40
                                && (v35 == 1 && *(uint8_t *)v6 != 0xFF
                                    || v35 == 2 && *(uint16_t *)v6 != 0xFFFF))
                        {
                            v31++;
                        }
                        v6 += v35;
                    }

                    v6 += v33 - 8 * v35;
                }

                dword_EA56A0[v3] = v31;
            }
            else
            {
                dword_EA56A0[v3] = 50;
            }
        }
    }

    // Get factor to bring depth values into [0.0, 1.0] range
    float v9;
    switch (v35)
    {
    case 1:
        v9 = flt_4BEE48;
        break; // 0x3b808081 ~ 1.0 / 0xFF
    case 2:
        v9 = flt_4BEE4C;
        break; // 0x37800080 ~ 1.0 / 0xFFFF
    case 3:
        v9 = flt_4BEE54;
        break; // 0x33800001 ~ 1.0 / 0xFFFFFE
    case 4:
        v9 = flt_4BEE50;
        break; // 0x2f800000 ~ 1.0 / 0xFFFFFFFF
    default:
        v9 = v42;
        break;
    }

    // 20 coordinates:
    //   X at dword_EA5A00[v10] (int)
    //   Y at dword_EA5A60[v10] (int)
    //   Z will be at dword_EA5AC0[v10] (float)
    for (int v10 = 0; v10 < 20; v10++)
    {
        int v11 = dword_EA5A00[v10];
        dword_EA5AC0[v10] = -1000.0f;
        if (v11 >= 0)
        {
            // Get depth pointer for pixel (v11, dword_EA5A60[v10])
            uint8_t *v13 = v32 + v33 * dword_EA5A60[v10] + v11 * v35 + v35;

            // Read depth bytes
            float v12 = 0.0;
            int v14 = 8 * v35;
            for (int v15 = 0; v15 < v35; v15++)
            {
                v14 -= 8;
                v40 = *--v13;
                v40 <<= v14;
                v12 += (int32_t)v40;
            }

            // Normalize depth
            dword_EA5AC0[v10] = v12 * v9;
        }
    }

    // 40 coordinates:
    //   byte_EA59C0[v17] must be != 0 or coord is ignored
    //   X at dword_EA4FC0[v17] (int)
    //   Y at dword_EA4F20[v17] (int)
    //   Z will be at dword_EA5060[v17] (float)
    for (int v17 = 0; v17 < 40; v17++)
    {
        if (byte_EA59C0[v17] == 0)
        {
            continue;
        }

        int v18 = dword_EA4FC0[v17];
        dword_EA5060[v17] = -1000.0;
        if (v18 >= 0)
        {
            uint8_t *v20 = v32 + v33 * dword_EA4F20[v17] + v18 * v35 + v35;

            float v19 = 0.0;
            int v21 = 8 * v35;
            for (int v22 = 0; v22 < v35; v22++)
            {
                v21 -= 8;
                v40 = *--v20;
                v40 <<= v21;
                v19 += (int32_t)v40;
            }

            dword_EA5060[v17] = v19 * v9;
        }
    }

    // dword_517348 coordinates
    //   X at dword_EA5B80[v23] (int)
    //   Y at dword_EA5C00[v23] (int)
    //   Z as output at EA5BC0 (float)
    for (int v23 = 0; v23 < dword_517348; v23++)
    {
        int32_t v25 = dword_EA5B80[v23];
        dword_EA5BC0[v23] = -1000.0;
        if (v25 >= 0)
        {
            uint8_t *v27 = v32 + v33 * dword_EA5C00[v23] + v25 * v35 + v35;

            float v26 = 0.0;
            int v28 = 8 * v35;
            for (int v29 = 0; v29 < v35; v29++)
            {
                v28 -= 8;
                v40 = *--v27;
                v40 <<= v28;
                v26 += (int32_t)v40;
            }

            dword_EA5BC0[v23] = v26 * v9;
        }
    }

    // Unlock zbuffer
    return sub_433D60();
}
char __cdecl sub_42E280(int a1)
{
    char result; // al
    float v2; // eax
    int v4; // edi
    float *v5; // ebx
    int *v6; // ebp
    float *v7; // esi
    int v10; // edx
    double v11; // st7
    char v13; // cl
    double v14; // st7
    int v15; // edx
    double v19; // st7
    unsigned __int8 v20; // c0
    unsigned __int8 v21; // c3
    double v23; // st7
    unsigned __int8 v24; // c0
    unsigned __int8 v25; // c3
    double v27; // st7
    unsigned __int8 v28; // c0
    unsigned __int8 v29; // c3
    __int16 v30; // ST14_2
    double v31; // st7
    double v32; // st5
    double v33; // st7
    double v34; // st7
    float v38; // [esp+0h] [ebp-3Ch]
    float v39; // [esp+4h] [ebp-38h]
    int v40; // [esp+8h] [ebp-34h]
    float v41; // [esp+Ch] [ebp-30h]
    int v43; // [esp+14h] [ebp-28h]
    float v44; // [esp+18h] [ebp-24h]
    float v45; // [esp+1Ch] [ebp-20h]
    float *v47; // [esp+24h] [ebp-18h]
    int v48; // [esp+28h] [ebp-14h]
    int v49; // [esp+2Ch] [ebp-10h]
    char v51; // [esp+34h] [ebp-8h]
    char v52; // [esp+38h] [ebp-4h]
    int v53; // [esp+40h] [ebp+4h]
    float v54; // [esp+40h] [ebp+4h]

    if (!byte_4BEEB8)
    {
        return 0;
    }

    result = byte_4BEEB8;

    // Lock z-buffer
    sub_433CD0((unsigned int *)&v43, &v48, &v49, &v52, &v51);

    // Get factor to normalize z-buffer values
    switch (v43)
    {
    case 1:
        v41 = flt_4BEE48;
        break;
    case 2:
        v41 = flt_4BEE4C;
        break;
    case 3:
        v41 = flt_4BEE54;
        break;
    case 4:
        v41 = flt_4BEE50;
        break;
    default:
        break;
    }

    v4 = a1;
    v5 = (float *)&unk_EA52E0;
    v6 = dword_EA5560;
    v7 = (float *)&unk_EA4B40;

    for (v40 = 0; v40 < dword_4BEECC; v40++)
    {
        if (*v6 != -1)
        {
            if (byte_EA5C40[v40])
            {
                v7[0] = v7[0] - flt_4BEEC0 * dbl_E2DD00;
                v7[2] = v7[2] - flt_4BEEC4 * dbl_E2DD00;
            }
            else
            {
                sub_429B60(*(_WORD *)v6, 0);
                if (frand() > 0.7f)
                {
                    v7[0] = flt_5179B8;
                    v7[1] = flt_5179BC;
                    v7[2] = flt_5179C0;

                    v10 = v40;
                    byte_EA5C40[v10] = 1;

                    v7[0] += frand(-400.0f, 400.0f) * *(float *)(v4 + 112);
                    v7[1] += frand(-400.0f, 400.0f) * *(float *)(v4 + 116);
                    v7[2] += frand(-400.0f, 400.0f) * *(float *)(v4 + 120);

                    v11 = frand(10.0f, 350.0f);
                    v7[0] += *(float *)(v4 + 128) * v11;
                    v7[1] += *(float *)(v4 + 132) * v11;
                    v7[2] += *(float *)(v4 + 136) * v11;

                    v7[0] += frand(10.0f, 200.0f) * *(float *)(v4 + 144);
                    v7[1] += frand(10.0f, 200.0f) * *(float *)(v4 + 148);
                    v7[2] += frand(10.0f, 200.0f) * *(float *)(v4 + 152);

                    v5[0] = -1.0;
                    v5[1] = -1.0;
                }
            }

            v13 = byte_EA5C40[v40];
            if (v13)
            {
                if (v13 == 2)
                {
                    byte_EA5C40[v40] = 0;
                }
                sub_42CCF0((signed __int16 *)v4, v7, &v38, &v39, &v44, &v45, 0);
                if (v38 <= 0.0 || v39 <= 0.0 || (double)dword_ED39A4 <= v38
                    || (double)dword_ED38C8 <= v39)
                {
                    if ((double)-dword_ED39A4 > v38
                        || (double)(2 * dword_ED39A4) < v38
                        || (double)(2 * dword_ED38C8) < v39)
                    {
                        byte_EA5C40[v40] = 0;
                    }
                }
                else
                {
                    if (v43 > 0)
                    {
                        // Get pointer into zbuffer
                        uint8_t *v16 = v43
                            + v48 * (unsigned __int64)(signed __int64)v39 + v49
                            + (signed __int64)v38;

                        // Get depth value
                        v14 = 0.0;
                        v15 = 8 * v43;
                        for (int v17 = 0; v17 < v43; v17++)
                        {
                            v15 -= 8;
                            v53 = *--v16;
                            v14 += (double)(v53 << v15);
                        }
                        while (v17)
                            ;
                    }

                    // Normalize depth value
                    v19 = v14 * v41;
                    if (!(v20 | v21) && v44 > v19)
                    {
                        byte_EA5C40[v40] = 2;
                    }
                }

                if (!(v24 | v25))
                {
                    v23 = 100.0f / v45;
                    if (v23 < 0.01f)
                    {
                        v23 = 0.01f;
                    }
                }
                else
                {
                    v23 = 100.0f;
                }
                v27 = v23 * 0.15f;

                v54 = v27;
                if (v28 | v29)
                {
                    if (flt_4BEEC4 <= 300.0f)
                    {
                        if (v27 > 0.15f)
                        {
                            v54 = 0.15f;
                        }
                    }
                    else if (v27 > 0.1f)
                    {
                        v54 = 0.1f;
                    }
                }
                else if (v27 > 0.04f)
                {
                    v54 = 0.04f;
                }

                v30 = *(_WORD *)v6;
                int16_t v47 = byte_4BEEBF; // FIXME: int16_t or uint16_t?!
                sub_429B60(v30, 1);
                sub_42D0E0(*(_WORD *)v6, (signed __int64)v38,
                           (signed __int64)v39);
                if (v5[0] >= 0.0f)
                {
                    v31 = 1.0 - flt_4BEEC8;
                    int32_t v46 =
                        (signed __int64)(v38 * v31 + flt_4BEEC8 * v5[0]);
                    int32_t v42 =
                        (signed __int64)(v39 * v31 + flt_4BEEC8 * v5[1]);

                    // Get delta X abs?
                    v33 = (double)v46 - v38;
                    if (v33 < 0.0)
                    {
                        v33 = -v33;
                    }

                    // Get delta Y abs?
                    v34 = (double)v42 - v39;
                    if (v34 < 0.0)
                    {
                        v34 = -v34;
                    }

                    if ((signed __int64)v33 >= 3
                        || (signed int)(signed __int64)v34 >= 3)
                    {
                        sub_42E910(*(_WORD *)v6, v46, (uint16_t)v42);
                        sub_429D70(*(_WORD *)v6, 0x4000);
                    }
                    else
                    {
                        sub_429D90(*(_WORD *)v6, 0x4000);
                    }
                }
                else
                {
                    sub_429B60(*(_WORD *)v6, 0);
                }
                sub_429C80(*(_WORD *)v6, SLODWORD(v54), SLODWORD(v54));

                signed __int64 v35; // rax //FIXME: Go home IDA, you are drunk!
                if (sub_449A80())
                {
                    v35 = (signed __int64)((double)(signed __int16)v47 * 0.5f);
                }
                else
                {
                    v35 = (uint8_t)v47; // FIXME: Signed or unsigned?
                }
                sub_429CD0(*(_WORD *)v6, byte_4BEEBC, byte_4BEEBD, byte_4BEEBE,
                           v35);

                v5[0] = v38;
                v5[1] = v39;
            }
        }
        v7 += 3;
        v5 += 2;
        v6++;
    }

    // Unlock z-Buffer
    result = sub_433D60();
    return result;
}
