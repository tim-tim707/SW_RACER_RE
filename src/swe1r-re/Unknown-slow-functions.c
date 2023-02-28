typedef union
{
    struct
    {
        float x;
        float y;
        float z;
    };
} Vec3;

typedef struct
{
    uint32_t unk0;
    uint32_t unk1;
    uint32_t unk2;
    uint32_t unk3;
    uint32_t unk4;
    float position[3];
    uint32_t unk9;
    float unkf10;
} Unknown;

//----- (00490550) --------------------------------------------------------
// a1 = pointer to elements
// a2 = n x 3 component vectors
// a3 = n
// a4 = m x 3 component vectors
// a5 = # x 3 component vectors
// a6 = # x 4x4 matrices
// a7 = # x 4 component vectors
// a8 = number of elements in a1
// a9 = some vector scale factor
// Probably returns void, if not: needs work
void __cdecl sub_490550(Unknown **a1, Vec3 *a2, int a3, int a4, Vec3 *a5,
                        int a6, int a7, int a8, float a9)
{
    signed int v15; // eax
    int v20; // eax
    double v21; // st7
    signed int v24; // edx
    double v25; // st7
    double v26; // st7
    double v27; // st6
    float *v28; // eax
    signed int v29; // edx
    float v32[3]; // [esp+4h] [ebp-20h]
    float v35; // [esp+10h] [ebp-14h]
    int v36; // [esp+14h] [ebp-10h]
    int v38; // [esp+1Ch] [ebp-8h]
    float v41; // [esp+38h] [ebp+14h]

    int v10 = a8 - 1;

    float *v11 = a7 + 16 * v10;
    float *v13 = a4 + 12 * v10;

    int offset = 0;
    int off2 = 0;

    for (int i = 0; i < a8; i++)
    {
        for (int v15 = 0; v15 < 3; v15++)
        {
            v11[v15] = *(float *)(dword_DF7F2C + 92 + v15 * 4);
        }
        v11[3] = 1.0f;

        Unknown **v43 = &a1[a3 - 1];
        Vec3 *v18 = &a2[a3 - 1];

        for (int j = 0; j < a3; j++)
        {
            Unknown *v19 = *v43--;
            v20 = v19->unk1;
            if (v20 == 1)
            {
                // Calculate distance vector
        v32[0] = v18->f[0] - a5[v10 + offset].f[0]);
        v32[1] = v18->f[1] - a5[v10 + offset].f[1]);
        v32[2] = v18->f[2] - a5[v10 + offset].f[2]);

        // Calculate distance
        v41 = v32[0] * v32[0] + v32[1] * v32[1] + v32[2] * v32[2];
        v35 = sqrt(v41);

        // Check if there was a collision
        if (v35 < v19->unkf10)
        {
            // Get collision normal
            sub_492440(&v32);
            v26 = v13[0] * v32[0] + v13[1] * v32[1] + v13[2] * v32[2];
            if (v26 > 0.0)
            {
                v27 = v35 * a9;
                v11[0] = (v19->position[0] - v27) * v26 + v11[0];
                v11[1] = (v19->position[1] - v27) * v26 + v11[1];
                v11[2] = (v19->position[2] - v27) * v26 + v11[2];
            }
        }
            }
            else if (v20 != 0)
            {
                v21 = v13[0] * v18->f[0] + v13[1] * v18->f[1]
                    + v13[2] * v18->f[2];
                if (v21 > 0.0)
                {
                    for (int k = 0; k < 3; k++)
                    {
                        v11[k] = v19->position[k] * v21 + v11[k];
                    }
                }
            }

            for (int v29 = 0; v29 < 4; v29++)
            {
                v11[v29] =
                    *(float *)(a6 + 16 * v10 + off2 + v29 * 4) * v11[v29];
            }

            v18 -= 1;
        }
        v13 -= 3;
        v11 -= 4;
        off2 -= 16;
        offset -= 3;
    }
}
//----- (0049C9F0) --------------------------------------------------------

typedef struct
{
    uint32_t unk0;
    float unkf1;
} A1;

typedef struct
{
    uint32_t unk0;
    uint32_t *unk1;
    uint32_t *unk2;
    uint32_t unk3; // Pointer to 12 byte per element
    uint32_t unk4; // Pointer to 8 byte per element
    uint32_t unk5; // Pointer to 16 byte per element
} A2;

typedef struct
{
    uint32_t unk0;
    uint32_t unk1;
    uint32_t unk2;
    uint32_t unk3; // Pointer to 12 byte per element
    uint32_t unk4; // Pointer to 8 byte per element
    uint32_t unk5; // Pointer to 16 byte per element
} A3;

signed int __cdecl sub_49C9F0(const A1 *a1, const A2 *a2, const A3 *a3)
{
    int v4; // ebx
    int v5; // ebp
    int *v6; // edx
    int v7; // eax
    double v17; // st7
    int v18; // eax
    signed int v28; // [esp+2Ch] [ebp+8h]

    dword_DFAA04 = 0;
    dword_DFAA08 = a2->unk4;
    dword_DFAA0C = a3->unk4;
    dword_DFAA10 = a3->unk5;
    dword_DFAA14 = a3->unk3;
    dword_DFAA18 = a2->unk1;
    dword_DFAA1C = a2->unk3;
    dword_DFAA20 = a2->unk5;
    dword_DFAA24 = a2->unk2;

    v28 = 0;

    // FIXME: load these from the globals instead
    float *v25 = a2->unk4 + 8 * a2->unk2[a2->unk0 - 1];
    float *v11 = a2->unk3 + 12 * a2->unk1[a2->unk0 - 1];
    float *v13 = a2->unk5 + 16 * a2->unk1[a2->unk0 - 1];

    for (int i = 0; i < a2->unk0; i++)
    {
        // Get source
        float *v15 = dword_DFAA08 + 8 * a2->unk2[i];
        float *v12 = dword_DFAA1C + 12 * a2->unk1[i];
        float *v14 = dword_DFAA20 + 16 * a2->unk1[i];

        // Get destination address
        float *tmp = dword_DFAA0C + 8 *v28 float *v20 = dword_DFAA10 + 16 * v28;
        float *v19 = dword_DFAA14 + 12 * v28;

        if (v11[1] >= a1->unkf1 || v12[1] >= a1->unkf1)
        {
            if (v11[1] != a1->unkf1 && v12[1] != a1->unkf1
                && (v11[1] < a1->unkf1 || v12[1] < a1->unkf1))
            {
                v17 = (a1->unkf1 - v11[1]) / (v12[1] - v11[1]);

                tmp[0] = (v15[0] - v25[0]) * v17 + v25[0];
                tmp[1] = (v15[1] - v25[1]) * v17 + v25[1];
                v19[0] = (v12[0] - v11[0]) * v17 + v11[0];
                v19[1] = a1->unkf1;
                v19[2] = (v12[2] - v11[2]) * v17 + v11[2];
                v20[0] = (v14[0] - v13[0]) * v17 + v13[0];
                v20[1] = (v14[1] - v13[1]) * v17 + v13[1];
                v20[2] = (v14[2] - v13[2]) * v17 + v13[2];
                v20[3] = (v14[3] - v13[3]) * v17 + v13[3];
                ++v28;

                dword_DFAA04 |= 1;
            }
            if (v12[1] >= a1->unkf1)
            {
                tmp[0] = v15[0];
                tmp[1] = v15[1];
                v19[0] = v12[0];
                v19[1] = v12[1];
                v19[2] = v12[2];
                v20[0] = v14[0];
                v20[1] = v14[1];
                v20[2] = v14[2];
                v20[3] = v14[3];
                ++v28;
            }
        }

        v25 = v15;
        v11 = v12;
        v13 = v14;
    }

    if (v28 < 3)
    {
        dword_DFAA04 |= 0x40u;
    }

    return v28;
}
