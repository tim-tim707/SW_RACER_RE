//----- (00448780) --------------------------------------------------------
// a1 = index of model to load
int *__cdecl models_load(int32_t a1)
{
    int v1; // ebx
    unsigned int v2; // edx
    int v3; // eax
    int *v4; // ecx
    unsigned int v6; // eax
    int v7; // esi
    signed int v8; // ebp
    unsigned int v11; // eax
    int v12; // eax
    int *v13; // edi
    int v14; // ebx
    int *result; // eax
    char *v16; // esi
    int v17; // ebp
    unsigned int *v18; // esi
    unsigned int v19; // eax
    int v20; // eax
    unsigned int v21; // [esp+10h] [ebp-14h]
    int v22; // [esp+14h] [ebp-10h]
    int v23; // [esp+18h] [ebp-Ch]
    int v24; // [esp+1Ch] [ebp-8h]
    int v25; // [esp+20h] [ebp-4h]
    int v26; // [esp+28h] [ebp+4h]

    // Load textureblock
    level_data_open(3);

    // Load modelblock
    level_data_open(0);

    dword_50C600 = 1;
    dword_50C628 = 0; // counter of some sort for malt parsing
    dword_50C62C = 0; // again
    dword_50C630 = 0; // and again
    dword_E981E0 = 0; // size of buffer ?
    dword_E98240 = 0;
    dword_E98248 = 0;

    // Read model count
    level_data_read(0, 0, &v21, 4u);
    v21 = = swap32(v21);

    // Check if model index is in valid range
    if ((a1 < 0) || (a1 >= v3))
    {
        level_data_close(3);
        level_data_close(0);
        return 0;
    }

    // Read model entry from offset table
    v4 = &v23;
    level_data_read(0, 8 * a1 + 4, v4, 3 * 4);
    for (int32_t v5 = 0; v5 < 3; v5++)
    {
        v4[v5] = swap32(v4[v5]);
    }

    v7 = v24 - v23;
    v8 = v25 - v24;
    if (v7 > 153600)
    {
        level_data_close(3);
        level_data_close(0);
        return 0;
    }

    int32_t *v9 = dword_E6B180;
    level_data_read(0, v23, v9, v7);
    for (int32_t v10 = 0; v10 < v7 / 4; v10++)
    {
        v9[v10] = swap32(v9[v10]);
    }

    // Read chunk header to 8 byte aligned buffer
    typdef struct
    {
        uint32_t magic;
        uint32_t unk1;
        uint32_t unk2;
    } V13;
    v12 = get_buffer_index();
    v13 = align_up(v12, 8);
    v22 = v12;
    level_data_read(0, v24, v13, 0xCu);

    if (swap32(v13[0]) == MAGIC('C', 'o', 'm', 'p'))
    {
        // If this chunk is compressed, decompress it

        // Get and validate length of compressed chunk
        v26 = v8 - 12;
        v8 = swap32(v13[2]);
        if (v8 + 8 > get_remaining_buffer_size())
        {
            dword_50C610 = 1;
            level_data_close(3);
            level_data_close(0);
            return 0;
        }

        v16 = (char *)((dword_E981E4 - (v8 - 12)) & 0xFFFFFFF8);
        if (v16 < (char *)v13 + v8)
        {
            level_data_close(3);
            level_data_close(0);
            dword_50C610 = 1;
            return 0;
        }

        // Load compressed data
        level_data_read(0, v24 + 12, v16, v26);

        // Uncompress
        sub_42D520(v16, v13);

        // Keep track of buffer position?
        set_buffer_index((int)v13 + v8);
    }
    else
    {
        // Chunk is not compressed, just load it

        // Validate length of chunk
        if (v8 + 8 > get_remaining_buffer_size())
        {
            level_data_close(3);
            level_data_close(0);
            dword_50C610 = 1;
            return 0;
        }

        // Load data
        level_data_read(0, v24, v13, v8);

        // Keep track of buffer position?
        set_buffer_index((int)v13 + v8);
    }

    dword_E9822C = v22;
    dword_E6B164 = get_buffer_index();
    v22 = get_buffer_index();

    if (dword_50C604)
    {
        get_buffer_index();
        get_buffer_index();
        get_buffer_index();
        get_buffer_index();
    }

    v17 = v8 / 4;
    v18 = (unsigned int *)v13;

    // Loop over each mesh [material?] (?)
    for (int32_t v1 = 0; v1 < v17; v1++)
    {
        // Check if this mesh is textured
        if ((1 << (31 - (v1 & 0x1F))) & dword_E6B180[v1 >> 5])
        {
            v18[v1] = swap32(v18[v1]);
            if ((v18[v1] & 0xFF000000) == 0x0A000000)
            {
                // Load texture
                sub_447490(v17, v18[v1] & 0x00FFFFFF, &v18[v1], &v18[v1 + 1]);
            }
            else if (v18[v1] != 0x00000000)
            {
                // Texture is already in memory, so point into an existing
                // buffer ???
                v18[v1] = (unsigned int)v13 + v18[v1];
            }
        }
    }

    // Parse the model
    sub_4485D0(v13);

    // For certain types, the header seems to be skipped?!
    v20 = v13[0];
    if ((v20 == MAGIC('M', 'o', 'd', 'l')) || // 0x4D6F646C
        (v20 == MAGIC('T', 'r', 'a', 'k')) || // 0x5472616B
        (v20 == MAGIC('P', 'o', 'd', 'd')) || // 0x506F6464
        (v20 == MAGIC('P', 'a', 'r', 't')) || // 0x50617274
        (v20 == MAGIC('S', 'c', 'e', 'n')) || // 0x5363656E
        (v20 == MAGIC('M', 'A', 'l', 't')) || // 0x4D416C74
        (v20 == MAGIC('P', 'u', 'p', 'p')))
    { // 0x50757070 ) {
        v13++;
    }
    else
    {
        nullsub_3();
    }

    if (dword_50C604)
    {
        get_buffer_index();
        get_buffer_index();
        get_buffer_index();
        get_buffer_index();
    }

    dword_E98240 = get_buffer_index() - v22;
    dword_E981E0 = dword_E6B164 - dword_E9822C;

    // Close files
    level_data_close(3);
    level_data_close(0);

    return v13;
}
void __cdecl sub_4485D0(unsigned int *a1)
{
    signed int *v3; // eax
    unsigned int *v5; // esi
    unsigned int v6; // ecx
    int v7; // eax
    signed int v8; // eax
    signed int v9; // ecx
    unsigned int v10; // eax
    _DWORD *v11; // eax
    unsigned int result; // eax

    // Swap magic and keep a copy for later
    a1[0] = swap32(a1[0]);

    dword_E6B168 = 0;
    dword_E981E8 = 0;

    // FIXME: What does this do?
    uint32_t *v1 = &a1[1];
    while (*v1 != -1)
    {
        if (*v1)
        {
            models_parse_malt(*v1);
        }
        v1++;
    }

    // Advance pointer to behind the data
    v5 = &v1[1];

    uint32_t tmp = swap32(*v5);
    if (tmp == MAGIC('D', 'a', 't', 'a'))
    {
        v5[0] = tmp;
        v5[1] = swap32(v5[1]);

        // Swap all data bytes
        uint32_t *vx = &v5[2];
        for (int32_t v9 = 0; v9 < v5[1]; v9++)
        {
            vx[v9] = swap32(vx[v9]);
        }

        // Advance pointer to behind the data
        v5 = &vx[v9];
    }

    uint32_t tmp = swap32(*v5);
    if (tmp == MAGIC('A', 'n', 'i', 'm'))
    {
        v5[0] = tmp;

        // Call anim parser until data pointer is null.
        uint32_t *v12 = &v5[1];
        while (*v12)
        {
            models_parse_anim(*v12++);
        }

        // Set pointer to after the last entry
        v5 = &v12[1];
    }

    uint32_t tmp = swap32(*v5);
    if (tmp == MAGIC('A', 'l', 't', 'N'))
    {
        v5[0] = tmp;
        if (a1[0] == MAGIC('M', 'A', 'l', 't'))
        {
            uint32_t *v15 = &v5[1];
            while (*v15)
            {
                models_parse_malt(*v15++);
            }
        }
    }

    return;
}

//----- (00448180) --------------------------------------------------------
_DWORD *__cdecl models_parse_anim(_DWORD *a1)
{
    a1[55] = swap32(a1[55]);
    a1[56] = swap32(a1[56]);
    a1[57] = swap32(a1[57]);
    a1[58] = swap32(a1[58]);
    a1[59] = swap32(a1[59]);
    a1[60] = swap32(a1[60]);
    a1[61] = swap32(a1[61]);
    a1[62] = swap32(a1[62]);
    a1[63] = swap32(a1[63]);
    a1[64] = swap32(a1[64]);
    a1[65] = swap32(a1[65]);
    a1[66] = swap32(a1[66]);
    a1[67] = swap32(a1[67]);
    a1[68] = swap32(a1[68]);
    a1[69] = swap32(a1[69]);
    a1[70] = swap32(a1[70]);
    // FIXME: what about 71,72,73 ?
    a1[74] = swap32(a1[74]);

    int32_t v2 = 0;
    switch (a1[64] & 0xF)
    {
    case 1u:
    case 11u:
    case 12u:
        v2 = 1;
        break;

    case 4u:
        v2 = 2;
        break;

    case 6u:
    case 8u:
        v2 = 4;
        break;

    case 7u:
    case 9u:
    case 10u:
        v2 = 3;
        break;

    default:
        break;
    }

    if (a1[71])
    {
        swap32(a1[71], a1[65]);
    }
    if (a1[72])
    {
        swap32(a1[72], a1[65] * v2);
    }

    return a1;
}
