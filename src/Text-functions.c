//----- (00421470) --------------------------------------------------------
const char *__cdecl sub_421470(const char *a1)
{
    if (a1 == NULL)
    {
        return NULL;
    }
    if (a1[0] == '\0')
    {
        return a1;
    } // This check is useless, but the original game checks this too

    if (a1[0] == '/' && strlen(a1) != 1)
    {
        return strchr(&a1[1], '/') + 1;
    }

    return a1;
}

//----- (00450530) --------------------------------------------------------
int __cdecl sub_450530(__int16 a1, __int16 a2, char a3, char a4, char a5,
                       char a6, int a7)
{
    return create_text_entry(a1, a2, a3, a4, a5, a6, a7, -1, 0);
}

//----- (00450560) --------------------------------------------------------
int __cdecl sub_450560(__int16 a1, __int16 a2, int a3)
{
    return create_text_entry(a1, a2, -1, -1, -1, -1, a3, -1, 0);
}

//----- (00450590) --------------------------------------------------------
// a1 = ?
// a2 = x
// a3 = y
// a4 = text
int __cdecl sub_450590(int a1, __int16 a2, __int16 a3, int a4)
{
    return create_text_entry(a2, a3, -1, -1, -1, -1, a4, a1, 0);
}

//----- (004505C0) --------------------------------------------------------
int __cdecl sub_4505C0(__int16 a1, __int16 a2, char a3, char a4, char a5,
                       char a6, int a7)
{
    return create_text_entry(a1, a2, a3, a4, a5, a6, a7, -1, 1);
}

//----- (004503E0) --------------------------------------------------------
int __cdecl create_text_entry(__int16 a1, __int16 a2, char a3, char a4, char a5,
                              char a6, int a7, int a8, int a9)
{
    int result; // eax
    int v10; // eax
    int v11; // eax

    if (a9)
    {
        result = dword_50C758;
        if (dword_50C758 < 32)
        {
            if (a8 < 0)
                sprintf(&byte_E303A0[128 * dword_50C758], aS_0, a7);
            else
                sprintf(&byte_E303A0[128 * dword_50C758], aFDS, a8, a7);
            v11 = dword_50C758;
            word_E34660[2 * dword_50C758] = a1;
            word_E34662[2 * v11] = a2;
            byte_E343A0[4 * v11] = a3;
            byte_E343A1[4 * v11] = a4;
            byte_E343A2[4 * v11] = a5;
            byte_E343A3[4 * v11] = a6;
            result = v11 + 1;
            dword_50C758 = result;
        }
    }
    else
    {
        result = dword_50C750;
        if (dword_50C750 < 128)
        {
            if (a8 < 0)
                sprintf(&byte_E2C380[128 * dword_50C750], aS_0, a7);
            else
                sprintf(&byte_E2C380[128 * dword_50C750], aFDS, a8, a7);
            v10 = dword_50C750;
            word_E34860[2 * dword_50C750] = a1;
            word_E34862[2 * v10] = a2;
            byte_E2B480[4 * v10] = a3;
            byte_E2B481[4 * v10] = a4;
            byte_E2B482[4 * v10] = a5;
            byte_E2B483[4 * v10] = a6;
            result = v10 + 1;
            dword_50C750 = result;
        }
    }
    return result;
}

//----- (00450100) --------------------------------------------------------
int sub_450100()
{
    int result = dword_50C750;

    uint8_t *v2 = byte_E2C380;
    uint32_t *v3 = &unk_E2BE80;
    int16_t *v4 = word_E34860;
    int *v5 = &unk_E2B680;

    for (int i = 0; i < dword_50C750; i++)
    {
        sub_42D950(byte_E2B480[4 * i], byte_E2B481[4 * i], byte_E2B482[4 * i],
                   byte_E2B483[4 * i]);
        sub_42D910(*v4, word_E34862[2 * i]);
        if (*v3)
        {
            dword_50C0B0 = 1;
            dword_E99750 = v5[0];
            dword_E99754 = v5[1];
            dword_E99758 = v5[2];
            dword_E9975C = v5[3];
        }
        sub_42EC50(v2);
        dword_50C0B0 = 0;

        v2 += 128;
        v3 += 1;
        v4 += 2;
        v5 += 4;
    }

    dword_50C750 = 0;
    return result;
}

//----- (004501F0) --------------------------------------------------------
int sub_4501F0()
{
    int result = dword_50C758;

    uint8_t *v2 = byte_E303A0;
    int16_t *v3 = word_E34660;

    for (int i = 0; i < dword_50C758; i++)
    {
        sub_42D950(byte_E343A0[4 * i], byte_E343A1[4 * i], byte_E343A2[4 * i],
                   byte_E343A3[4 * i]);
        sub_42D910(*v3, word_E34662[2 * i]);
        sub_42EC50(v2);
        result = dword_50C758;

        v2 += 128;
        v3 += 2;
    }

    dword_50C758 = 0;
    return result;
}
