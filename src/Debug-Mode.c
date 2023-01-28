int __cdecl sub_42A840(int a1, char *a2, uint8_t *a3, int32_t *a4, float *a5)
{
    const char *v5; // eax
    const char *v6; // eax
    int result; // eax
    const char *v8; // eax
    const char *v9; // eax
    const char *v10; // eax
    const char *v11; // eax
    const char *v12; // eax

    *a3 = 0;
    *a4 = -10000;
    *a5 = -10000.0f;
    switch (a1)
    {
    case 0:
        v5 = lookup_translation(aScreentext535C);
        sprintf(a2, v5);
        if (!dword_50C064)
        {
            result = 1;
            break;
        }
        v6 = lookup_translation(aScreentext366A);
        sprintf(a2, aCS, v6);
        result = 1;
        break;
    case 1:
        v10 = lookup_translation(aScreentext536C);
        sprintf(a2, v10);
        if (!dword_50C064)
        {
            result = 1;
            break;
        }
        v11 = lookup_translation(aScreentext367Y);
        sprintf(a2, aCS, v11);
        result = 1;
        break;
    case 2:
        v8 = lookup_translation(aScreentext657C);
        sprintf(a2, v8);
        if (!dword_50C064)
        {
            result = 1;
            break;
        }
        v9 = lookup_translation(aScreentext368N);
        sprintf(a2, aCS, v9);
        result = 1;
        break;
    case 3:
        v12 = lookup_translation(aScreentext658C);
        sprintf(a2, v12);
        if (dword_50C064)
        {
            sprintf(a2, &Class);
        }
        result = 1;
        break;
    case 4:
        if (dword_50C044 < 1)
        {
            sprintf(a2, aUnimplemented);
            result = 0;
        }
        else
        {
            sprintf(a2, aCgameCheats);
            result = 1;
        }
        break;
    default:
        sprintf(a2, aUnimplemented);
        result = 0;
        break;
    }
    return result;
}
int __cdecl sub_42AC70(int a1, char *a2, uint8_t *a3, int32_t *a4, float *a5)
{
    switch (dword_50C07C)
    {
    case 0: // Draws the generic cheats
        return sub_42A580(a1, a2, a3, a4, a5);
    case 1: // Draws menu to edit pods
        return sub_429DC0(a1, a2, a3, a4, a5);
    case 2: // Draws normal pause menu
        return sub_42A840(a1, a2, a3, a4, a5);
    }
    return a5;
}
void __cdecl sub_483BE0(signed int a1)
{
    int v1; // ST10_4
    int v2; // ST0C_4
    int v3; // ST08_4
    const char *v4; // eax
    double v5; // st7
    const char *v6; // eax
    char v7; // [esp+8h] [ebp-40h]

    // Check the debug level
    if (a1 >= 2)
    {
        // Get X,Y,Z position
        v1 = (signed __int64)*(float *)&dword_DFB254;
        v2 = (signed __int64)*(float *)&dword_DFB250;
        v3 = (signed __int64)*(float *)&dword_DFB24C;

        // Create a string for it
        v4 = lookup_translation(aRSposDDD);
        sprintf(&v7, v4, v3, v2, v1);

        // Draw the string
        sub_450590(4, 285, 214, (int)&v7);

        // Unknown check
        v5 = sub_45D390();
        if (v5 > 0.0)
        {
            // Create a string for it
            v6 = lookup_translation(aRScomp5f);
            sprintf(&v7, v6, LODWORD(v5),
                    (_DWORD)(*(unsigned __int64 *)&v5 >> 32));

            // Draw the string
            sub_450590(4, 300, 194, (int)&v7);
        }
    }
}
double sub_45D390()
{
    if (sub_450B30(MAGIC('T', 'e', 's', 't'), 0) == 0)
    {
        return -1.0;
    }

    if (dword_E2899C)
    {
        return sub_47F810(*(_DWORD *)(dword_E2899C + 132) + 172);
    }
    return -1.0;
}
float __cdecl sub_47F810(int a1)
{
    int32_t v1 = sub_44E620(a1, 0);
    float v3 = *(float *)(a1 + 8) * flt_E22A64[2 * v1] + flt_E22A60[2 * v1];

    float result; // st7
    if (dword_4C7BE4 < 0)
    {
        if (v3 < 1.0)
        {
            result = v3;
        }
        else
        {
            result = 0.99989998;
        }
    }
    else if (v3 <= 1.0)
    {
        result = v3;
    }
    else
    {
        result = 1.0;
    }
    return result;
}
