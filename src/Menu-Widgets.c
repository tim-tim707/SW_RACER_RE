int *__cdecl sub_413C50(int a1, int a2, int a3, char *a4, int a5, int a6,
                        int a7, int a8, int a9, int a10)
{
    int v10; // eax
    signed int v11; // ebp
    int v12; // ebx
    void **v13; // eax
    int *v14; // esi
    unsigned int v15; // eax
    int v16; // edi
    int v17; // edi
    char v18; // al
    int v19; // eax
    bool v20; // zf
    int *result; // eax
    int v22; // eax
    int v23; // eax
    unsigned int v24; // [esp+10h] [ebp-18h]
    int v25; // [esp+14h] [ebp-14h]
    int v26; // [esp+18h] [ebp-10h]
    int v27; // [esp+1Ch] [ebp-Ch]
    int v28; // [esp+20h] [ebp-8h]
    int v29; // [esp+24h] [ebp-4h]

    v10 = a10;
    v11 = 0;
    v24 = 0;
    v25 = 0;
    if (a10 & 0x80000)
    {
        v25 = (unsigned __int8)a10;
        v10 = 0;
    }
    v12 = a9;
    v13 = sub_416D90(a1, a2, a3, a4, a9, v10, 0, (int)sub_417940, 0);
    v14 = (int *)v13;
    v15 = (unsigned int)v13[8];
    if (v15 & 0x20000)
    {
        sub_417120(4003, &v24, &a10);
        v16 = v24 + a7;
        sub_417120(1015, &v24, &a10);
        v17 = v24 + v16;
        v11 = 1;
    }
    else if (v15 & 0x10000)
    {
        sub_417120(1011, &v24, &a10);
        v17 = v24 + a7;
        v11 = 1;
    }
    else if (v15 & 0x40000)
    {
        sub_417120(1012, &v24, &a10);
        v17 = a7;
        if (v24 > a7)
            v17 = (v24 >> 1) + a7;
    }
    else
    {
        v17 = a7;
    }
    sub_414B40((int)v14, v17, a8);
    sub_414B60((int)v14, a5, a6);
    if (v11)
    {
        v26 = v14[9];
        v27 = v14[10];
        v28 = v14[11];
        v29 = v14[12];
        sub_412FB0((int)v14, -1, 1009, (float *)&v26, 1, 0);
        sub_413090((int)v14, 0, 0, 0, 0, 130);
    }
    sub_414B80((int)v14, (int)a4, 0);
    sub_414420(v14, v12 & 0x20000);
    if (v14[8] & 0x20000)
    {
        sub_417120(4003, &a9, &a3);
        sub_417120(4004, &a1, &a2);
        v26 = v14[9];
        v27 = v14[10];
        v28 = a9 + v14[9] - 1;
        v29 = a3 + v14[10] - 1;
        sub_412FB0((int)v14, -1, 4003, (float *)&v26, 1, 0);
        v26 = v14[9] + a9;
        v27 = v14[10];
        v28 = v17 - v24 + v14[9] - 1;
        v29 = a2 + v14[10] - 1;
        sub_412FB0((int)v14, -1, 4004, (float *)&v26, 1, 0);
    }
    sub_414E60((int)v14, 1);
    v18 = *((_BYTE *)v14 + 32);
    v14[6] = 10;
    if (v18 >= 0)
    {
        if (dword_4D7C54)
        {
            v23 = v25;
            v14[335] = 1;
            if (v23)
                v14[336] = v23;
            else
                v14[336] = dword_4D7C50;
            ++dword_4D7C50;
        }
        result = v14;
    }
    else if (dword_4D7C54)
    {
        v22 = v25;
        v14[335] = 1;
        if (!v22)
            v22 = dword_4D7C50;
        v14[336] = v22;
        dword_4D7C54 = 0;
        dword_4D7C50 = 0;
        result = v14;
    }
    else
    {
        v19 = v25;
        dword_4D7C50 = 0;
        v20 = v25 == 0;
        v14[335] = 1;
        if (v20)
            v14[336] = dword_4D7C50;
        else
            v14[336] = v19;
        ++dword_4D7C54;
        ++dword_4D7C50;
        result = v14;
    }
    return result;
}
uint8_t *__cdecl sub_414BE0(uint8_t *a1, uint8_t a2, uint8_t a3, uint8_t a4,
                            uint8_t a5)
{
    a1[1216] = a2;
    a1[1217] = a3;
    a1[1218] = a4;
    a1[1219] = a5;
    return a1;
}
