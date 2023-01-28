BOOL sub_421C90()
{
    signed int v0; // edi
    FILE *v1; // eax
    FILE *v2; // esi
    int v4; // [esp+8h] [ebp-104h]
    CHAR FileName; // [esp+Ch] [ebp-100h]

    v4 = 65539;
    v0 = 0;
    if (sub_421D80())
    {
        sub_44E530(0, 0);
        sub_421B20(0);
    }
    create_dir(PathName);
    sprintf(&FileName, aSS_0, PathName, aTgfdDat);
    SetFileAttributesA(&FileName, 2u);
    v1 = fopen(&FileName, aWb);
    v2 = v1;
    if (!v1)
        return 0;
    if (!fwrite_locked(&v4, 1u, 4u, v1))
        v0 = 1;
    if (!fwrite_locked(&dword_E364A0, 1u, 0xFD4u, v2))
        v0 = 1;
    fclose(v2);
    return v0 == 0;
}
