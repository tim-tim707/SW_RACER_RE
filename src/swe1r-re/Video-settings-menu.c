//----- (0040E6A0) --------------------------------------------------------
int *__cdecl sub_40E6A0(int a1)
{
    int v1; // ST28_4
    const char *v2; // eax
    unsigned int v3; // esi
    int v4; // ST28_4
    const char *v5; // eax
    const char *v6; // eax
    int v7; // ST18_4
    const char *v8; // eax
    int v9; // eax
    void **v10; // eax
    const char *v11; // eax
    int v12; // edi
    int v13; // ebx
    int v14; // eax
    int v15; // ST28_4
    int v16; // edi
    const char *v17; // eax
    int v18; // eax
    int v19; // ebx
    int v20; // ST20_4
    const char *v21; // eax
    int v22; // ST1C_4
    char *v23; // eax
    const char *v24; // eax
    int v25; // ST1C_4
    char *v26; // eax
    const char *v27; // eax
    int v28; // ST1C_4
    char *v29; // eax
    char *v30; // eax
    void **v31; // ebx
    int v32; // ST28_4
    const char *v33; // eax
    int v34; // edi
    const char *v35; // eax
    int v36; // eax
    int v37; // eax
    int v38; // ebx
    int v39; // edi
    int v40; // ST20_4
    const char *v41; // eax
    int v42; // ST1C_4
    int v43; // ST14_4
    char *v44; // eax
    const char *v45; // eax
    int v46; // ST1C_4
    int v47; // ST14_4
    char *v48; // eax
    const char *v49; // eax
    int v50; // ST1C_4
    int v51; // ST14_4
    char *v52; // eax
    int v54; // [esp+Ch] [ebp-110h]
    int v55; // [esp+10h] [ebp-10Ch]
    int v56; // [esp+14h] [ebp-108h]
    char v57; // [esp+1Ch] [ebp-100h]

    // Restore Previous Settings

    v1 = dword_E99720[0];
    v2 = lookup_translation(aMondotextH0248);
    v3 = sub_42DE30((int)v2, v1);
    v4 = dword_E99720[0];
    v5 = lookup_translation(aMondotextH0248);
    sub_42DF70((int)v5, v4);

    // VIDEO SETTINGS

    v6 = lookup_translation(aMondotextH0292);
    sprintf(&v57, v6);
    v7 = dword_E99738;
    v8 = lookup_translation(aMondotextH0292);
    v9 = sub_42DE30((int)v8, v7);
    v10 = sub_413FC0(a1, 1, 6, &v57, ((v3 + (v3 >> 1)) >> 2) + 300, 160, v9,
                     0x80000, 1, 0, 0);
    sub_414BE0(v10, 255, 0, 0, 255);
    sub_411170(a1, 4, 0, 420, 1);
    sub_4112F0(a1, 205, 420);
    sub_411270(a1, 355, 420);
    sub_411210(a1, 520, 380);

    // Dynamic Lighting Enabled

    v11 = lookup_translation(aMondotextH0294);
    v12 = sub_42DE10((int)v11, 0);
    v13 = v12 + 10 * sub_42DE10((int)asc_4B51B8, 0);
    v14 = sub_42DE10((int)asc_4B53E0, 0);
    v15 = dword_E99720[0];
    v16 = v13 + v14;
    v17 = lookup_translation(aMondotextH0294);
    v18 = sub_42DF70((int)v17, v15);
    v19 = 3 * v18;
    v20 = 3 * v18;
    v21 = lookup_translation(aMondotextH0294);
    v22 = sub_42DE10((int)v21, 0);

    // Reflections Enabled

    v23 = (char *)lookup_translation(aMondotextH0297);
    sub_413C50(a1, 98, 0, v23, 30, 200, v22, v20, 0x20000, 0);

    // Dynamic Lighting Enabled

    v24 = lookup_translation(aMondotextH0294);
    v25 = sub_42DE10((int)v24, 0);

    // Smoke And Dust Enabled

    v26 = (char *)lookup_translation(aMondotextH0301);
    sub_413C50(a1, 10044, 0, v26, 30, 230, v25, v19, 0x20000, 0);

    // Dynamic Lighting Enabled

    v27 = lookup_translation(aMondotextH0294);
    v28 = sub_42DE10((int)v27, 0);

    // Lens Flare Enabled

    v29 = (char *)lookup_translation(aMondotextH0300);
    sub_413C50(a1, 10043, 0, v29, 30, 260, v28, v19, 0x20000, 0);

    // Model detail

    v30 = (char *)lookup_translation(aMondotextH0303);
    v31 = sub_4131C0(a1, 1, 6, v30, v16 / 16 + v16 + 60, 175, 0, 0);
    sub_414BE0(v31, 255, 125, 0, 255);
    v32 = dword_E99738;
    v33 = lookup_translation(aMondotextH0303);
    v34 = sub_42DF70((int)v33, v32) + 175;
    v35 = lookup_translation(aMondotextH0303);
    v36 = sub_42DE10((int)v35, 6);
    v37 = sub_41AF00((int)v31, v34, v36, 3, &v54);
    v38 = v37;
    v39 = v37 + v34;
    v40 = v37;

    // Display LOW, MEDIUM, HIGH settings

    v41 = lookup_translation(aMondotextH0235);
    v42 = sub_42DE10((int)v41, 0);
    v43 = v54;
    v44 = (char *)lookup_translation(aMondotextH0235);
    sub_413C50(a1, 103, 0, v44, v43, v39, v42, v40, 262272, 524289);
    v45 = lookup_translation(aMondotextH0236);
    v46 = sub_42DE10((int)v45, 0);
    v47 = v55;
    v48 = (char *)lookup_translation(aMondotextH0236);
    sub_413C50(a1, 103, 0, v48, v47, v39, v46, v38, 0x40000, 524290);
    v49 = lookup_translation(aMondotextH0237);
    v50 = sub_42DE10((int)v49, 0);
    v51 = v56;
    v52 = (char *)lookup_translation(aMondotextH0237);
    return sub_413C50(a1, 103, 0, v52, v51, v39, v50, v38, 262272, 524291);
}
