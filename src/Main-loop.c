int32_t game_loop(void)
{
    // 0x424140
    return ((int32_t(*)()) & g192)(); // g192 = off_4B7A38
}
void __usercall sub_423580 @<eax>(char *a1 @<ebx>, char *a2 @<esi>)
{
    DWORD result; // eax
    float v3; // st7
    int v4; // eax
    int v5; // ecx
    signed __int64 v6; // ST1C_8
    float v7; // st7

    uint32_t v8[4];
    //  signed int v8; // [esp+Ch] [ebp-40h]

    float v9[12];
    /*
      int v9; // [esp+1Ch] [ebp-30h]
      int v10; // [esp+20h] [ebp-2Ch]
      int v11; // [esp+24h] [ebp-28h]
      int v12; // [esp+28h] [ebp-24h]
      int v13; // [esp+2Ch] [ebp-20h]
      int v14; // [esp+30h] [ebp-1Ch]
      int v15; // [esp+34h] [ebp-18h]
      int v16; // [esp+38h] [ebp-14h]
      int v17; // [esp+3Ch] [ebp-10h]
      int v18; // [esp+40h] [ebp-Ch]
      int v19; // [esp+44h] [ebp-8h]
      int v20; // [esp+48h] [ebp-4h]
    */

    result = dword_4B4318;
    if (dword_4B4318 == 0)
    {
        return;
    }

    sub_404DD0(a1, a2);
    sub_41C1D0();
    sub_408220();
    sub_415400();
    sub_445980(word_4B7A3C, 1);
    *(_DWORD *)(*(_DWORD *)(dword_DF7F2C + 72) + 0) =
        0; // FIXME: is this correct?
    *(_DWORD *)(*(_DWORD *)(dword_DF7F2C + 72) + 4) = dword_DFB2EC;
    *(_DWORD *)(*(_DWORD *)(dword_DF7F2C + 72) + 8) = dword_DFB2F0;

    // FIXME: clamp
    if (flt_DFB2E0 < 5.0)
    {
        v3 = 5.0;
    }
    else if (flt_DFB2E0 > 179.0)
    {
        v3 = 179.0;
    }
    else
    {
        v3 = flt_DFB2E0;
    }

    *(float *)(dword_DF7F2C + 56) = v3;

    sub_48FD10(dword_DF7F2C, dword_DFB2E4);

    // Extract some matrix

    v9[0] = dword_DFB21C;
    v9[1] = dword_DFB220;
    v9[2] = dword_DFB224;

    v9[3] = dword_DFB22C;
    v9[4] = dword_DFB230;
    v9[5] = dword_DFB234;

    v9[6] = dword_DFB23C;
    v9[7] = dword_DFB240;
    v9[8] = dword_DFB244;

    v9[9] = dword_DFB24C;
    v9[10] = dword_DFB250;
    v9[11] = dword_DFB254;

    sub_490060(&v9);
    sub_48DB60();
    sub_41B7F0();
    if (dword_50B588)
    {
        sub_489CD0(word_E229A8, word_E229AA, word_E229AC, 0);
    }
    sub_445980(word_4B7A3C, 2);
    word_4B7A3C = 0;
    nullsub_3();
    sub_4104F0();
    sub_48DCE0();
    sub_48DD80();

    // Print last framerate
    if (dword_4D79DC && dword_50B5C0)
    {
        v4 = sub_48DB90();
        sprintf(OutputString, a023fD, flt_50B5D4, v4);
        sub_4887C0(OutputString, 4, 4);
    }

    sub_489AB0();
    if (dword_50B5C4)
    {
        if (dword_4B7A00)
        {
            sub_408640((int)a2, 98, v8);
            sub_4252A0((int)off_4B7A28[0]);
            sub_4252A0((int)off_4B7A2C[0]);
            sub_4252A0((int)off_4B7A30);
        }
        dword_50B5C4 = 0;
    }

    // Check if the framerate counter is turned on
    result = dword_4D79DC;
    if (dword_4D79DC)
    {
        result = dword_50B5C0;
        if (dword_50B5C0)
        {
            // Increment the framecount
            dword_50B5D8++;

            // Check how much time has passed since updating the framecounter
            result = timeGetTime();
            v5 = result - dword_50B5E4;
            dword_50B5E0 = result;

            // If it is more than 1000ms, update it
            if (v5 > 1000)
            {
                // Calculate how many frames have been done since last update
                v6 = (unsigned int)(dword_50B5D8 - dword_50B5DC);
                v7 = (double)(signed int)v6;

                // Time passed
                LODWORD(v6) = v5;

                // frames * 1000.0 / time_in_ms
                flt_50B5D4 = v7 * 1000.0 / (double)v6;

                // Update time of last update to "now" and keep framecount
                dword_50B5E4 = result;
                dword_50B5DC = dword_50B5D8;
            }
        }
    }

    return;
}
int __cdecl nullsub_1(_DWORD); // weak
