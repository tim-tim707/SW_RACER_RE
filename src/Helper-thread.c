//----- (00423330) --------------------------------------------------------
void __stdcall __noreturn StartAddress(LPVOID lpThreadParameter)
{
    while (1)
    {
        WaitForSingleObject(hHandle, -1);
        sub_4234C0();
    }
}

//----- (004233A0) --------------------------------------------------------
// a1 = some kind of file/stream-object which is at least 64 bytes
// a2 = Stream write offset in bytes
// a3 = Number of bytes to write
// Returns the number of bytes written to buffer
int32_t __cdecl sub_4233A0(int a1, int32_t a2, uint32_t a3)
{
    unsigned int v6; // ebx
    int v7; // eax

    if (!a1)
    {
        return 0;
    }

    if (!dword_4EB40C)
    {
        return 0;
    }

    // FIXME: Is it important that these have the values of a2 and a3 first?
    // probably not?
    uint8_t *t3 = a3;
    uint32_t t2 = a2;
    if (dword_4EB414->Lock(a2, a3, &t3, &t2, 0, 0, 0) < 0)
    {
        return 0;
    }

    v6 = dword_4EB40C;
    if (v6 >= a3)
    {
        v6 = a3;
    }

    // Read data from file
    memset(t3, 0x00, a3);
    dword_ECC420->unk14(dword_4EB404, t3, v6);

    // Check condition for second read
    // FIXME: what is the actual condition?
    if (v6 < a3 && dword_4EB408)
    {
        // Seek in file
        dword_ECC420->unk19(dword_4EB404, *(_DWORD *)(a1 + 60), 0);
        dword_4EB40C = *(_DWORD *)(a1 + 40);

        // Read again
        dword_ECC420->unk14(dword_4EB404, &t3[v6], a3 - v6);
    }

    // Unlock buffer, attempt this twice
    v7 = dword_4EB414->Unlock(t3, t2, 0, 0);
    if (v7 < 0)
    {
        v7 = dword_4EB414->Unlock(t3, t2, 0, 0);
    }

    return v7 < 0 ? 0 : v6;
}

//----- (004234C0) --------------------------------------------------------
signed void sub_4234C0()
{
    signed int result; // eax
    int v1; // esi
    unsigned int v2; // [esp+8h] [ebp-4h]

    if (!dword_4EB418)
    {
        return;
    }

    if (!dword_4EB40C)
    {
        if (!dword_4EB408)
        {
            return;
        }

        // Seek to current playback location (?)
        dword_ECC420->unk19(dword_4EB404, *(_DWORD *)(dword_4EB418 + 60), 0);
        dword_4EB40C = *(_DWORD *)(dword_4EB418 + 40);
    }

    ASSERT(dword_4EB414, aPbuffer, aDDevelQa5PcGno_5, 1774)

    // Get wave position so we know wether to overwrite first or last
    dword_4EB414->GetWavePosition(&v2);

    // Write bytes to stream
    int32_t r = sub_4233A0(dword_4EB418, v2 < 88200 ? 88200 : 0, 88200);
    dword_4EB40C -= r;

    return;
}
