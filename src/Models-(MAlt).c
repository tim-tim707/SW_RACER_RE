
//----- (004476B0) --------------------------------------------------------
void __cdecl models_parse_malt(signed int *a1)
{
    uintptr_t a1b = a1;

    if (a1b == 0)
    {
        return;
    }

    // FIXME: Did I invert this poorly?
    // FIXME: WTF?! *(uint32_t*)(a1b + 0) is not swapped here yet?!
    v2 = *(uint32_t *)(a1b + 0);
    if ((v2 == 20581) || (v2 == 20582) || (v2 == 53348) || (v2 == 53349)
        || (v2 == 20580) || (v2 == 12388) || (v2 == 53350))
    {
        return;
    }

    *(uint32_t *)(a1b + 0) = swap32(*(uint32_t *)(a1b + 0));
    *(uint32_t *)(a1b + 4) = swap32(*(uint32_t *)(a1b + 4));
    *(uint32_t *)(a1b + 8) = swap32(*(uint32_t *)(a1b + 8));
    *((_WORD *)(a1b + 12)) = swap16(*((_WORD *)(a1b + 12)));
    *((_WORD *)(a1b + 14)) = swap16(*((_WORD *)(a1b + 14)));
    *(uint32_t *)(a1b + 16) = swap32(*(uint32_t *)(a1b + 16));

    uint32_t v3 = *(uint32_t *)(a1b + 0);
    if (v3 == 53349)
    {
        swap32((uint32_t *)(a1b + 28), 12);
        swap32((uint32_t *)(a1b + 76), 3);
    }
    else if (v3 == 53350)
    {
        *((_WORD *)(a1b + 28)) = swap16(*((_WORD *)(a1b + 28)));
        *((_WORD *)(a1b + 30)) = swap16(*((_WORD *)(a1b + 30)));
        swap32((uint32_t *)(a1b + 32), 3);
    }
    else if (v3 == 53348)
    {
        swap32((uint32_t *)(a1b + 28), 12);
    }
    else if (v3 == 20582)
    {
        swap32((uint32_t *)(a1b + 28), 8);
        swap32((uint32_t *)(a1b + 60), 3);
    }
    else if (v3 == 20581)
    {
        *(uint32_t *)(a1b + 28) = swap32(*(uint32_t *)(a1b + 28));
    }
    else if (v3 == 12388)
    {
        *(uint32_t *)(a1b + 20) = swap32(*(uint32_t *)(a1b + 20));
        swap32((uint32_t *)(a1b + 28), 6);

        for (int32_t v15 = 0; v15 < *(uint32_t *)(a1b + 20); v15++)
        {
            typedef struct
            {
                uint32_t unk0; // A pointer of some sorts
                uint32_t unk4; // A pointer of some sorts
                uint32_t unk8[6]; // 8
                uint16_t unk32; // mode 3 = 3*unk32; mode 4 = 4*unk32; mode 5 =
                                // Count for unk36
                uint16_t unk34; // Some mode, {3,4,5} are typical values
                uint32_t unk36; // Pointer to uint32_t[], for mode 5, summed up
                                // is the count of unk40 (stripsize?)
                uint32_t unk40; // Pointer to uint16_t[] (indices?)
                uint32_t unk44; // Pointer to uint16_t[]
                uint8_t unk48[8];
                uint16_t unk56; // Count for unk44
                uint16_t unk58;
                uint16_t unk60;
                uint16_t unk62;
            } V16;

            uint32_t *base = *(uint32_t **)(a1b + 24);
            uintptr_t v16 = base[v15];
            if (!v16)
            {
                continue;
            }

            // Get item pointer and check if it's in the list already
            typedef struct
            {
                uint32_t unk0;
                uint16_t unk4;
                uint16_t unk6;
                uint32_t unk8; // A pointer of some sorts
                uint32_t unk12; // A pointer of some sorts
            } V17;
            uintptr_t v17 = *(_DWORD *)(v16 + 0);
            if (v17 && !sub_4475F0(v17))
            {
                // Add this pointer to the array
                dword_E95300[dword_50C628] = v17;
                dword_50C628 += 1;

                *(_DWORD *)(v17 + 0) = swap32(*(_DWORD *)(v17 + 0));
                *(_WORD *)(v17 + 4) = swap16(*(_WORD *)(v17 + 4));
                *(_WORD *)(v17 + 6) = swap16(*(_WORD *)(v17 + 6));

                // Get pointer and check if it's already in list
                typedef struct
                {
                    uint32_t unk0;
                    uint16_t unk4;
                    uint16_t unk6;
                    uint16_t unk8[2]; // 8 and 10
                    uint8_t unk12[4]; // 12
                    uint16_t unk16;
                    uint16_t unk18;
                    uint16_t unk20;
                    uint16_t unk22;
                    uint16_t unk24;
                    uint16_t unk26;
                } V19;
                uintptr_t v19 = *(_DWORD *)(v17 + 8);
                if (v19 && !sub_447630(v19))
                {
                    // Add pointer to list
                    dword_E90980[dword_50C62C] = v19;
                    dword_50C62C += 1;

                    *(_DWORD *)(v19 + 0) = swap32(*(_DWORD *)(v19 + 0));
                    *(_WORD *)(v19 + 4) = swap16(*(_WORD *)(v19 + 4));
                    *(_WORD *)(v19 + 6) = swap16(*(_WORD *)(v19 + 6));
                    swap16((__int16 *)(v19 + 8), 2);
                    *(_WORD *)(v19 + 16) = swap16(*(_WORD *)(v19 + 16));
                    *(_WORD *)(v19 + 18) = swap16(*(_WORD *)(v19 + 18));
                    *(_WORD *)(v19 + 20) = swap16(*(_WORD *)(v19 + 20));
                    *(_WORD *)(v19 + 22) = swap16(*(_WORD *)(v19 + 22));
                    *(_WORD *)(v19 + 24) = swap16(*(_WORD *)(v19 + 24));
                    *(_WORD *)(v19 + 26) = swap16(*(_WORD *)(v19 + 26));
                }

                // Get pointer and check if it's already in list
                typedef struct
                {
                    uint32_t unk0;
                    uint16_t unk4;
                    uint32_t unk6[2]; // 6 and 10
                    uint32_t unk14[2]; // 14 and 18
                    uint8_t unk22[2];
                    uint32_t unk24; // 24
                    uint32_t unk28; // 28
                } V36;
                uintptr_t v36 = *(_DWORD *)(v17 + 12);
                if (v36 && !sub_447670(*(_DWORD *)(v17 + 12)))
                {
                    // Add pointer to list
                    dword_E68280[dword_50C630] = v36;
                    dword_50C630 += 1;

                    *(_DWORD *)(v36 + 0) = swap32(*(_DWORD *)(v36 + 0));
                    *(_WORD *)(v36 + 4) = swap16(*(_WORD *)(v36 + 4));
                    swap32((unsigned int *)(v36 + 6), 2);
                    swap32((unsigned int *)(v36 + 14), 2);
          *(_DWORD *)(v36 + 24) = swap32(*(_DWORD *)(v36 + 24);
          *(_DWORD *)(v36 + 28) = swap32(*(_DWORD *)(v36 + 28));
                }
            }

            typedef struct
            {
                uint16_t unk0;
                uint8_t unk2[4];
                uint16_t unk6;
                uint16_t unk8;
                uint16_t unk10;
                uint8_t unk12[8];
                uint32_t unk20;
                uint32_t unk24;
                uint32_t unk28;
                uint32_t unk32;
                uint32_t unk36;
                uint32_t unk40;
                uint32_t unk44;
                uint16_t unk48;
                uint16_t unk50;
                uint32_t unk52;
                uint32_t unk56;
                uint32_t list_head; // 60 pointer to a list head, see v47
            } V46;
            uintptr_t v46 = *(_DWORD *)(v16 + 4);
            if (v46)
            {
                *(_WORD *)(v46 + 0) = swap16(*(_WORD *)(v46 + 0));
                // FIXME: Nothing here?
                *(_WORD *)(v46 + 6) = swap16(*(_WORD *)(v46 + 6));
                *(_WORD *)(v46 + 8) = swap16(*(_WORD *)(v46 + 8));
                *(_WORD *)(v46 + 10) = swap16(*(_WORD *)(v46 + 10));
                // FIXME: Nothing here?
                *(_DWORD *)(v46 + 20) = swap32(*(_DWORD *)(v46 + 20));
                *(_DWORD *)(v46 + 24) = swap32(*(_DWORD *)(v46 + 24));
                *(_DWORD *)(v46 + 28) = swap32(*(_DWORD *)(v46 + 28));
                *(_DWORD *)(v46 + 32) = swap32(*(_DWORD *)(v46 + 32));
                *(_DWORD *)(v46 + 36) = swap32(*(_DWORD *)(v46 + 36));
                *(_DWORD *)(v46 + 40) = swap32(*(_DWORD *)(v46 + 40));
                *(_DWORD *)(v46 + 44) = swap32(*(_DWORD *)(v46 + 44));
                *(_WORD *)(v46 + 48) = swap16(*(_WORD *)(v46 + 48));
                *(_WORD *)(v46 + 50) = swap16(*(_WORD *)(v46 + 50));
                *(_DWORD *)(v46 + 52) = swap32(*(_DWORD *)(v46 + 52));
                *(_DWORD *)(v46 + 56) = swap32(*(_DWORD *)(v46 + 56));

                // Walk through some list
                typedef struct
                {
                    uint32_t v74[3]; // 0
                    uint32_t v77[3]; // 12
                    uint32_t unk24; // 24
                    uint32_t unk28; // 28
                    uint32_t unk32; // 32 not touched?
                    uint16_t unk36; // 36
                    uint16_t unk38; // 38
                    struct _V47 *next; // 40
                } V47;
                uintptr_t v47 = *(_DWORD *)(v46 + 60);
                while (v47)
                {
                    swap32((v47 + 0), 3);
                    swap32((v47 + 12), 3);
                    *(_DWORD *)(v47 + 24) = swap32(*(_DWORD *)(v47 + 24));
                    *(_DWORD *)(v47 + 28) = swap32(*(_DWORD *)(v47 + 28));
                    // FIXME: Nothing?
                    *(_WORD *)(v47 + 36) = swap16(*(_WORD *)(v47 + 36))
                        * (_WORD *)(v47 + 38) = swap16(*(_WORD *)(v47 + 38));

                    v47 = *(_DWORD *)(v47 + 40);
                }
            }

            swap32((unsigned int *)(v16 + 8), 6);
      *(_WORD *)(v16 + 32) = swap16(*(_WORD *)(v16 + 32);
      *(_WORD *)(v16 + 34) = swap16(*(_WORD *)(v16 + 34));

      typedef struct {
                uint32_t unk0[];
      } V90;
      uintptr_t v90 = *(_DWORD *)(v16 + 36);
      if ( v90 ) {
                swap32(v90, *(_WORD *)(v16 + 32));
      }

      // Accumulate something?
      if ( *(_DWORD *)(v16 + 44) && *(_DWORD *)(v16 + 40) ) {
                uint16_t v94 = *(_WORD *)(v16 + 34);
                int32_t v95 = 0;
                switch (v94)
                {
                case 3:
                    v95 = 3 * *(signed __int16 *)(v16 + 32);
                    break;
                case 4:
                    v95 = 4 * *(signed __int16 *)(v16 + 32);
                    break;
                case 5:
                    int32_t *v97 = *(int32_t **)(v16 + 36);
                    for (int32_t v96 = 0; v96 < *(signed __int16 *)(v16 + 32);
                         v96++)
                    {
                        v95 += v97[v96] + 2;
                    }
                    break;
                default:
                    // Another noble error handler!
                    while (1)
                        ;
                }

        swap16((_WORD *)(*(_DWORD *)(v16 + 40), v95);

      }

      *(_WORD *)(v16 + 56) = swap16(*(_WORD *)(v16 + 56));

      if ( !dword_E6B168 ) {
                uintptr_t v104 = *(_DWORD *)(v16 + 44);
                if (v104)
                {
                    swap16(v104, *(_WORD *)(v16 + 56));
                }
      }

      *(_WORD *)(v16 + 58) = swap16(*(_WORD *)(v16 + 58));
      *(_WORD *)(v16 + 60) = swap16(*(_WORD *)(v16 + 60));
      *(_WORD *)(v16 + 62) = swap16(*(_WORD *)(v16 + 62));
        }
    }

    // Recursively parse children if this has any ???
    if (*(uint32_t *)(a1b + 0) & 0x4000)
    {
        // FIXME: This has been swapped before?! bug in RE?!
        *(uint32_t *)(a1b + 20) = swap32(*(uint32_t *)(a1b + 20));
        uint32_t *base24 = *(uint32_t **)(a1b + 24);
        for (int32_t v134 = 0; v134 < *(uint32_t *)(a1b + 20); v134++)
        {
            models_parse_malt(base24[v134]);
        }
    }
}

//----- (004475F0) --------------------------------------------------------
// a1 = value to search for
// returns 1 if value was found, 0 otherwise
signed int __cdecl sub_4475F0(int a1)
{
    int32_t *v2 = dword_E95300; // FIXME: Might also be &dword_E95300 ?
    for (int32_t v1 = 0; v1 < dword_50C628; v1++)
    {
        if (v2[v1] == a1)
        {
            return 1;
        }
    }
    return 0;
}

//----- (00447630) --------------------------------------------------------
// a1 = value to search for
// returns 1 if value was found, 0 otherwise
signed int __cdecl sub_447630(int a1)
{
    // Note: The check / loop has been inverted
    int32_t *v2 = dword_E90980; // FIXME: Might also be &dword_E90980 ?
    for (int32_t v1 = 0; v1 < dword_50C62C; v1++)
    {
        if (v2[v1] == a1)
        {
            return 1;
        }
    }
    return 0;
}
