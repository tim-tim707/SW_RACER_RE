signed int sub_404B10() {
  int v2; // eax

  if ( sub_485360() ) {
    return 1;
  }

  if ( sub_485570() ) {
    return 1;
  }

  sub_407DE0();

  dword_EC8824 = 0;
  dword_EC879C = 0;
  dword_EC887C = 0;
  dword_EC87A0 = 0;

  for(int32_t v1 = 0; v1 < 6; v1++) {
    if (sub_4855F0(6 * dword_4D6B3C + v1)) {
      dword_EC887C |= 1 << v1;
      dword_EC87A0++;
    }
  }

  if (dword_EC87A0) {
    v2 = dword_ECA0FC[157 * dword_4D6B3C];
    dword_EC879C = dword_ECA0F8[157 * dword_4D6B3C];
    dword_EC8824 = v2;
  } else {
    dword_4B294C = 0;
    dword_4B2944 = 0;
  }

  dword_EC8770 = 0;
  dword_EC8808 = 0;
  dword_EC878C = 0;

  for(int32_t v3 = 0; v3 < 3; v3++) {
    if ( sub_4855F0(48 + v3)) { // '0' + v3
      dword_EC8808 |= 1 << v3;
      dword_EC878C++;
    }
  }

  if ( dword_EC878C ) {
    dword_EC8770 = dword_ECB498;
  } else {
    dword_4B2950 = 0;
    dword_4D6B38 = 0;
  }

  InitializeCriticalSection(&CriticalSection);
  dword_EC8810 = 0;
  LOBYTE(dword_4D5E60) = 0;
  dword_EC8814 = 0;
  byte_4D6B54 = 1;
  dword_EC8818 = 0;
  dword_4D6300 = 0;
  LOWORD(dword_EC881C) = 0;
  dword_4D6824 = 0;
  BYTE2(dword_EC881C) = 0;
  dword_4D6304 = 1;
  dword_4D5FB8 = 1;
  dword_4D6308 = 0;
  sub_407800(-1);
  sub_40A120(0);
  sub_409D70(0);
  sub_409EE0(0x11u, -1, -1, -1);

  // Read force feedback config
  if ( sub_40AE40((int)aCurrent) < 0 ) {
    sub_40AB60();
    sub_40AB80((int)aCurrent);
  }

  // Read input config (for mouse, keyboard and joystick?)
  if ( sub_406470(-1, &Class, 1) < 0 ) {
    sub_405EA0(0);
    sub_405EA0(1);
    sub_405EA0(2);
  }

  // Read steering wheel input config (?)
  if ( dword_4D55D4 ) {
    sub_406470(0, aWheel, 1);
    dword_4B297C = 0;
    dword_EC876C = 0.0;
  }

  if ( sub_406470(-1, aCurrent, 0) <= -1 ) {
    sub_406080((int)aCurrent);
  }

  sub_407630(0);
  sub_407630(1);
  return 0;
}
int __cdecl sub_405EA0(signed int a1) {
  signed int v1; // ebp
  _BYTE *v2; // edx
  _BYTE *v3; // ecx
  int v5; // ecx
  BOOL v6; // ecx
  char *v7; // ecx
  int result; // eax
  char *v10; // [esp+10h] [ebp-Ch]
  int v11; // [esp+14h] [ebp-8h]
  int v12; // [esp+18h] [ebp-4h]

  v1 = a1;
  if ( a1 == 0) {
    a1 = dword_EC879C;
    v12 = dword_EC887C;
    v10 = byte_4D5FC0;
    memset(byte_4D5FC0, 0, 0x30Cu);
    v2 = &unk_4B2F80;
    v11 = dword_EC8824;
    LODWORD(dword_EC876C) = dword_4B297C;
    qmemcpy(dword_EC8880, &unk_4B2958, 0x18u);
    if ( dword_EC8824 && dword_EC879C > 4 ) {
      a1 = 4;
    }
  } else if ( a1 == 1 )
    v11 = 0;
    a1 = dword_EC8770;
    v12 = dword_EC8808;
    v10 = byte_4D6518;
    v2 = &unk_4B3290;
    memset(byte_4D6518, 0, 0x30Cu);
    dword_EC8790[0] = dword_4B2970;
    dword_EC8794 = dword_4B2974;
    dword_EC8798 = dword_4B2978;
  } else if ( a1 == 2 ) {
    v11 = 0;
    v12 = 0;
    v10 = byte_4D6828;
    v2 = &unk_4B35A0;
    a1 = 256;
    memset(byte_4D6828, 0, 0x30Cu);
  } else {
    v2 = (_BYTE *)a1;
  }

  dword_4D5E20[v1] = 0;
  dword_EC8780[v1] = 1.0f;

  while ( v2[0] != -1 ) {
    if ( *v2 & 8 && *((_DWORD *)v2 + 1) < a1
      || *v2 & 8 && ((v5 = *((_DWORD *)v2 + 1), v5 < 16) ? (v6 = 0) : (v6 = v5 <= 4 * v11 + 15), v6)
      || *v2 & 4 && (1 << *((_DWORD *)v2 + 1)) & v12 ) {
      v7 = &v10[12 * dword_4D5E20[v1]];
      *((_DWORD *)v7 + 0) = *((_DWORD *)v2 + 0);
      *((_DWORD *)v7 + 1) = *((_DWORD *)v2 + 1);
      *((_DWORD *)v7 + 2) = *((_DWORD *)v2 + 2);
      ++dword_4D5E20[v1];
    }
    v2 += 12;
  }

  result = 3 * dword_4D5E20[v1];
  v10[12 * dword_4D5E20[v1]] = -1;
  return result;
}
signed int __cdecl sub_4078A0(char *a1, const char *a2, int a3, int a4, int a5, int a6) {
  // Remove the old mapping
  int v6 = sub_407500(a1, a2, a4, a3, 0);

  // Create a new mapping
  int new_mapping = sub_4078E0(a1, a2, a6, a4, a5, v6);

  return new_maping;
}
signed int __cdecl sub_407500(char *a1, const char *a2, int a3, int a4, int a5) {
  char *v5; // ebp
  int v6; // esi
  int v7; // edi
  char v9; // cl
  char *v10; // eax
  char v11; // bl
  int v12; // ecx
  char *v13; // eax
  char *v14; // esi
  int v15; // [esp+10h] [ebp-10h]
  char v16; // [esp+14h] [ebp-Ch]
  int v17; // [esp+18h] [ebp-8h]
  int v18; // [esp+1Ch] [ebp-4h]

  v5 = a1;
  v6 = 0;
  v7 = -1;
  v15 = 0;
  v16 = 0;
  v17 = 0;
  v18 = 0;

  if ( a1 == 0) {
    a1 = byte_4D5FC0;
  } else if ( a1 == 1 ) {
    a1 = byte_4D6518;
  } else if ( a1 == 2 ) {
    a1 = byte_4D6828;
  }

  if ( !sub_407CD0((int)&v16, a2, 1) ) {
    return -1;
  }

  if ( a3 ) {
    v9 = v16 | 4;
  } else {
    v9 = v16 | 8;
  }

  v10 = a1;
  v16 = v9;

  //FIXME: Can I just put this in the beginning of the loop?
  if ( *a1 == -1 ) {
    if ( v7 < 0 ) {
      return -1;
    }
  } else {
    while ( v7 < 0 ) {
      if ( *((_DWORD *)v10 + 2) == v18 && ((unsigned __int8)*v10 & (unsigned __int8)v9) == v9 && ++v15 == a4 ) {
        v7 = v6;
     }
      v11 = v10[12];
      v10 += 12;
      ++v6;
      if ( v11 == -1 ) {
        if ( v7 < 0 ) {
          return -1;
        }
      }
    }
  }


  if ( a5 ) {

    v12 = v7;
    while (v12 <= (dword_4D5E20[(_DWORD)v5] - 1)) {
      v14 = &a1[12 * (v12 + 0)];
      v13 = &a1[12 * (v12 + 1)];
      *((_DWORD *)v14 + 0) = *((_DWORD *)v13 + 0);
      *((_DWORD *)v14 + 1) = *((_DWORD *)v13 + 1);
      *((_DWORD *)v14 + 2) = *((_DWORD *)v13 + 2);
      v12++;
    }

    //FIXME: Move this before the loop?
    dword_4D5E20[(_DWORD)v5]--;
  }

  return v7;
}
