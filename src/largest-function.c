/*

This appears to be the longest function (space wise) in the game. No idea what it does.
It seems to be full of unrolled loops though.

*/

// Research based on patched US version

typedef struct {
  uint8_t unk[16];
  uint32_t unk16; // +16 some flags register?
} A1unkA;

typedef A1unkA A1unkB;
typedef A1unkA A1unkC;

typedef A1unkA A1unkX;

typedef struct {
  uint32_t unk0; // +0
  A1unkX* unk4; // +4
  A1unkA* unk8; // +8
  A1unkX* unk12; // +12
  A1unkB* unk16; // +16
  A1unkX* unk20; // +20
  unk* unk24a[8] // +24 to +52
  uint32_t unk56; // +56
  A1unkC* unk248; // +248
  ...
  uint32_t unk296; // +296
} A1;

//----- (004337E0) --------------------------------------------------------
// a1 = an object of some sorts
// a2 = unk, only passed to sub_44BB10
// a3 = some boolean flag
// a4 = x?
// a6 = y?
// a7 = z?
// a8 = some boolean flag
// a9 = unk, only passed to sub_46F2C0
// a10 = unk, only passed to sub_46F2C0
void __cdecl sub_4337E0(int a1, int a2, int a3, float a4, float a5, float a6, int a7, int a8, float a9, float a10) {
  unsigned int v10; // edi
  float v11; // ST14_4
  double v12; // st7
  int v13; // eax
  int v14; // eax
  int v15; // eax
  int v16; // edi
  int v17; // edi
  _DWORD *v18; // esi
  float v19; // ST18_4
  _DWORD *v34; // edi
  float v35; // ST18_4
  float v36; // ST0C_4
  _DWORD *v37; // eax
  _DWORD *v38; // eax
  _DWORD *v39; // edi
  int v66; // eax
  int v67; // [esp+24h] [ebp-1F4h]
  float v72; // [esp+28h] [ebp-1F0h]
  float v73; // [esp+2Ch] [ebp-1ECh]
  float v74; // [esp+30h] [ebp-1E8h]
  float v75; // [esp+34h] [ebp-1E4h]
  int v76; // [esp+38h] [ebp-1E0h]
  int v77; // [esp+3Ch] [ebp-1DCh]
  int v78; // [esp+40h] [ebp-1D8h]
  float v79; // [esp+44h] [ebp-1D4h]
  float v80; // [esp+50h] [ebp-1C8h]
  float v81[3]; // [esp+5Ch] [ebp-1BCh]
  float v82[3]; // [esp+68h] [ebp-1B0h]
  int v83; // [esp+74h] [ebp-1A4h]
  char v84; // [esp+84h] [ebp-194h]
  int v85; // [esp+94h] [ebp-184h]
  int v86; // [esp+A4h] [ebp-174h]
  int v87; // [esp+ACh] [ebp-16Ch]
  float v88; // [esp+B4h] [ebp-164h]
  float v89; // [esp+B8h] [ebp-160h]
  int v90; // [esp+C0h] [ebp-158h]
  float v91[4]; // [esp+D0h] [ebp-148h]
  int v92; // [esp+E0h] [ebp-138h]
  int v93; // [esp+100h] [ebp-118h]
  int v94; // [esp+10Ch] [ebp-10Ch]

  // A 8 element array:
  float v95[8]; // [esp+118h] [ebp-100h] //0
#if 0
  float v96; // [esp+11Ch] [ebp-FCh] //1
  float v97; // [esp+120h] [ebp-F8h] //2
  float v98; // [esp+124h] [ebp-F4h] //3
  float v99; // [esp+128h] [ebp-F0h] //4
  float v100; // [esp+12Ch] [ebp-ECh] //5
  //E8 = 6
  //E4 = 7
#endif

  float v101[12]; // [esp+138h] [ebp-E0h]
  char v102; // [esp+168h] [ebp-B0h]
  float v103[12]; // [esp+178h] [ebp-A0h]
  char v104; // [esp+1A8h] [ebp-70h]
  int v105; // [esp+1B8h] [ebp-60h]
  int v106[8]; // [esp+1F8h] [ebp-20h]

  if ( a1 ) {
    v67 = *(_DWORD *)(a1 + 240);
    if ( a8 ) {

      //FIXME: Pretty sure that v76 is just a int32_t..
      v75 = 0.0;
      for(v10 = 0; v10 < 8; v10++) {
        v11 = ((double)SLODWORD(v75) * 0.01 + 0.1) * dbl_E22A38 * 360.0;
        sub_42F380(v11, &v95[v10], (int)&v106[v10]);
       
        v10++;
        v75 = *(float *)&v10;
        v10--;
      }

    }

    if ( a3 ) {
      v12 = flt_4C271C[13 * v67];
      if ( v12 < 0.3 || v12 > 5.0 ) {
        v12 = 1.0;
      }
      a4 = v12 * a4;
      a5 = v12 * a5;
      a6 = v12 * a6;
    }

    sub_481B30(*(_DWORD *)(a1 + 20), (float *)&unk_4C0088);
    sub_481B30(*(_DWORD *)(a1 + 4), (float *)&unk_4C0098);
    sub_481B30(*(_DWORD *)(a1 + 8), (float *)&unk_4C0098);
    sub_481B30(*(_DWORD *)(a1 + 12), (float *)&unk_4C0098);
    sub_481B30(*(_DWORD *)(a1 + 16), (float *)&unk_4C0098);

    v13 = *(_DWORD *)(a1 + 248);
    if ( v13 )
      *(_DWORD *)(v13 + 16) |= 1u;
    v14 = *(_DWORD *)(a1 + 8);
    if ( v14 )
      *(_DWORD *)(v14 + 16) |= 1u;
    v15 = *(_DWORD *)(a1 + 16);
    if ( v15 )
      *(_DWORD *)(v15 + 16) |= 1u;

    sub_44BB10(&v105, a2);
    sub_431450((int)&v105, a4, a5, a6, (int)&v105);

    v16 = *(_DWORD *)a1;
    if ( *(_DWORD *)a1 ) {
      sub_431740(v16, 0);
      sub_431A50(v16, 2, 3, 16, 2);
    }

    if ( (dword_50C048 & 0x80u) != 0 && dword_E98E94 & 0x400 ) {
      v17 = *(_DWORD *)a1;
      if ( *(_DWORD *)a1 ) {
        sub_431740(v17, 1);
        sub_431A50(v17, 2, 3, 16, 2);
      }

      v18 = *(_DWORD **)(a1 + 296);
      if ( v18 ) {
        sub_44BB10(&v83, (int)&v105);
        sub_431450((int)&v83, 0.004f, 0.004f, 0.004f, (int)&v83);
        if ( a8 ) {
          v19 = v95[3] * 0.2f;
          sub_42FA80((int)&v86, (int)&v86, v19, (int)&v85);
        }
        sub_431640(v18, &v83);
        sub_431A50((int)v18, 2, 3, 16, 2);
        return;
      }
    } else {

      // This is an unrolled loop over 2 elements
      for(int i = 0; i < 2; i++) {

        _DWORD *v20; // edi
        float v21; // ST18_4
        float v22; // ST0C_4
        _DWORD *v23; // edi
        float v24; // ST18_4
        float v25; // ST0C_4
        _DWORD *v26; // edi

        v20 = *(_DWORD **)(a1 + (4 + i * 4));
        if ( v20 )
        {
          sub_44BB10(&v83, (int)&v105);
          sub_42F7D0(&v88, (_DWORD *)(108 * v67 + 5009556));

          if (i % 2 != 0) {
            v88 = -v88;
          }

          sub_430980(&v72, &v88, (float *)&v83);
          sub_42F830((float *)&v86, (float *)&v86, &v72);
          if ( a8 )
          {
            v21 = v95[3 + i] * 0.2;
            sub_42FA80((int)&v86, (int)&v86, v21, (int)&v85);
            sub_42F7D0(&v72, &v84);
            sub_42F9B0(&v72);
            v22 = v95[1 + i] * 5.0;
            sub_431390((int)&v83, v22, v72, v73, v74, (int)&v83);
          }
          sub_431640(v20, &v83);
          sub_431A50((int)v20, 2, 3, 16, 2);
          v23 = *(_DWORD **)(a1 + (12 + i * 4));
          if ( v23 )
          {
            sub_42F7D0(&v88, &dword_4C7A40);

            if (i % 2 != 0) {
              v88 = -v88;
            }

            sub_430980(&v72, &v88, (float *)&v105);
            sub_42F830((float *)&v86, (float *)&v86, &v72);
            if ( a8 )
            {
              v24 = v95[3 + i] * 0.2;
              sub_42FA80((int)&v86, (int)&v86, v24, (int)&v85);
              sub_42F7D0(&v72, &v84);
              sub_42F9B0(&v72);
              v25 = v95[1 + i] * 5.0;
              sub_431390((int)&v83, v25, v72, v73, v74, (int)&v83);
            }
            sub_431640(v23, &v83);
            sub_431A50((int)v23, 2, 3, 16, 2);
          }
          v26 = *(_DWORD **)(a1 + (248 + i * 4));
          if ( v26 )
          {
            sub_42F7D0(&v72, &v86);
            sub_4310B0((int)&v83, a4, SLODWORD(a5), SLODWORD(a6));
            sub_42F7D0(&v86, &v72);
            v87 = a7;
            sub_431450((int)&v83, 0.004f, 0.004f, 0.004f, (int)&v83);
            sub_431640(v26, &v83);
            sub_431A50((int)v26, 2, 3, 16, 2);
          }
        }

      }

      //FIXME: This could actually be the same couple of inline function as
      //       the previous one, just with different parameters.
      v34 = *(_DWORD **)(a1 + 20);
      if ( v34 )
      {
        sub_44BB10(&v83, (int)&v105);
        sub_42F7D0(&v88, (_DWORD *)(108 * v67 + 5009544));
        sub_430980(&v72, &v88, (float *)&v83);
        sub_42F830((float *)&v86, (float *)&v86, &v72);
        if ( a8 )
        {
          LODWORD(v75) = 10 * byte_4C2724[52 * v67];
          *(float *)&v87 = (double)SLODWORD(v75) + a6 * 1.5 + *(float *)&a7;
          v35 = v95[5] * 0.1;
          sub_42FA80((int)&v86, (int)&v86, v35, (int)&v85);
          sub_42F7D0(&v72, &v84);
          sub_42F9B0(&v72);
          v36 = v95[1] * 10.0;
          sub_431390((int)&v83, v36, v72, v73, v74, (int)&v83);
        }
        sub_431640(v34, &v83);
        sub_431A50((int)v34, 2, 3, 16, 2);
        if ( v89 == 0.0 )
        {
          v37 = *(_DWORD **)(a1 + 4);
          if ( v37 )
            sub_431640(v37, &v83);
          v38 = *(_DWORD **)(a1 + 8);
          if ( v38 )
            sub_431640(v38, &v83);
        }
        v39 = *(_DWORD **)(a1 + 256);
        if ( v39 )
        {
          sub_42F7D0(&v72, &v86);
          sub_4310B0((int)&v83, a4, SLODWORD(a5), SLODWORD(a6));
          sub_42F7D0(&v86, &v72);
          v87 = a7;
          sub_431450((int)&v83, 0.004f, 0.004f, 0.004f, (int)&v83);
          sub_431640(v39, &v83);
          sub_431A50((int)v39, 2, 3, 16, 2);
        }
      }
      sub_46F2C0(0, a1, a9, a10);

      // This loop is unrolled in the games code
      for(int i = 0; i < 8; i++) {
        _DWORD v40 = *(_DWORD *)(a1 + (24 + i * 4));
        if (v40) {
          sub_431A50(v40, 2, -4, 16, 3);
        }
      }

      if ( dword_50C478 > 0 ) {
        --dword_50C478;
      }

      // This loop is unrolled in the games code
      for(int i = 0; i < 4; i++) {

        float v49; // ST18_4
        float v50; // ST14_4
        float v51; // ST10_4
        int v53; // eax

        float v68;

        if ( *(_DWORD *)(a1 + (40 + i * 4)) ) {
          sub_4316A0(*(_DWORD **)(a1 + 20), v101);
          sub_42F7D0(&v76, &v102);
          sub_4316A0(*(_DWORD **)(a1 + (4 + i * 4)), v103);
          sub_42F7D0(v81, &v104);
          sub_42F7D0(&v79, (_DWORD *)&unk_4C70AC + 27 * v67);

          if (i % 2 != 0) {
            v79 = -v79;
          }

          sub_430980(&v79, &v79, v101);
          sub_42F830((float *)&v76, &v79, (float *)&v76);
          sub_42F7D0(&v80, (_DWORD *)&unk_4C70B8 + 27 * v67);

          if (i % 2 != 0) {
            v80 = -v80;
          }

          sub_430980(&v80, &v80, v103);
          sub_42F830(v81, &v80, v81);
          sub_42F860(v82, (float *)&v76, v81);
          v75 = sub_42F8C0(v82);
          sub_42F9B0(v82);
          sub_431100(&v90, v76, v77, v78);
          sub_42F7D0(v91, v82);
          sub_42F7B0((int)&v92, 0.0f, 0.0f, 1.0f);
          sub_42F9F0((float *)&v90, v91, (float *)&v92);
          sub_42F9F0((float *)&v92, (float *)&v90, v91);
          v49 = a6 * 0.004f;
          v50 = v75 * 0.01f;
          v51 = a4 * 0.004f;
          sub_431450((int)&v90, v51, v50, v49, (int)&v90);
          sub_431640(*(_DWORD **)(a1 + (40 + i * 4)), &v90);
          if ( dword_50C478 > 0 ) {
            sub_42F7B0((int)&v94, 0.0f, 0.0f, 0.0f);
            sub_42F7B0((int)&v93, 0.0f, 0.0f, 0.0f);
            v68 = a8 ? 1.3f : 0.5f;
            sub_481C30(*(_DWORD *)(a1 + (40 + i * 4)), (int)&v94, (int)&v93, *(float *)&v68, 1.0f, 0.0f, 50.0f, 0);
          }
          v53 = *(_DWORD *)(a1 + (40 + i * 4));
          if ( v53 ) {
            sub_431A50(v53, 2, 3, 16, 2);
          }
        }

      }

      if ( dword_50C478 == 4 )
        sub_43E6F0();

      v66 = *(_DWORD *)(a1 + 236);
      if ( v66 )
        sub_431A50(v66, 2, -4, 16, 3);

      if ( (dword_50C048 & 0x80u) != 0 ) {
        if ( dword_E98E94 & 0x1000 ) {
          v18 = *(_DWORD **)(a1 + 236);
          if ( v18 ) {
            sub_431A50((int)v18, 2, 3, 16, 2);
            return;
          }
        }
      }
    }
  }
}
