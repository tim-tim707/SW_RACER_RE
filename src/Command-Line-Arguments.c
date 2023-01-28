int __cdecl sub_424430(char *a1) {
  char *v1; // esi
  char *v3; // eax
  double v4; // st7
  char *v5; // eax
  double v6; // st7
  char *v7; // eax

  v1 = strtok(a1, asc_4B7C68);
  if (v1 == 0) {
    return 0;
  }

  while(v1 != 0) {
    if (!_strcmpi(v1, aS_1)) {
      dword_4B6D20 = 0;
    } else if ( !_strcmpi(v1, aP) ) {
      dword_4B6D2C = 0;
    } else if ( !_strcmpi(v1, aR_0) ) {
      v3 = strtok(0, asc_4B7C68);
      if ( !v3 ) {
        return 1;
      }
      v4 = atof(v3);

      flt_4C7D78 = v4;
      if ( v4 < 0.0 ) {
        flt_4C7D78 = 0.0;
      }

    } else if ( !_strcmpi(v1, aD_1) ) {
      v5 = strtok(0, asc_4B7C68);
      if ( !v5 ) {
        return 1;
      }
      v6 = atof(v5);

      flt_4C7D74 = v6;
      if ( v6 < 0.0 )
        flt_4C7D74 = 0.0;

    } else if ( !_strcmpi(v1, aNut) ) {
      v7 = strtok(0, asc_4B7C68);
      if ( v7 ) {
        dword_4B6718 = atoi(v7);
      }
    } else if ( !_strcmpi(v1, aForce) ) {
      dword_4B4938 = 0;
    } else if ( !_strcmpi(v1, a3dimpacts) ) {
      dword_4C7AA8 = 0;
    } else if ( !_strcmpi(v1, aV) ) {
      dword_50B5B0 = 1;
    } else if ( !_strcmpi(v1, aI) ) {
      dword_4B7A00 = 0;
    } else if ( !_strcmpi(v1, asc_4B7C30) ) {
      dword_4B79F8 = 0;
    } else if ( !_strcmpi(v1, aSnafu) ) {
      dword_50B5C0 = 1;
    }

    v1 = strtok(0, asc_4B7C68);
  }

  return 1;
}
