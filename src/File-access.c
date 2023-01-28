int __cdecl sub_4877B0(char *a1) {
  return sub_487830(a1, aR);
}
int __cdecl sub_487830(char *a1, char* a2) {

  if ( dword_529500 ) {
    sub_487C00();
  }

  if ( !strcmp(a1, aNone) ) {
    dword_529504 = 0;
  } else {
    dword_529504 = dword_ECC420->unk12(a1, a2);
    if ( (unsigned int)dword_529504 <= 0 ) {
      dword_529504 = 0;
      if ( dword_529500 ) {
        sub_487C90();
      }
      return 0;
    }
  }

  dword_EC9E84 = dword_ECC420->unk8(4096);
  strncpy(byte_5143D8, a1, 0x7Fu);
  byte_514457 = 0;
  dword_5284F8 = 0;
  dword_529500 = 1;
  return 1;
}
void sub_487C00() {
  strcpy(&byte_513938[128 * dword_52950C], byte_5143D8);
  dword_514388[dword_52950C] = dword_5284F8;
  dword_5284F8 = 0;
  dword_514338[dword_52950C] = (int)dword_EC9E84;
  dword_5284A8[dword_52950C] = dword_529504;
  dword_529504 = 0;
  qmemcpy((void *)(0x514458 + 4100 * dword_52950C), &dword_EC8E80, 4100);
  dword_52950C++;
  return;
}
void sub_487C90() {
  if ( (unsigned int)dword_52950C >= 1 ) {
    dword_52950C--;
    strcpy(byte_5143D8, &byte_513938[128 * dword_52950C]);
    dword_529504 = dword_5284A8[dword_52950C];
    dword_5284F8 = dword_514388[dword_52950C];
    dword_EC9E84 = (LPCSTR)dword_514338[dword_52950C];
    qmemcpy(&dword_EC8E80, (const void *)(0x514458 + 4100 * dword_52950C), 4100);
  }
}
signed int sub_487AE0() {
  while( sub_487B20() ){
    if ( sub_487A50(dword_EC9E84) ) {
      break;
    }
    if ( dword_EC8E80 ) {
      return 1;
    }
  }
  return 0;
}
signed int sub_487B20()
{
  const CHAR *v0; // esi
  signed int v1; // ebp
  int v2; // ebx
  char v3; // al
  char *v4; // eax
  unsigned int v5; // ecx
  CHAR v6; // al
  CHAR *v7; // ecx

  v0 = dword_EC9E84;
  v1 = 0;
  v2 = 4095;
  while ( v2 )
  {
    if ( !(*(int (__cdecl **)(int, const CHAR *, int))(dword_ECC420 + 60))(dword_529504, v0, v2) )
      return 0;
    ++dword_5284F8;
    v3 = *v0;
    if ( *v0 != 59 && v3 != 35 && v3 != 10 && v3 != 13 )
    {
      v4 = strchr(v0, 35);
      if ( v4 )
        *v4 = 0;
      sub_49EDD0(v0);
      v5 = strlen(dword_EC9E84);
      if ( dword_EC9E84[v5 - 2] == 92 )
      {
        v0 = &dword_EC9E84[v5 - 2];
        v2 = 4096 - v5;
      }
      else
      {
        v6 = dword_EC9E84[v5 - 1];
        v7 = (CHAR *)&dword_EC9E84[v5 - 1];
        v1 = 1;
        if ( v6 == 13 || v6 == 10 )
          *v7 = 0;
      }
    }
    if ( v1 )
      return 1;
  }
  return 1;
}
char *__cdecl sub_487A50(char *a1)
{
  int v1; // ebx
  char *v2; // esi
  char **v3; // edi
  char *v4; // eax
  char *result; // eax

  v1 = 0;
  dword_EC8E80 = 0;
  v2 = strtok(a1, asc_4C86B0);
  if ( v2 )
  {
    v3 = &dword_EC8E88;
    while ( (signed int)v3 <= (signed int)&unk_EC9E88 )
    {
      v4 = strchr(v2, 61);
      if ( v4 )
      {
        *v4 = 0;
        *(v3 - 1) = v2;
        *v3 = v4 + 1;
      }
      else
      {
        *(v3 - 1) = v2;
        *v3 = v2;
      }
      ++v1;
      v3 += 2;
      result = strtok(0, asc_4C86B0);
      v2 = result;
      if ( !result )
      {
        dword_EC8E80 = v1;
        return result;
      }
    }
    result = (char *)1;
  }
  else
  {
    dword_EC8E80 = 0;
    result = 0;
  }
  return result;
}
void sub_487900() {
  if ( dword_529500 == 0) {
    return;
  }

  // If a file was opened, close it and reset handle to 0
  if ( dword_529504 != 0) {
    dword_ECC420->unk13(dword_529504); // fclose
    dword_529504 = 0;
  }

  dword_ECC420->unk9(dword_EC9E84); // something like free

  if ( dword_52950C ) {
    sub_487C90();
  } else {
    dword_529500 = 0;
  }
}
