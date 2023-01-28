/* Functions to load racer.tab and lookup translation entries */

// This research is based on the patched US version

//----- (004212F0) --------------------------------------------------------
// Sorting function for text entries
int __cdecl sub_4212F0(const void *a1, const void *a2) {
  return strcmp(*(const char **)a1, *(const char **)a2);
}

//----- (00421120) --------------------------------------------------------
// Parse racer.tab
signed int __cdecl sub_421120(const char* a1) {
  int v4; // ebp
  char *v10; // edi
  char *v12; // esi
  char *v13; // eax

  // Open file
  FILE* v2 = dword_ECC420->unk12(a1, aRb);
  if ( !v2 ) {
    return 1;
  }

  // Read 4 magic bytes
  uint32_t magic;
  dword_ECC420->unk14(v2, &magic, 4);

  // Query file size
  dword_ECC420->unk19(v2, 0, 2);
  v4 = ftell(v2);
  dword_ECC420->unk19(v2, 0, 0);

  // Allocate a buffer and read file to buffer
  lpSrcStr = dword_ECC420->unk8(v4);
  dword_ECC420->unk14(v2, lpSrcStr, v4);

  // Close file again
  dword_ECC420->unk13(v2);
  
  // Decrypt the file if it was encrypted (which is optional)
  if ( magic == 0x454E4352 ) { // 'ENCR' or 'RCNE'
    v4 -= 4;
    for (int i = 0; i < v4; i++ ) {
      lpSrcStr[i] = lpSrcStr[i + 4] ^ 0xDD;
    }
  }

  // Scan over the whole file to count entries
  int32_t v8;
  dword_4EB3CC = 0;
  char* v6 = lpSrcStr;
  char* v7 = &lpSrcStr[v4];
  do {
    if ( v6 < v7 ) {

      while ( v6 < v7 ) {
        if ((*v6 == 13) || (*v6 == 10)) { break; }
        v6++;
      }
      while(v6 < v7) {
        if ((*v6 != 13) && (*v6 != 10)) { break; }
        v6++;
      }

    }
    v8 = ++dword_4EB3CC;
  } while ( v6 < (v7 - 1) );

  // Allocate memory for the string table
  dword_4EB3C4 = dword_ECC420->unk8(4 * v8);

  // Scan over the file again to collect entries
  int32_t v1 = 0;
  char* v10 = lpSrcStr;
  char* v11 = &lpSrcStr[v4];
  do {
    char* v12 = v10;

    while(v12 < v11) {
      if (*v12 == 13) || (*v12 == 10)) { break; }
      v12++;
    } 

    while(v12 < v11) {
      if ((*v12 != 13) && (*v12 != 10)) { break; }

      // Replace newlines with zero termination
      *v12 = '\0';

      v12++;
    } 

    // Unescape key + value
    sub_4214C0(v10, v10);

    // Search first tab symbol and replace it with zero termination
    v13 = strchr(v10, '\t');
    if ( v13 ) {
      *v13 = '\0';
    }

    // Convert key to lowercase
    sub_4AB5D0(v10);

    // Store entry in string table
    *(_DWORD *)((char *)dword_4EB3C4 + v1 * 4) = v10;

    // Move cursor to end of this string entry
    v10 = v12;

    v1++;
  } while (v10 < (v11 - 1));

  // Sort the string table so it can be binary searched later
  qsort(dword_4EB3C4, dword_4EB3CC, 4u, sub_4212F0);

  return 1;
}

//----- (00421360) --------------------------------------------------------
// Lookup text entry from racer.tab
const char *__cdecl sub_421360(const char *a1) {
  const char *result; // eax
  char *v2; // edi
  char *v3; // eax
  const char **v4; // eax
  CHAR *v5; // [esp+Ch] [ebp-104h]
  CHAR SrcStr; // [esp+10h] [ebp-100h]

  v5 = &SrcStr;
  if ( !a1 )
    return 0;
  if ( !*a1 || *a1 != 47 || strlen(a1) == 1 )
    return a1;
  v2 = strchr(a1 + 1, 47) + 1;
  if ( !lpSrcStr )
    return v2;
  strncpy(&SrcStr, a1 + 1, 0xFEu);
  v3 = strchr(&SrcStr, 47);
  if ( v3 )
    *v3 = 0;
  sub_4AB5D0(&SrcStr);
  v4 = (const char **)bsearch(&v5, dword_4EB3C4, dword_4EB3CC, 4u, sub_4212F0);
  if ( !v4 )
    return v2;
  result = &(*v4)[strlen(*v4) + 1];
  if ( !*result )
    return a1;
  return result;
}
