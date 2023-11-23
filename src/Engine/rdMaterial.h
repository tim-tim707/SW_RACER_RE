#ifndef RDMATERIAL_H
#define RDMATERIAL_H

#include "types.h"

#define rdMaterial_Load_ADDR (0x0048e680) // TODO
// rdMaterial_Load(const char* filename);

#define rdMaterial_LoadEntry_ADDR (0x0048e6d0)

// rdMaterial* out
int rdMaterial_LoadEntry(char* mat_fpath, swrMaterial* material);

// 0x0048e680
// RdMaterial* __cdecl rdMaterial_Load(const char* pFilename)

// TODO
// 0x0048eac0
// void __cdecl rdMaterial_Free(RdMaterial* pMaterial)

// TODO
// 0x0048eb00
// void __cdecl rdMaterial_FreeEntry(RdMaterial* pMaterial)

#endif // RDMATERIAL_H
