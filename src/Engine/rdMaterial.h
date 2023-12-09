#ifndef RDMATERIAL_H
#define RDMATERIAL_H

#include "types.h"

#define rdMaterial_Load_ADDR (0x0048e680)
#define rdMaterial_LoadEntry_ADDR (0x0048e6d0)
#define rdMaterial_Free_ADDR (0x0048eac0)
#define rdMaterial_FreeEntry_ADDR (0x0048eb00)

RdMaterial* rdMaterial_Load(char* pFilename);
int rdMaterial_LoadEntry(char* mat_fpath, swrMaterial* material);
void rdMaterial_Free(RdMaterial* pMaterial);
void rdMaterial_FreeEntry(RdMaterial* pMaterial);

#endif // RDMATERIAL_H
