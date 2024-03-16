#ifndef RDMATERIAL_H
#define RDMATERIAL_H

#include "types.h"

#define rdMaterial_Load_ADDR (0x0048e680)
#define rdMaterial_LoadEntry_ADDR (0x0048e6d0)
#define rdMaterial_Free_ADDR (0x0048eac0)
#define rdMaterial_FreeEntry_ADDR (0x0048eb00)

#define rdMaterial_InvertTextureAlphaR4G4B4A4_ADDR (0x00431CF0)
#define rdMaterial_InvertTextureColorR4G4B4A4_ADDR (0x00431DF0)
#define rdMaterial_RemoveTextureAlphaR5G5B5A1_ADDR (0x00431EF0)
#define rdMaterial_RemoveTextureAlphaR4G4B4A4_ADDR (0x00431FD0)
#define rdMaterial_SaturateTextureR4G4B4A4_ADDR (0x004320B0)

RdMaterial* rdMaterial_Load(char* pFilename);
int rdMaterial_LoadEntry(char* mat_fpath, swrMaterial* material);
void rdMaterial_Free(RdMaterial* pMaterial);
void rdMaterial_FreeEntry(RdMaterial* pMaterial);

void rdMaterial_InvertTextureAlphaR4G4B4A4(RdMaterial *mat);
void rdMaterial_InvertTextureColorR4G4B4A4(RdMaterial *mat);
void rdMaterial_RemoveTextureAlphaR5G5B5A1(RdMaterial *mat);
void rdMaterial_RemoveTextureAlphaR4G4B4A4(RdMaterial *mat);
void rdMaterial_SaturateTextureR4G4B4A4(RdMaterial *mat);

#endif // RDMATERIAL_H
