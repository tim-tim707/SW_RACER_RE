#ifndef STD3D_H
#define STD3D_H

#include "types.h"

#define std3D_GetTextureFormat_ADDR (0x0048a230)

#define std3D_GetColorFormat_ADDR (0x0048a2d0)

#define std3d_AllocSystemTexture_ADDR (0x0048a5e0)

#define std3D_GetValidDimensions_ADDR (0x0048a9e0)

#define std3D_ClearTexture_ADDR (0x0048aa40)

#define std3D_RemoveTextureFromCacheList_ADDR (0x0048ba90)

// int __cdecl std3D_GetTextureFormat(StdColorFormatType type, ColorInfo *pDest, int *pbColorKeySet, LPDDCOLORKEY *ppColorKey)
int std3D_GetTextureFormat(StdColorFormatType type, rdTexFormat* pDest, int* pbColorKeySet, void* ppColorKey);

StdColorFormatType std3D_GetColorFormat(rdTexFormat* format);

// 0x0048a5e0
// void __cdecl std3D_AllocSystemTexture(tSystemTexture *pTexture, tVBuffer **apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType)
void std3d_AllocSystemTexture(void* pTexture, stdVBuffer** apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType);

// 0x0048a9e0
// void __cdecl std3D_GetValidDimensions(unsigned int width, unsigned int height, unsigned int *pOutWidth, unsigned int *pOutHeight)
void std3D_GetValidDimensions(unsigned int width, unsigned int height, unsigned int* outWidth, unsigned int* outHeight);

// 0x0048aa40
// void __cdecl std3D_ClearTexture(tSystemTexture* pTex)
void std3D_ClearTexture(void* pTex);

// 0x0048ba90
// void __cdecl std3D_RemoveTextureFromCacheList(tSystemTexture* pCacheTexture)
void std3D_RemoveTextureFromCacheList(void* pCacheTexture);

#endif // STD3D_H
