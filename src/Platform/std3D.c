#include "std3D.h"

// int __cdecl std3D_GetTextureFormat(StdColorFormatType type, ColorInfo *pDest, int *pbColorKeySet, LPDDCOLORKEY *ppColorKey)
// 0x0038a230
int std3D_GetTextureFormat(StdColorFormatType type, rdTexFormat* pDest, int* pbColorKeySet, void* ppColorKey)
{
    HANG("TODO");
}

// 0x0048a2d0
StdColorFormatType std3D_GetColorFormat(rdTexFormat* format)
{
    if (format->alpha_bits == 0)
    {
        return STDCOLOR_FORMAT_RGB; // RGB
    }
    if (format->alpha_bits != 1)
    {
        return STDCOLOR_FORMAT_RGBA; // RGB4444
    }
    return STDCOLOR_FORMAT_RGBA_1BIT_ALPHA; // RGB5551
}

// 0x0048a9e0
// void __cdecl std3D_GetValidDimensions(unsigned int width, unsigned int height, unsigned int *pOutWidth, unsigned int *pOutHeight)
void std3D_GetValidDimensions(unsigned int width, unsigned int height, unsigned int* outWidth, unsigned int* outHeight)
{
    HANG("TODO");
}

// 0x0048a5e0
// void __cdecl std3D_AllocSystemTexture(tSystemTexture *pTexture, tVBuffer **apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType)
void std3d_AllocSystemTexture(void* pTexture, stdVBuffer** apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType)
{
    HANG("TODO");
}

// 0x0048aa40
// void __cdecl std3D_ClearTexture(tSystemTexture* pTex)
void std3D_ClearTexture(void* pTex)
{
    HANG("TODO");
}

// 0x0048ba90
// void __cdecl std3D_RemoveTextureFromCacheList(tSystemTexture* pCacheTexture)
void std3D_RemoveTextureFromCacheList(void* pCacheTexture)
{
    HANG("TODO");
}
