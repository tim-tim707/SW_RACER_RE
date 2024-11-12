#pragma once

#include "types.h"

#include <Windows.h>
#include <commctrl.h>

int std3D_Startup_hook(void);
int std3D_Open_hook(unsigned int deviceNum);
int std3D_StartScene_hook(void);
void std3D_EndScene_hook(void);
void std3D_DrawRenderList_hook(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags,
                               LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices,
                               int indexCount);
void std3D_SetRenderState_hook(Std3DRenderState rdflags);
void std3D_AllocSystemTexture_hook(tSystemTexture *pTexture, tVBuffer **apVBuffers,
                                   unsigned int numMipLevels, StdColorFormatType formatType);
void std3D_ClearTexture_hook(tSystemTexture *pTex);
void std3D_AddToTextureCache_hook(tSystemTexture *pCacheTexture, StdColorFormatType format);
void std3D_ClearCacheList_hook(void);
int std3D_SetTexFilterMode_hook(void);
int std3D_SetProjection_hook(float fov, float aspectRatio, float nearPlane, float farPlane);
void std3D_AddTextureToCacheList_hook(tSystemTexture *pTexture);
void std3D_RemoveTextureFromCacheList_hook(tSystemTexture *pCacheTexture);
int std3D_PurgeTextureCache_hook(unsigned int size);
