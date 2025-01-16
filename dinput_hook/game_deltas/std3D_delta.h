#pragma once

#include "types.h"

int std3D_Startup_delta(void);
int std3D_Open_delta(unsigned int deviceNum);

int std3D_StartScene_delta(void);
void std3D_EndScene_delta(void);
void std3D_DrawRenderList_delta(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags,
                                LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices,
                                int indexCount);
void std3D_SetRenderState_delta(Std3DRenderState rdflags);
void std3D_AllocSystemTexture_delta(tSystemTexture *pTexture, tVBuffer **apVBuffers,
                                    unsigned int numMipLevels, StdColorFormatType formatType);
void std3D_ClearTexture_delta(tSystemTexture *pTex);
void std3D_AddToTextureCache_delta(tSystemTexture *pCacheTexture, StdColorFormatType format);
void std3D_ClearCacheList_delta(void);
int std3D_SetTexFilterMode_delta(void);
int std3D_SetProjection_delta(float fov, float aspectRatio, float nearPlane, float farPlane);

void std3D_AddTextureToCacheList_delta(tSystemTexture *pTexture);
void std3D_RemoveTextureFromCacheList_delta(tSystemTexture *pCacheTexture);
int std3D_PurgeTextureCache_delta(unsigned int size);

void renderer_setAlphaMask(bool useAlphaMask);
void renderer_setFog(bool useFog);
