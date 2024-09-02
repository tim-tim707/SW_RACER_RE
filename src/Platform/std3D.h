#ifndef STD3D_H
#define STD3D_H

#include "types.h"

#define std3D_Startup_ADDR (0x00489dc0)
#define std3D_Shutdown_ADDR (0x00489e40)
#define std3D_GetNumDevices_ADDR (0x00489ea0)
#define std3D_GetAllDevices_ADDR (0x00489eb0)
#define std3D_Open_ADDR (0x00489ec0)

#define std3D_Close_ADDR (0x0048a1c0)

#define std3D_GetNumTextureFormats_ADDR (0x0048a2f0)
#define std3D_StartScene_ADDR (0x0048a300)
#define std3D_EndScene_ADDR (0x0048a330)
#define std3D_DrawRenderList_ADDR (0x0048a350)
#define std3D_SetWireframeRenderState_ADDR (0x0048a3c0)
#define std3D_DrawLineStrip_ADDR (0x0048a3f0)
#define std3D_DrawPointList_ADDR (0x0048a420)
#define std3D_SetRenderState_ADDR (0x0048a450)
#define std3D_AllocSystemTexture_ADDR (0x0048a5e0)
#define std3D_GetValidDimensions_ADDR (0x0048a9e0)
#define std3D_ClearTexture_ADDR (0x0048aa40)
#define std3D_AddToTextureCache_ADDR (0x0048aa80)
#define std3D_ClearCacheList_ADDR (0x0048ac50)
#define std3D_UpdateFrameCount_ADDR (0x0048ace0)
#define std3D_GetDeviceCaps_ADDR (0x0048AD10)
#define std3D_FindMatching3DDevice_ADDR (0x0048AD50)
#define std3D_FindClosestMode_ADDR (0x0048add0)
#define std3D_InitRenderState_ADDR (0x0048aeb0)
#define std3D_SetTexFilterMode_ADDR (0x0048b1b0)
#define std3D_SetProjection_ADDR (0x0048b260)

#define std3D_GetZBufferFormat_ADDR (0x0048b4b0)
#define std3D_EnumZBufferFormatsCallback_ADDR (0x0048b500)

#define std3D_AddTextureToCacheList_ADDR (0x0048ba20)
#define std3D_RemoveTextureFromCacheList_ADDR (0x0048ba90)
#define std3D_PurgeTextureCache_ADDR (0x0048bb50)
#define std3D_BuildDisplayEnvironment_ADDR (0x0048bc10)
#define std3D_FreeDisplayEnvironment_ADDR (0x0048be20)

int std3D_Startup(void);
void std3D_Shutdown(void);
int std3D_GetNumDevices(void);
Device3D* std3D_GetAllDevices(void);
int std3D_Open(unsigned int deviceNum);

void std3D_Close(void);

int std3D_GetNumTextureFormats(void);
int std3D_StartScene(void);
void std3D_EndScene(void);
void std3D_DrawRenderList(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags, LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices, int indexCount);
void std3D_SetWireframeRenderState(void);
void std3D_DrawLineStrip(LPD3DTLVERTEX pVertices, unsigned int numVertices);
void std3D_DrawPointList(LPVOID lpvVertices, unsigned int dwVertexCount);
void std3D_SetRenderState(Std3DRenderState rdflags);
void std3D_AllocSystemTexture(tSystemTexture* pTexture, tVBuffer** apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType);
void std3D_GetValidDimensions(unsigned int width, unsigned int height, unsigned int* pOutWidth, unsigned int* pOutHeight);
void std3D_ClearTexture(tSystemTexture* pTex);
void std3D_AddToTextureCache(tSystemTexture* pCacheTexture, StdColorFormatType format);
void std3D_ClearCacheList(void);
void std3D_UpdateFrameCount(tSystemTexture* pTexture);
int std3D_GetDeviceCaps(int device_index, Device3DCaps *a2);
int std3D_FindMatching3DDevice(const Device3DCaps *caps);
int std3D_FindClosestMode(const ColorInfo* pCI);
int std3D_InitRenderState(void);
int std3D_SetTexFilterMode(void);
int std3D_SetProjection(float fov, float aspectRatio, float nearPlane, float farPlane);

void std3D_GetZBufferFormat(DDPIXELFORMAT* pPixelFormat);
HRESULT __stdcall std3D_EnumZBufferFormatsCallback(LPDDPIXELFORMAT lpDDPixFmt, void* lpContext);

void std3D_AddTextureToCacheList(tSystemTexture* pTexture);
void std3D_RemoveTextureFromCacheList(tSystemTexture* pCacheTexture);
int std3D_PurgeTextureCache(unsigned int size);
StdDisplayEnvironment* std3D_BuildDisplayEnvironment(void);
void std3D_FreeDisplayEnvironment(StdDisplayEnvironment* pEnv);

#endif // STD3D_H
