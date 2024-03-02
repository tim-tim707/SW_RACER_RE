#include "std3D.h"

#include <macros.h>

// 0x00489dc0
int std3D_Startup(void)
{
    HANG("TODO");
}

// 0x00489e40
void std3D_Shutdown(void)
{
    HANG("TODO");
}

// 0x00489ea0
int std3D_GetNumDevices(void)
{
    HANG("TODO");
}

// 0x00489eb0
Device3D* std3D_GetAllDevices(void)
{
    HANG("TODO");
}

// 0x00489ec0
int std3D_Open(unsigned int deviceNum)
{
    HANG("TODO");
}

// 0x0048a1c0
void std3D_Close(void)
{
    HANG("TODO");
}

// 0x0048a2f0
int std3D_GetNumTextureFormats(void)
{
    HANG("TODO");
}

// 0x0048a300
int std3D_StartScene(void)
{
    HANG("TODO");
}

// 0x0048a330
void std3D_EndScene(void)
{
    HANG("TODO");
}

// 0x0048a350
void std3D_DrawRenderList(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags, LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices, int indexCount)
{
    HANG("TODO");
}

// 0x0048a3c0
void std3D_SetWireframeRenderState(void)
{
    HANG("TODO");
}

// 0x0048a3f0
void std3D_DrawLineStrip(LPD3DTLVERTEX pVertices, unsigned int numVertices)
{
    HANG("TODO");
}

// 0x0048a420
int std3D_DrawPointList(LPVOID lpvVertices, unsigned int dwVertexCount)
{
    HANG("TODO");
}

// 0x0048a450
void std3D_SetRenderState(Std3DRenderState rdflags)
{
    HANG("TODO");
}

// 0x0048a5e0
void std3D_AllocSystemTexture(tSystemTexture* pTexture, tVBuffer** apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType)
{
    HANG("TODO");
}

// 0x0048a9e0
void std3D_GetValidDimensions(unsigned int width, unsigned int height, unsigned int* pOutWidth, unsigned int* pOutHeight)
{
    HANG("TODO");
}

// 0x0048aa40
void std3D_ClearTexture(tSystemTexture* pTex)
{
    HANG("TODO");
}

// 0x0048aa80
void std3D_AddToTextureCache(tSystemTexture* pCacheTexture, StdColorFormatType format)
{
    HANG("TODO");
}

// 0x0048ac50
void std3D_ClearCacheList(void)
{
    HANG("TODO");
}

// 0x0048ace0
void std3D_UpdateFrameCount(tSystemTexture* pTexture)
{
    HANG("TODO");
}

// 0x0048add0
int std3D_FindClosestMode(ColorInfo* pCI)
{
    HANG("TODO");
}

// 0x0048aeb0
int std3D_InitRenderState(void)
{
    HANG("TODO");
}

// 0x0048b1b0
int std3D_SetTexFilterMode(void)
{
    HANG("TODO");
}

// 0x0048b260
int std3D_SetProjection(float fov, float aspectRatio, float nearPlane, float farPlane)
{
    HANG("TODO");
}

// 0x0048b4b0
void std3D_GetZBufferFormat(DDPIXELFORMAT* pPixelFormat)
{
    HANG("TODO");
}

// 0x0048b500
HRESULT std3D_EnumZBufferFormatsCallback(LPDDPIXELFORMAT lpDDPixFmt, DDPIXELFORMAT* lpContext)
{
    HANG("TODO");
}

// 0x0048ba20
void std3D_AddTextureToCacheList(tSystemTexture* pTexture)
{
    HANG("TODO");
}

// 0x0048ba90
void std3D_RemoveTextureFromCacheList(tSystemTexture* pCacheTexture)
{
    HANG("TODO");
}

// 0x0048bb50
int std3D_PurgeTextureCache(unsigned int size)
{
    HANG("TODO");
}

// 0x0048bc10
StdDisplayEnvironment* std3D_BuildDisplayEnvironment(void)
{
    HANG("TODO");
}

// 0x0048be20
void std3D_FreeDisplayEnvironment(StdDisplayEnvironment* pEnv)
{
    HANG("TODO");
}
