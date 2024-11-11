#include "std3D.h"

#include <macros.h>

#include <globals.h>
#include <math.h>
#include <Win95/DirectX.h>
#include <Win95/Window.h>
#include <Win95/stdDisplay.h>

#if GLFW_BACKEND
#include <GLFW/glfw3.h>
#include <glad/glad.h>

extern void renderer_drawRenderList(int verticesCount, LPD3DTLVERTEX aVerticies, int indexCount, LPWORD lpwIndices);

#endif

extern FILE* hook_log;

#if GLFW_BACKEND

bool g_useAlphaMask;
bool g_useFog;

/**
 * TODO: Set an uniform that discard if useAlphaMask is enabled
 */
void renderer_setAlphaMask(bool useAlphaMask)
{
    // Use discard a <= 0 instead
    //      glEnable(GL_ALPHA_TEST);
    //      glAlphaFunc(GL_GREATER, 0); // drawn if a > 0
    // } else { // false
    //      glDisable(GL_ALPHA_TEST);
    g_useAlphaMask = useAlphaMask;
}

/**
 * TODO: Set an uniform to do fog computation if enabled
 * Use fog parameters provided by renderer_setLinearFogParameters
 */
void renderer_setFog(bool useFog)
{
    g_useFog = useFog;
}

#endif

// 0x00489dc0 HOOK
int std3D_Startup(void)
{
    // Added
    fprintf(hook_log, "std3D_Startup\n");
    fflush(hook_log);

    memset(std3D_aTextureFormats, 0, sizeof(std3D_aTextureFormats));
    memset(std3D_aDevices, 0, sizeof(std3D_aDevices));

#if GLFW_BACKEND

    std3D_numDevices = 1;
    std3D_aDevices[0] = (Device3D){
        .caps = {
            .bHAL = true,
            .bTexturePerspectiveSupported = true,
            .hasZBuffer = true,
            .bColorkeyTextureSupported = false,
            .bStippledShadeSupported = false,
            .bAlphaBlendSupported =  true,
            .bSqareOnlyTexture = false,
            .minTexWidth = 1,
            .minTexHeight = 1,
            .maxTexWidth = 4096,
            .maxTexHeight = 4096,
            .maxVertexCount = 65536,
        },
        .totalMemory = 1024 * 1024 * 1024,
        .availableMemory = 1024 * 1024 * 1024,
        .duid = {1,2,3,4,5,6, 7, 8}
    };

    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LEQUAL);

    renderer_setAlphaMask(true);

    std3D_renderState = 0;
    std3D_SetRenderState(STD3D_RS_BLEND_MODULATE);
#else
    std3D_pDirectDraw = stdDisplay_GetDirectDraw();
    if (std3D_pDirectDraw == NULL)
        return 0;

    if (IDirectDraw4_QueryInterface(std3D_pDirectDraw, &IID_IDirect3D3, (void**)&std3D_pDirect3D) != S_OK)
        return 0;

    std3D_numDevices = 0;
    if (IDirect3D_EnumDevices(std3D_pDirect3D, Direct3d_EnumDevices_Callback, 0) != S_OK)
        return 0;
#endif
    if (std3D_numDevices == 0)
        return 0;

    std3D_bStartup = 1;
    return 1;
}

// 0x00489e40 HOOK
void std3D_Shutdown(void)
{
    if (std3D_bOpen)
        std3D_Close();
    if (std3D_pDirect3D)
        IDirectDraw4_Release(std3D_pDirect3D);

    std3D_pD3Device = 0;
    memset(std3D_aTextureFormats, 0, sizeof(std3D_aTextureFormats));
    memset(std3D_aDevices, 0, sizeof(std3D_aDevices));
    std3D_pDirect3D = 0;
    std3D_numDevices = 0;
    std3D_bStartup = 0;
}

// 0x00489ea0 HOOK
int std3D_GetNumDevices(void)
{
    return std3D_numDevices;
}

// 0x00489eb0 HOOK
Device3D* std3D_GetAllDevices(void)
{
    return std3D_aDevices;
}

// 0x00489ec0 HOOK
int std3D_Open(unsigned int deviceNum)
{
    if (std3D_bOpen)
        return 0;
    if (deviceNum >= std3D_numDevices)
        return 0;

    std3D_curDevice = deviceNum;
    std3D_pCurDevice = &std3D_aDevices[deviceNum];
    if (!std3D_pCurDevice->caps.hasZBuffer)
        return 0;

#if GLFW_BACKEND
    std3D_g_maxVertices = std3D_pCurDevice->caps.maxVertexCount;

    std3D_frameCount = 1;
    std3D_numCachedTextures = 0;
    std3D_pFirstTexCache = 0;
    std3D_pLastTexCache = 0;

    std3D_numTextureFormats = 3;
    std3D_aTextureFormats[0].texFormat = (ColorInfo){
        .colorMode = T_STDCOLOR_RGB,
        .bpp = 16,
        .redBPP = 5,
        .greenBPP = 6,
        .blueBPP = 5,
        .redPosShift = 0,
        .greenPosShift = 5,
        .bluePosShift = 11,
        .RedShr = 3,
        .GreenShr = 2,
        .BlueShr = 3,
        .alphaBPP = 0,
        .alphaPosShift = 0,
        .AlphaShr = 0,
    };
    std3D_aTextureFormats[1].texFormat = (ColorInfo){
        .colorMode = T_STDCOLOR_RGBA,
        .bpp = 16,
        .redBPP = 5,
        .greenBPP = 5,
        .blueBPP = 5,
        .redPosShift = 0,
        .greenPosShift = 5,
        .bluePosShift = 10,
        .RedShr = 3,
        .GreenShr = 3,
        .BlueShr = 3,
        .alphaBPP = 1,
        .alphaPosShift = 15,
        .AlphaShr = 7,
    };
    std3D_aTextureFormats[2].texFormat = (ColorInfo){
        .colorMode = T_STDCOLOR_RGBA,
        .bpp = 16,
        .redBPP = 4,
        .greenBPP = 4,
        .blueBPP = 4,
        .redPosShift = 0,
        .greenPosShift = 4,
        .bluePosShift = 8,
        .RedShr = 4,
        .GreenShr = 4,
        .BlueShr = 4,
        .alphaBPP = 4,
        .alphaPosShift = 12,
        .AlphaShr = 4,
    };
    std3D_bHasRGBTextureFormat = true;

    std3D_RGBTextureFormat = std3D_FindClosestMode(&std3D_cfRGB565);
    std3D_RGBAKeyTextureFormat = std3D_FindClosestMode(&std3D_cfRGB5551);
    std3D_RGBA_TextureFormat = std3D_FindClosestMode(&std3D_cfRGB4444);
#else
    DDPIXELFORMAT zBufferFormat;
    std3D_GetZBufferFormat(&zBufferFormat);

    if (stdDisplay_CreateZBuffer(&zBufferFormat, std3D_pCurDevice->caps.bHAL == 0, (d3dDeviceDesc.dpcTriCaps.dwRasterCaps & D3DPRASTERCAPS_ZBUFFERLESSHSR) != 0))
        return 0;

    PALETTEENTRY palette[256];
    for (int i = 0; i < 256; i++)
        palette[i] = (PALETTEENTRY){ 0xFE, 0xFE, 0xFE, 0x80 };

    if (IDirectDraw4_CreatePalette(std3D_pDirectDraw, DDPCAPS_ALLOW256 | DDPCAPS_INITIALIZE | DDPCAPS_8BIT, palette, &std3D_pDDPalette, 0) != S_OK)
        return 0;

    if (IDirect3D3_CreateDevice(std3D_pDirect3D, &std3D_pCurDevice->duid, stdDisplay_g_backBuffer.pVSurface.pDDSurf, &std3D_pD3Device, 0) != S_OK)
        return 0;

    d3dDeviceDesc.dwSize = sizeof(D3DDEVICEDESC);

    D3DDEVICEDESC desc;
    desc.dwSize = sizeof(D3DDEVICEDESC);

    if (IDirect3DDevice3_GetCaps(std3D_pD3Device, &d3dDeviceDesc, &desc) != S_OK)
        return 0;

    std3D_numTextureFormats = 0;
    std3D_bHasRGBTextureFormat = 0;
    if (IDirect3DDevice3_EnumTextureFormats(std3D_pD3Device, Direct3d_EnumTextureFormats_Callback, 0))
        return 0;

    if (!std3D_numTextureFormats)
        return 0;
    if (!std3D_bHasRGBTextureFormat)
        return 0;

    if (!Direct3d_CreateAndAttachViewport())
        return 0;

    std3D_g_maxVertices = 512;
    if (std3D_pCurDevice->caps.maxVertexCount != 0)
        std3D_g_maxVertices = std3D_pCurDevice->caps.maxVertexCount;

    std3D_frameCount = 1;
    std3D_numCachedTextures = 0;
    std3D_pFirstTexCache = 0;
    std3D_pLastTexCache = 0;

    std3D_RGBTextureFormat = std3D_FindClosestMode(&std3D_cfRGB565);
    std3D_RGBAKeyTextureFormat = std3D_FindClosestMode(&std3D_cfRGB5551);
    std3D_RGBA_TextureFormat = std3D_FindClosestMode(&std3D_cfRGB4444);

    if (!std3D_aTextureFormats[std3D_RGBAKeyTextureFormat].texFormat.alphaBPP && std3D_pCurDevice->caps.bColorkeyTextureSupported)
    {
        std3D_aTextureFormats[std3D_RGBAKeyTextureFormat].bColorKey = 1;
        std3D_aTextureFormats[std3D_RGBAKeyTextureFormat].pColorKey = 0;
    }

    if (!std3D_aTextureFormats[std3D_RGBA_TextureFormat].texFormat.alphaBPP && std3D_pCurDevice->caps.bColorkeyTextureSupported)
    {
        std3D_aTextureFormats[std3D_RGBA_TextureFormat].bColorKey = 1;
        std3D_aTextureFormats[std3D_RGBA_TextureFormat].pColorKey = 0;
    }

    if (!std3D_InitRenderState())
        return 0;

    if (DirectDraw_GetAvailableVidMem(&std3D_pCurDevice->totalMemory, &std3D_pCurDevice->availableMemory))
        return 0;
#endif

    std3D_bOpen = 1;
    return 1;
}

// 0x0048a1c0 HOOK
void std3D_Close(void)
{
    std3D_ClearCacheList();
    if (std3D_pDDPalette)
    {
        std3D_pDDPalette->lpVtbl->Release(std3D_pDDPalette);
        std3D_pDDPalette = 0;
    }
    if (std3D_lpD3DViewPort)
    {
        std3D_lpD3DViewPort->lpVtbl->Release(std3D_lpD3DViewPort);
        std3D_lpD3DViewPort = 0;
    }
    if (std3D_pD3Device)
    {
        std3D_pD3Device->lpVtbl->Release(std3D_pD3Device);
        std3D_pD3Device = 0;
    }
    std3D_numTextureFormats = 0;
    std3D_curDevice = 0;
    std3D_pCurDevice = 0;
    std3D_bHasRGBTextureFormat = 0;
    std3D_bOpen = 0;
}

// 0x0048a2f0 HOOK
int std3D_GetNumTextureFormats(void)
{
    return std3D_numTextureFormats;
}

// 0x0048a300 HOOK
int std3D_StartScene(void)
{
    ++std3D_frameCount;
    std3D_pD3DTex = 0;
#if GLFW_BACKEND
    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);
    glViewport(0, 0, w, h);
#else
    return IDirect3DDevice3_BeginScene(std3D_pD3Device);
#endif
}

// 0x0048a330 HOOK
void std3D_EndScene(void)
{
#if GLFW_BACKEND
    // nothing to do here
#else
    IDirect3DDevice3_EndScene(std3D_pD3Device);
#endif
    std3D_pD3DTex = 0;
}

// 0x0048a350 HOOK
void std3D_DrawRenderList(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags, LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices, int indexCount)
{
    if (verticesCount > std3D_g_maxVertices)
        return;

    std3D_SetRenderState(rdflags);
#if GLFW_BACKEND
    if (pTex != std3D_pD3DTex)
    {
        std3D_pD3DTex = pTex;
        if (pTex)
        {
            // glEnable(GL_TEXTURE_2D);
            glBindTexture(GL_TEXTURE_2D, (GLuint)pTex);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, rdflags & STD3D_RS_TEX_CLAMP_U ? GL_CLAMP_TO_EDGE : GL_REPEAT);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, rdflags & STD3D_RS_TEX_CLAMP_V ? GL_CLAMP_TO_EDGE : GL_REPEAT);
        }
        else
        {
            // glDisable(GL_TEXTURE);
            glBindTexture(GL_TEXTURE_2D, 0);
        }
    }

    for (int i = 0; i < verticesCount; i++)
    {
        D3DTLVERTEX* vertex = &aVerticies[i];
        if (vertex->rhw != 0)
        {
            float w = 1.0 / vertex->rhw;
            vertex->sx *= w;
            vertex->sy *= w;
            vertex->sz *= w;
            vertex->rhw = w;
        }

        // BRGA to RGBA
        uint8_t* color = (uint8_t*)&vertex->color;
        uint8_t tmp = color[0];
        color[0] = color[2];
        color[2] = tmp;
    }

    renderer_drawRenderList(verticesCount, aVerticies, indexCount, lpwIndices);
#else
    if ((pTex != std3D_pD3DTex) && (IDirect3DDevice3_SetTexture(std3D_pD3Device, 0, pTex) == S_OK))
        std3D_pD3DTex = pTex;

    IDirect3DDevice3_DrawIndexedPrimitive(std3D_pD3Device, D3DPT_TRIANGLELIST, D3DFVF_XYZRHW | D3DFVF_DIFFUSE | D3DFVF_SPECULAR | D3DFVF_TEX1, aVerticies, verticesCount, lpwIndices, indexCount, D3DDP_DONOTUPDATEEXTENTS | D3DDP_DONOTLIGHT);
#endif
}

// 0x0048a3c0 HOOK
void std3D_SetWireframeRenderState(void)
{
    uint32_t rs = std3D_renderState;
    rs &= ~STD3D_RS_FOG_ENABLED;
    rs &= ~STD3D_RS_BLEND_MODULATE;
    rs &= ~STD3D_RS_BLEND_MODULATEALPHA;
    std3D_SetRenderState(rs);
    if (IDirect3DDevice3_SetTexture(std3D_pD3Device, 0, 0) == S_OK)
        std3D_pD3DTex = 0;
}

// 0x0048a3f0 HOOK
void std3D_DrawLineStrip(LPD3DTLVERTEX pVertices, unsigned int numVertices)
{
    if (numVertices > std3D_g_maxVertices)
        return;

    IDirect3DDevice3_DrawPrimitive(std3D_pD3Device, D3DPT_LINESTRIP, D3DFVF_XYZRHW | D3DFVF_DIFFUSE | D3DFVF_SPECULAR | D3DFVF_TEX1, pVertices, numVertices, D3DDP_DONOTCLIP);
}

// 0x0048a420 HOOK
void std3D_DrawPointList(LPVOID lpvVertices, unsigned int dwVertexCount)
{
    if (dwVertexCount > std3D_g_maxVertices)
        return;

    IDirect3DDevice3_DrawPrimitive(std3D_pD3Device, D3DPT_LINESTRIP, D3DFVF_XYZRHW | D3DFVF_DIFFUSE | D3DFVF_SPECULAR | D3DFVF_TEX1, lpvVertices, dwVertexCount, D3DDP_DONOTCLIP);
}

// 0x0048a450 HOOK
void std3D_SetRenderState(Std3DRenderState rdflags)
{
#if GLFW_BACKEND
    if (std3D_renderState == rdflags)
        return;

    // blend settings
    if (std3D_renderState ^ (rdflags & (STD3D_RS_BLEND_MODULATE | STD3D_RS_BLEND_MODULATEALPHA)))
    {
        if (rdflags & STD3D_RS_BLEND_MODULATEALPHA)
        {
            glEnable(GL_BLEND);
            // TODO modulate alpha
        }
        else if (rdflags & STD3D_RS_BLEND_MODULATE)
        {
            glEnable(GL_BLEND);
        }
        else
        {
            glDisable(GL_BLEND);
        }
    }

    // z write
    if (std3D_renderState ^ (rdflags & STD3D_RS_ZWRITE_DISABLED))
        glDepthMask((rdflags & STD3D_RS_ZWRITE_DISABLED) == 0);

    // texture wrap mode
    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_CLAMP_U))
    {
        // is set when the texture is bound
    }

    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_CLAMP_V))
    {
        // is set when the texture is bound
    }

    // fog
    if (std3D_renderState ^ (rdflags & STD3D_RS_FOG_ENABLED))
    {
        if (rdflags & STD3D_RS_FOG_ENABLED)
        {
            renderer_setFog(true);
        }
        else
        {
            renderer_setFog(false);
        }
    }

    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_MAGFILTER_LINEAR))
        std3D_SetTexFilterMode();

    std3D_renderState = rdflags;
#else
    if (std3D_renderState == rdflags)
        return;

    // blend settings
    if (std3D_renderState ^ (rdflags & (STD3D_RS_BLEND_MODULATE | STD3D_RS_BLEND_MODULATEALPHA)))
    {
        if (rdflags & STD3D_RS_BLEND_MODULATEALPHA)
        {
            IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ALPHABLENDENABLE, 1);
            IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_TEXTUREMAPBLEND, D3DTBLEND_MODULATEALPHA);
        }
        else if (rdflags & STD3D_RS_BLEND_MODULATE)
        {
            IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ALPHABLENDENABLE, 1);
            IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_TEXTUREMAPBLEND, D3DTBLEND_MODULATE);
        }
        else
        {
            IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ALPHABLENDENABLE, 0);
        }
    }

    // z write
    if (std3D_renderState ^ (rdflags & STD3D_RS_ZWRITE_DISABLED))
        IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ZWRITEENABLE, (rdflags & STD3D_RS_ZWRITE_DISABLED) == 0);

    // texture wrap mode
    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_CLAMP_U))
        IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_ADDRESSU, (rdflags & STD3D_RS_TEX_CLAMP_U) ? D3DTADDRESS_CLAMP : D3DTADDRESS_WRAP);

    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_CLAMP_V))
        IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_ADDRESSV, (rdflags & STD3D_RS_TEX_CLAMP_V) ? D3DTADDRESS_CLAMP : D3DTADDRESS_WRAP);

    // fog
    if (std3D_renderState ^ (rdflags & STD3D_RS_FOG_ENABLED))
        IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_FOGENABLE, (rdflags & STD3D_RS_FOG_ENABLED) != 0 && d3d_FogEnabled);

    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_MAGFILTER_LINEAR))
        std3D_SetTexFilterMode();

    std3D_renderState = rdflags;
#endif
}

// 0x0048a5e0 HOOK
void std3D_AllocSystemTexture(tSystemTexture* pTexture, tVBuffer** apVBuffers, unsigned int numMipLevels, StdColorFormatType formatType)
{
    *pTexture = (tSystemTexture){ 0 };
#if GLFW_BACKEND
    GLuint gl_tex = 0;
    glGenTextures(1, &gl_tex);
    if (gl_tex == 0)
        abort();

    GLenum format = GL_BGRA;
    GLenum type = GL_UNSIGNED_SHORT_4_4_4_4;
    const GLenum internal_format = GL_RGBA8;

    tVBuffer* buff = apVBuffers[0];
    tRasterInfo* info = &buff->rasterInfo;

    if (formatType == STDCOLOR_FORMAT_RGB)
    {
        format = GL_RGB;
        type = GL_UNSIGNED_SHORT_5_6_5;
    }
    else if (formatType == STDCOLOR_FORMAT_RGBA_1BIT_ALPHA)
    {
        format = GL_BGRA;
        type = GL_UNSIGNED_SHORT_1_5_5_5_REV;
    }
    else if (formatType == STDCOLOR_FORMAT_RGBA)
    {
        format = GL_BGRA;
        type = GL_UNSIGNED_SHORT_4_4_4_4_REV;
    }
    else
    {
        abort();
    }

    glBindTexture(GL_TEXTURE_2D, gl_tex);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, internal_format, info->width, info->height, 0, format, type, buff->pPixels);
    glGenerateMipmap(GL_TEXTURE_2D);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY, 8);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
    glBindTexture(GL_TEXTURE_2D, 0);

    pTexture->ddsd.dwWidth = info->width;
    pTexture->ddsd.dwHeight = info->height;
    pTexture->pD3DSrcTexture = (LPDIRECT3DTEXTURE2)gl_tex;
    pTexture->textureSize = (info->width * info->height * 4);
#else
    if (std3D_numTextureFormats == 0)
        return;

    uint32_t valid_width;
    uint32_t valid_height;
    std3D_GetValidDimensions(apVBuffers[0]->rasterInfo.width, apVBuffers[0]->rasterInfo.height, &valid_width, &valid_height);

    if (d3dMipFilter == 0)
        numMipLevels = 1;

    int format_index = formatType == STDCOLOR_FORMAT_RGBA_1BIT_ALPHA ? std3D_RGBAKeyTextureFormat : formatType == STDCOLOR_FORMAT_RGBA ? std3D_RGBA_TextureFormat : std3D_RGBTextureFormat;

    DDSURFACEDESC2 surface_desc = {};
    surface_desc.dwSize = sizeof(DDSURFACEDESC2);
    surface_desc.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PIXELFORMAT;
    surface_desc.ddsCaps.dwCaps = DDSCAPS_SYSTEMMEMORY | DDSCAPS_TEXTURE;
    surface_desc.dwWidth = apVBuffers[0]->rasterInfo.width;
    surface_desc.dwHeight = apVBuffers[0]->rasterInfo.height;
    surface_desc.ddpfPixelFormat = std3D_aTextureFormats[format_index].pixelFormat;
    if (numMipLevels > 1)
    {
        surface_desc.dwFlags |= DDSD_MIPMAPCOUNT;
        surface_desc.ddsCaps.dwCaps |= DDSCAPS_COMPLEX | DDSCAPS_MIPMAP;
        surface_desc.dwMipMapCount = numMipLevels;
    }

    IDirectDrawSurface4* surface = NULL;
    IDirect3DTexture2* texture = NULL;

    if (IDirectDraw4_CreateSurface(std3D_pDirectDraw, &surface_desc, &surface, 0) != S_OK)
        goto error;

    if (IDirectDraw4_QueryInterface(std3D_pDirectDraw, &IID_IDirect3DTexture2, (void**)&texture) != S_OK)
        goto error;

    for (int level = 0; level < numMipLevels; level++)
    {
        DDSURFACEDESC2 surface_desc2 = {};
        surface_desc2.dwSize = sizeof(DDSURFACEDESC2);
        if (IDirectDrawSurface4_Lock(surface, 0, &surface_desc2, 1, 0) != S_OK)
            goto error;

        // copy data
        tVBuffer* buff = apVBuffers[level];
        if (buff->rasterInfo.colorInfo.colorMode == T_STDCOLOR_RGB || buff->rasterInfo.colorInfo.colorMode == T_STDCOLOR_RGBA)
        {
            stdDisplay_VBufferLock(buff);
            for (int y = 0; y < surface_desc2.dwHeight; y++)
                memcpy(surface_desc2.lpSurface + y * surface_desc2.lPitch, buff->pPixels + y * buff->rasterInfo.rowSize, 2 * surface_desc2.dwWidth);

            stdDisplay_VBufferUnlock(buff);
        }

        if (IDirectDrawSurface4_Unlock(surface, 0) != S_OK)
            goto error;

        // retrieve next mip surface:
        if (level < numMipLevels - 1)
        {
            DDSCAPS2 caps = {};
            caps.dwCaps = DDSCAPS_MIPMAP | DDSCAPS_TEXTURE;
            if (IDirectDrawSurface4_GetAttachedSurface(surface, &caps, &surface) != S_OK)
                goto error;
        }
    }

    if (valid_width != surface_desc.dwWidth || valid_height != surface_desc.dwHeight)
        abort();

    if (surface)
        IDirectDrawSurface4_Release(surface);

    pTexture->pD3DSrcTexture = texture;
    pTexture->ddsd = surface_desc;
    pTexture->textureSize = (valid_width * valid_height * apVBuffers[0]->rasterInfo.colorInfo.bpp) / 8;

error:
    if (surface)
        IDirectDrawSurface4_Release(surface);
#endif
}

// 0x0048a9e0 HOOK
void std3D_GetValidDimensions(unsigned int width, unsigned int height, unsigned int* pOutWidth, unsigned int* pOutHeight)
{
    if (width < std3D_pCurDevice->caps.minTexWidth)
        width = std3D_pCurDevice->caps.minTexWidth;

    if (width > std3D_pCurDevice->caps.maxTexWidth)
        width = std3D_pCurDevice->caps.maxTexWidth;

    if (height < std3D_pCurDevice->caps.minTexHeight)
        height = std3D_pCurDevice->caps.minTexHeight;

    if (height > std3D_pCurDevice->caps.maxTexHeight)
        height = std3D_pCurDevice->caps.maxTexHeight;

    if (std3D_pCurDevice->caps.bSqareOnlyTexture)
    {
        if (width > height)
            height = width;

        *pOutWidth = height;
        *pOutHeight = height;
    }
    else
    {
        *pOutWidth = width;
        *pOutHeight = height;
    }
}

// 0x0048aa40 HOOK
void std3D_ClearTexture(tSystemTexture* pTex)
{
#if GLFW_BACKEND
    if (pTex->pD3DSrcTexture)
    {
        GLuint gl_tex = (GLuint)pTex->pD3DSrcTexture;
        glDeleteTextures(1, &gl_tex);
    }

    pTex->pD3DCachedTex = NULL;
#else
    if (pTex->pD3DSrcTexture)
    {
        IDirect3DTexture2_Release(pTex->pD3DSrcTexture);
    }

    if (pTex->pD3DCachedTex)
    {
        std3D_RemoveTextureFromCacheList(pTex);
        IDirect3DTexture2_Release(pTex->pD3DCachedTex);
    }
#endif

    *pTex = (tSystemTexture){ 0 };
}

// 0x0048aa80 HOOK
void std3D_AddToTextureCache(tSystemTexture* pCacheTexture, StdColorFormatType format)
{
#if GLFW_BACKEND
    pCacheTexture->pD3DCachedTex = pCacheTexture->pD3DSrcTexture;
    pCacheTexture->frameNum = std3D_frameCount;
    std3D_AddTextureToCacheList(pCacheTexture);
#else
    IDirectDrawSurface4* surface = NULL;
    IDirect3DTexture2* texture = NULL;

    if (pCacheTexture->pD3DSrcTexture == NULL)
        goto error;

    if (pCacheTexture->textureSize > std3D_pCurDevice->availableMemory)
        std3D_PurgeTextureCache(pCacheTexture->textureSize);

    DDSURFACEDESC2 surface_desc = pCacheTexture->ddsd;
    surface_desc.ddsCaps.dwCaps &= ~DDSCAPS_SYSTEMMEMORY;
    surface_desc.ddsCaps.dwCaps |= DDSCAPS_VIDEOMEMORY;
    surface_desc.ddsCaps.dwCaps |= DDSCAPS_ALLOCONLOAD;

    HRESULT err = IDirectDraw_CreateSurface(std3D_pDirectDraw, &surface_desc, &surface, 0);
    while (err == DDERR_OUTOFVIDEOMEMORY && std3D_PurgeTextureCache(pCacheTexture->textureSize))
        err = IDirectDraw_CreateSurface(std3D_pDirectDraw, &surface_desc, &surface, 0);

    if (err != S_OK)
        goto error;

    if (std3D_aTextureFormats[format].bColorKey)
        IDirectDrawSurface4_SetColorKey(surface, DDCKEY_SRCBLT, std3D_aTextureFormats[format].pColorKey);

    if (IDirectDrawSurface4_QueryInterface(surface, &IID_IDirect3DTexture2, (void**)&texture) != S_OK)
        goto error;

    err = IDirect3DTexture2_Load(texture, pCacheTexture->pD3DSrcTexture);
    while (err == DDERR_OUTOFVIDEOMEMORY && std3D_PurgeTextureCache(pCacheTexture->textureSize))
        err = IDirect3DTexture2_Load(texture, pCacheTexture->pD3DSrcTexture);

    if (err != S_OK)
        goto error;

    pCacheTexture->pD3DCachedTex = texture;
    IDirectDrawSurface4_Release(surface);
    pCacheTexture->frameNum = std3D_frameCount;
    std3D_AddTextureToCacheList(pCacheTexture);
    return;

error:
    if (surface)
        IDirectDrawSurface4_Release(surface);
    if (texture)
        IDirect3DTexture2_Release(texture);
    pCacheTexture->pD3DCachedTex = 0;
    pCacheTexture->frameNum = 0;
#endif
}

// 0x0048ac50 HOOK
void std3D_ClearCacheList(void)
{
#if GLFW_BACKEND
    std3D_pFirstTexCache = 0;
    std3D_pLastTexCache = 0;
    std3D_numCachedTextures = 0;
    if (std3D_pCurDevice)
        std3D_pCurDevice->availableMemory = std3D_pCurDevice->totalMemory;
    std3D_frameCount = 1;
#else
    tSystemTexture* curr = std3D_pFirstTexCache;
    while (curr)
    {
        tSystemTexture* next = curr->pNextCachedTexture;

        if (curr->pD3DCachedTex)
        {
            IDirect3DTexture2_Release(curr->pD3DCachedTex);
            curr->pD3DCachedTex = NULL;
        }
        curr->frameNum = 0;
        curr->pPrevCachedTexture = NULL;
        curr->pNextCachedTexture = NULL;
        curr = next;
    }

    std3D_pFirstTexCache = 0;
    std3D_pLastTexCache = 0;
    std3D_numCachedTextures = 0;
    if (std3D_pCurDevice)
        std3D_pCurDevice->availableMemory = std3D_pCurDevice->totalMemory;
    if (std3D_pD3Device)
        IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_TEXTUREHANDLE, 0);
    std3D_frameCount = 1;
#endif
}

// 0x0048ace0 HOOK
void std3D_UpdateFrameCount(tSystemTexture* pTexture)
{
    pTexture->frameNum = std3D_frameCount;
    std3D_RemoveTextureFromCacheList(pTexture);
    std3D_AddTextureToCacheList(pTexture);
}

// 0x0048AD10 HOOK
int std3D_GetDeviceCaps(int device_index, Device3DCaps* caps)
{
    if (std3D_numDevices == 0 || device_index >= std3D_numDevices)
        return 0;

    *caps = std3D_aDevices[device_index].caps;
    return 1;
}

// 0x0048AD50 HOOK
int std3D_FindMatching3DDevice(const Device3DCaps* caps)
{
    int best_matching_index = 0;
    int best_match = 0;
    for (int i = 0; i < std3D_numDevices; i++)
    {
        const Device3DCaps* device_caps = &std3D_aDevices[i].caps;
        int match = 0;
        if (!caps->bTexturePerspectiveSupported || device_caps->bTexturePerspectiveSupported == caps->bTexturePerspectiveSupported)
        {
            match = 1;
            if (!caps->hasZBuffer || device_caps->hasZBuffer == caps->hasZBuffer)
            {
                match = 2;
                if (device_caps->bHAL == caps->bHAL)
                    return i; // this is the best we can get.
            }
        }
        if (match > best_match)
        {
            best_match = match;
            best_matching_index = i;
        }
    }

    return best_matching_index;
}

// 0x0048add0 HOOK
int std3D_FindClosestMode(const ColorInfo* mode)
{
    int best_matching_index = 0;
    int best_match = 0;
    for (int i = 0; i < std3D_numTextureFormats; i++)
    {
        const ColorInfo* mode1 = &std3D_aTextureFormats[i].texFormat;
        int match = 0;
        if (mode1->colorMode == mode->colorMode)
        {
            match = 1;
            if (mode1->bpp == mode->bpp)
            {
                match = 2;
                if (mode1->colorMode == T_STDCOLOR_RGB)
                {
                    if (mode1->redBPP == mode->redBPP && mode1->greenBPP == mode->greenBPP && mode1->blueBPP == mode->blueBPP)
                        return i;
                }
                else if (mode->colorMode == T_STDCOLOR_RGBA)
                {
                    match = 3;
                    if (mode1->redBPP == mode->redBPP && mode1->greenBPP == mode->greenBPP && mode1->blueBPP == mode->blueBPP && mode1->alphaBPP == mode->alphaBPP)
                        return i;
                }
                else
                {
                    return i;
                }
            }
        }
        if (match > best_match)
        {
            best_match = match;
            best_matching_index = i;
        }
    }

    return best_matching_index;
}

// 0x0048aeb0 HOOK
int std3D_InitRenderState(void)
{
    std3D_renderState = 0;

    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ZENABLE, 1) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ZWRITEENABLE, 1) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ZFUNC, D3DCMP_LESSEQUAL) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_TEXTUREPERSPECTIVE, 1) != S_OK)
        return 0;

    std3D_renderState |= STD3D_RS_UNKNOWN_1;

    if (IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_MAGFILTER, D3DTFG_LINEAR) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_MINFILTER, D3DTFN_LINEAR) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_MIPFILTER, D3DTFP_NONE) != S_OK)
        return 0;

    std3D_renderState |= STD3D_RS_TEX_MAGFILTER_LINEAR;

    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_SUBPIXEL, 1) != S_OK)
        return 0;

    std3D_renderState |= STD3D_RS_UNKNOWN_10;

    if (IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_ADDRESSU, D3DTADDRESS_WRAP) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_ADDRESSV, D3DTADDRESS_WRAP) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ALPHABLENDENABLE, 0) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_TEXTUREMAPBLEND, D3DTBLEND_MODULATE) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_SRCBLEND, D3DBLEND_SRCALPHA) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_DESTBLEND, D3DBLEND_INVSRCALPHA) != S_OK)
        return 0;

    std3D_renderState |= STD3D_RS_BLEND_MODULATE;

    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ALPHATESTENABLE, 1) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ALPHAFUNC, D3DCMP_NOTEQUAL) != S_OK)
        return 0;
    if (std3D_aTextureFormats[std3D_RGBAKeyTextureFormat].bColorKey || std3D_aTextureFormats[std3D_RGBA_TextureFormat].bColorKey)
        if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_COLORKEYENABLE, 1) != S_OK)
            return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_STIPPLEDALPHA, std3D_pCurDevice->caps.bStippledShadeSupported) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DRENDERSTATE_SHADEMODE, D3DSHADE_GOURAUD) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DRENDERSTATE_MONOENABLE, 0) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_SPECULARENABLE, 0) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_FOGENABLE, 0) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_FILLMODE, D3DFILL_SOLID) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_DITHERENABLE, 1) != S_OK)
        return 0;

    std3D_renderState |= STD3D_RS_UNKNOWN_2;

    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_ANTIALIAS, 0) != S_OK)
        return 0;
    if (IDirect3DDevice3_SetRenderState(std3D_pD3Device, D3DRENDERSTATE_CULLMODE, D3DCULL_NONE) != S_OK)
        return 0;

    return 1;
}

// 0x0048b1b0 HOOK
int std3D_SetTexFilterMode(void)
{
#if GLFW_BACKEND
    // texture filter mode is always set to mipmapping with anisotropy.
#else
    HRESULT result = S_OK;
    if ((result = IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_MAGFILTER, std3D_renderState & STD3D_RS_TEX_MAGFILTER_LINEAR ? D3DTFG_LINEAR : D3DTFP_POINT)) != S_OK)
        return result;
    if ((result = IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_MINFILTER, std3D_renderState & STD3D_RS_TEX_MAGFILTER_LINEAR ? D3DTFG_LINEAR : D3DTFP_POINT)) != S_OK)
        return result;

    return IDirect3DDevice3_SetTextureStageState(std3D_pD3Device, 0, D3DTSS_MIPFILTER, d3dMipFilter == 1 ? D3DTFP_POINT : d3dMipFilter == 2 ? D3DTFP_LINEAR : D3DTFP_NONE);
#endif
}

// 0x0048b260 HOOK
int std3D_SetProjection(float fov, float aspectRatio, float nearPlane, float farPlane)
{
    if (fabs(farPlane - nearPlane) < 0.009999999776482582)
        return E_INVALIDARG;

    const float sf = sin(fov * 0.5);
    const float cf = cos(fov * 0.5);

    if (fabs(sf) < 0.009999999776482582)
        return E_INVALIDARG;

    rdMatrix44 proj_mat = {
        { aspectRatio * cf / sf, 0, 0 },
        { 0, cf / sf, 0, 0 },
        { 0, 0, farPlane / (farPlane - nearPlane), 0 },
        { 0, 0, -(farPlane / (farPlane - nearPlane) * nearPlane), 1 },
    };

#if GLFW_BACKEND
    return 0;
#else
    return IDirect3DDevice3_SetTransform(std3D_pD3Device, D3DTRANSFORMSTATE_PROJECTION, (D3DMATRIX*)&proj_mat);
#endif
}

// 0x0048b4b0 HOOK
void std3D_GetZBufferFormat(DDPIXELFORMAT* pPixelFormat)
{
    if (std3D_pDirect3D == NULL || std3D_pCurDevice == NULL || pPixelFormat == NULL)
        return;

    *pPixelFormat = (DDPIXELFORMAT){ 0 };
    pPixelFormat->dwZBufferBitDepth = -1;
    IDirect3D3_EnumZBufferFormats(std3D_pDirect3D, &std3D_pCurDevice->duid, std3D_EnumZBufferFormatsCallback, pPixelFormat);
}

// 0x0048b500 HOOK
HRESULT __stdcall std3D_EnumZBufferFormatsCallback(LPDDPIXELFORMAT lpDDPixFmt, void* lpContext)
{
    if (lpDDPixFmt == NULL || lpContext == NULL)
        return 0;

    DDPIXELFORMAT* curr = lpContext;
    if (lpDDPixFmt->dwFlags == DDPF_ZBUFFER && lpDDPixFmt->dwZBufferBitDepth >= 16 && curr->dwZBufferBitDepth > lpDDPixFmt->dwZBufferBitDepth)
        *curr = *lpDDPixFmt;

    return 1;
}

// 0x0048ba20 HOOK
void std3D_AddTextureToCacheList(tSystemTexture* pTexture)
{
#if GLFW_BACKEND
    ++std3D_numCachedTextures;
    std3D_pCurDevice->availableMemory -= pTexture->textureSize;
#else
    if (std3D_pFirstTexCache)
    {
        std3D_pLastTexCache->pNextCachedTexture = pTexture;
        pTexture->pPrevCachedTexture = std3D_pLastTexCache;
        pTexture->pNextCachedTexture = 0;
        std3D_pLastTexCache = pTexture;
    }
    else
    {
        std3D_pLastTexCache = pTexture;
        std3D_pFirstTexCache = pTexture;
        pTexture->pPrevCachedTexture = 0;
        pTexture->pNextCachedTexture = 0;
    }
    ++std3D_numCachedTextures;
    std3D_pCurDevice->availableMemory -= pTexture->textureSize;
#endif
}

// 0x0048ba90 HOOK
void std3D_RemoveTextureFromCacheList(tSystemTexture* pCacheTexture)
{
#if GLFW_BACKEND
    --std3D_numCachedTextures;
    std3D_pCurDevice->availableMemory += pCacheTexture->textureSize;
    pCacheTexture->pNextCachedTexture = 0;
    pCacheTexture->pPrevCachedTexture = 0;
    pCacheTexture->frameNum = 0;
#else
    if (pCacheTexture == std3D_pFirstTexCache)
    {
        std3D_pFirstTexCache = pCacheTexture->pNextCachedTexture;
        if (std3D_pFirstTexCache)
        {
            std3D_pFirstTexCache->pPrevCachedTexture = 0;
            if (!std3D_pFirstTexCache->pNextCachedTexture)
                std3D_pLastTexCache = std3D_pFirstTexCache;
        }
        else
        {
            std3D_pLastTexCache = 0;
        }
    }
    else
    {
        tSystemTexture* pPrevCachedTexture = pCacheTexture->pPrevCachedTexture;
        if (pCacheTexture == std3D_pLastTexCache)
        {
            std3D_pLastTexCache = pCacheTexture->pPrevCachedTexture;
            pPrevCachedTexture->pNextCachedTexture = 0;
        }
        else
        {
            pPrevCachedTexture->pNextCachedTexture = pCacheTexture->pNextCachedTexture;
            pCacheTexture->pNextCachedTexture->pPrevCachedTexture = pCacheTexture->pPrevCachedTexture;
        }
    }
    --std3D_numCachedTextures;
    std3D_pCurDevice->availableMemory += pCacheTexture->textureSize;
    pCacheTexture->pNextCachedTexture = 0;
    pCacheTexture->pPrevCachedTexture = 0;
    pCacheTexture->frameNum = 0;
#endif
}

// 0x0048bb50 HOOK
int std3D_PurgeTextureCache(unsigned int size)
{
#if GLFW_BACKEND
    return true;
#else
    if (std3D_pFirstTexCache == NULL)
        return false;

    // first try to find an exact match...
    {
        tSystemTexture* curr = std3D_pFirstTexCache;
        while (curr && curr->frameNum != std3D_frameCount)
        {
            if (curr->textureSize == size)
            {
                IDirect3DTexture2_Release(curr->pD3DCachedTex);
                curr->pD3DCachedTex = NULL;
                std3D_RemoveTextureFromCacheList(curr);
                return true;
            }
            curr = curr->pNextCachedTexture;
        }
    }

    // ... or purge as much textures as needed.
    int purged_size = 0;
    {
        tSystemTexture* curr = std3D_pFirstTexCache;
        while (curr && purged_size < size)
        {
            if (curr->frameNum != std3D_frameCount)
            {
                purged_size += curr->textureSize;
                IDirect3DTexture2_Release(curr->pD3DCachedTex);
                curr->pD3DCachedTex = NULL;
                std3D_RemoveTextureFromCacheList(curr);
            }
            curr = curr->pNextCachedTexture;
        }
    }

    return purged_size != 0;
#endif
}

// 0x0048bc10 HOOK
StdDisplayEnvironment* std3D_BuildDisplayEnvironment(void)
{
    StdDisplayEnvironment* env = stdPlatform_hostServices.alloc(sizeof(StdDisplayEnvironment));
    env->numInfos = 0;
    env->aDisplayInfos = NULL;

    if (!stdDisplay_Startup())
        goto error;

    env->numInfos = stdDisplay_GetNumDevices();
    if (env->numInfos != 0)
        env->aDisplayInfos = stdPlatform_hostServices.alloc(sizeof(StdDisplayInfo) * env->numInfos);

    for (int device = 0; device < env->numInfos; device++)
    {
        StdDisplayInfo* info = &env->aDisplayInfos[device];
        *info = (StdDisplayInfo){ 0 };

        if (stdDisplay_GetDevice(device, &info->displayDevice))
            goto error;

        if (!stdDisplay_Open(device))
            goto error;

        info->numModes = stdDisplay_GetNumVideoModes();
        if (info->numModes != 0)
            info->aModes = stdPlatform_hostServices.alloc(sizeof(StdVideoMode) * info->numModes);

        StdVideoMode* mode_ptr = info->aModes;
        for (int mode = 0; mode < info->numModes; mode++)
        {
            // TODO: this seems like a bug. goto error seems more appropriate.
            if (!stdDisplay_CopyVideoMode(mode, mode_ptr))
                mode_ptr++;
        }

        if (info->displayDevice.bGuidNotSet)
        {
            if (!std3D_Startup())
                goto error;

            info->numDevices = std3D_GetNumDevices();
            if (info->numDevices != 0)
            {
                info->aDevices = stdPlatform_hostServices.alloc(sizeof(Device3D) * info->numDevices);
                memcpy(info->aDevices, std3D_GetAllDevices(), sizeof(Device3D) * info->numDevices);
            }

            std3D_Shutdown();
        }
        else
        {
            info->numDevices = 0;
            info->aDevices = NULL;
        }

        stdDisplay_Close();
    }
    return env;

error:
    std3D_FreeDisplayEnvironment(env);
    return NULL;
}

// 0x0048be20 HOOK
void std3D_FreeDisplayEnvironment(StdDisplayEnvironment* pEnv)
{
    if (pEnv->aDisplayInfos)
    {
        for (int i = 0; i < pEnv->numInfos; i++)
        {
            StdDisplayInfo* info = &pEnv->aDisplayInfos[i];
            if (info->aModes)
            {
                stdPlatform_hostServices.free(info->aModes);
                info->aModes = NULL;
            }
            if (info->aDevices)
            {
                stdPlatform_hostServices.free(info->aDevices);
                info->aDevices = NULL;
            }
        }
        stdPlatform_hostServices.free(pEnv->aDisplayInfos);
    }
    stdPlatform_hostServices.free(pEnv);
}
