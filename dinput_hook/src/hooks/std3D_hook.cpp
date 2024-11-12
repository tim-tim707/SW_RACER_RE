#include "std3D_hook.h"

#include "../utils/renderer_utils.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <globals.h>

extern "C" {
#include <Platform/std3D.h>
}

extern "C" FILE *hook_log;

bool g_useFog;
/**
 * TODO: Set an uniform to do fog computation if enabled
 * Use fog parameters provided by renderer_setLinearFogParameters
 */
void renderer_setFog(bool useFog) {
    g_useFog = useFog;
}

int std3D_Startup_hook(void) {
    // Added
    fprintf(hook_log, "std3D_Startup\n");
    fflush(hook_log);

    memset(std3D_aTextureFormats, 0, sizeof(std3D_aTextureFormats));
    memset(std3D_aDevices, 0, sizeof(std3D_aDevices));

    std3D_numDevices = 1;
    std3D_aDevices[0] = (Device3D){
        .caps =
            {
                .bHAL = true,
                .bTexturePerspectiveSupported = true,
                .hasZBuffer = true,
                .bColorkeyTextureSupported = false,
                .bStippledShadeSupported = false,
                .bAlphaBlendSupported = true,
                .bSqareOnlyTexture = false,
                .minTexWidth = 1,
                .minTexHeight = 1,
                .maxTexWidth = 4096,
                .maxTexHeight = 4096,
                .maxVertexCount = 65536,
            },
        .totalMemory = 1024 * 1024 * 1024,
        .availableMemory = 1024 * 1024 * 1024,
        .duid = {1, 2, 3, 4, 5, 6, 7, 8},
    };

    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LEQUAL);

    renderer_setAlphaMask(true);

    std3D_renderState = 0;
    std3D_SetRenderState(STD3D_RS_BLEND_MODULATE);

    if (std3D_numDevices == 0)
        return 0;

    std3D_bStartup = 1;
    return 1;
}

int std3D_Open_hook(unsigned int deviceNum) {
    if (std3D_bOpen)
        return 0;
    if (deviceNum >= std3D_numDevices)
        return 0;

    std3D_curDevice = deviceNum;
    std3D_pCurDevice = &std3D_aDevices[deviceNum];
    if (!std3D_pCurDevice->caps.hasZBuffer)
        return 0;

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

    std3D_bOpen = 1;
    return 1;
}

int std3D_StartScene_hook(void) {
    ++std3D_frameCount;
    std3D_pD3DTex = 0;
    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);
    glViewport(0, 0, w, h);

    return 0;
}

void std3D_EndScene_hook(void) {
    std3D_pD3DTex = 0;
}

void std3D_DrawRenderList_hook(LPDIRECT3DTEXTURE2 pTex, Std3DRenderState rdflags,
                               LPD3DTLVERTEX aVerticies, int verticesCount, LPWORD lpwIndices,
                               int indexCount) {
    if (verticesCount > std3D_g_maxVertices)
        return;

    std3D_SetRenderState(rdflags);
    if (pTex != std3D_pD3DTex) {
        std3D_pD3DTex = pTex;
        if (pTex) {
            // glEnable(GL_TEXTURE_2D);
            glBindTexture(GL_TEXTURE_2D, (GLuint) pTex);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,
                            rdflags & STD3D_RS_TEX_CLAMP_U ? GL_CLAMP_TO_EDGE : GL_REPEAT);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T,
                            rdflags & STD3D_RS_TEX_CLAMP_V ? GL_CLAMP_TO_EDGE : GL_REPEAT);
        } else {
            // glDisable(GL_TEXTURE);
            glBindTexture(GL_TEXTURE_2D, 0);
        }
    }

    for (int i = 0; i < verticesCount; i++) {
        D3DTLVERTEX *vertex = &aVerticies[i];
        if (vertex->rhw != 0) {
            float w = 1.0 / vertex->rhw;
            vertex->sx *= w;
            vertex->sy *= w;
            vertex->sz *= w;
            vertex->rhw = w;
        }

        // BRGA to RGBA
        uint8_t *color = (uint8_t *) &vertex->color;
        uint8_t tmp = color[0];
        color[0] = color[2];
        color[2] = tmp;
    }

    renderer_drawRenderList(verticesCount, aVerticies, indexCount, lpwIndices);
}

void std3D_SetRenderState_hook(Std3DRenderState rdflags) {
    if (std3D_renderState == rdflags)
        return;

    // blend settings
    if (std3D_renderState ^ (rdflags & (STD3D_RS_BLEND_MODULATE | STD3D_RS_BLEND_MODULATEALPHA))) {
        if (rdflags & STD3D_RS_BLEND_MODULATEALPHA) {
            glEnable(GL_BLEND);
            // TODO modulate alpha
        } else if (rdflags & STD3D_RS_BLEND_MODULATE) {
            glEnable(GL_BLEND);
        } else {
            glDisable(GL_BLEND);
        }
    }

    // z write
    if (std3D_renderState ^ (rdflags & STD3D_RS_ZWRITE_DISABLED))
        glDepthMask((rdflags & STD3D_RS_ZWRITE_DISABLED) == 0);

    // texture wrap mode
    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_CLAMP_U)) {
        // is set when the texture is bound
    }

    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_CLAMP_V)) {
        // is set when the texture is bound
    }

    // fog
    if (std3D_renderState ^ (rdflags & STD3D_RS_FOG_ENABLED)) {
        if (rdflags & STD3D_RS_FOG_ENABLED) {
            renderer_setFog(true);
        } else {
            renderer_setFog(false);
        }
    }

    if (std3D_renderState ^ (rdflags & STD3D_RS_TEX_MAGFILTER_LINEAR))
        std3D_SetTexFilterMode();

    std3D_renderState = rdflags;
}

void std3D_AllocSystemTexture_hook(tSystemTexture *pTexture, tVBuffer **apVBuffers,
                                   unsigned int numMipLevels, StdColorFormatType formatType) {
    *pTexture = (tSystemTexture){0};
    GLuint gl_tex = 0;
    glGenTextures(1, &gl_tex);
    if (gl_tex == 0)
        abort();

    GLenum format = GL_BGRA;
    GLenum type = GL_UNSIGNED_SHORT_4_4_4_4;
    const GLenum internal_format = GL_RGBA8;

    tVBuffer *buff = apVBuffers[0];
    tRasterInfo *info = &buff->rasterInfo;

    if (formatType == STDCOLOR_FORMAT_RGB) {
        format = GL_RGB;
        type = GL_UNSIGNED_SHORT_5_6_5;
    } else if (formatType == STDCOLOR_FORMAT_RGBA_1BIT_ALPHA) {
        format = GL_BGRA;
        type = GL_UNSIGNED_SHORT_1_5_5_5_REV;
    } else if (formatType == STDCOLOR_FORMAT_RGBA) {
        format = GL_BGRA;
        type = GL_UNSIGNED_SHORT_4_4_4_4_REV;
    } else {
        abort();
    }

    glBindTexture(GL_TEXTURE_2D, gl_tex);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, internal_format, info->width, info->height, 0, format, type,
                 buff->pPixels);
    glGenerateMipmap(GL_TEXTURE_2D);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY, 8);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
    glBindTexture(GL_TEXTURE_2D, 0);

    pTexture->ddsd.dwWidth = info->width;
    pTexture->ddsd.dwHeight = info->height;
    pTexture->pD3DSrcTexture = (LPDIRECT3DTEXTURE2) gl_tex;
    pTexture->textureSize = (info->width * info->height * 4);
}

void std3D_ClearTexture_hook(tSystemTexture *pTex) {
    if (pTex->pD3DSrcTexture) {
        GLuint gl_tex = (GLuint) pTex->pD3DSrcTexture;
        glDeleteTextures(1, &gl_tex);
    }

    pTex->pD3DCachedTex = NULL;

    *pTex = (tSystemTexture){0};
}

void std3D_AddToTextureCache_hook(tSystemTexture *pCacheTexture, StdColorFormatType format) {
    pCacheTexture->pD3DCachedTex = pCacheTexture->pD3DSrcTexture;
    pCacheTexture->frameNum = std3D_frameCount;
    std3D_AddTextureToCacheList(pCacheTexture);
}

void std3D_ClearCacheList_hook(void) {
    std3D_pFirstTexCache = 0;
    std3D_pLastTexCache = 0;
    std3D_numCachedTextures = 0;
    if (std3D_pCurDevice)
        std3D_pCurDevice->availableMemory = std3D_pCurDevice->totalMemory;
    std3D_frameCount = 1;
}

int std3D_SetTexFilterMode_hook(void) {
    // texture filter mode is always set to mipmapping with anisotropy.
    return 0;
}

int std3D_SetProjection_hook(float fov, float aspectRatio, float nearPlane, float farPlane) {
    if (fabs(farPlane - nearPlane) < 0.009999999776482582)
        return E_INVALIDARG;

    const float sf = sin(fov * 0.5);
    const float cf = cos(fov * 0.5);

    if (fabs(sf) < 0.009999999776482582)
        return E_INVALIDARG;

    rdMatrix44 proj_mat = {
        {aspectRatio * cf / sf, 0, 0},
        {0, cf / sf, 0, 0},
        {0, 0, farPlane / (farPlane - nearPlane), 0},
        {0, 0, -(farPlane / (farPlane - nearPlane) * nearPlane), 1},
    };

    return 0;
}

void std3D_AddTextureToCacheList_hook(tSystemTexture *pTexture) {
    ++std3D_numCachedTextures;
    std3D_pCurDevice->availableMemory -= pTexture->textureSize;
}

void std3D_RemoveTextureFromCacheList_hook(tSystemTexture *pCacheTexture) {
    --std3D_numCachedTextures;
    std3D_pCurDevice->availableMemory += pCacheTexture->textureSize;
    pCacheTexture->pNextCachedTexture = 0;
    pCacheTexture->pPrevCachedTexture = 0;
    pCacheTexture->frameNum = 0;
}

int std3D_PurgeTextureCache_hook(unsigned int size) {
    return true;
}
