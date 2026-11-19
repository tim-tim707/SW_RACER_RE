#include "rdMaterial.h"

#include "globals.h"
#include "engine_config.h"
#include "Platform/std3D.h"
#include "General/stdFnames.h"
#include "Win95/stdDisplay.h"

#include <macros.h>
#include <stdio.h>
#include <string.h>

// 0x0048e680
RdMaterial* rdMaterial_Load(char* pFilename)
{
    RdMaterial* material;

    if (rdMaterial_pMaterialsLoader != NULL)
        return ((RdMaterial * (*)(char*)) rdMaterial_pMaterialsLoader)(pFilename);

    material = (RdMaterial*)(*rdroid_hostServices_ptr->alloc)(sizeof(RdMaterial));
    if (material != NULL && rdMaterial_LoadEntry(pFilename, (swrMaterial*)material) == 0)
        return material;

    rdMaterial_Free(material);
    return NULL;
}

// 0x0048e6d0
int rdMaterial_LoadEntry(char* mat_fpath, swrMaterial* material)
{
    stdFile_t file;
    rdMaterialHeader header;
    rdTexinfoHeader texinfo;
    rdTexinfoExtHeader texinfoExt;
    rdTextureHeader textureHeader;
    tRasterInfo rasterInfo;
    ColorInfo convertFormat;
    int hasColorKey;
    LPDDCOLORKEY colorKey;
    tVBuffer** mipBuffers;
    tVBuffer* buffer;
    unsigned int i;
    int mip;

    memset(material, 0, sizeof(swrMaterial));
    file = (*rdroid_hostServices_ptr->fileOpen)(mat_fpath, "rb");
    if (file == 0)
        return 1;

    if ((*rdroid_hostServices_ptr->fileRead)(file, &header, sizeof(header)) != sizeof(header) || strncmp((char*)header.magic, "MAT ", 4) != 0 || header.revision != RD_MATERIAL_FILE_REVISION || header.num_texinfo != header.num_textures)
        goto error;

    material->nbTextures = header.num_texinfo;
    material->colorInfo = header.tex_format;
    material->unk8c = 0;
    material->unk_mat_flag = std3D_GetTextureFormatClass_Maybe(&material->colorInfo);
    std3D_GetTextureFormatInfo_Maybe(material->unk_mat_flag, &convertFormat, &hasColorKey, &colorKey);

    for (i = 0; i < material->nbTextures; i++) {
        if ((*rdroid_hostServices_ptr->fileRead)(file, &texinfo, sizeof(texinfo)) != sizeof(texinfo))
            goto error;
        if ((texinfo.texture_type & rdTexinfo_TYPE_HAS_EXT_HEADER) != 0 && (*rdroid_hostServices_ptr->fileRead)(file, &texinfoExt, sizeof(texinfoExt)) != sizeof(texinfoExt))
            goto error;
    }

    material->textures_alloc = NULL;
    if (material->nbTextures != 0) {
        material->textures_alloc = (*rdroid_hostServices_ptr->alloc)(material->nbTextures * sizeof(tSystemTexture));
        if (material->textures_alloc == NULL)
            goto error;
        memset(material->textures_alloc, 0, material->nbTextures * sizeof(tSystemTexture));
    }

    for (i = 0; i < material->nbTextures; i++) {
        if ((*rdroid_hostServices_ptr->fileRead)(file, &textureHeader, sizeof(textureHeader)) != sizeof(textureHeader))
            goto error;

        material->height = textureHeader.height;
        rasterInfo.height = textureHeader.height;
        rasterInfo.width = textureHeader.width;
        material->width = textureHeader.width;
        rasterInfo.colorInfo = material->colorInfo;

        mipBuffers = NULL;
        if (textureHeader.num_mipmaps != 0) {
            mipBuffers = (tVBuffer**)(*rdroid_hostServices_ptr->alloc)(textureHeader.num_mipmaps * sizeof(tVBuffer*));
            if (mipBuffers == NULL)
                goto error;
            memset(mipBuffers, 0, textureHeader.num_mipmaps * sizeof(tVBuffer*));
        }

        for (mip = 0; mip < (int)textureHeader.num_mipmaps; mip++) {
            mipBuffers[mip] = stdDisplay_VBufferNew(&rasterInfo, 0, 0);
            if (mipBuffers[mip] == NULL)
                goto error;
            stdDisplay_VBufferLock(mipBuffers[mip]);
            buffer = mipBuffers[mip];
            if ((*rdroid_hostServices_ptr->fileRead)(file, buffer->pPixels, buffer->rasterInfo.size) != buffer->rasterInfo.size)
                goto error;
            stdDisplay_VBufferUnlock(buffer);
            // the unconverted buffer is not freed
            if (mipBuffers[mip]->rasterInfo.colorInfo.colorMode != T_STDCOLOR_PAL && std3D_GetNumTextureFormats() != 0)
                mipBuffers[mip] = stdDisplay_VBufferConvertColorFormat(&convertFormat, mipBuffers[mip], hasColorKey, colorKey);
            rasterInfo.height = (unsigned int)rasterInfo.height >> 1;
            rasterInfo.width = (unsigned int)rasterInfo.width >> 1;
        }

        std3D_AllocSystemTexture(&((tSystemTexture*)material->textures_alloc)[i], mipBuffers, textureHeader.num_mipmaps, material->unk_mat_flag);
        for (mip = 0; mip < (int)textureHeader.num_mipmaps; mip++)
            stdDisplay_VBufferFree(mipBuffers[mip]);
        (*rdroid_hostServices_ptr->free)(mipBuffers);
    }

    if ((header.type & 1) == 0) {
        strncpy(material->filename, stdFnames_Basename(mat_fpath), sizeof(material->filename) - 1);
        material->filename[sizeof(material->filename) - 1] = '\0';
        (*rdroid_hostServices_ptr->fileClose)(file);
        return 0;
    }

error:
    if (file != 0)
        (*rdroid_hostServices_ptr->fileClose)(file);
    return 1;
}

// 0x0048eac0
void rdMaterial_Free(RdMaterial* pMaterial)
{
    if (rdMaterial_pMaterialUnloader != NULL) {
        ((void (*)(RdMaterial*))rdMaterial_pMaterialUnloader)(pMaterial);
        return;
    }
    rdMaterial_FreeEntry(pMaterial);
    (*rdroid_hostServices_ptr->free)(pMaterial);
}

// 0x0048eb00
void rdMaterial_FreeEntry(RdMaterial* pMaterial)
{
    tSystemTexture* pTex = pMaterial->aTextures;

    if (pTex != NULL && pMaterial->curCelNum != 0) {
        unsigned int i = 0;
        do {
            std3D_ClearTexture(pTex);
            i++;
            pTex++;
        } while (i < (unsigned int)pMaterial->curCelNum);
    }
    if (pMaterial->aTextures != NULL) {
        (*rdroid_hostServices_ptr->free)(pMaterial->aTextures);
    }
}

// 0x00431CF0
void rdMaterial_InvertTextureAlphaR4G4B4A4(RdMaterial* mat)
{
    IDirectDrawSurface4* surface = NULL;
    DDSURFACEDESC2 desc;
    uint16_t* pixel;
    int pitch;
    int rows;
    int cols;

    if (strncmp(mat->aName, "invert", 5) == 0)
        return;

    sprintf(mat->aName, "invert");
    IDirect3DTexture2_QueryInterface(mat->aTextures->pD3DSrcTexture, &iDirectDrawSurface4_GUID, (void**)&surface);
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    IDirectDrawSurface4_Lock(surface, NULL, &desc, DDLOCK_WAIT, NULL);

    pixel = (uint16_t*)desc.lpSurface;
    // without DDSD_PITCH the EXE falls back to the surface pointer value as the pitch
    pitch = (desc.dwFlags & DDSD_PITCH) ? desc.lPitch / 2 : (int)surface;
    for (rows = desc.dwHeight; rows > 0; rows--) {
        for (cols = desc.dwWidth; cols > 0; cols--) {
            *pixel = (*pixel & RD_TEXEL_4444_COLOR_MASK) | ~(*pixel & RD_TEXEL_4444_ALPHA_MASK);
            pixel++;
        }
        pixel += pitch - (int)desc.dwWidth;
    }

    IDirectDrawSurface4_Unlock(surface, NULL);
}

// 0x00431DF0
void rdMaterial_InvertTextureColorR4G4B4A4(RdMaterial* mat)
{
    IDirectDrawSurface4* surface = NULL;
    DDSURFACEDESC2 desc;
    uint16_t* pixel;
    int pitch;
    int rows;
    int cols;

    if (strncmp(mat->aName, "invcol", 5) == 0)
        return;

    sprintf(mat->aName, "invcol");
    IDirect3DTexture2_QueryInterface(mat->aTextures->pD3DSrcTexture, &iDirectDrawSurface4_GUID, (void**)&surface);
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    IDirectDrawSurface4_Lock(surface, NULL, &desc, DDLOCK_WAIT, NULL);

    pixel = (uint16_t*)desc.lpSurface;
    // without DDSD_PITCH the EXE falls back to the surface pointer value as the pitch
    pitch = (desc.dwFlags & DDSD_PITCH) ? desc.lPitch / 2 : (int)surface;
    for (rows = desc.dwHeight; rows > 0; rows--) {
        for (cols = desc.dwWidth; cols > 0; cols--) {
            *pixel = (*pixel & RD_TEXEL_4444_ALPHA_MASK) | ~(*pixel & RD_TEXEL_4444_COLOR_MASK);
            pixel++;
        }
        pixel += pitch - (int)desc.dwWidth;
    }

    IDirectDrawSurface4_Unlock(surface, NULL);
}

// 0x00431EF0
void rdMaterial_RemoveTextureAlphaR5G5B5A1(RdMaterial* mat)
{
    IDirectDrawSurface4* surface = NULL;
    DDSURFACEDESC2 desc;
    uint16_t* pixel;
    int pitch;
    int rows;
    int cols;

    if (strncmp(mat->aName, "noalpha", 7) == 0)
        return;

    sprintf(mat->aName, "noalpha");
    IDirect3DTexture2_QueryInterface(mat->aTextures->pD3DSrcTexture, &iDirectDrawSurface4_GUID, (void**)&surface);
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    IDirectDrawSurface4_Lock(surface, NULL, &desc, DDLOCK_WAIT, NULL);

    pixel = (uint16_t*)desc.lpSurface;
    // without DDSD_PITCH the EXE falls back to the surface pointer value as the pitch
    pitch = (desc.dwFlags & DDSD_PITCH) ? desc.lPitch / 2 : (int)surface;
    for (rows = desc.dwHeight; rows > 0; rows--) {
        for (cols = desc.dwWidth; cols > 0; cols--) {
            *pixel |= RD_TEXEL_5551_ALPHA_MASK;
            pixel++;
        }
        pixel += pitch - (int)desc.dwWidth;
    }

    IDirectDrawSurface4_Unlock(surface, NULL);
}

// 0x00431FD0
void rdMaterial_RemoveTextureAlphaR4G4B4A4(RdMaterial* mat)
{
    IDirectDrawSurface4* surface = NULL;
    DDSURFACEDESC2 desc;
    uint16_t* pixel;
    int pitch;
    int rows;
    int cols;

    if (strncmp(mat->aName, "noalpha", 7) == 0)
        return;

    sprintf(mat->aName, "noalpha");
    IDirect3DTexture2_QueryInterface(mat->aTextures->pD3DSrcTexture, &iDirectDrawSurface4_GUID, (void**)&surface);
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    IDirectDrawSurface4_Lock(surface, NULL, &desc, DDLOCK_WAIT, NULL);

    pixel = (uint16_t*)desc.lpSurface;
    // without DDSD_PITCH the EXE falls back to the surface pointer value as the pitch
    pitch = (desc.dwFlags & DDSD_PITCH) ? desc.lPitch / 2 : (int)surface;
    for (rows = desc.dwHeight; rows > 0; rows--) {
        for (cols = desc.dwWidth; cols > 0; cols--) {
            *pixel |= RD_TEXEL_4444_ALPHA_MASK;
            pixel++;
        }
        pixel += pitch - (int)desc.dwWidth;
    }

    IDirectDrawSurface4_Unlock(surface, NULL);
}

// 0x004320B0
void rdMaterial_SaturateTextureR4G4B4A4(RdMaterial* mat)
{
    IDirectDrawSurface4* surface = NULL;
    DDSURFACEDESC2 desc;
    uint16_t* pixel;
    int pitch;
    int rows;
    int cols;

    if (strncmp(mat->aName, "saturate", 8) == 0)
        return;

    sprintf(mat->aName, "saturate");
    IDirect3DTexture2_QueryInterface(mat->aTextures->pD3DSrcTexture, &iDirectDrawSurface4_GUID, (void**)&surface);
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    IDirectDrawSurface4_Lock(surface, NULL, &desc, DDLOCK_WAIT, NULL);

    pixel = (uint16_t*)desc.lpSurface;
    // without DDSD_PITCH the EXE falls back to the surface pointer value as the pitch
    pitch = (desc.dwFlags & DDSD_PITCH) ? desc.lPitch / 2 : (int)surface;
    for (rows = desc.dwHeight; rows > 0; rows--) {
        for (cols = desc.dwWidth; cols > 0; cols--) {
            *pixel |= RD_TEXEL_4444_COLOR_MASK;
            pixel++;
        }
        pixel += pitch - (int)desc.dwWidth;
    }

    IDirectDrawSurface4_Unlock(surface, NULL);
}

// 0x00432190
void rdModel_SetCurrentMaterial(RdMaterial* a1)
{
    rdModel_CurrentMaterialSet = 1;
    rdModel_CurrentMaterial = a1;
}

// 0x00432580
void rdModel3Mesh_ApplyMaterialToAllFaces(rdModel3Mesh* a1)
{
    unsigned int i;

    for (i = 0; i < (unsigned int)a1->numFaces; i++)
        a1->aFaces[i].pMaterial = rdModel_CurrentMaterial;
}
