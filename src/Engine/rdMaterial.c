#include "rdMaterial.h"

#include <macros.h>

#if GLFW_BACKEND
#include <glad/glad.h>
#endif

// 0x0048e680
RdMaterial* rdMaterial_Load(char* pFilename)
{
    HANG("TODO");
}

// 0x0048e6d0
int rdMaterial_LoadEntry(char* mat_fpath, swrMaterial* material)
{
    HANG("TODO");
    return 0;
}

// 0x0048eac0
void rdMaterial_Free(RdMaterial* pMaterial)
{
    HANG("TODO");
}

// 0x0048eb00
void rdMaterial_FreeEntry(RdMaterial* pMaterial)
{
    HANG("TODO");
}

#if GLFW_BACKEND
static void modify_texture_data(RdMaterial* mat, const char* name, void(* modify_callback)(uint32_t* data, int w, int h))
{
    if (strncmp(mat->aName, name, strlen(name)) == 0)
        return;

    sprintf(mat->aName, name);

    tSystemTexture* tex = mat->aTextures;
    GLuint gl_tex = (GLuint)tex->pD3DSrcTexture;
    if (gl_tex == 0)
        abort();

    glBindTexture(GL_TEXTURE_2D, gl_tex);
    // clear error flag
    glGetError();

    uint32_t* pixel_data = malloc(tex->ddsd.dwWidth * tex->ddsd.dwHeight * 4);
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    glGetTexImage(GL_TEXTURE_2D, 0, GL_RGBA, GL_UNSIGNED_BYTE, pixel_data);
    if (glGetError() != GL_NO_ERROR)
        abort();

    modify_callback(pixel_data, tex->ddsd.dwWidth, tex->ddsd.dwHeight);

    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, tex->ddsd.dwWidth, tex->ddsd.dwHeight, 0, GL_RGBA, GL_UNSIGNED_BYTE, pixel_data);
    glGenerateMipmap(GL_TEXTURE_2D);
    if (glGetError() != GL_NO_ERROR)
        abort();

    glBindTexture(GL_TEXTURE_2D, 0);
    free(pixel_data);
}

static void invert_texture_alpha(uint32_t* data, int w, int h)
{
    for (int i = 0; i < w * h; i++)
    {
        uint8_t* pixel = (uint8_t*)&data[i];
        pixel[3] = ~pixel[3];
    }
}

static void invert_texture_color(uint32_t* data, int w, int h)
{
    for (int i = 0; i < w * h; i++)
    {
        uint8_t* pixel = (uint8_t*)&data[i];
        pixel[0] = ~pixel[0];
        pixel[1] = ~pixel[1];
        pixel[2] = ~pixel[2];
    }
}

static void remove_texture_alpha(uint32_t* data, int w, int h)
{
    for (int i = 0; i < w * h; i++)
    {
        uint8_t* pixel = (uint8_t*)&data[i];
        pixel[3] = 255;
    }
}

static void saturate_texture(uint32_t* data, int w, int h)
{
    for (int i = 0; i < w * h; i++)
    {
        uint8_t* pixel = (uint8_t*)&data[i];
        pixel[0] = 255;
        pixel[1] = 255;
        pixel[2] = 255;
    }
}
#endif

// 0x00431CF0 HOOK
void rdMaterial_InvertTextureAlphaR4G4B4A4(RdMaterial* mat)
{
#if GLFW_BACKEND
    modify_texture_data(mat, "invert", invert_texture_alpha);
#else
    HANG("TODO");
#endif
}

// 0x00431DF0 HOOK
void rdMaterial_InvertTextureColorR4G4B4A4(RdMaterial* mat)
{
#if GLFW_BACKEND
    modify_texture_data(mat, "invcol", invert_texture_color);
#else
    HANG("TODO");
#endif
}

// 0x00431EF0 HOOK
void rdMaterial_RemoveTextureAlphaR5G5B5A1(RdMaterial* mat)
{
#if GLFW_BACKEND
    modify_texture_data(mat, "noalpha", remove_texture_alpha);
#else
    HANG("TODO");
#endif
}

// 0x00431FD0 HOOK
void rdMaterial_RemoveTextureAlphaR4G4B4A4(RdMaterial* mat)
{
#if GLFW_BACKEND
    modify_texture_data(mat, "noalpha", remove_texture_alpha);
#else
    HANG("TODO");
#endif
}

// 0x004320B0 HOOK
void rdMaterial_SaturateTextureR4G4B4A4(RdMaterial* mat)
{
#if GLFW_BACKEND
    modify_texture_data(mat, "saturate", saturate_texture);
#else
    HANG("TODO");
#endif
}

// 0x00432190
void rdModel_SetCurrentMaterial(RdMaterial* a1)
{
    HANG("TODO");
}

// 0x00432580
void rdModel3Mesh_ApplyMaterialToAllFaces(rdModel3Mesh* a1)
{
    HANG("TODO");
}
