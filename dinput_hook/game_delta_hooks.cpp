#include "game_delta_hooks.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

extern "C" {
#include <Engine/rdMaterial.h>
}

// rdMaterial.c
static void modify_texture_data(RdMaterial *mat, const char *name,
                                void (*modify_callback)(uint32_t *data, int w, int h)) {
    if (strncmp(mat->aName, name, strlen(name)) == 0)
        return;

    sprintf(mat->aName, name);

    tSystemTexture *tex = mat->aTextures;
    GLuint gl_tex = (GLuint) tex->pD3DSrcTexture;
    if (gl_tex == 0)
        abort();

    glBindTexture(GL_TEXTURE_2D, gl_tex);
    // clear error flag
    glGetError();

    uint32_t *pixel_data = (uint32_t *) malloc(tex->ddsd.dwWidth * tex->ddsd.dwHeight * 4);
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    glGetTexImage(GL_TEXTURE_2D, 0, GL_RGBA, GL_UNSIGNED_BYTE, pixel_data);
    if (glGetError() != GL_NO_ERROR)
        abort();

    modify_callback(pixel_data, tex->ddsd.dwWidth, tex->ddsd.dwHeight);

    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, tex->ddsd.dwWidth, tex->ddsd.dwHeight, 0, GL_RGBA,
                 GL_UNSIGNED_BYTE, pixel_data);
    glGenerateMipmap(GL_TEXTURE_2D);
    if (glGetError() != GL_NO_ERROR)
        abort();

    glBindTexture(GL_TEXTURE_2D, 0);
    free(pixel_data);
}

static void saturate_texture(uint32_t *data, int w, int h) {
    for (int i = 0; i < w * h; i++) {
        uint8_t *pixel = (uint8_t *) &data[i];
        pixel[0] = 255;
        pixel[1] = 255;
        pixel[2] = 255;
    }
}

// 0x004320B0
void rdMaterial_SaturateTextureR4G4B4A4_delta(RdMaterial *mat) {
    modify_texture_data(mat, "saturate", saturate_texture);
}
