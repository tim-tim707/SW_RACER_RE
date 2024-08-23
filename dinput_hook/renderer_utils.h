#pragma once

#include "types.h"
#include <glad/glad.h>

#include <optional>

#ifdef __cplusplus
extern "C" {
#endif

struct progressBarShader {
    GLuint handle;
    GLuint emptyVAO;
    GLint progress_pos;
};

void renderer_drawProgressBar(int progress);

struct fullScreenTextureShader {
    GLuint handle;
    GLuint emptyVAO;
    GLuint texture;
};

void renderer_drawSmushFrame(const SmushImage *image);

struct renderListShader {
    GLuint handle;
    GLuint VAO;
    GLuint VBO;
    GLuint EBO;
    GLint proj_matrix_pos;
    GLint view_matrix_pos;
    GLint model_matrix_pos;
};

void renderer_drawRenderList(int verticesCount, LPD3DTLVERTEX aVerticies, int indexCount,
                             LPWORD lpwIndices);

#ifdef __cplusplus
}
#endif

std::optional<GLuint> compileProgram(GLsizei vertexCount, const GLchar **vertexShaderSource,
                                     GLsizei fragmentCount, const GLchar **fragmentShaderSource);
