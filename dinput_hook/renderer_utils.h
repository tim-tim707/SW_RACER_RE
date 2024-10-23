#pragma once

#include "types.h"
#include <glad/glad.h>
#include "tinygltf/tiny_gltf.h"
#include "tinygltf/gltf_utils.h"

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

struct replacementShader {
    GLuint handle;
    GLuint VAO;
    GLuint VBO;
    GLuint EBO;
    GLint proj_matrix_pos;
    GLint view_matrix_pos;
    GLint model_matrix_pos;
    GLint model_id_pos;
};

void renderer_drawCube(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix);
void renderer_drawTetrahedron(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                              const rdMatrix44 &model_matrix);

void renderer_drawGLTF(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix, gltfModel &model, envTextures env);

struct skyboxShader {
    GLuint handle{0};
    GLuint GLCubeTexture{0};
    GLuint VAO{0};
    GLuint VBO{0};
    GLint view_matrix_pos{-1};
    GLint proj_matrix_pos{-1};
};

void renderer_drawSkybox(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix);

extern rdVector3 cameraPos;
extern rdVector3 cameraFront;
extern rdVector3 cameraUp;
extern float cameraPitch;
extern float cameraYaw;
extern float cameraSpeed;

void draw_test_scene(void);
