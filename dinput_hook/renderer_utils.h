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
    GLint beam_texture_pos;
    GLuint beam_textures[16];
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

void renderer_lookAtForward(rdMatrix44 *view_mat, rdVector3 *position, rdVector3 *forward,
                            rdVector3 *up);
void renderer_lookAtPosition(rdMatrix44 *view_mat, rdVector3 *position, rdVector3 *position2,
                             rdVector3 *up);
void renderer_inverse4(rdMatrix44 *out, rdMatrix44 *in);

struct replacementShader {
    GLuint handle;
    GLuint VAO;
    GLuint VBO;
    GLuint EBO;
    GLint proj_matrix_pos;
    GLint view_matrix_pos;
    GLint model_matrix_pos;
    GLint model_id_pos;
    GLint color_pos;
};

void renderer_drawCube(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix);
void renderer_drawTetrahedron(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                              const rdMatrix44 &model_matrix, unsigned char color[4]);

void renderer_drawGLTF(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix, gltfModel &model, EnvInfos env);

void renderer_drawSkybox(skyboxShader &skybox, const rdMatrix44 &proj_matrix,
                         const rdMatrix44 &view_matrix);

void setupSkybox(skyboxShader &skybox);

extern rdVector3 debugCameraPos;
extern rdVector3 cameraFront;
extern rdVector3 cameraUp;
extern float cameraPitch;
extern float cameraYaw;
extern float cameraSpeed;

void draw_test_scene();
