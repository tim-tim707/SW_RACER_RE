#pragma once

#include "types.h"
#include <glad/glad.h>
#include "gltf_utils.h"

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

void renderer_drawGLTFPod(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                          const rdMatrix44 &engineR_model_matrix,
                          const rdMatrix44 &engineL_model_matrix,
                          const rdMatrix44 &cockpit_model_matrix, gltfModel &model,
                          const EnvInfos &env, bool mirrored, uint8_t type);
void renderer_drawGLTF(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix, gltfModel &model, const EnvInfos &env,
                       bool mirrored, uint8_t type, bool isTrackModel);

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
void debugEnvInfos(EnvInfos &envInfos, const rdMatrix44 &projMat, const rdMatrix44 &viewMat);
