#pragma once

#include "tiny_gltf.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <vector>
#include <map>

enum materialFlags {
    MaterialFlagEmpty = 0,
    HasNormalMap = 1 << 0,
    HasOcclusionMap = 1 << 1,
    HasEmissiveMap = 1 << 2,
    MaterialFlagLast = 1 << 3,
};

struct materialInfos {
    int flags{materialFlags::MaterialFlagEmpty};
    // Have default 1px texture
    GLuint baseColorGLTexture{0};
    GLuint metallicRoughnessGLTexture{0};

    GLuint normalMapGLTexture{0};
    GLuint occlusionMapGLTexture{0};
    GLuint emissiveMapGLTexture{0};
};

enum gltfFlags {
    GltfFlagEmpty = 0,
    IsIndexed = 1 << 0,
    Unlit = 1 << 1,
    HasNormals = 1 << 2,
    HasTexCoords = 1 << 3,// == hasTexture
};

struct meshInfos {
    int gltfFlags{gltfFlags::GltfFlagEmpty};
    GLuint VAO{0};
    GLuint PositionBO{0};
    GLuint NormalBO{0};
    GLuint TexCoordsBO{0};
    GLuint EBO{0};
};

struct pbrShader {
    GLuint handle{0};
    GLint proj_matrix_pos{-1};
    GLint view_matrix_pos{-1};
    GLint model_matrix_pos{-1};
    GLint baseColorFactor_pos{-1};
    GLint metallicFactor_pos{-1};
    GLint roughnessFactor_pos{-1};
    GLint cameraWorldPosition_pos{-1};
    GLint model_id_pos{-1};
};

struct gltfModel {
    std::string filename;
    int setuped;
    tinygltf::Model gltf;
    // material index, materialInfos
    std::map<int, materialInfos> material_infos;
    // mesh index, meshInfos
    std::map<int, meshInfos> mesh_infos;
    // (gltfFlags << materialFlag::Last | materialFlag), pbrShader
    std::map<int, pbrShader> shader_pool;
};

struct iblShader {
    GLuint handle{0};
    GLuint emptyVAO{0};
    GLint roughness_pos{-1};
    GLint sampleCount_pos{-1};
    GLint width_pos{-1};
    GLint distribution_pos{-1};
    GLint currentFace_pos{-1};
    GLint isGeneratingLUT_pos{-1};
    GLint floatTexture_pos{-1};
    GLint intensityScale_pos{-1};
    GLint cubemapTexture_pos{-1};
};

struct skyboxShader {
    GLuint handle{0};
    GLuint GLCubeTexture{0};
    GLuint depthTexture{0};
    GLuint VAO{0};
    GLuint VBO{0};
    GLint view_matrix_pos{-1};
    GLint proj_matrix_pos{-1};
};

struct EnvInfos {
    skyboxShader skybox{};
    GLuint ibl_framebuffer{0};
    GLuint lambertianCubemapID{0};
    GLuint ggxCubemapID{0};
    GLuint ggxLutTextureID{0};
    size_t mipmapLevels{0};
};

extern std::vector<gltfModel> g_models;

// (gltfFlags << materialFlag::Last | materialFlag), pbrShader
extern std::map<int, pbrShader> shader_pool;

extern bool default_material_infos_initialized;
extern tinygltf::Material default_material;
extern materialInfos default_material_infos;

void setTextureParameters(GLint wrapS, GLint wrapT, GLint minFilter, GLint magFilter);

void load_gltf_models();

/**
 * @param outEnvInfos Generate the textures if needed, or reuse them
 * @param frameCount Compute the cubemaps one face per frame according to frameCount, instead of all at once (-1)
 */
void setupIBL(EnvInfos &outEnvInfos, GLuint inputCubemap, int frameCount);
void setupModel(gltfModel &model);
