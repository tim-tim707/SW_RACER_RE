#pragma once

#include <fastgltf/core.hpp>
#include <fastgltf/types.hpp>
#include <fastgltf/tools.hpp>

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <array>
#include <vector>
#include <map>
#include <optional>

extern "C" {
#include <Primitives/rdMatrix.h>
}

enum materialFlags {
    MaterialFlagEmpty = 0,
    HasNormalMap = 1 << 0,
    HasOcclusionMap = 1 << 1,
    HasEmissiveMap = 1 << 2,
    IsAlphaBlend = 1 << 3,
    Unlit = 1 << 4,

    MaterialFlagLastBit = 5,
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
    HasNormals = 1 << 0,
    HasTexCoords = 1 << 1, // == hasTexture
    HasTexCoords2 = 1 << 2,// has lightmap in the emissive map slot
    HasVertexColor = 1 << 3,
    HasWeights = 1 << 4,// weights + joints = skinning
    HasJoints = 1 << 5,
};

struct meshInfos {
    int gltfFlags{gltfFlags::GltfFlagEmpty};
    GLuint VAO{0};
    GLuint PositionBO{0};
    GLuint NormalBO{0};
    GLuint TexCoordsBO{0};
    GLuint TexCoords2BO{0};
    GLuint VertexColorBO{0};
    GLuint WeightBO{0};
    GLuint JointBO{0};
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

struct skinInfos {
    // buffer of 2 4x4 matrices per joint
    GLuint jointsMatricesSSBO{0};
};

struct gltfModel {
    std::string filename;
    int setuped;
    fastgltf::Asset gltf;
    // material index, materialInfos
    std::map<int, materialInfos> material_infos;
    // <meshIndex, primitiveIndex>, meshInfos
    std::map<std::tuple<size_t, size_t>, meshInfos> mesh_infos;
    // (gltfFlags << materialFlag::MaterialFlagLastBit | materialFlag), pbrShader
    std::map<int, pbrShader> shader_pool;
    // skinId, skinInfo
    std::map<int, skinInfos> skin_infos;
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

enum TRS_PATH {
    TRANSLATION,
    ROTATION,
    SCALE,
    WEIGHTS,
};

struct TRS {
    std::array<float, 3> translation;
    std::array<float, 4> rotation;// GLTF convention: XYZW
    std::array<float, 3> scale;
};

extern std::vector<gltfModel> g_models_testScene;

// (gltfFlags << materialFlag::MaterialFlagLastBit | materialFlag), pbrShader
extern std::map<int, pbrShader> shader_pool;

extern bool default_material2_initialized;
extern fastgltf::Material default_material2;
extern materialInfos default_material_infos;

void setTextureParameters(GLint wrapS, GLint wrapT, GLint minFilter, GLint magFilter);
const std::byte *getBufferPointer(const fastgltf::Asset &asset, const fastgltf::Accessor &accessor);

void loadGltfModelsForTestScene();
void PushDebugGroup(std::string message);
void PopDebugGroup(void);

/**
 * @param outEnvInfos Generate the textures if needed, or reuse them
 * @param faceIndexd Compute the cubemaps one face per frame according to faceIndex, instead of all at once (-1)
 */
void setupIBL(EnvInfos &outEnvInfos, GLuint inputCubemap, int faceIndex);
void setupModel(gltfModel &model);
void deleteModel(gltfModel &model);
