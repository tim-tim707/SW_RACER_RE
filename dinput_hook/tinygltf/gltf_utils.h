#pragma once

#include "tiny_gltf.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <vector>
#include <map>

struct materialInfos {
    GLuint baseColorGLTexture{0};
    GLuint metallicRoughnessGLTexture{0};
};

enum gltfFlags {
    Empty = 0,
    IsIndexed = 1 << 0,
    Unlit = 1 << 1,
    HasNormals = 1 << 2,
    HasTexCoords = 1 << 3,// == hasTexture
};

struct meshInfos {
    int gltfFlags{gltfFlags::Empty};
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
    // gltfFlags, pbrShader
    std::map<int, pbrShader> shader_pool;
};

extern std::vector<gltfModel> g_models;

extern bool default_material_infos_initialized;
extern materialInfos default_material_infos;

void load_gltf_models();

void gltfModel_to_imgui(gltfModel &model);

void setupModel(gltfModel &model);
