#include "gltf_utils.h"

// Define these only in *one* .cc file.
#define TINYGLTF_IMPLEMENTATION
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define TINYGLTF_NOEXCEPTION// optional. disable exception handling.
#include "tiny_gltf.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include <format>

#include "../imgui_utils.h"
#include "../shaders_utils.h"
#include "../meshes.h"

extern "C" FILE *hook_log;

extern ImGuiState imgui_state;

std::vector<gltfModel> g_models;

bool default_material_infos_initialized = false;
materialInfos default_material_infos{};

std::optional<struct iblShader> g_iblShader = std::nullopt;

void load_gltf_models() {
    fprintf(hook_log, "[load_gltf_models]\n");
    tinygltf::TinyGLTF loader;

    std::vector<std::string> asset_names = {"Box.gltf", "BoxTextured.gltf", "box_textured_red.gltf",
                                            "MetalRoughSpheresNoTextures.gltf",
                                            "MetalRoughSpheresTextured.gltf"};
    std::string asset_dir = "./assets/gltf/";

    for (auto name: asset_names) {
        std::string err;
        std::string warn;
        tinygltf::Model model;
        bool ret = loader.LoadASCIIFromFile(&model, &err, &warn, asset_dir + name);
        //bool ret = loader.LoadBinaryFromFile(&model, &err, &warn, argv[1]); // for binary glTF(.glb)

        if (!warn.empty()) {
            fprintf(hook_log, "Warn: %s\n", warn.c_str());
        }

        if (!err.empty()) {
            fprintf(hook_log, "Err: %s\n", err.c_str());
        }

        if (!ret) {
            fprintf(hook_log, "Failed to parse %s glTF\n", name.c_str());
        }
        fflush(hook_log);

        g_models.push_back(gltfModel{.filename = name,
                                     .setuped = false,
                                     .gltf = model,
                                     .material_infos = {},
                                     .mesh_infos = {},
                                     .shader_pool = {}});
        fprintf(hook_log, "Loaded %s\n", name.c_str());
    }
}

static unsigned int getComponentCount(int tinygltfType) {
    switch (tinygltfType) {
        case TINYGLTF_TYPE_SCALAR:
            return 1;
        case TINYGLTF_TYPE_VEC2:
            return 2;
        case TINYGLTF_TYPE_VEC3:
            return 3;
        case TINYGLTF_TYPE_VEC4:
            return 4;
        case TINYGLTF_TYPE_MAT2:
            return 4;
        case TINYGLTF_TYPE_MAT3:
            return 9;
        case TINYGLTF_TYPE_MAT4:
            return 16;
    }

    fprintf(hook_log, "Unrecognized tinygltfType %d", tinygltfType);
    fflush(hook_log);
    assert(false);
}

static unsigned int getComponentByteSize(int componentType) {
    switch (componentType) {
        case TINYGLTF_COMPONENT_TYPE_BYTE:         //GL_BYTE
        case TINYGLTF_COMPONENT_TYPE_UNSIGNED_BYTE:// GL_UNSIGNED_BYTE
            return 1;
        case TINYGLTF_COMPONENT_TYPE_SHORT:         // GL_SHORT
        case TINYGLTF_COMPONENT_TYPE_UNSIGNED_SHORT:// GL_UNSIGNED_SHORT
            return 2;
            // No GL equivalent ?
            // TINYGLTF_COMPONENT_TYPE_INT
        case TINYGLTF_COMPONENT_TYPE_UNSIGNED_INT:// GL_UNSIGNED_INT
        case TINYGLTF_COMPONENT_TYPE_FLOAT:       // GL_FLOAT
            return 4;
    }

    fprintf(hook_log, "Unrecognized glType %d", componentType);
    fflush(hook_log);
    assert(false);
}

/**
 * Texture MUST be bound beforehand
 */
static void setTextureParameters(GLint wrapS, GLint wrapT, GLint minFilter, GLint magFilter) {
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, wrapS);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, wrapT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, minFilter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, magFilter);
}

static void setupAttribute(unsigned int bufferObject, tinygltf::Model &model, int accessorId,
                           unsigned int location) {
    const tinygltf::Accessor &accessor = model.accessors[accessorId];
    const tinygltf::BufferView &bufferView = model.bufferViews[accessor.bufferView];
    auto buffer = reinterpret_cast<const float *>(model.buffers[bufferView.buffer].data.data() +
                                                  accessor.byteOffset + bufferView.byteOffset);

    glBindBuffer(bufferView.target, bufferObject);
    glBufferData(bufferView.target,
                 accessor.count * getComponentCount(accessor.type) *
                     getComponentByteSize(accessor.componentType),
                 buffer, GL_STATIC_DRAW);

    glVertexAttribPointer(location, getComponentCount(accessor.type), accessor.componentType,
                          GL_FALSE, bufferView.byteStride, 0);
}

static void setupTexture(GLuint textureObject, tinygltf::Model &model, int textureId) {
    tinygltf::Texture texture = model.textures[textureId];
    if (texture.source == -1) {
        fprintf(hook_log, "Source not provided for texture %d\n", textureId);
        fflush(hook_log);
        return;
    }
    tinygltf::Image image = model.images[texture.source];

    glBindTexture(GL_TEXTURE_2D, textureObject);
    GLint internalFormat = GL_RGBA;
    glTexImage2D(GL_TEXTURE_2D, 0, internalFormat, image.width, image.height, 0, internalFormat,
                 image.pixel_type, image.image.data());
    glGenerateMipmap(GL_TEXTURE_2D);

    if (texture.sampler == -1) {// Default sampler
        // Might be ugly but we'll see
        setTextureParameters(GL_REPEAT, GL_REPEAT, GL_NEAREST, GL_NEAREST);
    } else {
        tinygltf::Sampler sampler = model.samplers[texture.sampler];

        setTextureParameters(sampler.wrapS, sampler.wrapT, sampler.minFilter, sampler.magFilter);
    }
}

static void createTexture(GLuint &textureObjectOut, int width, int height, int pixelType,
                          void *pixelData, GLint wrapS, GLint wrapT, GLint minFilter,
                          GLint magFilter, bool generateMipMaps) {

    glGenTextures(1, &textureObjectOut);

    glBindTexture(GL_TEXTURE_2D, textureObjectOut);
    GLint internalFormat = GL_RGBA;
    glTexImage2D(GL_TEXTURE_2D, 0, internalFormat, width, height, 0, internalFormat, pixelType,
                 pixelData);
    if (generateMipMaps)
        glGenerateMipmap(GL_TEXTURE_2D);

    setTextureParameters(wrapS, wrapT, minFilter, magFilter);
}

// IBL Parameters
const size_t ibl_textureSize = 256;
const size_t ibl_lambertianSampleCount = 2048;
const size_t ibl_ggxSampleCount = 1024;
const size_t ibl_lowestMipLevel = 4;
const size_t ibl_lutResolution = 1024;
// TODO: Should switch based on OES_texture_float_linear, EXT_color_buffer_half_float, default byte
const GLint ibl_internalFormat = GL_RGBA32F;
const GLint ibl_format = GL_RGBA;
const GLint ibl_targetType = GL_FLOAT;
size_t ibl_mipmapLevels;
// GLuint cubemapTextureID;

static GLuint createIBLCubemapTexture(bool generateMipMaps) {
    GLuint targetCubemap;
    glGenTextures(1, &targetCubemap);
    glBindTexture(GL_TEXTURE_CUBE_MAP, targetCubemap);

    for (size_t i = 0; i < 6; i++) {
        glTexImage2D(GL_TEXTURE_CUBE_MAP_POSITIVE_X + i, 0, ibl_internalFormat, ibl_textureSize,
                     ibl_textureSize, 0, ibl_format, ibl_targetType, NULL);
    }

    if (generateMipMaps) {
        glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
        glGenerateMipmap(GL_TEXTURE_CUBE_MAP);
    } else {
        glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    }
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    return targetCubemap;
}

GLuint createIBLLutTexture(void) {
    GLuint targetTexture;
    glGenTextures(1, &targetTexture);
    glBindTexture(GL_TEXTURE_2D, targetTexture);

    glTexImage2D(GL_TEXTURE_2D, 0, ibl_internalFormat, ibl_lutResolution, ibl_lutResolution, 0,
                 ibl_format, ibl_targetType, NULL);
    setTextureParameters(GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE, GL_LINEAR, GL_LINEAR);

    return targetTexture;
}

enum IBLDistribution {
    Lambertian = 0,
    GGX = 1,
    Charlie = 2,
};

iblShader createIBLShader() {
    iblShader shader;

    std::string vertex_shader_source_s = readFileAsString("./assets/shaders/fullscreen_ibl.vert");
    std::string fragment_shader_source_s = readFileAsString("./assets/shaders/ibl_filtering.frag");
    const char *vertex_shader_source = vertex_shader_source_s.c_str();
    const char *fragment_shader_source = fragment_shader_source_s.c_str();

    std::optional<GLuint> program_opt =
        compileProgram(1, &vertex_shader_source, 1, &fragment_shader_source);
    if (!program_opt.has_value())
        std::abort();
    GLuint program = program_opt.value();

    GLuint VAO;
    glGenVertexArrays(1, &VAO);

    shader = {
        .handle = program,
        .emptyVAO = VAO,
        .roughness_pos = glGetUniformLocation(program, "roughness"),
        .sampleCount_pos = glGetUniformLocation(program, "sampleCount"),
        .width_pos = glGetUniformLocation(program, "width"),
        .distribution_pos = glGetUniformLocation(program, "distribution"),
        .currentFace_pos = glGetUniformLocation(program, "currentFace"),
        .isGeneratingLUT_pos = glGetUniformLocation(program, "isGeneratingLUT"),
        .floatTexture_pos = glGetUniformLocation(program, "floatTexture"),
        .intensityScale_pos = glGetUniformLocation(program, "intensityScale"),
    };
    return shader;
}


void applyFilter(GLuint framebuffer, GLuint inputCubemap, int distribution, float roughness,
                 unsigned int targetMipLevel, GLuint targetCubemap, unsigned int sampleCount) {
    size_t currentTextureSize = ibl_textureSize >> targetMipLevel;

    for (size_t i = 0; i < 6; i++) {
        glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                               GL_TEXTURE_CUBE_MAP_POSITIVE_X + i, targetCubemap, targetMipLevel);
        glBindTexture(GL_TEXTURE_CUBE_MAP, targetCubemap);
        glViewport(0, 0, currentTextureSize, currentTextureSize);
        glClearColor(1.0, 0.0, 0.0, 0.0);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

        iblShader shader = g_iblShader.value();
        GLuint ibl_filtering_program = shader.handle;
        glUseProgram(ibl_filtering_program);

        glActiveTexture(GL_TEXTURE0);
        // glBindTexture(GL_TEXTURE_CUBE_MAP, cubemapTextureID);
        glBindTexture(GL_TEXTURE_CUBE_MAP, inputCubemap);
        glUniform1i(glGetUniformLocation(shader.handle, "cubemapTexture"), 0);

        glUniform1f(shader.roughness_pos, roughness);
        glUniform1i(shader.sampleCount_pos, sampleCount);
        glUniform1i(shader.width_pos, ibl_textureSize);
        glUniform1i(shader.distribution_pos, distribution);
        glUniform1i(shader.currentFace_pos, i);
        glUniform1i(shader.isGeneratingLUT_pos, 0);
        glUniform1i(shader.floatTexture_pos, 1);
        glUniform1f(shader.intensityScale_pos, 1.0);// TODO: scaleValue on HDR

        glBindVertexArray(shader.emptyVAO);
        glDrawArrays(GL_TRIANGLES, 0, 3);
        glBindVertexArray(0);
    }

    glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void sampleLut(GLuint framebuffer, GLuint input_cubemap, int distribution, GLuint targetTexture,
               size_t currentTextureSize) {
    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, targetTexture, 0);

    glBindTexture(GL_TEXTURE_2D, targetTexture);
    glViewport(0, 0, currentTextureSize, currentTextureSize);
    glClearColor(1.0, 0.0, 0.0, 0.0);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    iblShader shader = g_iblShader.value();
    glUseProgram(shader.handle);

    glActiveTexture(GL_TEXTURE0);
    // glBindTexture(GL_TEXTURE_CUBE_MAP, cubemapTextureID);
    glBindTexture(GL_TEXTURE_CUBE_MAP, input_cubemap);
    glUniform1i(glGetUniformLocation(shader.handle, "cubemapTexture"), 0);

    glUniform1f(shader.roughness_pos, 0.0);
    glUniform1i(shader.sampleCount_pos, 512);
    glUniform1i(shader.width_pos, 0.0);
    glUniform1i(shader.distribution_pos, distribution);
    glUniform1i(shader.currentFace_pos, 0);
    glUniform1i(shader.isGeneratingLUT_pos, 1);

    glBindVertexArray(shader.emptyVAO);
    glDrawArrays(GL_TRIANGLES, 0, 3);
    glBindVertexArray(0);

    glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

envInfos setupIBL(GLuint inputCubemap) {
    // TODO: check for OES_float_texture here

    GLuint ibl_framebuffer;
    glGenFramebuffers(1, &ibl_framebuffer);
    // cubemapTextureID = createIBLCubemapTexture(true);
    GLuint lambertianCubemapID = createIBLCubemapTexture(false);
    GLuint ggxCubemapID = createIBLCubemapTexture(true);
    // GLuint sheenCubemapID;

    ibl_mipmapLevels = floor(log2(ibl_textureSize)) + 1 - ibl_lowestMipLevel;

    // Read and create HDR texture and convert it to cubemap. We already have a cubemap as input in this case

    if (!g_iblShader.has_value()) {
        g_iblShader = createIBLShader();
    }

    {// cubeMapToLambertian
        applyFilter(ibl_framebuffer, inputCubemap, IBLDistribution::Lambertian, 0.0, 0,
                    lambertianCubemapID, ibl_lambertianSampleCount);
    }
    {// cubeMapToGGX
        for (size_t currentMipLevel = 0; currentMipLevel <= ibl_mipmapLevels; currentMipLevel++) {
            float roughness = currentMipLevel / (ibl_mipmapLevels - 1);
            applyFilter(ibl_framebuffer, inputCubemap, IBLDistribution::GGX, roughness,
                        currentMipLevel, ggxCubemapID, ibl_ggxSampleCount);
        }
    }
    // cubeMapToSheen
    // applyFilter(...)

    GLuint ggxLutTextureID;
    {// sampleGGXLut
        ggxLutTextureID = createIBLLutTexture();
        sampleLut(ibl_framebuffer, inputCubemap, IBLDistribution::GGX, ggxLutTextureID,
                  ibl_lutResolution);
    }

    glDeleteFramebuffers(1, &ibl_framebuffer);
    envInfos res = {
        .lambertianCubemapID = lambertianCubemapID,
        .ggxCubemapID = ggxCubemapID,
        .ggxLutTextureID = ggxLutTextureID,
        .mipmapLevels = ibl_mipmapLevels,
    };

    return res;
}

pbrShader compile_pbr(ImGuiState &state, int gltfFlags) {
    pbrShader shader;
    bool hasNormals = gltfFlags & gltfFlags::HasNormals;
    bool hasTexCoords = gltfFlags & gltfFlags::HasTexCoords;
    bool unlit = gltfFlags & gltfFlags::Unlit;
    fprintf(hook_log, "Compiling shader %s%s%s...", hasNormals ? "NORMALS," : "",
            hasTexCoords ? "TEXCOORDS," : "", unlit ? "UNLIT" : "");
    fflush(hook_log);

    (void) state;

    const std::string defines = std::format("{}{}{}", hasNormals ? "#define HAS_NORMALS\n" : "",
                                            hasTexCoords ? "#define HAS_TEXCOORDS\n" : "",
                                            unlit ? "#define MATERIAL_UNLIT\n" : "");

    std::string vertex_shader_source_s = readFileAsString("./assets/shaders/pbrShader.vert");
    std::string fragment_shader_source_s = readFileAsString("./assets/shaders/pbrShader.frag");
    const char *vertex_shader_source = vertex_shader_source_s.c_str();
    const char *fragment_shader_source = fragment_shader_source_s.c_str();

    const char *vertex_sources[]{"#version 420\n", defines.c_str(), vertex_shader_source};
    const char *fragment_sources[]{"#version 420\n", defines.c_str(), fragment_shader_source};

    std::optional<GLuint> program_opt = compileProgram(
        std::size(vertex_sources), vertex_sources, std::size(fragment_sources), fragment_sources);
    if (!program_opt.has_value())
        std::abort();
    GLuint program = program_opt.value();

    shader = {
        .handle = program,
        .proj_matrix_pos = glGetUniformLocation(program, "projMatrix"),
        .view_matrix_pos = glGetUniformLocation(program, "viewMatrix"),
        .model_matrix_pos = glGetUniformLocation(program, "modelMatrix"),
        .baseColorFactor_pos = glGetUniformLocation(program, "baseColorFactor"),
        .metallicFactor_pos = glGetUniformLocation(program, "metallicFactor"),
        .roughnessFactor_pos = glGetUniformLocation(program, "roughnessFactor"),
        .model_id_pos = glGetUniformLocation(program, "model_id"),
        /**
         * lambertianEnvSampler
         * GGXEnvSampler
         * GGXLUT
         * GGXEnvSampler_mipcount
         */
    };

    fprintf(hook_log, "Done\n");
    fflush(hook_log);

    return shader;
}

void setupModel(gltfModel &model) {
    fprintf(hook_log, "Setuping model %s...\n", model.filename.c_str());
    fflush(hook_log);

    model.setuped = true;

    // flags for some models
    const char *unlit_models[] = {
        "Box.gltf", "BoxTextured.gltf", "box_textured_red.gltf",
        //   "MetalRoughSpheresTextured.gltf"
    };
    int additionnalFlags = gltfFlags::Empty;
    for (size_t i = 0; i < std::size(unlit_models); i++) {
        if (strcmp(unlit_models[i], model.filename.c_str()) == 0)
            additionnalFlags |= gltfFlags::Unlit;
    }

    for (size_t meshId = 0; meshId < model.gltf.meshes.size(); meshId++) {
        meshInfos mesh_infos{};
        mesh_infos.gltfFlags |= additionnalFlags;

        if (model.gltf.meshes[meshId].primitives.size() > 1) {
            fprintf(hook_log, "Multiples primitives for mesh %zu not yet supported in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }

        int primitiveId = 0;
        tinygltf::Primitive primitive = model.gltf.meshes[meshId].primitives[primitiveId];
        int indicesAccessorId = primitive.indices;
        if (indicesAccessorId == -1) {
            fprintf(hook_log, "Un-indexed topology not yet supported for mesh %zu in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }
        mesh_infos.gltfFlags |= gltfFlags::IsIndexed;

        GLint drawMode = primitive.mode;
        if (drawMode == -1) {
            fprintf(hook_log, "Unsupported draw mode %d in renderer\n", drawMode);
            fflush(hook_log);
            continue;
        }
        int materialIndex = primitive.material;
        if (materialIndex == -1) {
            fprintf(hook_log, "Material-less model not yet supported in renderer\n");
            fflush(hook_log);
            continue;
        }

        int positionAccessorId = -1;
        int normalAccessorId = -1;
        int texcoordAccessorId = -1;
        for (const auto &[key, value]: primitive.attributes) {
            if (key == "POSITION")
                positionAccessorId = value;
            if (key == "NORMAL") {
                mesh_infos.gltfFlags |= gltfFlags::HasNormals;
                normalAccessorId = value;
            }
            if (key == "TEXCOORD_0") {
                mesh_infos.gltfFlags |= gltfFlags::HasTexCoords;
                texcoordAccessorId = value;
            }
        }

        if (positionAccessorId == -1) {
            fprintf(hook_log, "Unsupported mesh %zu without position attribute in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }
        if (mesh_infos.gltfFlags & gltfFlags::HasNormals == 0) {
            fprintf(hook_log, "Unsupported mesh %zu without normal attribute in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }

        if (model.gltf.accessors[indicesAccessorId].type != TINYGLTF_TYPE_SCALAR) {
            fprintf(hook_log,
                    "Error: indices accessor does not have type scalar in renderer for mesh %zu\n",
                    meshId);
            fflush(hook_log);
            continue;
        }
        const tinygltf::Accessor &indicesAccessor = model.gltf.accessors[indicesAccessorId];

        if (indicesAccessor.componentType != GL_UNSIGNED_SHORT)// 0x1403
        {
            fprintf(hook_log, "Unsupported type for indices buffer of mesh %zu in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }

        // compile shader with options
        // https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#appendix-b-brdf-implementation
        if (!model.shader_pool.contains(mesh_infos.gltfFlags)) {
            model.shader_pool[mesh_infos.gltfFlags] =
                compile_pbr(imgui_state, mesh_infos.gltfFlags);
        }

        // create GL objects
        GLuint VAO;
        glGenVertexArrays(1, &VAO);
        GLuint VBOs[3];
        glGenBuffers(std::size(VBOs), VBOs);

        GLuint EBO;
        glGenBuffers(1, &EBO);

        mesh_infos.VAO = VAO;
        mesh_infos.PositionBO = VBOs[0];
        mesh_infos.NormalBO = VBOs[1];
        mesh_infos.TexCoordsBO = VBOs[2];
        mesh_infos.EBO = EBO;

        if (materialIndex != -1 && !model.material_infos.contains(materialIndex)) {

            unsigned int glTextures[2];
            glGenTextures(std::size(glTextures), glTextures);

            materialInfos material_infos{.baseColorGLTexture = glTextures[0],
                                         .metallicRoughnessGLTexture = glTextures[1]};
            model.material_infos[materialIndex] = material_infos;
        }
        model.mesh_infos[meshId] = mesh_infos;

        // Setup VAO
        pbrShader shader = model.shader_pool[mesh_infos.gltfFlags];
        glUseProgram(shader.handle);

        glBindVertexArray(mesh_infos.VAO);

        // Position is mandatory attribute
        setupAttribute(mesh_infos.PositionBO, model.gltf, positionAccessorId, 0);
        glEnableVertexArrayAttrib(mesh_infos.VAO, 0);

        if (mesh_infos.gltfFlags & gltfFlags::HasNormals) {
            setupAttribute(mesh_infos.NormalBO, model.gltf, normalAccessorId, 1);
            glEnableVertexArrayAttrib(mesh_infos.VAO, 1);
        }

        if (mesh_infos.gltfFlags & gltfFlags::HasTexCoords) {
            setupAttribute(mesh_infos.TexCoordsBO, model.gltf, texcoordAccessorId, 2);
            glEnableVertexArrayAttrib(mesh_infos.VAO, 2);

            if (!default_material_infos_initialized) {
                unsigned char data[] = {255, 255, 255, 255};
                createTexture(default_material_infos.baseColorGLTexture, 1, 1, GL_UNSIGNED_BYTE,
                              data, GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE, GL_NEAREST, GL_NEAREST,
                              false);
                createTexture(default_material_infos.metallicRoughnessGLTexture, 1, 1,
                              GL_UNSIGNED_BYTE, data, GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE,
                              GL_NEAREST, GL_NEAREST, false);

                default_material_infos_initialized = true;
            }

            materialInfos material_infos = model.material_infos[materialIndex];
            tinygltf::Material material = model.gltf.materials[materialIndex];
            int baseColorTextureId = material.pbrMetallicRoughness.baseColorTexture.index;
            if (baseColorTextureId == -1) {
                material_infos.baseColorGLTexture = default_material_infos.baseColorGLTexture;
            } else {
                setupTexture(material_infos.baseColorGLTexture, model.gltf, baseColorTextureId);
            }

            int metallicRoughnessTextureId =
                material.pbrMetallicRoughness.metallicRoughnessTexture.index;
            if (metallicRoughnessTextureId == -1) {
                material_infos.metallicRoughnessGLTexture =
                    default_material_infos.metallicRoughnessGLTexture;
            } else {
                setupTexture(material_infos.metallicRoughnessGLTexture, model.gltf,
                             metallicRoughnessTextureId);
            }
        }

        // is indexed geometry
        const tinygltf::BufferView &indicesBufferView =
            model.gltf.bufferViews[indicesAccessor.bufferView];
        auto indexBuffer = reinterpret_cast<const unsigned short *>(
            model.gltf.buffers[indicesBufferView.buffer].data.data() + indicesAccessor.byteOffset +
            indicesBufferView.byteOffset);

        glBindBuffer(indicesBufferView.target, mesh_infos.EBO);
        glBufferData(indicesBufferView.target,
                     indicesAccessor.count * getComponentCount(indicesAccessor.type) *
                         getComponentByteSize(indicesAccessor.componentType),
                     indexBuffer, GL_STATIC_DRAW);

        glBindVertexArray(0);
    }
    fprintf(hook_log, "Model %s setup Done\n", model.filename.c_str());
    fflush(hook_log);
}
