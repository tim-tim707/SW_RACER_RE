#include "gltf_utils.h"

#define TINYGLTF_IMPLEMENTATION
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define TINYGLTF_NOEXCEPTION// optional. disable exception handling.
#include "tiny_gltf.h"
#undef TINYGLTF_IMPLEMENTATION
#undef STB_IMAGE_IMPLEMENTATION
#undef STB_IMAGE_WRITE_IMPLEMENTATION
#undef TINYGLTF_NOEXCEPTION

#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include <format>

#include "../imgui_utils.h"
#include "../shaders_utils.h"
#include "../meshes.h"

extern "C" FILE *hook_log;

extern ImGuiState imgui_state;

std::vector<gltfModel> g_models;

// (gltfFlags << materialFlag::Last | materialFlag), pbrShader
std::map<int, pbrShader> shader_pool;

bool default_material_initialized = false;
tinygltf::Material default_material;
materialInfos default_material_infos{};

std::optional<struct iblShader> g_iblShader = std::nullopt;

void load_gltf_models() {
    fprintf(hook_log, "[load_gltf_models]\n");
    tinygltf::TinyGLTF loader;

    std::vector<std::string> asset_names = {
        "Box.gltf",
        "BoxTextured.gltf",
        "box_textured_red.gltf",
        "MetalRoughSpheresNoTextures.gltf",
        "MetalRoughSpheresTextured.gltf",
        "sphere.gltf",
        "DamagedHelmet.gltf",
        "AnimatedCube2.gltf",
    };
    std::string asset_dir = "./assets/gltf/";

    for (auto name: asset_names) {
        std::string err;
        std::string warn;
        tinygltf::Model gltf;
        if (!loader.LoadASCIIFromFile(&gltf, &err, &warn, asset_dir + name)) {
            fprintf(hook_log, "Failed to parse %s glTF\n", name.c_str());
        }
        //bool ret = loader.LoadBinaryFromFile(&model, &err, &warn, argv[1]); // for binary glTF(.glb)

        if (!warn.empty()) {
            fprintf(hook_log, "Warn: %s\n", warn.c_str());
        }

        if (!err.empty()) {
            fprintf(hook_log, "Err: %s\n", err.c_str());
        }

        fflush(hook_log);

        g_models.push_back(gltfModel{.filename = name,
                                     .setuped = false,
                                     .gltf = gltf,
                                     .material_infos = {},
                                     .mesh_infos = {}});
        fprintf(hook_log, "Loaded %s\n", name.c_str());
    }
}

unsigned int getComponentCount(int tinygltfType) {
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

unsigned int getComponentByteSize(int componentType) {
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

unsigned int getBufferByteSize(tinygltf::Accessor accessor) {
    return accessor.count * getComponentCount(accessor.type) *
           getComponentByteSize(accessor.componentType);
}

void trsToMatrix(rdMatrix44 *out_mat, const TRS &trs) {
    rdVector3 translation;
    if (trs.translation.has_value()) {
        translation.x = trs.translation.value()[0];
        translation.y = trs.translation.value()[1];
        translation.z = trs.translation.value()[2];
    } else {
        translation.x = 0.0;
        translation.y = 0.0;
        translation.z = 0.0;
    }

    float roll;
    float yaw;
    float pitch;
    rdMatrix44 rot;
    if (trs.rotation.has_value()) {
        quatToEulerAngles(trs.rotation.value().data(), roll, pitch, yaw);
        rdMatrix_BuildRotation44(&rot, yaw, roll, pitch);
    } else {
        rdMatrix_SetIdentity44(&rot);
    }

    rdVector3 scale;
    if (trs.scale.has_value()) {
        scale.x = trs.scale.value()[0];
        scale.y = trs.scale.value()[1];
        scale.z = trs.scale.value()[2];
    } else {
        scale.x = 1.0;
        scale.y = 1.0;
        scale.z = 1.0;
    }

    rdMatrix_FromTransRotScale(out_mat, &translation, &rot, &scale);
    out_mat->vD.w = 1.0;// missing value
}

/**
 * Texture MUST be bound beforehand
 */
void setTextureParameters(GLint wrapS, GLint wrapT, GLint minFilter, GLint magFilter) {
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
    glBufferData(bufferView.target, getBufferByteSize(accessor), buffer, GL_STATIC_DRAW);

    glVertexAttribPointer(location, getComponentCount(accessor.type), accessor.componentType,
                          GL_FALSE, bufferView.byteStride, 0);
}

static std::optional<GLuint> setupTexture(tinygltf::Model &model, int textureId) {
    tinygltf::Texture texture = model.textures[textureId];
    if (texture.source == -1) {
        fprintf(hook_log, "Source not provided for texture %d\n", textureId);
        fflush(hook_log);
        return std::nullopt;
    }
    tinygltf::Image image = model.images[texture.source];

    GLuint textureObject;
    glGenTextures(1, &textureObject);

    glBindTexture(GL_TEXTURE_2D, textureObject);
    GLint internalFormat = GL_RGBA;
    glTexImage2D(GL_TEXTURE_2D, 0, internalFormat, image.width, image.height, 0, internalFormat,
                 image.pixel_type, image.image.data());
    glGenerateMipmap(GL_TEXTURE_2D);

    if (texture.sampler == -1) {// Default sampler
        setTextureParameters(GL_REPEAT, GL_REPEAT, GL_NEAREST, GL_NEAREST);
    } else {
        tinygltf::Sampler &sampler = model.samplers[texture.sampler];

        // Implementation defined default filters
        if (sampler.minFilter == -1) {
            sampler.minFilter = GL_LINEAR;
        }
        if (sampler.magFilter == -1) {
            sampler.magFilter = GL_LINEAR;
        }

        setTextureParameters(sampler.wrapS, sampler.wrapT, sampler.minFilter, sampler.magFilter);
    }

    return textureObject;
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
const size_t ibl_lambertianSampleCount_static = 2048;
const size_t ibl_ggxSampleCount_static = 1024;
const size_t ibl_lambertianSampleCount_dynamic = 16;
const size_t ibl_ggxSampleCount_dynamic = 16;
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
        .cubemapTexture_pos = glGetUniformLocation(program, "cubemapTexture"),
    };
    return shader;
}


void applyFilter(GLuint framebuffer, GLuint inputCubemap, int distribution, float roughness,
                 unsigned int targetMipLevel, GLuint targetCubemap, unsigned int sampleCount,
                 int frameCount) {
    size_t currentTextureSize = ibl_textureSize >> targetMipLevel;

    iblShader shader = g_iblShader.value();
    GLuint ibl_filtering_program = shader.handle;
    glUseProgram(ibl_filtering_program);

    glUniform1f(shader.roughness_pos, roughness);
    glUniform1i(shader.sampleCount_pos, sampleCount);
    glUniform1i(shader.width_pos, ibl_textureSize);
    glUniform1i(shader.distribution_pos, distribution);
    glUniform1i(shader.isGeneratingLUT_pos, 0);
    glUniform1i(shader.floatTexture_pos, 1);
    glUniform1f(shader.intensityScale_pos, 1.0);// TODO: scaleValue on HDR

    glViewport(0, 0, currentTextureSize, currentTextureSize);
    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
    glActiveTexture(GL_TEXTURE0);

    glBindVertexArray(shader.emptyVAO);

    if (frameCount == -1) {
        for (size_t i = 0; i < 6; i++) {
            glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                                   GL_TEXTURE_CUBE_MAP_POSITIVE_X + i, targetCubemap,
                                   targetMipLevel);
            // For debug
            // glClearColor(1.0, 0.0, 0.0, 0.0);
            // glBindTexture(GL_TEXTURE_CUBE_MAP, targetCubemap);
            // glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

            glBindTexture(GL_TEXTURE_CUBE_MAP, inputCubemap);
            glUniform1i(shader.cubemapTexture_pos, 0);

            glUniform1i(shader.currentFace_pos, i);

            glDrawArrays(GL_TRIANGLES, 0, 3);
        }
    } else {
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                               GL_TEXTURE_CUBE_MAP_POSITIVE_X + frameCount, targetCubemap,
                               targetMipLevel);

        glBindTexture(GL_TEXTURE_CUBE_MAP, inputCubemap);
        glUniform1i(shader.cubemapTexture_pos, 0);

        glUniform1i(shader.currentFace_pos, frameCount);

        glDrawArrays(GL_TRIANGLES, 0, 3);
    }

    glBindVertexArray(0);
    glUseProgram(0);
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void sampleLut(GLuint framebuffer, GLuint input_cubemap, int distribution, GLuint targetTexture,
               size_t currentTextureSize) {
    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, targetTexture, 0);

    glBindTexture(GL_TEXTURE_2D, targetTexture);
    glViewport(0, 0, currentTextureSize, currentTextureSize);
    // glClearColor(1.0, 0.0, 0.0, 0.0);
    // glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    iblShader shader = g_iblShader.value();
    glUseProgram(shader.handle);

    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_CUBE_MAP, input_cubemap);
    glUniform1i(shader.cubemapTexture_pos, 0);

    glUniform1f(shader.roughness_pos, 0.0);
    glUniform1i(shader.sampleCount_pos, 512);
    glUniform1i(shader.width_pos, 0.0);
    glUniform1i(shader.distribution_pos, distribution);
    glUniform1i(shader.currentFace_pos, 0);
    glUniform1i(shader.isGeneratingLUT_pos, 1);

    glBindVertexArray(shader.emptyVAO);
    glDrawArrays(GL_TRIANGLES, 0, 3);
    glBindVertexArray(0);

    glUseProgram(0);
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void setupIBL(EnvInfos &outEnvInfos, GLuint inputCubemap, int frameCount) {
    // TODO: check for OES_float_texture here
    // Not an actual frame count: should be called only once per frame !

    if (outEnvInfos.ibl_framebuffer == 0) {
        glGenFramebuffers(1, &outEnvInfos.ibl_framebuffer);
        outEnvInfos.mipmapLevels = floor(log2(ibl_textureSize)) + 1 - ibl_lowestMipLevel;
    }
    // cubemapTextureID = createIBLCubemapTexture(true);
    // GLuint sheenCubemapID;

    // Read and create HDR texture and convert it to cubemap. We already have a cubemap as input in this case

    if (!g_iblShader.has_value()) {
        g_iblShader = createIBLShader();
    }

    {// cubeMapToLambertian
        if (outEnvInfos.lambertianCubemapID == 0) {
            outEnvInfos.lambertianCubemapID = createIBLCubemapTexture(false);
        }
        applyFilter(outEnvInfos.ibl_framebuffer, inputCubemap, IBLDistribution::Lambertian, 0.0, 0,
                    outEnvInfos.lambertianCubemapID,
                    frameCount == -1 ? ibl_lambertianSampleCount_static
                                     : ibl_lambertianSampleCount_dynamic,
                    frameCount);
    }

    {// cubeMapToGGX
        if (outEnvInfos.ggxCubemapID == 0) {
            outEnvInfos.ggxCubemapID = createIBLCubemapTexture(true);
        }
        for (size_t currentMipLevel = 0; currentMipLevel <= outEnvInfos.mipmapLevels;
             currentMipLevel++) {
            float roughness = currentMipLevel / (outEnvInfos.mipmapLevels - 1);
            applyFilter(outEnvInfos.ibl_framebuffer, inputCubemap, IBLDistribution::GGX, roughness,
                        currentMipLevel, outEnvInfos.ggxCubemapID,
                        frameCount == -1 ? ibl_ggxSampleCount_static : ibl_ggxSampleCount_dynamic,
                        frameCount);
        }
    }
    // cubeMapToSheen
    // applyFilter(...)

    {// sampleGGXLut
        if (outEnvInfos.ggxLutTextureID == 0) {
            outEnvInfos.ggxLutTextureID = createIBLLutTexture();
            sampleLut(outEnvInfos.ibl_framebuffer, inputCubemap, IBLDistribution::GGX,
                      outEnvInfos.ggxLutTextureID, ibl_lutResolution);
        }
    }

    // Restore old Viewport
    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);
    glViewport(0, 0, w, h);
}

pbrShader compile_pbr(int gltfFlags, int materialFlags) {
    pbrShader shader;
    // Model flags
    bool hasNormals = gltfFlags & gltfFlags::HasNormals;
    bool hasTexCoords = gltfFlags & gltfFlags::HasTexCoords;
    bool unlit = gltfFlags & gltfFlags::Unlit;

    // Material flags
    bool hasNormalMap = materialFlags & materialFlags::HasNormalMap;
    bool hasOcclusionMap = materialFlags & materialFlags::HasOcclusionMap;
    bool hasEmissiveMap = materialFlags & materialFlags::HasEmissiveMap;

    fprintf(hook_log, "Compiling pbrShader %s%s%s%s%s%s...", hasNormals ? "NORMALS," : "",
            hasTexCoords ? "TEXCOORDS," : "", unlit ? "UNLIT," : "",
            hasNormalMap ? "NORMAL_MAP," : "", hasOcclusionMap ? "OCCLUSION_MAP," : "",
            hasEmissiveMap ? "EMISSIVE_MAP," : "");
    fflush(hook_log);

    const std::string defines = std::format(
        "{}{}{}{}{}{}", hasNormals ? "#define HAS_NORMALS\n" : "",
        hasTexCoords ? "#define HAS_TEXCOORDS\n" : "", unlit ? "#define MATERIAL_UNLIT\n" : "",
        hasNormalMap ? "#define HAS_NORMAL_MAP\n" : "",
        hasOcclusionMap ? "#define HAS_OCCLUSION_MAP\n" : "",
        hasEmissiveMap ? "#define HAS_EMISSIVE_MAP\n" : "");

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
        .cameraWorldPosition_pos = glGetUniformLocation(program, "cameraWorldPosition"),
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

void setupDefaultMaterial(void) {
    if (!default_material_initialized) {
        unsigned char data[] = {255, 255, 255, 255};
        createTexture(default_material_infos.baseColorGLTexture, 1, 1, GL_UNSIGNED_BYTE, data,
                      GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE, GL_NEAREST, GL_NEAREST, false);
        createTexture(default_material_infos.metallicRoughnessGLTexture, 1, 1, GL_UNSIGNED_BYTE,
                      data, GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE, GL_NEAREST, GL_NEAREST, false);

        default_material = tinygltf::Material{};
        default_material.name = std::string("Default Material");
        // Set color to 1.0, 0.0, 1.0, 1.0
        default_material.pbrMetallicRoughness.baseColorFactor[1] = 0.0;
        default_material.pbrMetallicRoughness.metallicFactor = 3.0;

        default_material_initialized = true;
    }
}

void setupModel(gltfModel &model) {
    fprintf(hook_log, "Setuping model %s...\n", model.filename.c_str());
    fflush(hook_log);

    model.setuped = true;

    // flags for some models
    const char *unlit_models[] = {
        "Box.gltf", "BoxTextured.gltf", "box_textured_red.gltf",
        // "part_control01_part.gltf"
        //   "MetalRoughSpheresTextured.gltf"
    };
    int additionnalFlags = gltfFlags::GltfFlagEmpty;
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
            setupDefaultMaterial();
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
        if ((mesh_infos.gltfFlags & gltfFlags::HasNormals) == 0) {
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

        if (indicesAccessor.componentType != GL_UNSIGNED_BYTE &&
            indicesAccessor.componentType != GL_UNSIGNED_SHORT &&
            indicesAccessor.componentType != GL_UNSIGNED_INT) {
            fprintf(hook_log, "Unsupported type for indices buffer of mesh %zu in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }

        tinygltf::Material material{};
        materialInfos material_infos{};

        if (materialIndex == -1) {
            material = default_material;
            material_infos = default_material_infos;
        } else {
            material = model.gltf.materials[materialIndex];

            {// Get material Flags
                if (material.normalTexture.index != -1) {
                    material_infos.flags |= materialFlags::HasNormalMap;
                }
                if (material.occlusionTexture.index != -1) {
                    material_infos.flags |= materialFlags::HasOcclusionMap;
                }
                if (material.emissiveTexture.index != -1) {
                    material_infos.flags |= materialFlags::HasEmissiveMap;
                }
            }
        }

        // compile shader with options
        // https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#appendix-b-brdf-implementation
        int flag = (mesh_infos.gltfFlags << materialFlags::MaterialFlagLast) | material_infos.flags;
        if (!shader_pool.contains(flag)) {
            shader_pool[flag] = compile_pbr(mesh_infos.gltfFlags, material_infos.flags);
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
        model.mesh_infos[meshId] = mesh_infos;

        // Setup VAO
        pbrShader shader = shader_pool[flag];
        glUseProgram(shader.handle);

        glBindVertexArray(mesh_infos.VAO);

        // Position is mandatory attribute
        setupAttribute(mesh_infos.PositionBO, model.gltf, positionAccessorId, 0);
        glEnableVertexArrayAttrib(mesh_infos.VAO, 0);

        if (mesh_infos.gltfFlags & gltfFlags::HasNormals) {
            setupAttribute(mesh_infos.NormalBO, model.gltf, normalAccessorId, 1);
            glEnableVertexArrayAttrib(mesh_infos.VAO, 1);
        }

        bool material_initialized = model.material_infos.contains(materialIndex);
        if (mesh_infos.gltfFlags & gltfFlags::HasTexCoords) {
            setupAttribute(mesh_infos.TexCoordsBO, model.gltf, texcoordAccessorId, 2);
            glEnableVertexArrayAttrib(mesh_infos.VAO, 2);

            int baseColorTextureId = material.pbrMetallicRoughness.baseColorTexture.index;
            if (baseColorTextureId == -1) {
                setupDefaultMaterial();

                material_infos.baseColorGLTexture = default_material_infos.baseColorGLTexture;
            } else if (!material_initialized) {
                if (std::optional<GLuint> texture = setupTexture(model.gltf, baseColorTextureId)) {
                    material_infos.baseColorGLTexture = texture.value();
                } else {
                    fprintf(hook_log, "No source image for baseColorTexture\n");
                    fflush(hook_log);
                    std::abort();
                }
            }

            int metallicRoughnessTextureId =
                material.pbrMetallicRoughness.metallicRoughnessTexture.index;
            if (metallicRoughnessTextureId == -1) {
                setupDefaultMaterial();

                material_infos.metallicRoughnessGLTexture =
                    default_material_infos.metallicRoughnessGLTexture;
            } else if (!material_initialized) {
                if (std::optional<GLuint> texture =
                        setupTexture(model.gltf, metallicRoughnessTextureId)) {
                    material_infos.metallicRoughnessGLTexture = texture.value();
                } else {
                    fprintf(hook_log, "No source image for metallicRoughnessTexture\n");
                    fflush(hook_log);
                    std::abort();
                }
            }

            if (material_infos.flags & materialFlags::HasNormalMap && !material_initialized) {
                if (std::optional<GLuint> texture =
                        setupTexture(model.gltf, material.normalTexture.index)) {
                    material_infos.normalMapGLTexture = texture.value();
                } else {
                    fprintf(hook_log, "No source image for normal Map texture\n");
                    fflush(hook_log);
                    std::abort();
                }
            }
            if (material_infos.flags & materialFlags::HasOcclusionMap && !material_initialized) {
                if (std::optional<GLuint> texture =
                        setupTexture(model.gltf, material.occlusionTexture.index)) {
                    material_infos.occlusionMapGLTexture = texture.value();
                } else {
                    fprintf(hook_log, "No source image for occlusion Map texture\n");
                    fflush(hook_log);
                    std::abort();
                }
            }
            if (material_infos.flags & materialFlags::HasEmissiveMap && !material_initialized) {
                if (std::optional<GLuint> texture =
                        setupTexture(model.gltf, material.emissiveTexture.index)) {
                    material_infos.emissiveMapGLTexture = texture.value();
                } else {
                    fprintf(hook_log, "No source image for emissive Map texture\n");
                    fflush(hook_log);
                    std::abort();
                }
            }
        }

        if (!material_initialized) {
            model.material_infos[materialIndex] = material_infos;
        }

        // is indexed geometry
        const tinygltf::BufferView &indicesBufferView =
            model.gltf.bufferViews[indicesAccessor.bufferView];

        void *indexBuffer = model.gltf.buffers[indicesBufferView.buffer].data.data() +
                            indicesAccessor.byteOffset + indicesBufferView.byteOffset;
        glBindBuffer(indicesBufferView.target, mesh_infos.EBO);
        glBufferData(indicesBufferView.target, getBufferByteSize(indicesAccessor), indexBuffer,
                     GL_STATIC_DRAW);

        glBindVertexArray(0);
    }
    fprintf(hook_log, "Model %s setup Done\n", model.filename.c_str());
    fflush(hook_log);
}

void deleteModel(gltfModel &model) {
    // Clean buffers
    for (auto const &[key_mesh, mesh_infos]: model.mesh_infos) {
        GLuint buffers[] = {
            mesh_infos.PositionBO,
            mesh_infos.NormalBO,
            mesh_infos.TexCoordsBO,
            mesh_infos.EBO,
        };
        glDeleteBuffers(std::size(buffers), buffers);
        glDeleteVertexArrays(1, &mesh_infos.VAO);
    }

    // Clean textures
    for (auto &[key_mat, matInfos]: model.material_infos) {
        if (matInfos.baseColorGLTexture != -1 &&
            matInfos.baseColorGLTexture != default_material_infos.baseColorGLTexture) {
            glDeleteTextures(1, &matInfos.baseColorGLTexture);
        }
        if (matInfos.metallicRoughnessGLTexture != -1 &&
            matInfos.metallicRoughnessGLTexture !=
                default_material_infos.metallicRoughnessGLTexture) {
            glDeleteTextures(1, &matInfos.metallicRoughnessGLTexture);
        }
        if (matInfos.emissiveMapGLTexture != -1) {
            glDeleteTextures(1, &matInfos.emissiveMapGLTexture);
        }
        if (matInfos.normalMapGLTexture != -1) {
            glDeleteTextures(1, &matInfos.normalMapGLTexture);
        }
        if (matInfos.occlusionMapGLTexture != -1) {
            glDeleteTextures(1, &matInfos.occlusionMapGLTexture);
        }
    }
}
