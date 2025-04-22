#include "gltf_utils.h"

#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include <format>

#include <fastgltf/types.hpp>

#include "shaders_utils.h"

extern "C" FILE *hook_log;

std::vector<gltfModel> g_models_testScene;

// (gltfFlags << materialFlag::MaterialFlagLastBit | materialFlag), pbrShader
std::map<int, pbrShader> shader_pool;

bool default_material2_initialized = false;
fastgltf::Material default_material2;
materialInfos default_material_infos{};

std::optional<struct iblShader> g_iblShader = std::nullopt;

static bool gltf_models_loaded = false;
void loadGltfModelsForTestScene() {
    if (gltf_models_loaded) {
        return;
    }
    gltf_models_loaded = true;

    fprintf(hook_log, "[loadGltfModelsForTestScene]\n");

    std::vector<std::string> asset_names = {
        "RiggedSimple.gltf",
    };
    std::string asset_dir = "./assets/gltf/";

    for (auto name: asset_names) {
        std::string path = asset_dir + name;
        constexpr auto supportedExtensions = fastgltf::Extensions::KHR_materials_unlit;
        fastgltf::Parser parser(supportedExtensions);

        constexpr auto gltfOptions =
            fastgltf::Options::DontRequireValidAssetMember |
            fastgltf::Options::LoadExternalBuffers | fastgltf::Options::LoadExternalImages |
            fastgltf::Options::GenerateMeshIndices | fastgltf::Options::DecomposeNodeMatrices;

        auto gltfFile = fastgltf::MappedGltfFile::FromPath(path);
        if (!bool(gltfFile)) {
            fprintf(hook_log, "Failed to open glTF file: %s\n",
                    std::string(fastgltf::getErrorMessage(gltfFile.error())).c_str());
        }

        auto asset =
            parser.loadGltf(gltfFile.get(), std::filesystem::path(path).parent_path(), gltfOptions);
        if (asset.error() != fastgltf::Error::None) {
            fprintf(hook_log, "Failed to load glTF file: %s\n",
                    std::string(fastgltf::getErrorMessage(asset.error())).c_str());
        }

        g_models_testScene.push_back(gltfModel{.filename = name,
                                               .setuped = false,
                                               .gltf = std::move(asset.get()),
                                               .material_infos = {},
                                               .mesh_infos = {}});
        fprintf(hook_log, "Loaded %s\n", name.c_str());
    }
}

void PushDebugGroup(std::string message) {
#if !defined(NDEBUG)
    glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, message.length(), message.c_str());
#endif
}

void PopDebugGroup(void) {
#if !defined(NDEBUG)
    glPopDebugGroup();
#endif
}

unsigned int getBufferByteSize2(const fastgltf::Accessor &accessor) {
    return accessor.count * fastgltf::getElementByteSize(accessor.type, accessor.componentType);
}

const std::byte *getBufferPointer(const fastgltf::Asset &asset,
                                  const fastgltf::Accessor &accessor) {
    const fastgltf::BufferView &bufferView = asset.bufferViews[accessor.bufferViewIndex.value()];
    const std::byte *ptr = nullptr;

    std::visit(fastgltf::visitor{
                   [](auto &) {
                       assert(
                           false &&
                           "Tried accessing a buffer with no data, likely because no buffers were "
                           "loaded. Perhaps you forgot to specify the LoadExternalBuffers option?");
                   },
                   [](const fastgltf::sources::Fallback &fallback) {
                       assert(false && "Tried accessing data of a fallback buffer.");
                   },
                   [&](const fastgltf::sources::Array &array) { ptr = array.bytes.data(); },
                   [&](const fastgltf::sources::Vector &vec) { ptr = vec.bytes.data(); },
                   [&](const fastgltf::sources::ByteView &bv) { ptr = bv.bytes.data(); },
               },
               asset.buffers[bufferView.bufferIndex].data);

    return ptr;
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

static void setupAttribute(unsigned int bufferObject, fastgltf::Asset &asset, int accessorId,
                           unsigned int location) {
    const fastgltf::Accessor &accessor = asset.accessors[accessorId];
    // Assumes its never sparse morph targets since there is no bufferViewIndex in this case
    const fastgltf::BufferView &bufferView = asset.bufferViews[accessor.bufferViewIndex.value()];
    const std::byte *bufferPtr = getBufferPointer(asset, accessor);
    auto buffer =
        reinterpret_cast<const float *>(bufferPtr + accessor.byteOffset + bufferView.byteOffset);

    glBindBuffer(static_cast<GLenum>(bufferView.target.value()), bufferObject);
    glBufferData(static_cast<GLenum>(bufferView.target.value()), getBufferByteSize2(accessor),
                 buffer, GL_STATIC_DRAW);

    glVertexAttribPointer(location, fastgltf::getNumComponents(accessor.type),
                          fastgltf::getGLComponentType(accessor.componentType),
                          accessor.normalized ? GL_TRUE : GL_FALSE,
                          bufferView.byteStride.value_or(0), 0);
}

static GLint getLevelCount(int width, int height) {
    return 1 + floor(log2(width > height ? width : height));
};

static std::optional<GLuint> setupTexture(fastgltf::Asset &asset, int textureId) {
    fastgltf::Texture texture = asset.textures[textureId];
    if (!texture.imageIndex.has_value()) {
        fprintf(hook_log, "Source not provided for texture %d\n", textureId);
        fflush(hook_log);
        return std::nullopt;
    }
    fastgltf::Image image = asset.images[texture.imageIndex.value()];

    GLuint textureObject;
    glGenTextures(1, &textureObject);

    glBindTexture(GL_TEXTURE_2D, textureObject);

    stbi_set_flip_vertically_on_load(false);

    // Copied from fastgltf example
    std::visit(
        fastgltf::visitor{
            [](auto &arg) {},
            [&](fastgltf::sources::URI &filePath) {
                assert(filePath.fileByteOffset == 0);// We don't support offsets with stbi.
                assert(filePath.uri.isLocalPath());  // We're only capable of loading local files.
                int width, height, nrChannels;

                const std::string path(filePath.uri.path().begin(),
                                       filePath.uri.path().end());// Thanks C++.
                unsigned char *data = stbi_load(path.c_str(), &width, &height, &nrChannels, 4);

                glTexStorage2D(GL_TEXTURE_2D, getLevelCount(width, height), GL_RGBA8, width,
                               height);
                glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE,
                                data);
                stbi_image_free(data);
            },
            [&](fastgltf::sources::Array &vector) {
                int width, height, nrChannels;
                unsigned char *data = stbi_load_from_memory(
                    reinterpret_cast<const stbi_uc *>(vector.bytes.data()),
                    static_cast<int>(vector.bytes.size()), &width, &height, &nrChannels, 4);
                glTexStorage2D(GL_TEXTURE_2D, getLevelCount(width, height), GL_RGBA8, width,
                               height);
                glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE,
                                data);
                stbi_image_free(data);
            },
            [&](fastgltf::sources::BufferView &view) {
                auto &bufferView = asset.bufferViews[view.bufferViewIndex];
                auto &buffer = asset.buffers[bufferView.bufferIndex];
                // Yes, we've already loaded every buffer into some GL buffer. However, with GL it's simpler
                // to just copy the buffer data again for the texture. Besides, this is just an example.
                std::visit(
                    fastgltf::visitor{
                        // We only care about VectorWithMime here, because we specify LoadExternalBuffers, meaning
                        // all buffers are already loaded into a vector.
                        [](auto &arg) {},
                        [&](fastgltf::sources::Array &vector) {
                            int width, height, nrChannels;
                            unsigned char *data = stbi_load_from_memory(
                                reinterpret_cast<const stbi_uc *>(vector.bytes.data() +
                                                                  bufferView.byteOffset),
                                static_cast<int>(bufferView.byteLength), &width, &height,
                                &nrChannels, 4);
                            glTexStorage2D(GL_TEXTURE_2D, getLevelCount(width, height), GL_RGBA8,
                                           width, height);
                            glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, GL_RGBA,
                                            GL_UNSIGNED_BYTE, data);
                            stbi_image_free(data);
                        }},
                    buffer.data);
            },
        },
        image.data);
    glGenerateMipmap(GL_TEXTURE_2D);

    if (!texture.samplerIndex.has_value()) {// Default sampler
        setTextureParameters(GL_REPEAT, GL_REPEAT, GL_NEAREST, GL_NEAREST);
    } else {
        fastgltf::Sampler &sampler = asset.samplers[texture.samplerIndex.value()];

        // Implementation defined default filters
        if (!sampler.minFilter.has_value()) {
            sampler.minFilter = fastgltf::Filter::Linear;
        }
        if (!sampler.magFilter.has_value()) {
            sampler.magFilter = fastgltf::Filter::Linear;
        }

        setTextureParameters(static_cast<GLint>(sampler.wrapS), static_cast<GLint>(sampler.wrapT),
                             static_cast<GLint>(sampler.minFilter.value()),
                             static_cast<GLint>(sampler.magFilter.value()));
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
                 int faceId) {
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

    if (faceId == -1) {
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
                               GL_TEXTURE_CUBE_MAP_POSITIVE_X + faceId, targetCubemap,
                               targetMipLevel);

        glBindTexture(GL_TEXTURE_CUBE_MAP, inputCubemap);
        glUniform1i(shader.cubemapTexture_pos, 0);

        glUniform1i(shader.currentFace_pos, faceId);

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

void setupIBL(EnvInfos &outEnvInfos, GLuint inputCubemap, int faceIndex) {
    // Not an actual frame count: should be called only once per frame !

    if (faceIndex == 0) {
        glBindTexture(GL_TEXTURE_CUBE_MAP, inputCubemap);
        glGenerateMipmap(GL_TEXTURE_CUBE_MAP);
    }
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

        PushDebugGroup(std::format("lambertian filtering face #{}", faceIndex));
        applyFilter(outEnvInfos.ibl_framebuffer, inputCubemap, IBLDistribution::Lambertian, 0.0, 0,
                    outEnvInfos.lambertianCubemapID,
                    faceIndex == -1 ? ibl_lambertianSampleCount_static
                                    : ibl_lambertianSampleCount_dynamic,
                    faceIndex);
        PopDebugGroup();

        // GLuint debug_framebuffer;
        // glGenFramebuffers(1, &debug_framebuffer);
        // size_t ibl_textureSize = 256;
        // if (1) {
        //     for (size_t i = 0; i < 6; i++) {
        //         glBindFramebuffer(GL_FRAMEBUFFER, debug_framebuffer);
        //         glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
        //                                GL_TEXTURE_CUBE_MAP_POSITIVE_X + i, inputCubemap, 0);
        //         size_t start = i * ibl_textureSize;
        //         size_t end = start + ibl_textureSize;

        //         glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
        //         glBindFramebuffer(GL_READ_FRAMEBUFFER, debug_framebuffer);
        //         glBlitFramebuffer(0, 0, ibl_textureSize, ibl_textureSize, start, 0, end,
        //                           ibl_textureSize, GL_COLOR_BUFFER_BIT, GL_LINEAR);
        //     }
        // }
        // glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
        // glDeleteFramebuffers(1, &debug_framebuffer);
        // glBindFramebuffer(GL_FRAMEBUFFER, env.ibl_framebuffer);
        // glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT, GL_TEXTURE_2D,
        //                        env.skybox.depthTexture, 0);
        // glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
        //                        GL_TEXTURE_CUBE_MAP_POSITIVE_X + faceIndex,
        //                        env.skybox.GLCubeTexture, 0);
    }

    {// cubeMapToGGX
        if (outEnvInfos.ggxCubemapID == 0) {
            outEnvInfos.ggxCubemapID = createIBLCubemapTexture(true);
        }
        PushDebugGroup(std::format("GGX filtering #{}", faceIndex));
        for (size_t currentMipLevel = 0; currentMipLevel <= outEnvInfos.mipmapLevels;
             currentMipLevel++) {
            float roughness = (float) currentMipLevel / (float) (outEnvInfos.mipmapLevels - 1);
            applyFilter(outEnvInfos.ibl_framebuffer, inputCubemap, IBLDistribution::GGX, roughness,
                        currentMipLevel, outEnvInfos.ggxCubemapID,
                        faceIndex == -1 ? ibl_ggxSampleCount_static : ibl_ggxSampleCount_dynamic,
                        faceIndex);
        }
        PopDebugGroup();
    }
    // cubeMapToSheen
    // applyFilter(...)

    {// sampleGGXLut
        if (outEnvInfos.ggxLutTextureID == 0) {
            PushDebugGroup(std::string("Generate GGX LUT"));
            outEnvInfos.ggxLutTextureID = createIBLLutTexture();
            sampleLut(outEnvInfos.ibl_framebuffer, inputCubemap, IBLDistribution::GGX,
                      outEnvInfos.ggxLutTextureID, ibl_lutResolution);
            PopDebugGroup();
        }
    }

    // Restore old Viewport
    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);
    glViewport(0, 0, w, h);
}

pbrShader compile_pbr(const fastgltf::Node &node, int gltfFlags, int materialFlags) {
    pbrShader shader;
    // Model flags
    bool hasNormals = gltfFlags & gltfFlags::HasNormals;
    bool hasTexCoords = gltfFlags & gltfFlags::HasTexCoords;
    bool hasVertexColor = gltfFlags & gltfFlags::HasVertexColor;
    bool hasWeights = gltfFlags & gltfFlags::HasWeights;
    bool hasJoints = gltfFlags & gltfFlags::HasJoints;
    bool hasSkin = node.skinIndex.has_value() && hasWeights && hasJoints;

    // Material flags
    bool hasNormalMap = materialFlags & materialFlags::HasNormalMap;
    bool hasOcclusionMap = materialFlags & materialFlags::HasOcclusionMap;
    bool hasEmissiveMap = materialFlags & materialFlags::HasEmissiveMap;
    bool unlit = materialFlags & materialFlags::Unlit;

    fprintf(hook_log, "Compiling pbrShader %s%s%s%s%s%s%s%s%s...", hasNormals ? "NORMALS," : "",
            hasTexCoords ? "TEXCOORDS," : "", hasVertexColor ? "VERTEXCOLOR" : "",
            unlit ? "UNLIT," : "", hasNormalMap ? "NORMAL_MAP," : "",
            hasOcclusionMap ? "OCCLUSION_MAP," : "", hasEmissiveMap ? "EMISSIVE_MAP," : "",
            hasWeights ? "WEIGHTS," : "", hasJoints ? "JOINTS," : "", hasSkin ? "SKIN" : "");
    fflush(hook_log);

    const std::string defines = std::format(
        "{}{}{}{}{}{}{}{}{}", hasNormals ? "#define HAS_NORMALS\n" : "",
        hasTexCoords ? "#define HAS_TEXCOORDS\n" : "",
        hasVertexColor ? "#define HAS_VERTEXCOLOR\n" : "", unlit ? "#define MATERIAL_UNLIT\n" : "",
        hasNormalMap ? "#define HAS_NORMAL_MAP\n" : "",
        hasOcclusionMap ? "#define HAS_OCCLUSION_MAP\n" : "",
        hasEmissiveMap ? "#define HAS_EMISSIVE_MAP\n" : "",
        hasWeights ? "#define HAS_WEIGHTS\n" : "", hasJoints ? "#define HAS_JOINTS\n" : "",
        hasSkin ? "#define HAS_SKINNING" : "");

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
    };

    fprintf(hook_log, "Done\n");
    fflush(hook_log);

    return shader;
}

void setupDefaultMaterial2(void) {
    if (!default_material2_initialized) {
        unsigned char data[] = {255, 255, 255, 255};
        createTexture(default_material_infos.baseColorGLTexture, 1, 1, GL_UNSIGNED_BYTE, data,
                      GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE, GL_NEAREST, GL_NEAREST, false);
        createTexture(default_material_infos.metallicRoughnessGLTexture, 1, 1, GL_UNSIGNED_BYTE,
                      data, GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE, GL_NEAREST, GL_NEAREST, false);

        default_material2 = fastgltf::Material{};
        default_material2.name = std::string("Default Material");
        default_material2.pbrData.baseColorFactor[0] = 1.0;
        default_material2.pbrData.baseColorFactor[1] = 1.0;
        default_material2.pbrData.baseColorFactor[2] = 1.0;
        default_material2.pbrData.baseColorFactor[3] = 1.0;
        default_material2.pbrData.metallicFactor = 0.0;
        default_material2.pbrData.roughnessFactor = 0.0;

        default_material2_initialized = true;
    }
}

void setupModel(gltfModel &model) {
    fprintf(hook_log, "Setuping model %s...\n", model.filename.c_str());
    fflush(hook_log);

    model.setuped = true;

    for (size_t nodeId = 0; nodeId < model.gltf.nodes.size(); nodeId++) {
        const fastgltf::Node &node = model.gltf.nodes[nodeId];
        if (!node.meshIndex.has_value()) {
            continue;
        }
        size_t meshId = node.meshIndex.value();
        const fastgltf::Mesh &mesh = model.gltf.meshes[meshId];
        fprintf(hook_log, "Setuping mesh %zu skin %zu...\n", meshId,
                node.skinIndex.has_value() ? node.skinIndex.value() : 69);
        fflush(hook_log);

        for (size_t primitiveId = 0; primitiveId < mesh.primitives.size(); primitiveId++) {
            const fastgltf::Primitive &primitive = mesh.primitives[primitiveId];

            meshInfos mesh_infos{};
            if (!primitive.indicesAccessor.has_value()) {
                fprintf(hook_log,
                        "Un-indexed topology not yet supported for mesh %zu in renderer\n", meshId);
                fflush(hook_log);
                continue;
            }
            size_t indicesAccessorId = primitive.indicesAccessor.value();

            mesh_infos.gltfFlags |= gltfFlags::IsIndexed;

            ssize_t materialIndex =
                primitive.materialIndex.has_value() ? primitive.materialIndex.value() : -1;
            if (materialIndex == -1) {
                setupDefaultMaterial2();
            }

            unsigned int nbAttributes = 0;
            int positionAccessorId = -1;
            int positionIndex = 0;
            int normalAccessorId = -1;
            int normalIndex = 0;
            int texcoordAccessorId = -1;
            int texcoordIndex = 0;
            int vertexColorAccessorId = -1;
            int vertexColorIndex = 0;
            int weightAccessorId = -1;
            int weightIndex = 0;
            int jointAccessorId = -1;
            int jointIndex = 0;
            for (const auto &[key, value]: primitive.attributes) {
                if (key == "POSITION") {
                    positionAccessorId = value;
                    positionIndex = nbAttributes;
                    nbAttributes += 1;
                }
                if (key == "NORMAL") {
                    mesh_infos.gltfFlags |= gltfFlags::HasNormals;
                    normalAccessorId = value;
                    normalIndex = nbAttributes;
                    nbAttributes += 1;
                }
                if (key == "TEXCOORD_0") {
                    mesh_infos.gltfFlags |= gltfFlags::HasTexCoords;
                    texcoordAccessorId = value;
                    texcoordIndex = nbAttributes;
                    nbAttributes += 1;
                }
                if (key == "COLOR_0") {
                    mesh_infos.gltfFlags |= gltfFlags::HasVertexColor;
                    vertexColorAccessorId = value;
                    vertexColorIndex = nbAttributes;
                    nbAttributes += 1;
                }
                // has Weights && hasJoints && node.skin -> skinning
                if (key == "WEIGHTS_0") {
                    mesh_infos.gltfFlags |= gltfFlags::HasWeights;
                    weightAccessorId = value;
                    weightIndex = nbAttributes;
                    nbAttributes += 1;
                }
                if (key == "JOINTS_0") {
                    mesh_infos.gltfFlags |= gltfFlags::HasJoints;
                    jointAccessorId = value;
                    jointIndex = nbAttributes;
                    nbAttributes += 1;
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

            if (model.gltf.accessors[indicesAccessorId].type != fastgltf::AccessorType::Scalar) {
                fprintf(
                    hook_log,
                    "Error: indices accessor does not have type scalar in renderer for mesh %zu\n",
                    meshId);
                fflush(hook_log);
                continue;
            }
            const fastgltf::Accessor &indicesAccessor = model.gltf.accessors[indicesAccessorId];

            if (indicesAccessor.componentType != fastgltf::ComponentType::UnsignedByte &&
                indicesAccessor.componentType != fastgltf::ComponentType::UnsignedShort &&
                indicesAccessor.componentType != fastgltf::ComponentType::UnsignedInt) {
                fprintf(hook_log, "Unsupported type for indices buffer of mesh %zu in renderer\n",
                        meshId);
                fflush(hook_log);
                continue;
            }

            fastgltf::Material *material = nullptr;
            materialInfos material_infos{};

            if (materialIndex == -1) {
                material = &default_material2;
                material_infos = default_material_infos;
            } else {
                material = &(model.gltf.materials[primitive.materialIndex.value()]);

                {// Get material Flags
                    if (material->normalTexture.has_value()) {
                        material_infos.flags |= materialFlags::HasNormalMap;
                    }
                    if (material->occlusionTexture.has_value()) {
                        material_infos.flags |= materialFlags::HasOcclusionMap;
                    }
                    if (material->emissiveTexture.has_value()) {
                        material_infos.flags |= materialFlags::HasEmissiveMap;
                    }
                    if (material->alphaMode == fastgltf::AlphaMode::Blend) {
                        material_infos.flags |= materialFlags::IsAlphaBlend;
                    }
                    if (material->unlit) {
                        material_infos.flags |= materialFlags::Unlit;
                    }
                }
                {// validate roughness and metallic factors
                    if (material->pbrData.metallicFactor < 0.0)
                        material->pbrData.metallicFactor = 0.0;
                    if (material->pbrData.metallicFactor > 1.0)
                        material->pbrData.metallicFactor = 1.0;
                    if (material->pbrData.roughnessFactor < 0.0)
                        material->pbrData.roughnessFactor = 0.0;
                    if (material->pbrData.roughnessFactor > 1.0)
                        material->pbrData.roughnessFactor = 1.0;
                }
            }

            // compile shader with options
            // https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#appendix-b-brdf-implementation
            int flag =
                (mesh_infos.gltfFlags << materialFlags::MaterialFlagLastBit) | material_infos.flags;
            if (!shader_pool.contains(flag)) {
                shader_pool[flag] = compile_pbr(node, mesh_infos.gltfFlags, material_infos.flags);
            }

            // create GL objects
            GLuint VAO;
            glGenVertexArrays(1, &VAO);
            std::vector<GLuint> VBOs(nbAttributes);
            glGenBuffers(VBOs.size(), VBOs.data());

            GLuint EBO;
            glGenBuffers(1, &EBO);

            mesh_infos.VAO = VAO;
            mesh_infos.PositionBO = VBOs[positionIndex];
            if (mesh_infos.gltfFlags & gltfFlags::HasNormals)
                mesh_infos.NormalBO = VBOs[normalIndex];
            if (mesh_infos.gltfFlags & gltfFlags::HasTexCoords)
                mesh_infos.TexCoordsBO = VBOs[texcoordIndex];
            if (mesh_infos.gltfFlags & gltfFlags::HasVertexColor)
                mesh_infos.VertexColorBO = VBOs[vertexColorIndex];
            if (mesh_infos.gltfFlags & gltfFlags::HasWeights)
                mesh_infos.WeightBO = VBOs[weightIndex];
            if (mesh_infos.gltfFlags & gltfFlags::HasJoints)
                mesh_infos.JointBO = VBOs[jointIndex];
            mesh_infos.EBO = EBO;
            model.mesh_infos[std::tuple<size_t, size_t>{meshId, primitiveId}] = mesh_infos;

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

                if (!material->pbrData.baseColorTexture.has_value()) {
                    setupDefaultMaterial2();

                    material_infos.baseColorGLTexture = default_material_infos.baseColorGLTexture;
                } else if (!material_initialized) {
                    if (std::optional<GLuint> texture = setupTexture(
                            model.gltf, material->pbrData.baseColorTexture.value().textureIndex)) {
                        material_infos.baseColorGLTexture = texture.value();
                    } else {
                        fprintf(hook_log, "No source image for baseColorTexture\n");
                        fflush(hook_log);
                        std::abort();
                    }
                }

                if (!material->pbrData.metallicRoughnessTexture.has_value()) {
                    setupDefaultMaterial2();

                    material_infos.metallicRoughnessGLTexture =
                        default_material_infos.metallicRoughnessGLTexture;
                } else if (!material_initialized) {
                    if (std::optional<GLuint> texture = setupTexture(
                            model.gltf,
                            material->pbrData.metallicRoughnessTexture.value().textureIndex)) {
                        material_infos.metallicRoughnessGLTexture = texture.value();
                    } else {
                        fprintf(hook_log, "No source image for metallicRoughnessTexture\n");
                        fflush(hook_log);
                        std::abort();
                    }
                }

                if (material_infos.flags & materialFlags::HasNormalMap && !material_initialized) {
                    if (std::optional<GLuint> texture = setupTexture(
                            model.gltf, material->normalTexture.value().textureIndex)) {
                        material_infos.normalMapGLTexture = texture.value();
                    } else {
                        fprintf(hook_log, "No source image for normal Map texture\n");
                        fflush(hook_log);
                        std::abort();
                    }
                }
                if (material_infos.flags & materialFlags::HasOcclusionMap &&
                    !material_initialized) {
                    if (std::optional<GLuint> texture = setupTexture(
                            model.gltf, material->occlusionTexture.value().textureIndex)) {
                        material_infos.occlusionMapGLTexture = texture.value();
                    } else {
                        fprintf(hook_log, "No source image for occlusion Map texture\n");
                        fflush(hook_log);
                        std::abort();
                    }
                }
                if (material_infos.flags & materialFlags::HasEmissiveMap && !material_initialized) {
                    if (std::optional<GLuint> texture = setupTexture(
                            model.gltf, material->emissiveTexture.value().textureIndex)) {
                        material_infos.emissiveMapGLTexture = texture.value();
                    } else {
                        fprintf(hook_log, "No source image for emissive Map texture\n");
                        fflush(hook_log);
                        std::abort();
                    }
                }
            }

            if (mesh_infos.gltfFlags & gltfFlags::HasVertexColor) {
                setupAttribute(mesh_infos.VertexColorBO, model.gltf, vertexColorAccessorId, 3);
                glEnableVertexArrayAttrib(mesh_infos.VAO, 3);
            }
            if (mesh_infos.gltfFlags & gltfFlags::HasWeights) {
                setupAttribute(mesh_infos.WeightBO, model.gltf, weightAccessorId, 4);
                glEnableVertexArrayAttrib(mesh_infos.VAO, 4);
            }
            if (mesh_infos.gltfFlags & gltfFlags::HasJoints) {
                setupAttribute(mesh_infos.JointBO, model.gltf, jointAccessorId, 5);
                glEnableVertexArrayAttrib(mesh_infos.VAO, 5);
            }

            if (!material_initialized) {
                model.material_infos[materialIndex] = material_infos;
            }

            // is indexed geometry
            const fastgltf::BufferView &indicesBufferView =
                model.gltf.bufferViews[indicesAccessor.bufferViewIndex.value()];

            const std::byte *indicesPtr = getBufferPointer(model.gltf, indicesAccessor);
            const void *indexBuffer =
                indicesPtr + indicesAccessor.byteOffset + indicesBufferView.byteOffset;
            glBindBuffer(static_cast<GLenum>(indicesBufferView.target.value()), mesh_infos.EBO);
            glBufferData(static_cast<GLenum>(indicesBufferView.target.value()),
                         getBufferByteSize2(indicesAccessor), indexBuffer, GL_STATIC_DRAW);

            glBindVertexArray(0);
        }
    }

    fprintf(hook_log, "Model %s setup Done\n", model.filename.c_str());
    fflush(hook_log);
}


void deleteModel(gltfModel &model) {
    // Clean buffers
    for (auto const &[key_mesh, mesh_infos]: model.mesh_infos) {
        GLuint buffers[] = {
            mesh_infos.PositionBO,    mesh_infos.NormalBO, mesh_infos.TexCoordsBO,
            mesh_infos.VertexColorBO, mesh_infos.WeightBO, mesh_infos.JointBO,
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
