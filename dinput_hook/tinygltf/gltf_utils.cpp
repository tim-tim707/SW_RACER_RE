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

extern "C" FILE *hook_log;

extern ImGuiState imgui_state;

std::vector<gltfModel> g_models;

void load_gltf_models() {
    fprintf(hook_log, "[load_gltf_models]\n");
    tinygltf::TinyGLTF loader;

    std::vector<std::string> asset_names = {"Box.gltf", "BoxTextured.gltf", "box_textured_red.gltf",
                                            "MetalRoughSpheresNoTextures.gltf"};
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

        g_models.push_back(
            gltfModel{.setuped = false, .gltf = model, .mesh_infos = {}, .shader_pool = {}});
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

static void setupTexture(unsigned int textureObject, tinygltf::Model &model,
                         int textureId /*TODO: , int textureSlot default to texture 0 */) {
    auto texture = model.textures[textureId];
    auto image = model.images[texture.source];

    glBindTexture(GL_TEXTURE_2D, textureObject);
    GLint internalFormat = GL_RGBA;
    glTexImage2D(GL_TEXTURE_2D, 0, internalFormat, image.width, image.height, 0, internalFormat,
                 image.pixel_type, image.image.data());
    glGenerateMipmap(GL_TEXTURE_2D);
    // activate texture TEXTURE0 + texslot
    // uniform1i loc texslot
    auto sampler = model.samplers[texture.sampler];

    // Sampler parameters. TODO: Should use glSamplerParameter here
    // if not exist, use defaults wrapS wrapT, auto filtering
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, sampler.wrapS);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, sampler.wrapT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, sampler.minFilter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, sampler.magFilter);
}

pbrShader compile_pbr(ImGuiState &state, meshInfos &meshInfos) {
    pbrShader shader;
    fprintf(hook_log, "Compiling shader...");
    fflush(hook_log);

    (void) state;

    const std::string defines = std::format(
        "{}{}", meshInfos.gltfFlags & gltfFlags::hasNormals ? "#define HAS_NORMALS\n" : "",
        meshInfos.gltfFlags & gltfFlags::hasTexCoords ? "#define HAS_TEXCOORDS\n" : "");

    const char *vertex_shader_source = R"(
layout(location = 0) in vec3 position;
#ifdef HAS_NORMALS
layout(location = 1) in vec3 normal;
#endif
#ifdef HAS_TEXCOORDS
layout(location = 2) in vec2 texcoords;
#endif

uniform mat4 projMatrix;
uniform mat4 viewMatrix;
uniform mat4 modelMatrix;

uniform int model_id;

#ifdef HAS_TEXCOORDS
out vec2 passTexcoords;
#endif

void main() {
    // Yes, precomputing modelView is better and we should do it
    gl_Position = projMatrix * viewMatrix * modelMatrix * vec4(position, 1.0);
#ifdef HAS_TEXCOORDS
    passTexcoords = texcoords;
#endif
}
)";
    const char *fragment_shader_source = R"(
#ifdef HAS_TEXCOORDS
in vec2 passTexcoords;
#endif

uniform vec4 baseColorFactor;
// useful with punctual light or IBL
uniform float metallicFactor;

#ifdef HAS_TEXCOORDS
uniform sampler2D baseColorTexture;
#endif

out vec4 outColor;

void main() {
    // outColor = vec4(1.0, 0.0, 1.0, 0.0);

    // TODO: decode sRGB to linear values before pairwise multiplication with factor
#ifdef HAS_TEXCOORDS
    vec4 texColor = texture(baseColorTexture, passTexcoords);
    outColor = baseColorFactor * texColor;
#else
    outColor = baseColorFactor;
#endif
}
)";

    const char *vertex_sources[]{"#version 330 core\n", defines.c_str(), vertex_shader_source};
    const char *fragment_sources[]{"#version 330 core\n", defines.c_str(), fragment_shader_source};

    std::optional<GLuint> program_opt = compileProgram(
        std::size(vertex_sources), vertex_sources, std::size(fragment_sources), fragment_sources);
    if (!program_opt.has_value())
        std::abort();
    GLuint program = program_opt.value();

    GLuint VAO;
    glGenVertexArrays(1, &VAO);
    GLuint VBOs[3];
    glGenBuffers(3, VBOs);

    GLuint EBO;
    glGenBuffers(1, &EBO);

    unsigned int glTexture;
    glGenTextures(1, &glTexture);

    meshInfos.VAO = VAO;
    meshInfos.PositionBO = VBOs[0];
    meshInfos.NormalBO = VBOs[1];
    meshInfos.TexCoordsBO = VBOs[2];
    meshInfos.EBO = EBO;
    meshInfos.glTexture = glTexture;

    shader = {
        .handle = program,
        .proj_matrix_pos = glGetUniformLocation(program, "projMatrix"),
        .view_matrix_pos = glGetUniformLocation(program, "viewMatrix"),
        .model_matrix_pos = glGetUniformLocation(program, "modelMatrix"),
        .baseColorFactor_pos = glGetUniformLocation(program, "baseColorFactor"),
        .metallicFactor_pos = glGetUniformLocation(program, "metallicFactor"),
        .model_id_pos = glGetUniformLocation(program, "model_id"),
    };

    fprintf(hook_log, "Done\n");
    fflush(hook_log);

    return shader;
}

void setupModel(gltfModel &model) {
    fprintf(hook_log, "Setuping model...\n");
    fflush(hook_log);

    model.setuped = true;

    for (size_t meshId = 0; meshId < model.gltf.meshes.size(); meshId++) {
        meshInfos mesh_infos{};
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
        mesh_infos.gltfFlags |= gltfFlags::isIndexed;

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
                mesh_infos.gltfFlags |= gltfFlags::hasNormals;
                normalAccessorId = value;
            }
            if (key == "TEXCOORD_0") {
                mesh_infos.gltfFlags |= gltfFlags::hasTexCoords;
                texcoordAccessorId = value;
            }
        }

        if (positionAccessorId == -1) {
            fprintf(hook_log, "Unsupported mesh %zu without position attribute in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }
        if (mesh_infos.gltfFlags & gltfFlags::hasNormals == 0) {
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
        model.shader_pool[mesh_infos.gltfFlags] = compile_pbr(imgui_state, mesh_infos);
        model.mesh_infos[meshId] = mesh_infos;
        pbrShader shader = model.shader_pool[mesh_infos.gltfFlags];
        glUseProgram(shader.handle);

        glBindVertexArray(mesh_infos.VAO);

        // Position is mandatory attribute
        setupAttribute(mesh_infos.PositionBO, model.gltf, positionAccessorId, 0);
        glEnableVertexArrayAttrib(mesh_infos.VAO, 0);

        if (mesh_infos.gltfFlags & gltfFlags::hasNormals) {
            setupAttribute(mesh_infos.NormalBO, model.gltf, normalAccessorId, 1);
            glEnableVertexArrayAttrib(mesh_infos.VAO, 1);
        }

        if (mesh_infos.gltfFlags & gltfFlags::hasTexCoords) {
            setupAttribute(mesh_infos.TexCoordsBO, model.gltf, texcoordAccessorId, 2);
            glEnableVertexArrayAttrib(mesh_infos.VAO, 2);

            int textureId =
                model.gltf.materials[materialIndex].pbrMetallicRoughness.baseColorTexture.index;
            setupTexture(mesh_infos.glTexture, model.gltf, textureId);
        }

        // is indexed geometry
        const tinygltf::BufferView &indicesBufferView =
            model.gltf.bufferViews[indicesAccessor.bufferView];
        auto indexBuffer = reinterpret_cast<const unsigned short *>(
            model.gltf.buffers[indicesBufferView.buffer].data.data() + indicesAccessor.byteOffset +
            indicesBufferView.byteOffset);

        glBindBuffer(indicesBufferView.target, mesh_infos.EBO);
        glBufferData(indicesBufferView.target, indicesBufferView.byteLength, indexBuffer,
                     GL_STATIC_DRAW);

        glBindVertexArray(0);
    }
    fprintf(hook_log, "Done\n");
    fflush(hook_log);
}
