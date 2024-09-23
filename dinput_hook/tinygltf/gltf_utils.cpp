#include "gltf_utils.h"

// Define these only in *one* .cc file.
#define TINYGLTF_IMPLEMENTATION
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define TINYGLTF_NOEXCEPTION// optional. disable exception handling.
#include "tiny_gltf.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

extern "C" FILE *hook_log;

std::vector<tinygltf::Model> g_models;

static void setupModel(tinygltf::Model &model);

void init_tinygltf() {
    fprintf(hook_log, "[init_tinygltf]\n");
    tinygltf::TinyGLTF loader;

    std::vector<std::string> asset_names = {"Box.gltf", "BoxTextured.gltf"};
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

        // compile shader with correct options
        setupModel(model);
        g_models.push_back(model);
        fprintf(hook_log, "Setup-ed %s\n", name.c_str());
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

void setupAttribute(unsigned int bufferObject, tinygltf::Model &model, int accessorId,
                    unsigned int location) {
    const tinygltf::Accessor &accessor = model.accessors[accessorId];
    const tinygltf::BufferView &bufferView = model.bufferViews[accessor.bufferView];
    auto positionBuffer = reinterpret_cast<const float *>(
        model.buffers[bufferView.buffer].data.data() + accessor.byteOffset + bufferView.byteOffset);

    glBindBuffer(bufferView.target, bufferObject);
    glBufferData(bufferView.target,
                 accessor.count * getComponentCount(accessor.type) *
                     getComponentByteSize(accessor.componentType),
                 positionBuffer, GL_STATIC_DRAW);

    glVertexAttribPointer(location, getComponentCount(accessor.type), accessor.componentType,
                          GL_FALSE, bufferView.byteStride, 0);
}

void setupTexture(unsigned int textureObject, tinygltf::Model &model,
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

static void setupModel(tinygltf::Model &model) {}
