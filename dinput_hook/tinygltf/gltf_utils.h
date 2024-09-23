#pragma once

#include "tiny_gltf.h"

extern tinygltf::Model g_model;

enum gltfFlags {
    Empty = 0,
    isIndexed = 1 << 0,
    hasNormals = 1 << 1,
    hasTexCoords = 1 << 2,// == hasTexture
};

void gltfModel_to_imgui(tinygltf::Model &model);

void init_tinygltf();

void setupAttribute(unsigned int bufferObject, tinygltf::Model &model, int accessorId,
                    unsigned int location);
void setupTexture(unsigned int textureObject, tinygltf::Model &model,
                  int textureId /* TODO: ,int textureSlot default to texture 0 */);
