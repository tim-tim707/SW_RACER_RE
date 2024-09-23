#pragma once

#include "tiny_gltf.h"

extern tinygltf::Model g_model;

void gltfModel_to_imgui(tinygltf::Model &model);

void init_tinygltf();

unsigned int getComponentCount(int tinygltfType);
unsigned int getComponentByteSize(int componentType);
