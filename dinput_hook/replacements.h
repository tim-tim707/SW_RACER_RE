#pragma once

#include "renderer_utils.h"
#include "tinygltf/gltf_utils.h"

extern "C" {
#include <Swr/swrModel.h>
}

extern const char *modelid_cstr[];

bool try_replace(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                 const rdMatrix44 &model_matrix, EnvInfos envInfos);
