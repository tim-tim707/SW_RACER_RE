#pragma once

#include "renderer_utils.h"
#include "tinygltf/gltf_utils.h"

extern "C" {
#include <Swr/swrModel.h>
}

extern uint8_t replacedTries[323];// 323 MODELIDs
extern const char *modelid_cstr[];

struct ReplacementModel {
    bool fileExist;
    gltfModel model;
};

// MODELID, ReplacementModel
extern std::map<int, ReplacementModel> replacement_map;

bool try_replace(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                 const rdMatrix44 &model_matrix, EnvInfos envInfos, bool mirrored, uint8_t type);
