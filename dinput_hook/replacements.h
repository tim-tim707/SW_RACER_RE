#pragma once

#include "renderer_utils.h"
#include "gltf_utils.h"

extern "C" {
#include <Swr/swrModel.h>
}

extern uint8_t replacedTries[323];// 323 MODELIDs
extern const char *modelid_cstr[];

struct ReplacementModel {
    bool fileExist;
    gltfModel model;
};

bool isEnvModel(MODELID modelId);
bool isPodModel(MODELID modelId);
bool isAIPodModel(MODELID modelId);
bool isTrackModel(MODELID modelId);

// MODELID, ReplacementModel
extern std::map<int, ReplacementModel> replacement_map;

bool try_replace(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                 const rdMatrix44 &model_matrix, EnvInfos envInfos, bool mirrored, uint8_t type);

bool try_replace_pod(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                     const rdMatrix44 &model_matrix, EnvInfos envInfos, bool mirrored);

bool try_replace_AIPod(MODELID model_id, const rdMatrix44 &proj_matrix,
                       const rdMatrix44 &view_matrix, const rdMatrix44 &model_matrix,
                       EnvInfos envInfos, bool mirrored);

bool try_replace_track(MODELID model_id, const rdMatrix44 &proj_matrix,
                       const rdMatrix44 &view_matrix, EnvInfos envInfos, bool mirrored);
bool try_replace_env(MODELID model_id, const rdMatrix44 &proj_matrix,
                       const rdMatrix44 &view_matrix, EnvInfos envInfos, bool mirrored);
