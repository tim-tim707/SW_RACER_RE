#pragma once

#include "renderer_utils.h"
#include "gltf_utils.h"

extern "C" {
#include <Swr/swrModel.h>
}

struct swrRace;

extern uint8_t replacedTries[323];// 323 MODELIDs
extern std::map<MODELID, uint8_t> additionnalReplacedTries;
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

// In-race HD pod draw bound to the racer entity that owns the pod node (resolved via
// find_entity_for_node), instead of the single global currentPlayer_Test. Draws from owner's own
// engineXf/cockpitXf, so every full-pod racer (player + ai_full_lod AI) renders at its own position.
bool try_replace_pod_entity(MODELID model_id, swrRace *owner, const rdMatrix44 &proj_matrix,
                            const rdMatrix44 &view_matrix, EnvInfos envInfos, bool mirrored);

bool try_replace_AIPod(MODELID model_id, const rdMatrix44 &proj_matrix,
                       const rdMatrix44 &view_matrix, const rdMatrix44 &model_matrix,
                       EnvInfos envInfos, bool mirrored);

bool try_replace_track(MODELID model_id, const rdMatrix44 &proj_matrix,
                       const rdMatrix44 &view_matrix, EnvInfos envInfos, bool mirrored);
bool try_replace_env(MODELID model_id, const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                     EnvInfos envInfos, bool mirrored);
