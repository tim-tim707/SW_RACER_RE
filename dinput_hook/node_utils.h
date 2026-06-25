#pragma once

#include <map>
#include <set>
#include <vector>
#include <cstdint>
#include <optional>

extern "C" {
#include <swr.h>
#include <Primitives/rdMatrix.h>
#include <Swr/swrModel.h>
}

struct NodeMember {
    const char *name;
    uint32_t (*getter)(const swrModel_Node &);
    std::map<uint32_t, int> count;
    std::set<uint32_t> banned;
};

struct MaterialMember {
    const char *name;
    uint32_t (*getter)(const swrModel_MeshMaterial &);
    std::map<uint32_t, int> count;
    std::set<uint32_t> banned;
};

struct AssetPointerToModel {
    char *asset_pointer_begin;
    char *asset_pointer_end;
    MODELID id;
};

// Maps a contiguous pod-model asset range to the racer entity that owns it. Each racer loads its own
// distinct copy of its pod model (swrModel_LoadFromId never caches), so the ranges are disjoint and a
// node pointer resolves to exactly one owner. Rebuilt per frame from the swrScores[] roster.
struct PodNodeOwner {
    char *begin;
    char *end;
    swrRace *entity;
};

extern swrModel_Node *root_node;
#ifndef NDEBUG
extern uint32_t banned_sprite_flags;
extern int num_sprites_with_flag[32];
extern NodeMember node_members[5];
extern MaterialMember node_material_members[9];
#endif
extern std::vector<AssetPointerToModel> asset_pointer_to_model;
extern std::vector<PodNodeOwner> pod_node_owners;

std::optional<MODELID> find_model_id_for_node(const swrModel_Node *node);

// Rebuilds pod_node_owners from the live racer roster (swrScores[]). Cheap (<=20 entries); call once
// per frame before scene traversal while in a race.
void rebuild_pod_node_owners();

// Resolves a scene node to the racer entity whose pod model owns it, or nullptr if the node is not
// part of any racer's pod (track/env/internal nodes, or not in a race).
swrRace *find_entity_for_node(const swrModel_Node *node);

void apply_node_transform(rdMatrix44 &model_mat, const swrModel_Node *node,
                          rdVector3 *viewport_position);
