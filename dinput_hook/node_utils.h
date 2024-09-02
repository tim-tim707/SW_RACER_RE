#pragma once

#include <map>
#include <set>
#include <vector>
#include <cstdint>
#include <optional>

extern "C" {
#include <swr.h>
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

extern swrModel_Node *root_node;
extern uint32_t banned_sprite_flags;
extern int num_sprites_with_flag[32];
extern NodeMember node_members[5];
extern MaterialMember node_material_members[9];
extern std::vector<AssetPointerToModel> asset_pointer_to_model;

std::optional<MODELID> find_model_id_for_node(swrModel_Node *node);
