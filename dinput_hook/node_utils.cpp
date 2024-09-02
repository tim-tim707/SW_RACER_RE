#include "node_utils.h"

#include <map>
#include <set>
#include <vector>
#include <optional>
#include <algorithm>
#include <cstdint>

extern "C" {
#include <swr.h>
#include <Swr/swrModel.h>
}

NodeMember node_members[5]{
    {
        "flags_1",
        [](const swrModel_Node &m) { return (uint32_t) m.flags_1; },
    },
    {
        "flags_2",
        [](const swrModel_Node &m) { return (uint32_t) m.flags_2; },
    },
    {
        "flags_3",
        [](const swrModel_Node &m) { return (uint32_t) m.flags_3; },
    },
    {
        "flags_4",
        [](const swrModel_Node &m) { return (uint32_t) m.light_index; },
    },
    {
        "flags_5",
        [](const swrModel_Node &m) { return m.flags_5; },
    },
};

MaterialMember node_material_members[9]{
    {
        "type",
        [](const swrModel_MeshMaterial &m) { return m.type; },
    },
    {
        "unk1",
        [](const swrModel_MeshMaterial &m) { return m.material->unk1; },
    },
    {
        "render_mode_1",
        [](const swrModel_MeshMaterial &m) { return m.material->render_mode_1; },
    },
    {
        "render_mode_2",
        [](const swrModel_MeshMaterial &m) { return m.material->render_mode_2; },
    },
    {
        "cc_cycle1",
        [](const swrModel_MeshMaterial &m) { return m.material->color_combine_mode_cycle1; },
    },
    {
        "ac_cycle1",
        [](const swrModel_MeshMaterial &m) { return m.material->alpha_combine_mode_cycle1; },
    },
    {
        "cc_cycle2",
        [](const swrModel_MeshMaterial &m) { return m.material->color_combine_mode_cycle2; },
    },
    {
        "ac_cycle2",
        [](const swrModel_MeshMaterial &m) { return m.material->alpha_combine_mode_cycle2; },
    },
    {
        "tex_flags",
        [](const swrModel_MeshMaterial &m) {
            return m.material_texture && m.material_texture->specs[0]
                       ? m.material_texture->specs[0]->flags
                       : 0;
        },
    },
};

swrModel_Node *root_node = nullptr;

uint32_t banned_sprite_flags = 0;
int num_sprites_with_flag[32] = {};

std::vector<AssetPointerToModel> asset_pointer_to_model;

std::optional<MODELID> find_model_id_for_node(swrModel_Node *node) {
    char *raw_ptr = (char *) node;
    auto it = std::upper_bound(
        asset_pointer_to_model.begin(), asset_pointer_to_model.end(), raw_ptr,
        [](char *raw_ptr, const auto &elem) { return raw_ptr < elem.asset_pointer_end; });

    if (it == asset_pointer_to_model.end())
        std::abort();// TODO: this should never happen, maybe error?

    if (raw_ptr < it->asset_pointer_begin)
        return std::nullopt;// internal static node

    return it->id;
}
