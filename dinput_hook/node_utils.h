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
    // Where the model's own data starts (its type tag; the loader may pad before it), so a pointer
    // maps to the same byte offset as in the model file whatever the buffer's alignment was.
    char *data_begin = nullptr;
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

constexpr uintptr_t kMinMappableAddress = 0x10000;// Win32 never maps the first 64 KB

// Returns specs[i], or nullptr when the slot holds a value below the first mappable page. Crash
// reports show in-race textures with specs[0] == 0x3 / 0xf, which a plain null check dereferences.
inline const swrModel_MaterialTextureChild *material_texture_spec(const swrModel_MaterialTexture *tex,
                                                                   int i) {
    const swrModel_MaterialTextureChild *spec = tex->specs[i];
    return (uintptr_t) spec >= kMinMappableAddress ? spec : nullptr;
}

std::optional<MODELID> find_model_id_for_node(const swrModel_Node *node);

// Model id and byte offset (from the start of that model's asset data) of any pointer into a loaded
// model -- stable across loads, so it identifies a mesh the same way every session.
bool find_asset_offset(const void *ptr, MODELID *id, uint32_t *offset);
// Same, but the offset from the model data's start: the byte offset in the model file (stable across
// loads, unlike find_asset_offset's, which depends on the asset buffer's alignment at load time).
bool find_model_offset(const void *ptr, MODELID *id, uint32_t *offset);

// Rebuilds pod_node_owners from the live racer roster (swrScores[]). Cheap (<=20 entries); call once
// per frame before scene traversal while in a race.
void rebuild_pod_node_owners();

// Resolves a scene node to the racer entity whose pod model owns it, or nullptr if the node is not
// part of any racer's pod (track/env/internal nodes, or not in a race).
swrRace *find_entity_for_node(const swrModel_Node *node);

// True when `node` is the pod-root node of a racer that is NOT the local player and whose pod its own
// camera is hiding (POD_HIDDEN set, DEAD clear) -- a pod the stock game re-shows to other viewports
// in swrViewport_Render, which the OpenGL renderer replaces and skips. Scene traversal uses this to
// draw such a pod anyway (otherwise a remote player in bumper cam, or an AI on the post-race autopilot
// cam, is invisible to everyone). Keyed on the exact node the game hides (owner->partNodes[0])
// so the sub-nodes hidden on purpose (cockpit interior, shadows) are not un-hidden with it.
bool is_foreign_hidden_pod_root(const swrModel_Node *node);

// Owner if `node` is a racer's pod root (owner->partNodes[0]), else nullptr.
swrRace *pod_root_owner(const swrModel_Node *node);

void apply_node_transform(rdMatrix44 &model_mat, const swrModel_Node *node,
                          rdVector3 *viewport_position);
