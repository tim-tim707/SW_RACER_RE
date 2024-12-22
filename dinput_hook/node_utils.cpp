#include "node_utils.h"

#include <map>
#include <set>
#include <vector>
#include <optional>
#include <algorithm>
#include <cstdint>

extern "C" {
#include <swr.h>
#include <Primitives/rdMatrix.h>
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

std::optional<MODELID> find_model_id_for_node(const swrModel_Node *node) {
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

void apply_node_transform(rdMatrix44 &model_mat, const swrModel_Node *node,
                          const rdVector3 *viewport_position) {
    if (node->type == NODE_TRANSFORMED || node->type == NODE_TRANSFORMED_WITH_PIVOT) {
        // this node has a transform.
        rdMatrix44 mat{};
        swrModel_NodeGetTransform((const swrModel_NodeTransformed *) node, &mat);
        if (node->type == NODE_TRANSFORMED_WITH_PIVOT && (node->flags_3 & 0x10)) {
            // some kind of pivot point: the translation v is removed from the transform and then added untransformed.
            const rdVector3 v = ((const swrModel_NodeTransformedWithPivot *) node)->pivot;
            const rdVector3 v_transformed = {
                mat.vA.x * v.x + mat.vB.x * v.y + mat.vC.x * v.z,
                mat.vA.y * v.x + mat.vB.y * v.y + mat.vC.y * v.z,
                mat.vA.z * v.x + mat.vB.z * v.y + mat.vC.z * v.z,
            };
            mat.vD.x += v.x - v_transformed.x;
            mat.vD.y += v.y - v_transformed.y;
            mat.vD.z += v.z - v_transformed.z;
        }

        rdMatrix44 model_mat_new;
        rdMatrix_Multiply44(&model_mat_new, &mat, &model_mat);
        model_mat = model_mat_new;
    } else if (node->type == NODE_TRANSFORMED_COMPUTED) {
        const swrModel_NodeTransformedComputed *transformed_node =
            (const swrModel_NodeTransformedComputed *) node;
        rdMatrix34 transform{
            *(const rdVector3 *) &model_mat.vA,
            *(const rdVector3 *) &model_mat.vB,
            *(const rdVector3 *) &model_mat.vC,
            *(const rdVector3 *) &model_mat.vD,
        };

        switch (transformed_node->orientation_option) {
            case 0:
                break;
            case 1: {
                rdVector3 forward;
                rdVector_Sub3(&forward, &transform.scale, viewport_position);
                rdVector_Normalize3Acc(&forward);

                // first transform up vector into the current coordinate system:
                rdVector3 up;
                rdVector_Scale3(&up, transformed_node->up_vector.x, &transform.rvec);
                rdVector_Scale3Add3(&up, &up, transformed_node->up_vector.y, &transform.lvec);
                rdVector_Scale3Add3(&up, &up, transformed_node->up_vector.z, &transform.uvec);
                float length = rdVector_Normalize3Acc(&up);

                // now build an orthonormal basis
                transform.uvec = up;
                // forward x up -> right
                rdVector_Cross3(&transform.rvec, &forward, &transform.uvec);
                rdVector_Normalize3Acc(&transform.rvec);
                // up x right -> forward
                rdVector_Cross3(&transform.lvec, &transform.uvec, &transform.rvec);
                // no normalize, because uvec and rvec are orthogonal

                // scale
                rdVector_Scale3(&transform.rvec, length, &transform.rvec);
                rdVector_Scale3(&transform.lvec, length, &transform.lvec);
                rdVector_Scale3(&transform.uvec, length, &transform.uvec);
            } break;
            case 2:// TODO
            case 3:// TODO
            default:
                std::abort();
        }

        if (transformed_node->follow_model_position == 1)
            transform.scale = *viewport_position;

        rdMatrix_Copy44_34(&model_mat, &transform);
    }
}
