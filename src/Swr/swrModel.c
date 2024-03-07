#include "swrModel.h"

#include <globals.h>
#include <macros.h>
#include <Primitives/rdMath.h>
#include <Primitives/rdMatrix.h>

// 0x00431900
void swrModel_GetTransforms(swrModel_unk* param_1, rdVector3* translation, rdVector3* rotation)
{
    swrTranslationRotation tmp;
    rdMatrix_ExtractTransform(&param_1->clipMat, &tmp);
    translation->x = tmp.translation.x;
    translation->y = tmp.translation.y;
    translation->z = tmp.translation.z;
    rotation->x = tmp.yaw_roll_pitch.x;
    rotation->y = tmp.yaw_roll_pitch.y;
    rotation->z = tmp.yaw_roll_pitch.z;
}

// 0x00448780
swrModel_Header* swrModel_LoadFromId(int id)
{
    HANG("TODO");
    return NULL;
}

// 0x004485D0 HOOK
void swrModel_ByteSwapModelData(swrModel_Header* header)
{
    swrModel_HeaderEntry* curr = header->entries;

    curr->value = SWAP32(curr->value);
    uint32_t model_type = curr->value;
    curr++;

    swrModel_SkipByteswapCollisionVertices = 0;
    assetBufferUnknown = 0; // <- only used in this function?

    while (curr->value != 0xFFFFFFFF)
    {
        if (curr->node)
            swrModel_ByteSwapNode(curr->node);

        curr++;
    }
    curr++;

    if (SWAP32(curr->value) == 'Data')
    {
        curr->value = 'Data';
        curr++;

        curr->value = SWAP32(curr->value);
        uint32_t size = curr->value;
        curr++;

        for (int i = 0; i < size; i++)
        {
            curr->value = SWAP32(curr->value);
            curr++;
        }
    }

    if (SWAP32(curr->value) == 'Anim')
    {
        curr->value = 'Anim';
        curr++;

        while (curr->animation)
        {
            swrModel_ByteSwapAnimation(curr->animation);
            curr++;
        }
        curr++;
    }

    if (SWAP32(curr->value) == 'AltN')
    {
        curr->value = 'AltN';
        curr++;

        if (model_type == 'MAlt')
        {
            while (curr->node)
            {
                swrModel_ByteSwapNode(curr->node);
                curr++;
            }
        }
    }
}

// 0x004476B0 HOOK
void swrModel_ByteSwapNode(swrModel_Node* node)
{
    if (node == NULL)
        return;

    if (node->flags_0 == 0x3064 || node->flags_0 == 0x5064 || node->flags_0 == 0x5065 || node->flags_0 == 0x5066 || node->flags_0 == 0xD064 || node->flags_0 == 0xD065 || node->flags_0 == 0xD066)
        return; // node already byte swapped before.

    node->flags_0 = SWAP32(node->flags_0);
    node->flags_1 = SWAP32(node->flags_1);
    node->flags_2 = SWAP32(node->flags_2);
    node->flags_3 = SWAP16(node->flags_3);
    node->flags_4 = SWAP16(node->flags_4);
    node->flags_5 = SWAP32(node->flags_5);

    switch (node->flags_0)
    {
    case 0x3064:
        node->num_children = SWAP32(node->num_children);

        for (int i = 0; i < ARRAYSIZE(node->node_3064_data.aabb); i++)
            FLOAT_SWAP32_INPLACE(&node->node_3064_data.aabb[i]);

        for (int i = 0; i < node->num_children; i++)
        {
            swrModel_Mesh* mesh = node->meshes[i];
            if (mesh == NULL)
                continue;

            swrModel_MeshMaterial* mesh_material = mesh->mesh_material;
            if (mesh_material && !swrModel_MeshMaterialAlreadyByteSwapped(mesh_material))
            {
                swrModel_AlreadyByteSwappedMeshMaterials[swrModel_NumAlreadyByteSwappedMeshMaterials++] = mesh_material;
                mesh_material->type = SWAP32(mesh_material->type);
                mesh_material->texture_offset[0] = SWAP16(mesh_material->texture_offset[0]);
                mesh_material->texture_offset[1] = SWAP16(mesh_material->texture_offset[1]);

                swrModel_MaterialTexture* mesh_texture = mesh_material->material_texture;
                if (mesh_texture && !swrModel_MeshTextureAlreadyByteSwapped(mesh_texture))
                {
                    swrModel_AlreadyByteSwappedMeshTextures[swrModel_NumAlreadyByteSwappedMeshTextures++] = mesh_texture;
                    mesh_texture->unk0 = SWAP32(mesh_texture->unk0);
                    mesh_texture->res[0] = SWAP16(mesh_texture->res[0]);
                    mesh_texture->res[1] = SWAP16(mesh_texture->res[1]);
                    mesh_texture->unk1[0] = SWAP16(mesh_texture->unk1[0]);
                    mesh_texture->unk1[1] = SWAP16(mesh_texture->unk1[1]);
                    mesh_texture->width = SWAP16(mesh_texture->width);
                    mesh_texture->height = SWAP16(mesh_texture->height);
                    mesh_texture->unk2 = SWAP16(mesh_texture->unk2);
                    mesh_texture->unk3 = SWAP16(mesh_texture->unk3);
                    mesh_texture->unk4 = SWAP16(mesh_texture->unk4);
                    mesh_texture->unk5 = SWAP16(mesh_texture->unk5);
                    // the rest of the struct is not byte swapped...
                }

                swrModel_Material* material = mesh_material->material;
                if (material && !swrModel_MaterialAlreadyByteSwapped(material))
                {
                    swrModel_AlreadyByteSwappedMaterials[swrModel_NumAlreadyByteSwappedMaterials++] = material;
                    material->unk1 = SWAP32(material->unk1);
                    material->unk2 = SWAP16(material->unk2);

                    for (int j = 0; j < ARRAYSIZE(material->unk3); j++)
                        material->unk3[j] = SWAP32(material->unk3[j]);

                    for (int j = 0; j < ARRAYSIZE(material->unk4); j++)
                        material->unk4[j] = SWAP32(material->unk4[j]);

                    material->unk6 = SWAP32(material->unk6);
                    material->unk7 = SWAP32(material->unk7);
                }
            }

            swrModel_Mapping* mapping = mesh->mapping;
            if (mapping)
            {
                mapping->unk1 = SWAP16(mapping->unk1);
                mapping->fog_start = SWAP16(mapping->fog_start);
                mapping->fog_end = SWAP16(mapping->fog_end);

                mapping->light_flags = SWAP16(mapping->light_flags);
                FLOAT_SWAP32_INPLACE(&mapping->light_vector[0]);
                FLOAT_SWAP32_INPLACE(&mapping->light_vector[1]);
                FLOAT_SWAP32_INPLACE(&mapping->light_vector[2]);

                mapping->unk14 = SWAP32(mapping->unk14);
                mapping->unk15 = SWAP32(mapping->unk15);
                mapping->unk16 = SWAP32(mapping->unk16);

                mapping->vehicle_reaction = SWAP32(mapping->vehicle_reaction);

                mapping->unk18 = SWAP16(mapping->unk18);
                mapping->unk19 = SWAP16(mapping->unk19);

                mapping->unk20 = SWAP32(mapping->unk20);
                mapping->unk21 = SWAP32(mapping->unk21);

                swrModel_MappingChild* sub = mapping->subs;
                // some kind of linked list
                while (sub)
                {
                    for (int j = 0; j < ARRAYSIZE(sub->vector0); j++)
                        FLOAT_SWAP32_INPLACE(&sub->vector0[j]);

                    for (int j = 0; j < ARRAYSIZE(sub->vector1); j++)
                        FLOAT_SWAP32_INPLACE(&sub->vector1[j]);

                    sub->unk3 = SWAP32(sub->unk3);
                    sub->unk4 = SWAP32(sub->unk4);
                    // unk5, unk6 missing
                    sub->unk7 = SWAP16(sub->unk7);
                    sub->unk9 = SWAP16(sub->unk9);
                    sub = sub->next;
                }
            }

            for (int j = 0; j < ARRAYSIZE(mesh->aabb); j++)
                FLOAT_SWAP32_INPLACE(&mesh->aabb[j]);

            mesh->num_primitives = SWAP16(mesh->num_primitives);
            mesh->primitive_type = SWAP16(mesh->primitive_type);

            if (mesh->primitive_sizes)
            {
                for (int j = 0; j < mesh->num_primitives; j++)
                    mesh->primitive_sizes[j] = SWAP32(mesh->primitive_sizes[j]);
            }

            int num_unknown_vertices = 0;
            if (mesh->collision_vertices && mesh->unknown_ptr)
            {
                switch (mesh->primitive_type)
                {
                case 3:
                    num_unknown_vertices = 3 * mesh->num_primitives;
                    break;
                case 4:
                    num_unknown_vertices = 4 * mesh->num_primitives;
                    break;
                case 5:
                    for (int j = 0; j < mesh->num_primitives; j++)
                        num_unknown_vertices += mesh->primitive_sizes[j] + 2;

                    break;
                default:
                    HANG("invalid primitive type in swrModel_Mesh");
                }
            }
            if (num_unknown_vertices > 0)
            {
                for (int j = 0; j < num_unknown_vertices; j++)
                    mesh->unknown_ptr[j] = SWAP16(mesh->unknown_ptr[j]);
            }

            mesh->num_collision_vertices = SWAP16(mesh->num_collision_vertices);
            if (!swrModel_SkipByteswapCollisionVertices && mesh->collision_vertices)
            {
                for (int j = 0; j < mesh->num_collision_vertices; j++)
                {
                    mesh->collision_vertices[j].x = SWAP16(mesh->collision_vertices[j].x);
                    mesh->collision_vertices[j].y = SWAP16(mesh->collision_vertices[j].y);
                    mesh->collision_vertices[j].z = SWAP16(mesh->collision_vertices[j].z);
                }
            }

            mesh->num_vertices = SWAP16(mesh->num_vertices);
            // it seems like vertices and index buffer are not swapped, this seems weird...

            mesh->unk1 = SWAP16(mesh->unk1);
            mesh->unk2 = SWAP16(mesh->unk2);
        }

        break;
    case 0x5064:
        // those nodes dont contain any data of their own.
        break;
    case 0x5065:
        node->node_5065_data.unk = SWAP32(node->node_5065_data.unk);
        break;
    case 0x5066:
        for (int i = 0; i < ARRAYSIZE(node->node_5066_data.lods_distances); i++)
            FLOAT_SWAP32_INPLACE(&node->node_5066_data.lods_distances[i]);

        for (int i = 0; i < ARRAYSIZE(node->node_5066_data.unk); i++)
            node->node_5066_data.unk[i] = SWAP32(&node->node_5066_data.unk[i]);

        break;
    case 0xD064:
        for (int i = 0; i < ARRAYSIZE(node->node_d064_data.transform); i++)
            FLOAT_SWAP32_INPLACE(&node->node_d064_data.transform[i]);

        break;
    case 0xD065:
        for (int i = 0; i < ARRAYSIZE(node->node_d065_data.transform); i++)
            FLOAT_SWAP32_INPLACE(&node->node_d065_data.transform[i]);

        for (int i = 0; i < ARRAYSIZE(node->node_d065_data.vector); i++)
            FLOAT_SWAP32_INPLACE(&node->node_d065_data.vector[i]);

        break;
    case 0xD066:
        node->node_d066_data.unk1 = SWAP16(node->node_d066_data.unk1);
        node->node_d066_data.unk2 = SWAP16(node->node_d066_data.unk2);

        for (int i = 0; i < ARRAYSIZE(node->node_d066_data.vector); i++)
            FLOAT_SWAP32_INPLACE(&node->node_d066_data.vector[i]);

        break;
    default:
        HANG("invalid swrModel_Node.flags_0");
    }

    // if node has children
    if (node->flags_0 & 0x4000)
    {
        node->num_children = SWAP32(node->num_children);
        if (node->num_children > 0)
        {
            for (int i = 0; i < node->num_children; i++)
                swrModel_ByteSwapNode(node->child_nodes[i]);
        }
    }
}

// 0x00448180 HOOK
void swrModel_ByteSwapAnimation(swrModel_Animation* animation)
{
    FLOAT_SWAP32_INPLACE(&animation->loop_transition_speed);
    FLOAT_SWAP32_INPLACE(&animation->transition_speed);
    animation->transition_from_this_key_frame_index = SWAP32(animation->transition_from_this_key_frame_index);
    FLOAT_SWAP32_INPLACE(&animation->transition_interp_factor);
    animation->transition_from_this_animation_time = SWAP32(&animation->transition_from_this_animation_time);
    FLOAT_SWAP32_INPLACE(&animation->animation_start_time);
    FLOAT_SWAP32_INPLACE(&animation->animation_end_time);
    FLOAT_SWAP32_INPLACE(&animation->animation_duration);
    FLOAT_SWAP32_INPLACE(&animation->duration3);
    animation->flags = SWAP32(animation->flags);
    animation->num_key_frames = SWAP32(animation->num_key_frames);
    FLOAT_SWAP32_INPLACE(&animation->duration4);
    FLOAT_SWAP32_INPLACE(&animation->duration5);
    FLOAT_SWAP32_INPLACE(&animation->animation_speed);
    FLOAT_SWAP32_INPLACE(&animation->animation_time);
    animation->key_frame_index = SWAP32(animation->key_frame_index);
    animation->unk11 = SWAP32(animation->unk11);

    int num_elems_per_value = 0;
    switch (animation->type)
    {
    case 0x1:
    case 0xB:
    case 0xC:
        num_elems_per_value = 1;
        break;
    case 0x4:
        num_elems_per_value = 2;
        break;
    case 0x6:
    case 0x8:
        num_elems_per_value = 4;
        break;
    case 0x7:
    case 0x9:
    case 0xA:
        num_elems_per_value = 3;
        break;
    }
    if (animation->key_frame_times)
    {
        for (int i = 0; i < animation->num_key_frames; i++)
            FLOAT_SWAP32_INPLACE(&animation->key_frame_times[i]);
    }
    if (animation->key_frame_values && num_elems_per_value != 0)
    {
        for (int i = 0; i < num_elems_per_value * animation->num_key_frames; i++)
            FLOAT_SWAP32_INPLACE(&animation->key_frame_values[i]);
    }
}

// 0x004475F0 HOOK
bool swrModel_MeshMaterialAlreadyByteSwapped(swrModel_MeshMaterial* material)
{
    for (int i = 0; i < swrModel_NumAlreadyByteSwappedMeshMaterials; i++)
    {
        if (swrModel_AlreadyByteSwappedMeshMaterials[i] == material)
            return true;
    }
    return false;
}

// 0x00447630 HOOK
bool swrModel_MeshTextureAlreadyByteSwapped(swrModel_MaterialTexture* texture)
{
    for (int i = 0; i < swrModel_NumAlreadyByteSwappedMeshTextures; i++)
    {
        if (swrModel_AlreadyByteSwappedMeshTextures[i] == texture)
            return true;
    }
    return false;
}

// 0x00447670 HOOK
bool swrModel_MaterialAlreadyByteSwapped(swrModel_Material* material)
{
    for (int i = 0; i < swrModel_NumAlreadyByteSwappedMaterials; i++)
    {
        if (swrModel_AlreadyByteSwappedMaterials[i] == material)
            return true;
    }
    return false;
}

// 0x004258E0 HOOK
void swrModel_ClearLoadedAnimations()
{
    memset(swrModel_LoadedAnimationsBuffer, 0, sizeof(swrModel_LoadedAnimationsBuffer));
    swrModel_NumLoadedAnimations = 0;
}

// 0x00425900 HOOK
void swrModel_LoadAnimation(swrModel_Animation* animation)
{
    swrModel_LoadedAnimationsBuffer[swrModel_NumLoadedAnimations++] = animation;
    // now reset the animations internal state:
    animation->animation_start_time = 0;

    float duration = animation->flags & 0x20 ? animation->duration5 : animation->duration4;
    animation->animation_end_time = duration;
    animation->animation_duration = duration;
    animation->duration3 = duration;
    animation->loop_transition_speed = 0;
    if (animation->type == 8 && animation->node_ptr)
        animation->node_ptr->flags_3 &= ~8u;

    animation->flags |= ANIMATION_RESET;
}

// 0x00448BD0 HOOK
swrModel_Animation** swrModel_LoadAllAnimationsOfModel(swrModel_Header* model_header)
{
    swrModel_HeaderEntry* curr = model_header->entries;
    // skip over nodes...
    while (curr->value != 0xFFFFFFFF)
        curr++;

    // skip over data...
    curr++;
    if (curr->value == 'Data')
    {
        curr++;
        uint32_t size = curr->value;
        curr += size;
    }

    uint32_t min_anim_ptr = 0xFFFFFFFF;
    swrModel_Animation** anim_list_ptr = NULL;
    if (curr->value == 'Anim')
    {
        // load animations into buffer
        curr++;
        anim_list_ptr = &curr->animation;

        while (curr->animation)
        {
            if (curr->value < min_anim_ptr)
                min_anim_ptr = curr->value;

            swrModel_LoadAnimation(curr->animation);
            curr++;
        }
    }

    if (min_anim_ptr == 0xFFFFFFFF)
    {
        // did not find any animation
        assetBufferUnknownStats2 = 0;
        return anim_list_ptr;
    }

    assetBufferUnknownStats2 = assetBufferUnknownStats3 - min_anim_ptr;
    assetBufferUnknownStats1 -= assetBufferUnknownStats3 - min_anim_ptr;

    return anim_list_ptr;
}

// 0x00426740 HOOK
swrModel_Animation* swrModel_FindLoadedAnimation(void* affected_object, int animation_type)
{
    if (affected_object == NULL)
        return NULL;

    for (int i = 0; i < swrModel_NumLoadedAnimations; i++)
    {
        swrModel_Animation* anim = swrModel_LoadedAnimationsBuffer[i];
        if (anim == NULL)
            continue;

        // cannot find a deactivated animation
        if ((anim->flags & ANIMATION_DISABLED) == 0 && anim->type == animation_type && anim->node_ptr == affected_object)
            return anim;
    }

    return NULL;
}

// 0x00425980 HOOK
double swrModel_AnimationComputeInterpFactor(swrModel_Animation* anim, float anim_time, int key_frame_index)
{
    return (anim_time - anim->key_frame_times[key_frame_index]) / (anim->key_frame_times[key_frame_index + 1] - anim->key_frame_times[key_frame_index]);
}

// 0x004259B0 HOOK
void swrModel_AnimationInterpolateSingleValue(float* result, swrModel_Animation* anim, float time, int key_frame_index)
{
    const float t0 = anim->key_frame_times[key_frame_index];
    const float t1 = anim->key_frame_times[key_frame_index + 1];

    const float v0 = anim->key_frame_values[key_frame_index];
    const float v1 = anim->key_frame_values[key_frame_index + 1];

    if (time >= t1)
    {
        *result = v1;
    }
    else if (time <= t0)
    {
        *result = v0;
    }
    else
    {
        const float t = swrModel_AnimationComputeInterpFactor(anim, time, key_frame_index);
        *result = (1 - t) * v0 + t * v1;
    }
}

// 0x00425A60 HOOK
void swrModel_AnimationInterpolateVec3(rdVector3* result, swrModel_Animation* anim, float time, int key_frame_index)
{
    const float t0 = anim->key_frame_times[key_frame_index];
    const float t1 = anim->key_frame_times[key_frame_index + 1];

    const rdVector3 v0 = anim->key_frame_translations[key_frame_index];
    const rdVector3 v1 = anim->key_frame_translations[key_frame_index + 1];

    if (time >= t1)
    {
        *result = v1;
    }
    else if (time <= t0)
    {
        *result = v0;
    }
    else
    {
        const float t = swrModel_AnimationComputeInterpFactor(anim, time, key_frame_index);
        rdVector_Scale3Add3_both(result, (1 - t), &v0, t, &v1);
    }
}

// 0x00425BA0 HOOK
void swrModel_AnimationInterpolateAxisAngle(rdVector4* result, swrModel_Animation* anim, float time, int key_frame_index)
{
    const float t0 = anim->key_frame_times[key_frame_index];
    const float t1 = anim->key_frame_times[key_frame_index + 1];

    const rdVector4 v0 = anim->key_frame_axis_angle_rotations[key_frame_index];
    const rdVector4 v1 = anim->key_frame_axis_angle_rotations[key_frame_index + 1];

    if (time >= t1)
    {
        *result = v1;
    }
    else if (time <= t0)
    {
        *result = v0;
    }
    else
    {
        const float t = swrModel_AnimationComputeInterpFactor(anim, time, key_frame_index);

        rdVector4 q0;
        rdVector4 q1;
        rdMath_AxisAngleToQuaternion(&q0, &v0);
        rdMath_AxisAngleToQuaternion(&q1, &v1);

        rdVector4 qr;
        rdMath_SlerpQuaternions(&q0, &q1, t, &qr);

        rdMath_QuaternionToAxisAngle(result, &qr);
    }
}

// 0x00425D10
void swrModel_UpdateTranslationAnimation(swrModel_Animation* anim)
{
    rdVector3 result;
    swrModel_AnimationInterpolateVec3(&result, anim, anim->animation_time, anim->key_frame_index);
    if (anim->flags & ANIMATION_TRANSITION)
    {
        // lerp result with transition position
        rdVector3 transition_result;
        swrModel_AnimationInterpolateVec3(&transition_result, anim, anim->transition_from_this_animation_time, anim->transition_from_this_key_frame_index);
        rdVector_Scale3Add3_both(&result, (1 - anim->transition_interp_factor), &transition_result, anim->transition_interp_factor, &result);
    }
    if (anim->node_ptr)
        swrModel_NodeSetTranslation(anim->node_ptr, result.x, result.y, result.z);
}

// 0x00425DE0
void swrModel_UpdateScaleAnimation(swrModel_Animation* anim)
{
    rdVector3 result;
    swrModel_AnimationInterpolateVec3(&result, anim, anim->animation_time, anim->key_frame_index);
    if (anim->flags & ANIMATION_TRANSITION)
    {
        // lerp result with transition position
        rdVector3 transition_result;
        swrModel_AnimationInterpolateVec3(&transition_result, anim, anim->transition_from_this_animation_time, anim->transition_from_this_key_frame_index);
        rdVector_Scale3Add3_both(&result, (1 - anim->transition_interp_factor), &transition_result, anim->transition_interp_factor, &result);
    }
    if (anim->node_ptr)
    {
        rdMatrix44 matrix;
        swrModel_NodeGetTransform(anim->node_ptr, &matrix);

        rdVector3 translation;
        rdMatrix44 rotation;
        rdVector3 scale;
        rdMatrix_ToTransRotScale(&matrix, &translation, &rotation, &scale);
        rdMatrix_FromTransRotScale(&matrix, &translation, &rotation, &result);

        swrModel_NodeSetTransform(anim->node_ptr, &matrix);
    }
}

// 0x00425F00 HOOK
void swrModel_UpdateAxisAngleAnimation(swrModel_Animation* anim)
{
    rdVector4 result;
    swrModel_AnimationInterpolateAxisAngle(&result, anim, anim->animation_time, anim->key_frame_index);
    if (anim->flags & ANIMATION_TRANSITION)
    {
        // lerp result with transition position
        rdVector4 transition_result;
        swrModel_AnimationInterpolateAxisAngle(&transition_result, anim, anim->transition_from_this_animation_time, anim->transition_from_this_key_frame_index);

        rdVector4 q0;
        rdVector4 q1;
        rdMath_AxisAngleToQuaternion(&q0, &transition_result);
        rdMath_AxisAngleToQuaternion(&q1, &result);

        rdVector4 qr;
        rdMath_SlerpQuaternions(&q0, &q1, anim->transition_interp_factor, &qr);

        rdMath_QuaternionToAxisAngle(&result, &qr);
    }
    if (anim->node_ptr)
    {
        if (result.w >= 0.0001 || result.w <= -0.0001)
        {
            rdMatrix44 matrix;
            swrModel_NodeGetTransform(anim->node_ptr, &matrix);

            rdVector3 translation;
            rdMatrix44 rotation;
            rdVector3 scale;
            rdMatrix_ToTransRotScale(&matrix, &translation, &rotation, &scale);
            rdMatrix_BuildFromVectorAngle44(&rotation, result.w, result.x, result.y, result.z);
            rdMatrix_FromTransRotScale(&matrix, &translation, &rotation, &scale);

            swrModel_NodeSetTransform(anim->node_ptr, &matrix);
        }
        else
        {
            swrModel_NodeSetRotationByEulerAngles(anim->node_ptr, 0, 0, 0);
        }
    }
}

// 0x00426080
void swrModel_UpdateUnknownAnimation(swrModel_Animation* anim)
{
    HANG("TODO");
}

// 0x004260F0 HOOK
void swrModel_UpdateTextureScrollAnimation(swrModel_Animation* anim, int coord)
{
    float result;
    swrModel_AnimationInterpolateSingleValue(&result, anim, anim->animation_time, anim->key_frame_index);
    if (anim->flags & ANIMATION_TRANSITION)
    {
        // lerp result with transition position
        float transition_result;
        // game has a bug here and calls the Vec3 version instead
        swrModel_AnimationInterpolateSingleValue(&transition_result, anim, anim->transition_from_this_animation_time, anim->transition_from_this_key_frame_index);
        result = (1 - anim->transition_interp_factor) * transition_result + anim->transition_interp_factor * result;
    }
    if (anim->material_ptr && anim->material_ptr->material_texture)
    {
        swrModel_MeshMaterial* mat = anim->material_ptr;
        swrModel_MaterialTexture* tex = mat->material_texture;
        int16_t* offset = &mat->texture_offset[coord];
        int16_t res = tex->res[coord];

        *offset = res * result;

        // correct wrap around
        while (*offset > res)
            *offset -= res;

        while (*offset < 0)
            *offset += res;
    }
}

// 0x00426290 HOOK
void swrModel_AnimationHandleLoopTransition(swrModel_Animation* anim, float curr_time, float new_time)
{
    anim->flags |= ANIMATION_TRANSITION;
    anim->transition_speed = anim->loop_transition_speed;

    double curr_delta = anim->animation_time - curr_time;
    anim->transition_interp_factor = (abs(curr_delta) - swrRace_deltaTimeSecs) / anim->transition_speed;

    // just set here s.t. the next function call uses the right param...
    anim->animation_time = curr_time;
    anim->transition_from_this_key_frame_index = swrModel_AnimationFindKeyFrameIndex(anim);
    anim->transition_from_this_animation_time = curr_time;

    anim->animation_time = new_time;
    anim->key_frame_index = swrModel_AnimationFindKeyFrameIndex(anim);

    swrModel_AnimationUpdateTime(anim);
}

// 0x00426330 HOOK
void swrModel_AnimationUpdateTime(swrModel_Animation* anim)
{
    // first: set the animation time

    anim->flags &= ~ANIMATION_TRANSITIONING_NOW;
    if (anim->flags & ANIMATION_RESET)
    {
        // setting animation time is skipped if the animation was reset.
        anim->flags &= ~ANIMATION_RESET;
    }
    else if (anim->flags & ANIMATION_TRANSITION)
    {
        anim->flags |= ANIMATION_TRANSITIONING_NOW;
        anim->transition_interp_factor += swrRace_deltaTimeSecs / anim->transition_speed;
        if (anim->transition_interp_factor >= 1)
        {
            // transition is finished.
            anim->flags &= ~ANIMATION_TRANSITION;
            // i dont really understand this calculation...
            anim->animation_time += (anim->transition_interp_factor - 1) * swrModel_GlobalAnimationSpeed * anim->transition_speed;
        }
    }
    else
    {
        anim->animation_time += anim->animation_speed * swrModel_GlobalAnimationSpeed * swrRace_deltaTimeSecs;
    }

    // then: update loops, wraparounds etc.

    // TODO there seems to be undefined behavior in the original game... those vars here are not initialized.
    float end_time = anim->animation_end_time;
    float start_time = anim->animation_start_time;
    float duration = anim->animation_duration;

    // i dont understand this parts, its some kind of special mode.
    if (anim->flags & 0x06000000)
    {
        if (anim->animation_time < anim->animation_start_time || anim->animation_time > anim->animation_end_time)
        {
            end_time = anim->duration3;
            start_time = 0.0;
            duration = anim->duration3;
        }
        else if (anim->flags & 0x02000000)
        {
            anim->flags &= ~0x02000000;
            anim->flags |= ANIMATION_LOOP;
        }
        else
        {
            anim->flags &= ~0x04000000;
            anim->flags &= ~ANIMATION_LOOP;
        }
    }

    // special case1: animation reached end.
    if (anim->animation_time > end_time)
    {
        if (anim->flags & ANIMATION_LOOP)
        {
            if (anim->flags & ANIMATION_LOOP_WITH_TRANSITION)
            {
                swrModel_AnimationHandleLoopTransition(anim, end_time, start_time);
            }
            else
            {
                // rewind
                while (anim->animation_time > end_time)
                {
                    anim->flags |= ANIMATION_TRANSITIONING_NOW;
                    anim->animation_time -= duration;
                }
            }
        }
        else
        {
            anim->animation_time = end_time; // just stop here.
        }
        anim->key_frame_index = swrModel_AnimationFindKeyFrameIndex(anim);
    }
    // special case 2: animation reached start (reversed animation speed)
    else if (anim->animation_time < start_time)
    {
        if (anim->flags & ANIMATION_LOOP)
        {
            if (anim->flags & ANIMATION_LOOP_WITH_TRANSITION)
            {
                swrModel_AnimationHandleLoopTransition(anim, start_time, end_time);
            }
            else
            {
                // rewind
                while (anim->animation_time < start_time)
                {
                    anim->flags |= ANIMATION_TRANSITIONING_NOW;
                    anim->animation_time += duration;
                }
            }
        }
        else
        {
            anim->animation_time = start_time; // just stop here.
        }
        anim->key_frame_index = swrModel_AnimationFindKeyFrameIndex(anim);
    }
    // normal case: animation time within start/end bounds.
    else
    {
        // this is just an optimized version of swrModel_AnimationFindKeyFrameIndex that starts the search at the current key frame index.

        while (anim->animation_time < anim->key_frame_times[anim->key_frame_index] && anim->key_frame_index > 0)
            anim->key_frame_index--;

        while (anim->animation_time > anim->key_frame_times[anim->key_frame_index + 1] && anim->key_frame_index < anim->num_key_frames - 2)
            anim->key_frame_index++;
    }
}

// 0x00426220 HOOK
uint32_t swrModel_AnimationFindKeyFrameIndex(swrModel_Animation* anim)
{
    const float time = anim->animation_time;
    const float* keys = anim->key_frame_times;
    const int n = anim->num_key_frames;

    if (time > keys[n - 1])
        return n - 2;

    if (time < keys[0])
        return 0;

    // searches from back to front
    int i = n - 2;
    while (time < keys[i])
        i--;

    return i;
}

// 0x00426660 HOOK
void swrModel_UpdateAnimations()
{
    for (int i = 0; i < swrModel_NumLoadedAnimations; i++)
    {
        swrModel_Animation* anim = swrModel_LoadedAnimationsBuffer[i];
        if ((anim == NULL) || (anim->flags & ANIMATION_DISABLED) || !(anim->flags & ANIMATION_ENABLED))
            continue;

        swrModel_AnimationUpdateTime(anim);

        switch (anim->type)
        {
        case 0x2:
            swrModel_UpdateUnknownAnimation(anim);
            break;
        case 0x8:
            swrModel_UpdateAxisAngleAnimation(anim);
            break;
        case 0x9:
            swrModel_UpdateTranslationAnimation(anim);
            break;
        case 0xA:
            swrModel_UpdateScaleAnimation(anim);
            break;
        case 0xB:
            swrModel_UpdateTextureScrollAnimation(anim, 0);
            break;
        case 0xC:
            swrModel_UpdateTextureScrollAnimation(anim, 1);
            break;
        }
    }
}

// 0x004267A0 HOOK
void swrModel_AnimationSetLoopPoints(swrModel_Animation* anim, float start_time, float end_time)
{
    if (start_time > end_time)
        HANG("invalid start_time/end_time");

    if (start_time < 0)
        start_time = 0;
    if (end_time < 0)
        end_time = 0;

    anim->animation_start_time = start_time;
    anim->animation_end_time = end_time;
    anim->animation_duration = end_time - start_time;
}

// 0x00426810 HOOK
void swrModel_AnimationSetFlags(swrModel_Animation *anim, swrModel_AnimationFlags flags)
{
    anim->flags |= flags;
}

// 0x00426820 HOOK
void swrModel_AnimationClearFlags(swrModel_Animation *anim, swrModel_AnimationFlags flags)
{
    anim->flags &= ~flags;
}

// 0x00426840 HOOK
void swrModel_AnimationSetTime(swrModel_Animation *anim, float time)
{
    anim->animation_time = time;
    anim->key_frame_index = swrModel_AnimationFindKeyFrameIndex(anim);
    anim->flags |= ANIMATION_RESET;
}

// 0x00426880 HOOK
void swrModel_AnimationSetSpeed(swrModel_Animation* anim, float speed)
{
    anim->animation_speed = speed;
}

// 0x00426890 HOOK
void swrModel_AnimationTransitionToTime(swrModel_Animation* anim, float time, float transition_speed)
{
    anim->flags |= ANIMATION_TRANSITION;
    anim->transition_interp_factor = 0;
    anim->transition_speed = transition_speed;
    anim->transition_from_this_key_frame_index = anim->key_frame_index;
    anim->transition_from_this_animation_time = anim->animation_time;
    anim->animation_time = time;
    anim->key_frame_index = swrModel_AnimationFindKeyFrameIndex(anim);
}

// 0x00426900 HOOK
void swrModel_AnimationSetLoopTransitionSpeed(swrModel_Animation* anim, float transition_speed)
{
    anim->loop_transition_speed = transition_speed;
}

// 0x0044B360 HOOK
void swrModel_AnimationsSetSettings(swrModel_Animation** anims, float animation_time, float loop_start_time, float loop_end_time, bool set_loop, float transition_speed, float loop_transition_speed)
{
    if (anims == NULL)
        return;

    while (*anims)
    {
        swrModel_Animation* anim = *anims;
        swrModel_AnimationSetLoopPoints(anim, loop_start_time, loop_end_time);

        if (set_loop)
        {
            swrModel_AnimationSetFlags(anim, 0x02000000 | ANIMATION_LOOP);
            swrModel_AnimationClearFlags(anim, 0x04000000);

            if (loop_transition_speed <= 0)
            {
                swrModel_AnimationClearFlags(anim, ANIMATION_LOOP_WITH_TRANSITION);
            }
            else
            {
                swrModel_AnimationSetFlags(anim, ANIMATION_LOOP_WITH_TRANSITION);
                swrModel_AnimationSetLoopTransitionSpeed(anim, loop_transition_speed);
            }
        }
        else
        {
            swrModel_AnimationSetFlags(anim, 0x04000000);
            swrModel_AnimationClearFlags(anim, 0x02000000);
        }

        if (animation_time >= 0)
        {
            if (transition_speed <= 0)
            {
                swrModel_AnimationSetTime(anim, animation_time);
            } else
            {
                swrModel_AnimationTransitionToTime(anim, animation_time, transition_speed);
            }
        }

        anims++;
    }
}

// 0x00431620 HOOK
void swrModel_NodeSetTranslation(swrModel_Node* node, float x, float y, float z)
{
    node->node_d064_data.transform[9] = x;
    node->node_d064_data.transform[10] = y;
    node->node_d064_data.transform[11] = z;
    node->flags_3 |= 3u;
}

// 0x004316A0 HOOK
void swrModel_NodeGetTransform(const swrModel_Node* node, rdMatrix44* matrix)
{
    const float* t = node->node_d064_data.transform;
    *matrix = (rdMatrix44){
        { t[0], t[1], t[2], 0 },
        { t[3], t[4], t[5], 0 },
        { t[6], t[7], t[8], 0 },
        { t[9], t[10], t[11], 1 },
    };
}

// 0x00431640 HOOK
void swrModel_NodeSetTransform(swrModel_Node* node, const rdMatrix44* m)
{
    float* t = node->node_d064_data.transform;
    t[0] = m->vA.x;
    t[1] = m->vA.y;
    t[2] = m->vA.z;

    t[3] = m->vB.x;
    t[4] = m->vB.y;
    t[5] = m->vB.z;

    t[6] = m->vC.x;
    t[7] = m->vC.y;
    t[8] = m->vC.z;

    t[9] = m->vD.x;
    t[10] = m->vD.y;
    t[11] = m->vD.z;

    node->flags_3 |= 3u;
}

// 0x004315F0 HOOK
void swrModel_NodeSetRotationByEulerAngles(swrModel_Node* node, float rot_x, float rot_y, float rot_z)
{
    rdMatrix_BuildRotation33((rdMatrix33*)node->node_d064_data.transform, rot_x, rot_y, rot_z);
    node->flags_3 |= 3u;
}