#include "swrModel.h"

#include <globals.h>
#include <macros.h>
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
                mesh_material->unk1 = SWAP16(mesh_material->unk1);
                mesh_material->unk2 = SWAP16(mesh_material->unk2);

                swrModel_MaterialTexture* mesh_texture = mesh_material->material_texture;
                if (mesh_texture && !swrModel_MeshTextureAlreadyByteSwapped(mesh_texture))
                {
                    swrModel_AlreadyByteSwappedMeshTextures[swrModel_NumAlreadyByteSwappedMeshTextures++] = mesh_texture;
                    mesh_texture->unk0 = SWAP32(mesh_texture->unk0);
                    mesh_texture->w = SWAP16(mesh_texture->w);
                    mesh_texture->h = SWAP16(mesh_texture->h);
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
    FLOAT_SWAP32_INPLACE(&animation->default_transition_speed);
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

// 0x004258E0 HOOKs
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
    animation->default_transition_speed = 0;
    if (animation->type == 8 && animation->node_ptr)
        animation->node_ptr->flags_3 &= ~8u;

    animation->flags |= 0x01000000u;
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
        if ((anim->flags & 0x80000000u) == 0 && anim->type == animation_type && anim->node_ptr == affected_object)
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
    float t0 = anim->key_frame_times[key_frame_index];
    float t1 = anim->key_frame_times[key_frame_index + 1];

    float v0 = anim->key_frame_values[key_frame_index];
    float v1 = anim->key_frame_values[key_frame_index + 1];

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
        float t = swrModel_AnimationComputeInterpFactor(anim, time, key_frame_index);
        *result = (1 - t) * v0 + t * v1;
    }
}

// 0x00425A60 HOOK
void swrModel_AnimationInterpolateVec3(rdVector3* result, swrModel_Animation* anim, float time, int key_frame_index)
{
    float t0 = anim->key_frame_times[key_frame_index];
    float t1 = anim->key_frame_times[key_frame_index + 1];

    rdVector3 v0 = anim->key_frame_translations[key_frame_index];
    rdVector3 v1 = anim->key_frame_translations[key_frame_index + 1];

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
        float t = swrModel_AnimationComputeInterpFactor(anim, time, key_frame_index);
        rdVector_Scale3Add3_both(result, (1-t), &v0, t, &v1);
    }
}
