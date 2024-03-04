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
void* swrModel_LoadFromId(int id)
{
    HANG("TODO");
    return NULL;
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
    animation->unk2 = SWAP32(animation->unk2);
    animation->unk3 = SWAP32(animation->unk3);
    animation->unk4 = SWAP32(animation->unk4);
    animation->unk5 = SWAP32(animation->unk5);
    animation->unk6 = SWAP32(animation->unk7);
    FLOAT_SWAP32_INPLACE(&animation->duration1);
    FLOAT_SWAP32_INPLACE(&animation->duration2);
    FLOAT_SWAP32_INPLACE(&animation->duration3);
    animation->flags = SWAP32(animation->flags);
    animation->num_key_frames = SWAP32(animation->num_key_frames);
    FLOAT_SWAP32_INPLACE(&animation->duration4);
    FLOAT_SWAP32_INPLACE(&animation->duration5);
    FLOAT_SWAP32_INPLACE(&animation->unk8);
    FLOAT_SWAP32_INPLACE(&animation->unk9);
    FLOAT_SWAP32_INPLACE(&animation->unk10);
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
