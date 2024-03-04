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

        for (int i = 0; i < ARRAYSIZE(node->data.node_3064_data.aabb); i++)
            FLOAT_SWAP32_INPLACE(&node->data.node_3064_data.aabb[i]);

        for (int i = 0; i < node->num_children; i++)
        {
            swrModel_Mesh* mesh = node->children.meshes[i];
            if (mesh == NULL)
                continue;

            swrModel_MeshMaterial* mesh_material = mesh->mesh_material;
            if (mesh_material && !swrModel_MeshMaterialAlreadyByteSwapped(mesh_material))
            {
                swrModel_AlreadyByteSwappedMeshMaterials[swrModel_NumAlreadyByteSwappedMeshMaterials++] = mesh_material;
                mesh_material->type = SWAP32(mesh_material->type);
                mesh_material->unk1 = SWAP16(mesh_material->unk1);
                mesh_material->unk2 = SWAP16(mesh_material->unk2);

                swrModel_MeshTexture* mesh_texture = mesh_material->mesh_texture;
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

            swrModel_Light* light = mesh->light;
            if (false && light)
            {
                light->unk1 = SWAP16(light->unk1);
                // unk2, unk3 missing
                light->unk4 = SWAP16(light->unk4);
                light->unk5 = SWAP16(light->unk5);
                light->unk6 = SWAP16(light->unk6);
                // unk7, unk8, unk9, unk10 missing
                light->unk11 = SWAP32(light->unk11);
                light->unk12 = SWAP32(light->unk12);
                light->unk13 = SWAP32(light->unk13);
                light->unk14 = SWAP32(light->unk14);
                light->unk15 = SWAP32(light->unk15);
                light->unk16 = SWAP32(light->unk16);
                light->unk17 = SWAP32(light->unk17);

                light->unk18 = SWAP16(light->unk18);
                light->unk19 = SWAP16(light->unk19);

                light->unk20 = SWAP32(light->unk20);
                light->unk21 = SWAP32(light->unk21);

                swrModel_Light2* light2 = light->light2;
                // some kind of linked list
                while (light2)
                {
                    for (int j = 0; j < ARRAYSIZE(light2->unk1); j++)
                       light2->unk1[j] = SWAP32(light2->unk1[j]);

                    for (int j = 0; j < ARRAYSIZE(light2->unk2); j++)
                        light2->unk2[j] = SWAP32(light2->unk2[j]);

                    light2->unk3 = SWAP32(light2->unk3);
                    light2->unk4 = SWAP32(light2->unk4);
                    // unk5, unk6 missing
                    light->unk7 = SWAP16(light->unk7);
                    light->unk9 = SWAP16(light->unk9);
                    light2 = light2->next;
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
        node->data.node_5065_data.unk = SWAP32(node->data.node_5065_data.unk);
        break;
    case 0x5066:
        for (int i = 0; i < ARRAYSIZE(node->data.node_5066_data.lods_distances); i++)
            FLOAT_SWAP32_INPLACE(&node->data.node_5066_data.lods_distances[i]);

        for (int i = 0; i < ARRAYSIZE(node->data.node_5066_data.unk); i++)
            FLOAT_SWAP32_INPLACE(&node->data.node_5066_data.unk[i]);

        break;
    case 0xD064:
        for (int i = 0; i < ARRAYSIZE(node->data.node_d064_data.transform); i++)
            FLOAT_SWAP32_INPLACE(&node->data.node_d064_data.transform[i]);

        break;
    case 0xD065:
        for (int i = 0; i < ARRAYSIZE(node->data.node_d065_data.transform); i++)
            FLOAT_SWAP32_INPLACE(&node->data.node_d065_data.transform[i]);

        for (int i = 0; i < ARRAYSIZE(node->data.node_d065_data.unk); i++)
            FLOAT_SWAP32_INPLACE(&node->data.node_d065_data.unk[i]);

        break;
    case 0xD066:
        node->data.node_d066_data.unk1 = SWAP16(node->data.node_d066_data.unk1);
        node->data.node_d066_data.unk2 = SWAP16(node->data.node_d066_data.unk2);

        for (int i = 0; i < ARRAYSIZE(node->data.node_d066_data.unk3); i++)
            FLOAT_SWAP32_INPLACE(&node->data.node_d066_data.unk3[i]);

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
                swrModel_ByteSwapNode(node->children.nodes[i]);
        }
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
bool swrModel_MeshTextureAlreadyByteSwapped(swrModel_MeshTexture* texture)
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
