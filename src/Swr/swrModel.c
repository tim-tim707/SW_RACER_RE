#include "swrModel.h"

#include "swrAssetBuffer.h"
#include "swrLoader.h"

#include <globals.h>
#include <macros.h>
#include <Primitives/rdMath.h>
#include <Primitives/rdMatrix.h>
#include <math.h> // fabs

// 0x00408e60
void* swrModel_AllocMaterial(unsigned int offset, unsigned int byteSize)
{
    int i;
    swrMaterialSlot* spriteSlot;
    void* buffer;

    i = swrAssetBuffer_GetNewIndex(offset);
    spriteSlot = (swrMaterialSlot*)(*stdPlatform_hostServices_ptr->alloc)(8);
    buffer = (*stdPlatform_hostServices_ptr->alloc)(byteSize);
    spriteSlot->data = buffer;
    spriteSlot->next = swrMaterialSlot_array[i];
    swrMaterialSlot_array[i] = spriteSlot;
    return spriteSlot->data;
}

// 0x004258e0 HOOK
void swrModel_ClearSceneAnimations(void)
{
    memset(swrScene_animations, 0, sizeof(swrScene_animations));
    swrScene_animations_count = 0;
}

// 0x004318c0 HOOK
int swrModel_GetNumUnks()
{
    return 4;
}

// 0x004318d0 HOOK
swrModel_unk* swrModel_GetUnk(int index)
{
    return &swrModel_unk_array[index];
}

// 0x00431900 HOOK
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

// 0x00431950 HOOK
void swrModel_UnkSetMat3(swrModel_unk* a1, const rdMatrix44* a2)
{
    a1->unk_mat3 = *a2;
    rdMatrix_Multiply44(&a1->model_matrix, &a1->unk_mat1, &a1->unk_mat3);
}

// 0x00431a00 HOOK
void swrModel_UnkSetRootNode(swrModel_unk* a1, swrModel_Node* a2)
{
    a1->model_root_node = a2;
}

// 0x00431a10 HOOK
void swrModel_UnkSetNodeFlags(swrModel_unk* a1, int flag, int value)
{
    switch (flag)
    {
    case 3:
        a1->unk164 = value;
        break;
    case 4:
        a1->node_flags1_any_match_for_rendering = value;
        break;
    case 5:
        a1->unk160 = value;
        break;
    case 6:
        a1->node_flags1_exact_match_for_rendering = value;
        break;
    }
}

// 0x00448780 TODO broken...
swrModel_Header* swrModel_LoadFromId(MODELID id)
{
    swrLoader_OpenBlock(swrLoader_TYPE_TEXTURE_BLOCK);
    swrLoader_OpenBlock(swrLoader_TYPE_MODEL_BLOCK);

    swrModel_NumAlreadyByteSwappedMeshMaterials = 0;
    swrModel_NumAlreadyByteSwappedMeshTextures = 0;
    swrModel_NumAlreadyByteSwappedMaterials = 0;

    assetBufferModelLoaded = 1;
    assetBufferUnknownStats1 = 0;
    assetBufferUnknownStats4 = 0;
    assetBufferUnknownStats2 = 0;

    uint32_t num_models = 0;
    swrLoader_ReadAt(swrLoader_TYPE_MODEL_BLOCK, 0, &num_models, sizeof(num_models));
    num_models = SWAP32(num_models);

    // check if model id is valid
    if (id < 0 || id >= num_models)
        goto exit;

    struct
    {
        uint32_t mask_offset;
        uint32_t model_offset;
        uint32_t next_model_offset;
    } offsets;

    // read offsets from table
    swrLoader_ReadAt(swrLoader_TYPE_MODEL_BLOCK, 8 * id + 4, &offsets, sizeof(offsets));
    offsets.mask_offset = SWAP32(offsets.mask_offset);
    offsets.model_offset = SWAP32(offsets.model_offset);
    offsets.next_model_offset = SWAP32(offsets.next_model_offset);

    uint32_t mask_size = offsets.model_offset - offsets.mask_offset;
    int model_size = offsets.next_model_offset - offsets.model_offset;

    swrModel_Header* header = NULL;

    // check if model too big to load.
    if (mask_size > 153600)
        goto exit;

    // read mask into buffer
    swrLoader_ReadAt(swrLoader_TYPE_MODEL_BLOCK, offsets.mask_offset, swrLoader_MaskBuffer, mask_size);
    // byte swap masks
    for (unsigned int i = 0; i < mask_size / 4; i++)
        swrLoader_MaskBuffer[i] = SWAP32(swrLoader_MaskBuffer[i]);

    char* buff = swrAssetBuffer_GetBuffer();
    // align buffer
    uint32_t* model_buff = (uint32_t*)(((uintptr_t)buff + 7) & 0xFFFFFFF8);

    // read first bytes to determine if the model is compressed
    swrLoader_ReadAt(swrLoader_TYPE_MODEL_BLOCK, offsets.model_offset, model_buff, 12);
    if (SWAP32(model_buff[0]) == TAG("Comp"))
    {
        int decompressed_size = SWAP32(model_buff[2]);
        char* compressed_data_buff = (char*)((uintptr_t)(assetBufferEnd - (model_size - 12)) & 0xFFFFFFF8);
        if (decompressed_size + 8 <= swrAssetBuffer_RemainingSize() && compressed_data_buff >= (char*)model_buff + decompressed_size)
        {
            swrLoader_ReadAt(swrLoader_TYPE_MODEL_BLOCK, offsets.model_offset + 12, compressed_data_buff, model_size - 12);
            swrLoader_DecompressData(compressed_data_buff, (char*)model_buff);
            swrAssetBuffer_SetBuffer((char*)model_buff + decompressed_size);
        }
        else
        {
            assetBufferOverflow = 1;
            goto exit;
        }
    }
    else if (model_size + 8 <= swrAssetBuffer_RemainingSize())
    {
        // read whole model data
        swrLoader_ReadAt(swrLoader_TYPE_MODEL_BLOCK, offsets.model_offset, model_buff, model_size);
        swrAssetBuffer_SetBuffer((char*)model_buff + model_size);
    }
    else
    {
        assetBufferOverflow = 1;
        goto exit;
    }

    assetBuffer_ModelBeginPtr = buff;
    assetBufferUnknownStats3 = (int)swrAssetBuffer_GetBuffer();

    // use mask to patch up addresses in the model data
    for (int i = 0; i < model_size / 4; i++)
    {
        uint32_t mask_bit_set = swrLoader_MaskBuffer[i / 32] & (1 << (31 - i % 32));
        if (!mask_bit_set)
            continue;

        model_buff[i] = SWAP32(model_buff[i]);
        uint32_t data = model_buff[i];
        if ((data & 0xFF000000) == 0xA000000)
        {
            // this is a texture index
            swrModel_LoadModelTexture(data & 0xFFFFFF, (swrMaterial**)&model_buff[i], (uint8_t**)&model_buff[i + 1]);
        }
        else if (data != 0)
        {
            // this is a pointer
            model_buff[i] = (uintptr_t)model_buff + data;
        }
    }

    header = (swrModel_Header*)model_buff;
    swrModel_ByteSwapModelData(header);

    uint32_t type = header->entries[0].value;
    if (type == TAG("Modl") || type == TAG("Trak") || type == TAG("Podd") || type == TAG("Part") || type == TAG("Scen") || type == TAG("Malt") || type == TAG("Pupp"))
    {
        // skip type part in model header
        header = (swrModel_Header*)(model_buff + 1);
    }

    assetBufferUnknownStats4 = swrAssetBuffer_GetBuffer() - buff;
    assetBufferUnknownStats1 = (char*)assetBufferUnknownStats3 - assetBuffer_ModelBeginPtr;

exit:
    swrLoader_CloseBlock(swrLoader_TYPE_TEXTURE_BLOCK);
    swrLoader_CloseBlock(swrLoader_TYPE_MODEL_BLOCK);
    return header;
}

// 0x004485D0 TODO: crashes on game startup
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

    if (SWAP32(curr->value) == TAG("Data"))
    {
        curr->value = TAG("Data");
        curr++;

        curr->value = SWAP32(curr->value);
        uint32_t size = curr->value;
        curr++;

        for (unsigned int i = 0; i < size; i++)
        {
            curr->value = SWAP32(curr->value);
            curr++;
        }
    }

    if (SWAP32(curr->value) == TAG("Anim"))
    {
        curr->value = TAG("Anim");
        curr++;

        while (curr->animation)
        {
            swrModel_ByteSwapAnimation(curr->animation);
            curr++;
        }
        curr++;
    }

    if (SWAP32(curr->value) == TAG("AltN"))
    {
        curr->value = TAG("AltN");
        curr++;

        if (model_type == TAG("MAlt"))
        {
            while (curr->node)
            {
                swrModel_ByteSwapNode(curr->node);
                curr++;
            }
        }
    }
}

// 0x004476B0 TODO: crashes on game startup
void swrModel_ByteSwapNode(swrModel_Node* node)
{
    if (node == NULL)
        return;

    if (node->type == NODE_MESH_GROUP || node->type == NODE_BASIC || node->type == NODE_SELECTOR || node->type == NODE_LOD_SELECTOR || node->type == NODE_TRANSFORMED || node->type == NODE_TRANSFORMED_WITH_PIVOT || node->type == NODE_TRANSFORMED_COMPUTED)
        return; // node already byte swapped before.

    node->type = SWAP32(node->type);
    node->flags_1 = SWAP32(node->flags_1);
    node->flags_2 = SWAP32(node->flags_2);
    node->flags_3 = SWAP16(node->flags_3);
    node->light_index = SWAP16(node->light_index);
    node->flags_5 = SWAP32(node->flags_5);

    switch (node->type)
    {
    case NODE_MESH_GROUP: {
        swrModel_NodeMeshGroup* mesh_group = (swrModel_NodeMeshGroup*)node;
        node->num_children = SWAP32(node->num_children);

        for (unsigned int i = 0; i < ARRAYSIZE(mesh_group->aabb); i++)
            FLOAT_SWAP32_INPLACE(&mesh_group->aabb[i]);

        for (unsigned int i = 0; i < node->num_children; i++)
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

                    material->color_combine_mode_cycle1 = SWAP32(material->color_combine_mode_cycle1);
                    material->alpha_combine_mode_cycle1 = SWAP32(material->alpha_combine_mode_cycle1);

                    material->color_combine_mode_cycle2 = SWAP32(material->color_combine_mode_cycle2);
                    material->alpha_combine_mode_cycle2 = SWAP32(material->alpha_combine_mode_cycle2);

                    material->render_mode_1 = SWAP32(material->render_mode_1);
                    material->render_mode_2 = SWAP32(material->render_mode_2);
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

                mapping->unk14_node = (swrModel_Node*)SWAP32(mapping->unk14_node);
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
                    for (unsigned int j = 0; j < ARRAYSIZE(sub->vector0); j++)
                        FLOAT_SWAP32_INPLACE(&sub->vector0[j]);

                    for (unsigned int j = 0; j < ARRAYSIZE(sub->vector1); j++)
                        FLOAT_SWAP32_INPLACE(&sub->vector1[j]);

                    sub->unk3 = SWAP32(sub->unk3);
                    sub->unk4 = SWAP32(sub->unk4);
                    // unk5, unk6 missing
                    sub->unk7 = SWAP16(sub->unk7);
                    sub->unk9 = SWAP16(sub->unk9);
                    sub = sub->next;
                }
            }

            for (unsigned int j = 0; j < ARRAYSIZE(mesh->aabb); j++)
                FLOAT_SWAP32_INPLACE(&mesh->aabb[j]);

            mesh->num_primitives = SWAP16(mesh->num_primitives);
            mesh->primitive_type = SWAP16(mesh->primitive_type);

            if (mesh->primitive_sizes)
            {
                for (int j = 0; j < mesh->num_primitives; j++)
                    mesh->primitive_sizes[j] = SWAP32(mesh->primitive_sizes[j]);
            }

            int num_unknown_vertices = 0;
            if (mesh->collision_vertices && mesh->primitive_indices)
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
                    mesh->primitive_indices[j] = SWAP16(mesh->primitive_indices[j]);
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
            mesh->vertex_base_offset = SWAP16(mesh->vertex_base_offset);
        }

        break;
    }
    case NODE_BASIC:
        // those nodes dont contain any data of their own.
        break;
    case NODE_SELECTOR: {
        swrModel_NodeSelector* selector = (swrModel_NodeSelector*)node;
        selector->selected_child_node = SWAP32(selector->selected_child_node);
        break;
    }
    case NODE_LOD_SELECTOR: {
        swrModel_NodeLODSelector* lod = (swrModel_NodeLODSelector*)node;
        for (unsigned int i = 0; i < ARRAYSIZE(lod->lod_distances); i++)
            FLOAT_SWAP32_INPLACE(&lod->lod_distances[i]);

        for (unsigned int i = 0; i < ARRAYSIZE(lod->unk); i++)
            lod->unk[i] = SWAP32(&lod->unk[i]);

        break;
    }
    case NODE_TRANSFORMED: {
        swrModel_NodeTransformed* transformed = (swrModel_NodeTransformed*)node;
        for (int i = 0; i < 12; i++)
            FLOAT_SWAP32_INPLACE((float*)&transformed->transform + i);

        break;
    }
    case NODE_TRANSFORMED_WITH_PIVOT: {
        swrModel_NodeTransformedWithPivot* transformed = (swrModel_NodeTransformedWithPivot*)node;
        for (int i = 0; i < 12; i++)
            FLOAT_SWAP32_INPLACE((float*)&transformed->transform + i);

        for (int i = 0; i < 3; i++)
            FLOAT_SWAP32_INPLACE((float*)&transformed->pivot + i);

        break;
    }
    case NODE_TRANSFORMED_COMPUTED: {
        swrModel_NodeTransformedComputed* transformd = (swrModel_NodeTransformedComputed*)node;
        transformd->follow_model_position = SWAP16(transformd->follow_model_position);
        transformd->orientation_option = SWAP16(transformd->orientation_option);

        for (int i = 0; i < 3; i++)
            FLOAT_SWAP32_INPLACE((float*)&transformd->up_vector + i);

        break;
    }
    default:
        HANG("invalid swrModel_Node.type");
    }

    // if node has children
    if (node->type & NODE_HAS_CHILDREN)
    {
        node->num_children = SWAP32(node->num_children);
        if (node->num_children > 0)
        {
            for (unsigned int i = 0; i < node->num_children; i++)
                swrModel_ByteSwapNode(node->child_nodes[i]);
        }
    }
}

// 0x00448180 TODO: crashes on game startup
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
        for (unsigned int i = 0; i < animation->num_key_frames; i++)
            FLOAT_SWAP32_INPLACE(&animation->key_frame_times[i]);
    }
    if (animation->key_frame_values && num_elems_per_value != 0)
    {
        for (unsigned int i = 0; i < num_elems_per_value * animation->num_key_frames; i++)
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

// 0x00425900 HOOK
void swrModel_LoadAnimation(swrModel_Animation* animation)
{
    swrScene_animations[swrScene_animations_count++] = animation;
    // now reset the animations internal state:
    animation->animation_start_time = 0;

    float duration = animation->flags & 0x20 ? animation->duration5 : animation->duration4;
    animation->animation_end_time = duration;
    animation->animation_duration = duration;
    animation->duration3 = duration;
    animation->loop_transition_speed = 0;
    if (animation->type == 8 && animation->node_ptr)
        animation->node_ptr->node.flags_3 &= ~8u;

    animation->flags |= ANIMATION_RESET;
}

// 0x00448BD0 TODO: crashes on game startup
swrModel_Animation** swrModel_LoadAllAnimationsOfModel(swrModel_Header* model_header)
{
    swrModel_HeaderEntry* curr = model_header->entries;
    // skip over nodes...
    while (curr->value != 0xFFFFFFFF)
        curr++;

    // skip over data...
    curr++;
    if (curr->value == TAG("Data"))
    {
        curr++;
        uint32_t size = curr->value;
        curr += size;
    }

    uint32_t min_anim_ptr = 0xFFFFFFFF;
    swrModel_Animation** anim_list_ptr = NULL;
    if (curr->value == TAG("Anim"))
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

    for (int i = 0; i < swrScene_animations_count; i++)
    {
        swrModel_Animation* anim = swrScene_animations[i];
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

// 0x00425D10 HOOK
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

// 0x00425DE0 HOOK
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
void swrModel_UpdateTextureFlipbookAnimation(swrModel_Animation* anim)
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
    anim->transition_interp_factor = (fabs(curr_delta) - swrRace_deltaTimeSecs) / anim->transition_speed;

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

        while (anim->animation_time > anim->key_frame_times[anim->key_frame_index + 1] && anim->key_frame_index < (int)(anim->num_key_frames - 2))
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

// 0x00426660 TODO: crashes on release build, works fine on debug
void swrModel_UpdateAnimations()
{
    for (int i = 0; i < swrScene_animations_count; i++)
    {
        swrModel_Animation* anim = swrScene_animations[i];
        if ((anim == NULL) || (anim->flags & ANIMATION_DISABLED) || !(anim->flags & ANIMATION_ENABLED))
            continue;

        swrModel_AnimationUpdateTime(anim);

        switch (anim->type)
        {
        case 0x2:
            swrModel_UpdateTextureFlipbookAnimation(anim);
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
void swrModel_AnimationSetFlags(swrModel_Animation* anim, swrModel_AnimationFlags flags)
{
    anim->flags |= flags;
}

// 0x00426820 HOOK
void swrModel_AnimationClearFlags(swrModel_Animation* anim, swrModel_AnimationFlags flags)
{
    anim->flags &= ~flags;
}

// 0x00426840 HOOK
void swrModel_AnimationSetTime(swrModel_Animation* anim, float time)
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
            }
            else
            {
                swrModel_AnimationTransitionToTime(anim, animation_time, transition_speed);
            }
        }

        anims++;
    }
}

// 0x0044C9D0 HOOK
Gfx* swrModel_MeshGetDisplayList(const swrModel_Mesh* mesh)
{
    // if the mesh was already converted to rdModel3Mesh*, the original index buffer is stored inside the rdModel3Mesh*
    if (strncmp(mesh->converted_mesh->name, "aes", 3) == 0)
        return *(Gfx**)&mesh->converted_mesh->name[10];

    return mesh->vertex_display_list;
}

// 0x00465480
void swrModel_LoadAllLightStreaks(swrModel_Header* header)
{
    HANG("TODO");
}

// 0x0046D610 HOOK
void swrModel_AnimationsResetToZero(swrModel_Animation** anims)
{
    while (*anims)
    {
        swrModel_Animation* anim = *anims;
        swrModel_AnimationSetFlags(anim, ANIMATION_ENABLED);
        swrModel_AnimationSetTime(anim, 0.0f);

        anims++;
    }
}

// 0x0046D5C0 HOOK
void swrModel_AnimationsResetToZero2(swrModel_Animation** anims, float animation_speed)
{
    while (*anims)
    {
        swrModel_Animation* anim = *anims;
        swrModel_AnimationSetFlags(anim, ANIMATION_ENABLED);
        swrModel_AnimationSetTime(anim, 0.0f);
        swrModel_AnimationSetSpeed(anim, animation_speed);

        anims++;
    }
}

// 0x00431620 HOOK
void swrModel_NodeSetTranslation(swrModel_NodeTransformed* node, float x, float y, float z)
{
    node->transform.scale = (rdVector3){ x, y, z };
    node->node.flags_3 |= 3u;
}

// 0x004316A0 HOOK
void swrModel_NodeGetTransform(const swrModel_NodeTransformed* node, rdMatrix44* matrix)
{
    rdMatrix_Copy44_34(matrix, &node->transform);
}

// 0x00431640 HOOK
void swrModel_NodeSetTransform(swrModel_NodeTransformed* node, const rdMatrix44* m)
{
    node->transform = (rdMatrix34){ *(const rdVector3*)&m->vA, *(const rdVector3*)&m->vB, *(const rdVector3*)&m->vC, *(const rdVector3*)&m->vD };
    node->node.flags_3 |= 3u;
}

// 0x004315F0 HOOK
void swrModel_NodeSetRotationByEulerAngles(swrModel_NodeTransformed* node, float rot_x, float rot_y, float rot_z)
{
    rdMatrix_BuildRotation33((rdMatrix33*)&node->transform, rot_x, rot_y, rot_z);
    node->node.flags_3 |= 3u;
}

// 0x0042B560
swrModel_MeshMaterial* swrModel_NodeFindFirstMeshMaterial(swrModel_Node* node)
{
    HANG("TODO");
}

// 0x0042B5E0
void swrModel_MeshMaterialSetColors(swrModel_MeshMaterial* a1, int16_t a2, int16_t a3, int16_t a4, int16_t a5_G, int16_t a6, int16_t a7)
{
    HANG("TODO");
}

// 0x0042B640
void swrModel_NodeSetColorsOnAllMaterials(swrModel_Node* a1_pJdge0x10, int a2, int a3, int a4, int a5_G, int a6, int a7)
{
    HANG("TODO");
}

// functions for placing sprites onto the screen while ingame (like player positions, sun and lens flares, light streaks)

// 0x0042B710
void ProjectPointOntoScreen(swrModel_unk* arg0, rdVector3* position, float* pixel_pos_x, float* pixel_pos_y, float* pixel_depth, float* pixel_w, bool position_is_global)
{
    HANG("TODO");
}

// 0x0042BA20
void swrSprite_UpdateLensFlareSpriteSettings(int16_t id, int a2, int a3, float a4, float width, float a6, uint8_t r, uint8_t g, uint8_t b)
{
    HANG("TODO");
}

// 0x0042BB00
void swrSprite_SetScreenPos(int16_t id, int16_t x, int16_t y)
{
    HANG("TODO");
}

// 0x0042BE60
void UpdateDepthValuesOfSpritesWithZBuffer()
{
    HANG("TODO");
}

// 0x0042C400
void ResetPlayerSpriteValues()
{
    HANG("TODO");
}

// 0x0042C420
void SetPlayerSpritePositionOnMap(int player_id, const rdVector3* position, int unknown_value)
{
    HANG("TODO");
}

// 0x0042C460
void ResetLightStreakSprites()
{
    HANG("TODO");
}

// 0x0042C490
void InitLightStreak(int index, rdVector3* position)
{
    HANG("TODO");
}

// 0x0042C4E0
void SetLightStreakSpriteIDs(int index, int sprite_id1, int sprite_id2)
{
    HANG("TODO");
}

// 0x0042C510
void UpdatePlayerPositionSprites(swrModel_unk* a1, BOOL a2)
{
    HANG("TODO");
}

// 0x0042C7A0
void swrText_CreateTextEntry2(int16_t screen_x, int16_t screen_y, char r, char g, char b, char a, char* screenText)
{
    HANG("TODO");
}

// 0x0042C800
void UpdateLightStreakSprites(swrModel_unk* a1)
{
    HANG("TODO");
}

// 0x0042CB00
void UpdateUnknownIngameSprites1(swrModel_unk* a1)
{
    HANG("TODO");
}

// 0x0042CCA0
void UpdateUnknownIngameSprites2(swrModel_unk* a1)
{
    HANG("TODO");
}

// 0x0042D490
void UpdateIngameSprites(swrModel_unk* a1, BOOL a2)
{
    HANG("TODO");
}

// 0x00431710
void swrModel_NodeSetTransformFromTranslationRotation(swrModel_NodeTransformed* node, swrTranslationRotation* arg4)
{
    HANG("TODO");
}

// 0x00431740
void swrModel_NodeSetSelectedChildNode(swrModel_NodeSelector* node, int a2)
{
    HANG("TODO");
}

// 0x00431770
int swrModel_NodeGetFlags(const swrModel_Node* node)
{
    HANG("TODO");
}

// 0x00431780
uint32_t swrModel_NodeGetNumChildren(swrModel_Node* node)
{
    HANG("TODO");
}

// 0x00431790
swrModel_Node* swrModel_NodeGetChild(swrModel_Node* node, int a2)
{
    HANG("TODO");
}

// 0x00431820
void swrModel_MeshGetAABB(swrModel_Mesh* mesh, float* aabb)
{
    HANG("TODO");
}

// 0x00431850
swrModel_Mesh* swrModel_NodeGetMesh(swrModel_NodeMeshGroup* node, int a2)
{
    HANG("TODO");
}

// 0x004318b0 HOOK
swrModel_Mapping* swrModel_MeshGetMapping(swrModel_Mesh* mesh)
{
    return mesh->mapping;
}

// 0x00431B00
uint32_t swrModel_NodeGetFlags1Or2(swrModel_Node* node, int a2)
{
    HANG("TODO");
}

// 0x00431B20
void swrModel_NodeInit(swrModel_Node* node, uint32_t base_flags)
{
    HANG("TODO");
}

// 0x0044FC00
void swrModel_MeshMaterialSetTextureUVOffset(swrModel_MeshMaterial* a1, float a2, float a3)
{
    HANG("TODO");
}

// 0x00454BC0
void swrModel_LoadModelIntoScene(MODELID model_id, MODELID alt_model_id, INGAME_MODELID ingame_model_id, bool load_animations)
{
    HANG("TODO");
}

// 0x00454C60
void swrModel_ClearLoadedModels()
{
    HANG("TODO");
}

// 0x00454C90
void swrModel_ReloadAnimations()
{
    HANG("TODO");
}

// 0x0047BD80
void swrModel_NodeSetAnimationFlagsAndSpeed(swrModel_Node* node, swrModel_AnimationFlags flags_to_disable, swrModel_AnimationFlags flags_to_enable, float speed)
{
    HANG("TODO");
}

// 0x0047e760 HOOK
void swrModel_AddMapping(swrModel_Mapping* mapping)
{
    if ((mapping != NULL) && (swrModel_NbMappings < 200))
    {
        swrModelMappings[swrModel_NbMappings] = mapping;
        swrModel_NbMappings = swrModel_NbMappings + 1;
    }
}

// 0x0047e790 HOOK
int swrModel_FindMapping(swrModel_Mapping* mapping)
{
    int res;
    int i;
    swrModel_Mapping** mappings;

    i = 0;
    res = -1;
    if (0 < swrModel_NbMappings)
    {
        mappings = swrModelMappings;
        do
        {
            if (res != -1)
            {
                return res;
            }
            if (*mappings == mapping)
            {
                res = i;
            }
            i = i + 1;
            mappings = mappings + 1;
        } while (i < swrModel_NbMappings);
    }
    return res;
}

// 0x0047e7c0 HOOK
swrModel_Mapping* swrModel_GetMapping(int index)
{
    if ((-1 < index) && (index < swrModel_NbMappings))
    {
        return swrModelMappings[index];
    }
    return NULL;
}

// 0x00482000
int swrModel_NodeComputeFirstMeshAABB(swrModel_Node* node, float* aabb, int a3)
{
    HANG("TODO");
}

// 0x00447370
void swrModel_LoadTextureDataAndPalette(int* texture_offsets, uint8_t** texture_data_ptr, uint8_t** palette_ptr)
{
    HANG("TODO");
}

// 0x00447420
void swrModel_InitializeTextureBuffer()
{
    swrLoader_OpenBlock(swrLoader_TYPE_TEXTURE_BLOCK);
    swrLoader_ReadAt(swrLoader_TYPE_TEXTURE_BLOCK, 0, &texture_count, 4u);
    texture_count = SWAP32(texture_count);
    if (texture_count > 1700)
        HANG("invalid texture_count");

    memset(texture_buffer, 0, sizeof(texture_buffer));
    swrLoader_CloseBlock(swrLoader_TYPE_TEXTURE_BLOCK);
}

// 0x00447490
void swrModel_LoadModelTexture(TEXID texture_index, swrMaterial** material_ptr, uint8_t** palette_data_ptr)
{
    HANG("TODO");
}

// 0x00431A50
void swrModel_NodeModifyFlags(swrModel_Node* node, int flag_id, int value, char modify_children, int modify_op)
{
    HANG("TODO");
}

// 0x00481B30
void swrModel_NodeSetLodDistances(swrModel_NodeLODSelector* node, float* a2)
{
    HANG("TODO");
}

// 0x00431750
void swrModel_NodeSetLodDistance(swrModel_NodeLODSelector* node, unsigned int a2, float a3)
{
    HANG("TODO");
}

// 0x0045cf30 HOOK
void swrModel_SwapSceneModels(int index, int index2)
{
    swrModel_Header* ptr;

    ptr = swr_sceneModels[index];
    swr_sceneModels[index] = swr_sceneModels[index2];
    swr_sceneModels[index2] = ptr;
}

// 0x0045CE10
void swrModel_LoadPuppet(MODELID model, INGAME_MODELID index, int a3, float a4)
{
    HANG("TODO");
}

// 0x00482f10
void swrModel_ComputeClipMatrix(swrModel_unk* model)
{
    HANG("TODO");
}

// 0x00483fc0
void swrModel_SetRootNodeOnAllUnks(swrModel_Node* unk)
{
    HANG("TODO");
}

// 0x00483ff0
void swrModel_SetNodeFlagsOnAllUnks(int flag, int value)
{
    HANG("TODO");
}
