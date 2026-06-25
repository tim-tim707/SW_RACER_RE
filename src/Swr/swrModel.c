#include "swrModel.h"

#include "swrAssetBuffer.h"
#include "swrLoader.h"

#include <globals.h>
#include <macros.h>
#include <Primitives/rdMath.h>
#include <Primitives/rdMatrix.h>
#include <Primitives/rdVector.h>
#include <Unknown/rdMatrixStack.h>
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

// 0x004258e0
void swrModel_ClearSceneAnimations(void)
{
    memset(swrScene_animations, 0, sizeof(swrScene_animations));
    swrScene_animations_count = 0;
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
            swrLoader_DecompressLZSS(compressed_data_buff, (char*)model_buff);
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
            swrModel_LoadModelTexture((TEXID)(data & 0xFFFFFF), (swrMaterial**)&model_buff[i], (uint8_t**)&model_buff[i + 1]);
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
            swrModel_Mesh* mesh = node->children.meshes[i];
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

            swrModel_Behavior* behavior = mesh->behavior;
            if (behavior)
            {
                behavior->unk1 = SWAP16(behavior->unk1);
                behavior->fog_start = SWAP16(behavior->fog_start);
                behavior->fog_end = SWAP16(behavior->fog_end);

                behavior->light_flags = SWAP16(behavior->light_flags);
                FLOAT_SWAP32_INPLACE(&behavior->light_vector[0]);
                FLOAT_SWAP32_INPLACE(&behavior->light_vector[1]);
                FLOAT_SWAP32_INPLACE(&behavior->light_vector[2]);

                behavior->unk14_node = (swrModel_Node*)SWAP32(behavior->unk14_node);
                behavior->unk15 = SWAP32(behavior->unk15);
                behavior->unk16 = SWAP32(behavior->unk16);

                behavior->vehicle_reaction = SWAP32(behavior->vehicle_reaction);

                behavior->unk18 = SWAP16(behavior->unk18);
                behavior->unk19 = SWAP16(behavior->unk19);

                behavior->unk20 = SWAP32(behavior->unk20);
                behavior->unk21 = SWAP32(behavior->unk21);

                swrModel_TriggerDescription* trigger = behavior->triggers;
                // some kind of linked list
                while (trigger)
                {
                    for (unsigned int j = 0; j < 3; j++)
                        FLOAT_SWAP32_INPLACE(&trigger->center.x + j);

                    for (unsigned int j = 0; j < 3; j++)
                        FLOAT_SWAP32_INPLACE(&trigger->direction.x + j);

                    FLOAT_SWAP32_INPLACE(&trigger->size_xy);
                    FLOAT_SWAP32_INPLACE(&trigger->size_z);
                    trigger->type = SWAP16(trigger->type);
                    trigger->flags = SWAP16(trigger->flags);
                    trigger = trigger->next;
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
                swrModel_ByteSwapNode(node->children.nodes[i]);
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

// 0x004475F0
bool swrModel_MeshMaterialAlreadyByteSwapped(swrModel_MeshMaterial* material)
{
    for (int i = 0; i < swrModel_NumAlreadyByteSwappedMeshMaterials; i++)
    {
        if (swrModel_AlreadyByteSwappedMeshMaterials[i] == material)
            return true;
    }
    return false;
}

// 0x00447630
bool swrModel_MeshTextureAlreadyByteSwapped(swrModel_MaterialTexture* texture)
{
    for (int i = 0; i < swrModel_NumAlreadyByteSwappedMeshTextures; i++)
    {
        if (swrModel_AlreadyByteSwappedMeshTextures[i] == texture)
            return true;
    }
    return false;
}

// 0x00447670 TODO crashes on MSVC
bool swrModel_MaterialAlreadyByteSwapped(swrModel_Material* material)
{
    for (int i = 0; i < swrModel_NumAlreadyByteSwappedMaterials; i++)
    {
        if (swrModel_AlreadyByteSwappedMaterials[i] == material)
            return true;
    }
    return false;
}

// 0x00425900
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

// 0x00426740
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

// 0x00425980
double swrModel_AnimationComputeInterpFactor(swrModel_Animation* anim, float anim_time, int key_frame_index)
{
    return (anim_time - anim->key_frame_times[key_frame_index]) / (anim->key_frame_times[key_frame_index + 1] - anim->key_frame_times[key_frame_index]);
}

// 0x004259B0
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

// 0x00425A60
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

// 0x00425BA0
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

// 0x00425F00
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

// 0x004260F0
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

// 0x00426290
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

// 0x00426330
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

// 0x00426220
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

// 0x004267A0
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

// 0x00426810
void swrModel_AnimationSetFlags(swrModel_Animation* anim, swrModel_AnimationFlags flags)
{
    anim->flags |= flags;
}

// 0x00426820
void swrModel_AnimationClearFlags(swrModel_Animation* anim, swrModel_AnimationFlags flags)
{
    anim->flags &= ~flags;
}

// 0x00426840
void swrModel_AnimationSetTime(swrModel_Animation* anim, float time)
{
    anim->animation_time = time;
    anim->key_frame_index = swrModel_AnimationFindKeyFrameIndex(anim);
    anim->flags |= ANIMATION_RESET;
}

// 0x00426880
void swrModel_AnimationSetSpeed(swrModel_Animation* anim, float speed)
{
    anim->animation_speed = speed;
}

// 0x00426890
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

// 0x00426900
void swrModel_AnimationSetLoopTransitionSpeed(swrModel_Animation* anim, float transition_speed)
{
    anim->loop_transition_speed = transition_speed;
}

// 0x0044B360
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

// 0x0044C9D0
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

// 0x0046D610
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

// 0x0046D5C0
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

// 0x0046d650
int swrModel_AnyFxAnimDone(swrModel_Animation** anims)
{
    swrModel_Animation* anim = anims[0];
    if (anim == NULL) {
        return 0;
    }
    while ((anim->flags & 0x10000000) != 0 && anim->animation_time < anim->duration4) {
        anim = anims[1];
        anims = anims + 1;
        if (anim == NULL) {
            return 0;
        }
    }
    return 1;
}

// 0x00431620
void swrModel_NodeSetTranslation(swrModel_NodeTransformed* node, float x, float y, float z)
{
    node->transform.scale = (rdVector3){ x, y, z };
    node->node.flags_3 |= 3u;
}

// 0x004316A0
void swrModel_NodeGetTransform(const swrModel_NodeTransformed* node, rdMatrix44* matrix)
{
    rdMatrix_Copy44_34(matrix, &node->transform);
}

// 0x00431640
void swrModel_NodeSetTransform(swrModel_NodeTransformed* node, const rdMatrix44* m)
{
    node->transform = (rdMatrix34){ *(const rdVector3*)&m->vA, *(const rdVector3*)&m->vB, *(const rdVector3*)&m->vC, *(const rdVector3*)&m->vD };
    node->node.flags_3 |= 3u;
}

// 0x004315F0
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

// 0x0042BA20
void swrSprite_UpdateLensFlareSpriteSettings(int16_t id, int a2, int a3, float a4, float width, float a6, uint8_t r, uint8_t g, uint8_t b)
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

// 0x0042C7A0
void swrText_CreateTextEntry2(int16_t screen_x, int16_t screen_y, char r, char g, char b, char a, char* screenText)
{
    HANG("TODO");
}

// 0x0042C800
void UpdateLightStreakSprites(swrViewport* a1)
{
    HANG("TODO");
}

// 0x0042D510
void DisableIngameSprites()
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
    return node->type;
}

// 0x00431780
uint32_t swrModel_NodeGetNumChildren(swrModel_Node* node)
{
    return node->num_children;
}

// 0x00431790
swrModel_Node* swrModel_NodeGetChild(swrModel_Node* node, int child_index)
{
    if (node == NULL) {
        return node;
    }
    return node->children.nodes[child_index];
}

// 0x004317b0
int swrModel_MeshGetNumPrimitives(const swrModel_Mesh* mesh)
{
    return (int16_t) mesh->num_primitives;
}

// 0x004317c0
int swrModel_MeshGetPrimitiveType(const swrModel_Mesh* mesh)
{
    return (int16_t) mesh->primitive_type;
}

// 0x004317d0
uint32_t* swrModel_MeshGetPrimitiveSizes(swrModel_Mesh* mesh)
{
    return mesh->primitive_sizes;
}

// Hands back a mesh's collision geometry: the shared vertex array and, for indexed primitives, the
// index list (NULL for sequential primitives). `disable` != 0 returns nulls (collision turned off).
// 0x004317e0
void swrModel_MeshGetCollisionData(swrModel_Mesh* mesh, int disable, swrModel_CollisionVertex** vertices, uint16_t** optional_indices)
{
    if (disable == 0) {
        *vertices = mesh->collision_vertices;
        *optional_indices = mesh->primitive_indices;
    } else {
        *vertices = NULL;
        *optional_indices = NULL;
    }
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

// Classifies a mesh material's collision facing from its swrModel_MeshMaterial::type bits, telling
// the ray test which face sides to accept: -1 = no material (or not enabled), 0 = double-sided,
// 1 = front-facing one-sided (0x8), 2/3 = mirrored one-sided (0x40, +1 when also front-facing).
// 0x00431880
int swrModel_ClassifyMaterialFacing(swrModel_MeshMaterial* material, int enable)
{
    if (material == NULL || enable != 1)
        return -1;
    int front = (material->type & 0x8) >> 3;
    if ((material->type & 0x40) != 0)
        return (front != 0) + 2;
    return front;
}

// 0x004318b0
swrModel_Behavior* swrModel_MeshGetBehavior(swrModel_Mesh* mesh)
{
    return mesh->behavior;
}

// 0x00431B00
uint32_t swrModel_NodeGetFlags1Or2(swrModel_Node* node, int flag_id)
{
    if (flag_id == 0) {
        return node->flags_2;
    }
    if (flag_id == 2) {
        return node->flags_1;
    }
    return 0;
}

// 0x00431B20
void swrModel_NodeInit(swrModel_Node* node, uint32_t base_flags)
{
    node->flags_1 = 0xffffffff;
    node->flags_2 = 0xffffffff;
    node->type = base_flags;
    node->flags_3 = 0;
    node->light_index = 0;
    node->flags_5 = 0;
    if ((base_flags & NODE_HAS_CHILDREN) != 0) {
        node->num_children = 0;
        node->children.nodes = NULL;
        // a transform-with-pivot node is followed by two extra swrModel_Node-sized
        // slots holding the pivot scale/offset (1.0f == 0x3f800000 bit pattern).
        if (base_flags == NODE_TRANSFORMED_WITH_PIVOT) {
            node[2].num_children = 0;
            node[2].children.nodes = NULL;
            node[3].type = 0;
            node[1].type = 0x3f800000;
            node[1].flags_1 = 0;
            node[1].flags_2 = 0;
            node[1].flags_3 = 0;
            node[1].light_index = 0;
            node[1].flags_5 = 0x3f800000;
            node[1].num_children = 0;
            node[1].children.nodes = NULL;
            node[2].type = 0;
            node[2].flags_1 = 0x3f800000;
            node[2].flags_2 = 0;
            node[2].flags_3 = 0;
            node[2].light_index = 0;
            node[2].flags_5 = 0;
        }
    }
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
    if (node == NULL) {
        return;
    }

    uint32_t* flags;
    if (flag_id == 0) {
        flags = &node->flags_2;
    } else if (flag_id == 2) {
        flags = &node->flags_1;
    } else {
        return;
    }

    if ((modify_children & 0x10) != 0) {
        if (modify_op == 2) {
            *flags |= value;
        } else if (modify_op == 3) {
            *flags &= value;
        } else if (modify_op == 1) {
            *flags = value;
        }
    }

    if ((modify_children & 0x20) != 0 && (swrModel_NodeGetFlags(node) & NODE_HAS_CHILDREN) != 0) {
        for (int i = 0; i < (int) swrModel_NodeGetNumChildren(node); i++) {
            swrModel_Node* child = swrModel_NodeGetChild(node, i);
            swrModel_NodeModifyFlags(child, flag_id, value, modify_children & 0x10, modify_op);
        }
    }
}

// 0x00481B30
void swrModel_NodeSetLodDistances(swrModel_NodeLODSelector* node, float* a2)
{
    HANG("TODO");
}

// 0x00431750
void swrModel_NodeSetLodDistance(swrModel_NodeLODSelector* node, unsigned int lod_index, float distance)
{
    if ((int) lod_index < 8 && (int) lod_index >= 0) {
        node->lod_distances[lod_index] = distance;
    }
}

// 0x0045cf30
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

// Is the plane-hit point inside triangle a,b,c? Tests that the three edge-cross products
// (hitPoint->vertex x edge) agree in sign on their dominant axis. Quirk preserved from the asm:
// the dominant component is read signed for X/Y but absolute for Z (the original abs's n.z in
// place), so a Z-dominant axis always takes the ">= 0" branch.
// 0x00441040
int swrModel_PointInTriangle(float* origin, float* a, float* b, float* c,
                             rdVector3* edgeAB, rdVector3* edgeBC, rdVector3* edgeCA)
{
    rdVector3 toA, toB, toC, faceN, n0, n1, n2;

    toA.x = a[0] - origin[0]; toA.y = a[1] - origin[1]; toA.z = a[2] - origin[2];
    toB.x = b[0] - origin[0]; toB.y = b[1] - origin[1]; toB.z = b[2] - origin[2];
    toC.x = c[0] - origin[0]; toC.y = c[1] - origin[1]; toC.z = c[2] - origin[2];

    rdVector_Cross3(&faceN, edgeAB, edgeBC);
    if (faceN.x == 0.0f && faceN.y == 0.0f && faceN.z == 0.0f)
        return 0;

    rdVector_Cross3(&n0, &toA, edgeAB);
    rdVector_Cross3(&n1, &toB, edgeBC);
    rdVector_Cross3(&n2, &toC, edgeCA);

    float ax = (n0.x < 0.0f) ? -n0.x : n0.x;
    float ay = (n0.y < 0.0f) ? -n0.y : n0.y;
    if (n0.z < 0.0f) n0.z = -n0.z; // abs in place (matches the asm); n0.x/n0.y stay signed
    float az = n0.z;

    if (az + ay + ax <= 0.0001f) {
        // n0 ~ 0 (hit near vertex a): decide from n1's dominant axis against n2
        ax = (n1.x < 0.0f) ? -n1.x : n1.x;
        ay = (n1.y < 0.0f) ? -n1.y : n1.y;
        if (n1.z < 0.0f) n1.z = -n1.z;
        az = n1.z;
        if (az + ay + ax < 0.001f)
            return 1;
        int axis = (ay <= ax) ? ((az <= ax) ? 0 : 2) : ((az <= ay) ? 1 : 2);
        if (0.0f <= (&n1.x)[axis]) {
            if (0.0f <= (&n2.x)[axis]) return 1;
        } else {
            if ((&n2.x)[axis] <= 0.0f) return 1;
        }
    } else {
        int axis = (ay <= ax) ? ((az <= ax) ? 0 : 2) : ((az <= ay) ? 1 : 2);
        if (0.0f <= (&n0.x)[axis]) {
            if (0.0f <= (&n1.x)[axis] && 0.0f <= (&n2.x)[axis]) return 1;
        } else {
            if ((&n1.x)[axis] <= 0.0f && (&n2.x)[axis] <= 0.0f) return 1;
        }
    }
    return 0;
}

// Ray-plane intersection. plane = {normal.xyz, offset}; ray = {origin[3], dir[3], maxDist}.
// Returns the hit distance t (and writes the point to outPoint), or -1 on a miss: ray parallel
// to the plane (|normal.dir| < 1e-4), behind the origin, or past maxDist.
// 0x00442470
float IntersectRayPlane(float* plane, float* ray, rdVector3* outPoint)
{
    float denom = plane[0] * ray[3] + plane[1] * ray[4] + plane[2] * ray[5];
    if (denom >= -0.0001 && denom <= 0.0001)
        return -1.0f;
    float t = (plane[3] - (plane[0] * ray[0] + plane[1] * ray[1] + plane[2] * ray[2])) / denom;
    if (t < 0.0f)
        return -1.0f;
    if (ray[6] < t)
        return -1.0f;
    outPoint->x = ray[0] + t * ray[3];
    outPoint->y = ray[1] + t * ray[4];
    outPoint->z = ray[2] + t * ray[5];
    return t;
}

// Tests one triangle (plane + verts a,b,c) against the active ray; on a closer in-triangle hit,
// records distance/point/node/normal into the swrModel_collision* result globals. Honours the
// front/back accept flags (a back-face hit flips the recorded normal to oppose the ray).
// 0x00442550
void swrModel_CollideRayTriangle(float* plane, float* a, float* b, float* c, float* ray)
{
    float facing = plane[0] * ray[3] + plane[1] * ray[4] + plane[2] * ray[5];
    int backFace;
    if (facing <= 0.0f) {
        if (swrModel_collisionAcceptFrontFaces == 0)
            return;
        backFace = 0;
    } else {
        if (swrModel_collisionAcceptBackFaces == 0)
            return;
        backFace = 1;
    }

    rdVector3 hit;
    float t = IntersectRayPlane(plane, ray, &hit);
    if (t < 0.0f || swrModel_collisionResultDist <= t)
        return;

    rdVector3 edgeAB, edgeBC, edgeCA;
    edgeAB.x = b[0] - a[0]; edgeAB.y = b[1] - a[1]; edgeAB.z = b[2] - a[2];
    edgeBC.x = c[0] - b[0]; edgeBC.y = c[1] - b[1]; edgeBC.z = c[2] - b[2];
    edgeCA.x = a[0] - c[0]; edgeCA.y = a[1] - c[1]; edgeCA.z = a[2] - c[2];

    if (swrModel_PointInTriangle(&hit.x, a, b, c, &edgeAB, &edgeBC, &edgeCA)) {
        swrModel_collisionResultDist = t;
        swrModel_collisionHitPoint = hit;
        swrModel_collisionUnk250 = 1;
        swrModel_collisionResultNode = (swrModel_Node*) swrModel_collisionCurrentMesh;
        if (backFace) {
            swrModel_collisionHitNormal.x = -plane[0];
            swrModel_collisionHitNormal.y = -plane[1];
            swrModel_collisionHitNormal.z = -plane[2];
        } else {
            swrModel_collisionHitNormal.x = plane[0];
            swrModel_collisionHitNormal.y = plane[1];
            swrModel_collisionHitNormal.z = plane[2];
        }
    }
}

// Does any of `count` verts straddle the ray's bounding box on every axis? (broad-phase cull
// shared by the two face callbacks below).
static int faceBBoxOverlapsRay(const rdVector3* verts, int count)
{
    const float* mn = &swrModel_collisionRayBBoxMin.x;
    const float* mx = &swrModel_collisionRayBBoxMax.x;
    for (int axis = 0; axis < 3; axis++) {
        int aboveMin = 0, belowMax = 0;
        for (int i = 0; i < count; i++) {
            float coord = (&verts[i].x)[axis];
            if (mn[axis] <= coord) aboveMin = 1;
            if (coord <= mx[axis]) belowMax = 1;
        }
        if (!aboveMin || !belowMax)
            return 0;
    }
    return 1;
}

// Per-face hook for indexed primitives: gathers the 3/4 verts via the index list, broad-phase
// culls against the ray bbox, then ray-tests each triangle (a quad is split into two).
// 0x00442720
void swrModel_MeshCollisionFaceCallbackIndexed(swrModel_CollisionVertex* vertices, int16_t primitive_type, uint16_t* indices)
{
    rdVector3 v[4];
    rdVector4 plane;
    float* ray = (float*) &swrModel_collisionRayOrigin;
    int n = (primitive_type == 2) ? 4 : 3;
    for (int i = 0; i < n; i++) {
        swrModel_CollisionVertex* vp = &vertices[indices[i]];
        v[i].x = (float) vp->x;
        v[i].y = (float) vp->y;
        v[i].z = (float) vp->z;
    }
    if (!faceBBoxOverlapsRay(v, n))
        return;
    if (primitive_type == 2) {
        rdMath_CalcSurfaceNormal2(&plane, &v[0], &v[1], &v[3]);
        swrModel_CollideRayTriangle((float*) &plane, &v[0].x, &v[1].x, &v[3].x, ray);
        rdMath_CalcSurfaceNormal2(&plane, &v[1], &v[2], &v[3]);
        swrModel_CollideRayTriangle((float*) &plane, &v[1].x, &v[2].x, &v[3].x, ray);
    } else if (primitive_type == 1) {
        rdMath_CalcSurfaceNormal2(&plane, &v[0], &v[2], &v[1]);
        swrModel_CollideRayTriangle((float*) &plane, &v[0].x, &v[2].x, &v[1].x, ray);
    } else {
        rdMath_CalcSurfaceNormal2(&plane, &v[0], &v[1], &v[2]);
        swrModel_CollideRayTriangle((float*) &plane, &v[0].x, &v[1].x, &v[2].x, ray);
    }
}

// Per-face hook for non-indexed primitives (verts are sequential). Same broad-phase cull + per-
// triangle ray test as the indexed variant.
// 0x00442C30
void swrModel_MeshCollisionFaceCallback(swrModel_CollisionVertex* vertices, int16_t primitive_type)
{
    rdVector3 v[4];
    rdVector4 plane;
    float* ray = (float*) &swrModel_collisionRayOrigin;
    int n = (primitive_type == 2) ? 4 : 3;
    for (int i = 0; i < n; i++) {
        v[i].x = (float) vertices[i].x;
        v[i].y = (float) vertices[i].y;
        v[i].z = (float) vertices[i].z;
    }
    if (!faceBBoxOverlapsRay(v, n))
        return;
    if (primitive_type == 2) {
        rdMath_CalcSurfaceNormal2(&plane, &v[0], &v[1], &v[3]);
        swrModel_CollideRayTriangle((float*) &plane, &v[0].x, &v[1].x, &v[3].x, ray);
        rdMath_CalcSurfaceNormal2(&plane, &v[1], &v[2], &v[3]);
        swrModel_CollideRayTriangle((float*) &plane, &v[1].x, &v[2].x, &v[3].x, ray);
    } else if (primitive_type == 1) {
        rdMath_CalcSurfaceNormal2(&plane, &v[0], &v[2], &v[1]);
        swrModel_CollideRayTriangle((float*) &plane, &v[0].x, &v[2].x, &v[1].x, ray);
    } else {
        rdMath_CalcSurfaceNormal2(&plane, &v[0], &v[1], &v[2]);
        swrModel_CollideRayTriangle((float*) &plane, &v[0].x, &v[1].x, &v[2].x, ray);
    }
}

// Walks every collision face of a mesh, handing each to the active face callback. Sequential and
// indexed primitives use different callbacks; triangle strips (types 5/7) flip winding each step.
// 0x004439f0
void swrModel_MeshIterateOverCollisionFaces(swrModel_Mesh* mesh)
{
    swrModel_collisionCurrentMesh = mesh;
    int primitive_type = swrModel_MeshGetPrimitiveType(mesh);
    int num_primitives = swrModel_MeshGetNumPrimitives(mesh);

    swrModel_CollisionVertex* vertices;
    uint16_t* indices;
    swrModel_MeshGetCollisionData(mesh, 0, &vertices, &indices);
    if (vertices == NULL)
        return;

    if (indices == NULL) {
        switch (primitive_type) {
        case 3: // independent triangles
            for (int i = 0; i < num_primitives; i++)
                swrModel_meshCollisionFaceCallback(vertices + i * 3, 0);
            break;
        case 4: // independent quads
            for (int i = 0; i < num_primitives; i++)
                swrModel_meshCollisionFaceCallback(vertices + i * 4, 2);
            break;
        case 5:
        case 7: { // triangle strips
            uint32_t* strip_lengths = swrModel_MeshGetPrimitiveSizes(mesh);
            int base = 0;
            for (int strip = 0; strip < num_primitives; strip++) {
                int flip = 0;
                for (int j = 0; j < (int) strip_lengths[strip] - 2; j++) {
                    swrModel_meshCollisionFaceCallback(vertices + base + j, flip);
                    flip = 1 - flip;
                }
                base += strip_lengths[strip];
            }
            break;
        }
        }
    } else {
        switch (primitive_type) {
        case 3:
            for (int i = 0; i < num_primitives; i++)
                swrModel_meshCollisionFaceCallbackIndexed(vertices, 0, indices + i * 3);
            break;
        case 4:
            for (int i = 0; i < num_primitives; i++)
                swrModel_meshCollisionFaceCallbackIndexed(vertices, 2, indices + i * 4);
            break;
        case 5:
        case 7: {
            uint32_t* strip_lengths = swrModel_MeshGetPrimitiveSizes(mesh);
            int base = 0;
            for (int strip = 0; strip < num_primitives; strip++) {
                int flip = 0;
                for (int j = 0; j < (int) strip_lengths[strip] - 2; j++) {
                    swrModel_meshCollisionFaceCallbackIndexed(vertices, flip, indices + base + j);
                    flip = 1 - flip;
                }
                base += strip_lengths[strip];
            }
            break;
        }
        }
    }
}

// Maps a recorded hit (point + normal) from the mesh-local space the test ran in back into parent
// space using the matrix-stack top. flags bit0 = transform active; bit1 set = full rotate+translate,
// clear = translate only. The normal is left untouched when swrModel_collisionUnkE1c == 2.
// 0x00443e70
void swrModel_TransformCollisionResult(unsigned char flags)
{
    if ((flags & 1) == 0)
        return;

    rdMatrix44 stack;
    rdMatrixStack44_Peek(&stack);
    if ((flags & 2) == 0) {
        swrModel_collisionHitPoint.x += stack.vD.x;
        swrModel_collisionHitPoint.y += stack.vD.y;
        swrModel_collisionHitPoint.z += stack.vD.z;
    } else {
        rdMatrix_Transform3(&swrModel_collisionHitPoint, &swrModel_collisionHitPoint, &stack);
        if (swrModel_collisionUnkE1c != 2)
            rdMatrix_Multiply3(&swrModel_collisionHitNormal, &swrModel_collisionHitNormal, &stack);
    }
}

// Transforms `count` ray entries (origin xyz, direction xyz, max-distance) from src into dst,
// moving the ray into the current matrix-stack space so a mesh can be tested in its local frame.
// flags bit0 clear = raw copy; bit0 set + bit1 clear = subtract the translation; bit0+bit1 = full
// transform. Each entry is 7 floats wide; the 7th (max distance) is preserved.
// 0x004447b0
void swrModel_TransformCollisionVerts(unsigned char flags, int count, int dst, rdVector3* src)
{
    float* d = (float*) dst;
    float* s = (float*) src;

    if ((flags & 1) == 0) {
        for (int i = 0; i < count; i++) {
            d[0] = s[0]; d[1] = s[1]; d[2] = s[2];
            d[3] = s[3]; d[4] = s[4]; d[5] = s[5];
            d += 7;
            s += 7;
        }
        return;
    }

    rdMatrix44 stack;
    rdMatrixStack44_Peek(&stack);
    if ((flags & 2) == 0) {
        for (int i = 0; i < count; i++) {
            d[0] = s[0] - stack.vD.x;
            d[1] = s[1] - stack.vD.y;
            d[2] = s[2] - stack.vD.z;
            d[3] = s[3]; d[4] = s[4]; d[5] = s[5];
            d += 7;
            s += 7;
        }
        return;
    }

    rdMatrix44 mat;
    rdMatrix_Unk1(&mat, &stack);
    for (int i = 0; i < count; i++) {
        rdMatrix_Transform3((rdVector3*) d, (rdVector3*) s, &mat);
        rdMatrix_Multiply3((rdVector3*) (d + 3), (rdVector3*) (s + 3), &mat);
        d += 7;
        s += 7;
    }
}

// Builds the ray's axis-aligned bounding box (origin .. origin + maxDist*dir) into the collision
// globals, ordering each axis by the ray direction's sign.
static void buildRayAABB(void)
{
    rdVector3 endpoint;
    rdVector_Scale3Add3(&endpoint, &swrModel_collisionRayOrigin, swrModel_collisionRayMaxDist, &swrModel_collisionRayDir);
    const float* origin = &swrModel_collisionRayOrigin.x;
    const float* end = &endpoint.x;
    const float* dir = &swrModel_collisionRayDir.x;
    float* mn = &swrModel_collisionRayBBoxMin.x;
    float* mx = &swrModel_collisionRayBBoxMax.x;
    for (int axis = 0; axis < 3; axis++) {
        if (0.0f <= dir[axis]) {
            mn[axis] = origin[axis];
            mx[axis] = end[axis];
        } else {
            mx[axis] = origin[axis];
            mn[axis] = end[axis];
        }
    }
}

// Tests an AABB (min xyz, max xyz) against the ray's bounding box.
static int rayAABBOverlaps(const float* aabb)
{
    const float* mn = &swrModel_collisionRayBBoxMin.x;
    const float* mx = &swrModel_collisionRayBBoxMax.x;
    for (int axis = 0; axis < 3; axis++) {
        if (aabb[axis] > mx[axis] || mn[axis] > aabb[axis + 3])
            return 0;
    }
    return 1;
}

// Picks which face sides (front/back) the ray test accepts for `mesh`, from its material facing
// (unless swrModel_collisionForceBothFaces overrides to accept both).
static void selectFaceAcceptance(swrModel_Mesh* mesh)
{
    if (swrModel_collisionForceBothFaces != 0) {
        swrModel_collisionAcceptBackFaces = 1;
        swrModel_collisionAcceptFrontFaces = 1;
        return;
    }
    swrModel_MeshMaterial* material = (swrModel_MeshMaterial*) swrModel_NodeGetFlags((swrModel_Node*) mesh);
    int facing = swrModel_ClassifyMaterialFacing(material, 1);
    swrModel_collisionAcceptBackFaces = (facing == 1 || facing == 3) ? 0 : 1;
    swrModel_collisionAcceptFrontFaces = (facing == 2 || facing == 3) ? 0 : 1;
}

// Tests the ray against a mesh-group node: AABB-culls the node and each child mesh, then iterates
// the surviving meshes' collision faces. Transforms the ray in on first entry and the hit back out.
// 0x00444910
void swrModel_CollideMeshNodeRay(swrModel_Node* node, void* query, unsigned int flags)
{
    if (node == NULL) {
        swrModel_collisionResultDist = -1.0f;
        return;
    }
    if (swrModel_collisionUnkE70 != 0) {
        swrModel_collisionUnkE70 = 0;
        swrModel_TransformCollisionVerts(flags, 1, (int) &swrModel_collisionRayOrigin, query);
    }
    buildRayAABB();

    // the node's own AABB is stored as six floats immediately after the node header
    const float* node_aabb = (const float*) (node + 1);
    if (!rayAABBOverlaps(node_aabb))
        return;

    uint32_t num_children = swrModel_NodeGetNumChildren(node);
    for (int i = 0; i < (int) num_children; i++) {
        swrModel_Mesh* mesh = node->children.meshes[i];
        if (rayAABBOverlaps(mesh->aabb)) {
            selectFaceAcceptance(mesh);
            swrModel_MeshIterateOverCollisionFaces(mesh);
        }
    }
    if (swrModel_collisionUnk250 != 0) {
        swrModel_TransformCollisionResult(flags);
        swrModel_collisionUnk250 = 0;
    }
}

// Recursively walks the model tree to the ray. Mesh-group nodes (type 0x3064) are tested directly;
// group nodes (0x4000) push their transform onto the matrix stack and recurse into children that
// pass the node flag masks.
// 0x00444bf0
void swrModel_CollideNodeRecursiveRay(swrModel_NodeTransformed* node, void* query, unsigned int flags)
{
    uint32_t node_type = swrModel_NodeGetFlags(&node->node);
    if (node_type == 0x3064) {
        swrModel_CollideMeshNodeRay(&node->node, query, flags);
        return;
    }
    if ((node_type & 0x4000) == 0)
        return;

    int pushed = (node_type & 0x8000) != 0;
    if (pushed) {
        flags |= ((node->node.flags_3 & 8) == 0) ? 3 : 1;
        rdMatrix44 transform;
        swrModel_NodeGetTransform(node, &transform);
        rdMatrixStack44_Push(&transform);
        swrModel_collisionUnkE70 = 1;
    }

    uint32_t num_children = swrModel_NodeGetNumChildren(&node->node);
    for (int i = 0; i < (int) num_children; i++) {
        swrModel_Node* child = node->node.children.nodes[i];
        if (child != NULL &&
            (swrModel_NodeGetFlags1Or2(child, 0) & swrModel_collisionNodeAllMask) == swrModel_collisionNodeAllMask &&
            (swrModel_NodeGetFlags1Or2(child, 0) & swrModel_collisionNodeAnyMask) != 0) {
            swrModel_CollideNodeRecursiveRay((swrModel_NodeTransformed*) child, query, flags);
        }
    }

    if (pushed) {
        rdMatrixStack44_Pop();
        swrModel_collisionUnkE70 = 1;
    }
}

// Entry point: casts a ray (origin, dir, maxDist packed as 7 floats) against a single mesh, writing
// the nearest hit point/normal and returning the hit distance (-1 if none). Records the hit node.
// 0x00444f10
float swrModel_CollideRayWithMesh(swrModel_Mesh* mesh, float* ray, float* outPoint, float* outNormal)
{
    if (mesh == NULL) {
        swrModel_collisionResultDist = -1.0f;
    } else {
        swrModel_collisionResultDist = ray[6] - swrModel_collisionRayDistBias;
        swrModel_collisionRayMaxDist = ray[6];
        swrModel_collisionRayDir.x = ray[3];
        swrModel_collisionRayDir.y = ray[4];
        swrModel_collisionRayDir.z = ray[5];
        swrModel_collisionRayOrigin.x = ray[0];
        swrModel_collisionRayOrigin.y = ray[1];
        swrModel_collisionRayOrigin.z = ray[2];
        swrModel_collisionUnkE1c = 1;
        swrModel_meshCollisionFaceCallback = swrModel_MeshCollisionFaceCallback;
        swrModel_meshCollisionFaceCallbackIndexed = swrModel_MeshCollisionFaceCallbackIndexed;

        buildRayAABB();
        selectFaceAcceptance(mesh);
        swrModel_MeshIterateOverCollisionFaces(mesh);

        if (swrModel_collisionResultDist <= ray[6]) {
            outPoint[0] = swrModel_collisionHitPoint.x;
            outPoint[1] = swrModel_collisionHitPoint.y;
            outPoint[2] = swrModel_collisionHitPoint.z;
            outNormal[0] = swrModel_collisionHitNormal.x;
            outNormal[1] = swrModel_collisionHitNormal.y;
            outNormal[2] = swrModel_collisionHitNormal.z;
        } else {
            swrModel_collisionResultDist = -1.0f;
        }
    }
    if (swrModel_collisionResultNode != NULL)
        swrRace_collisionHitNode = swrModel_collisionResultNode;
    return swrModel_collisionResultDist;
}
