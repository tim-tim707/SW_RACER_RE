#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct swrModel_Node
    {
        uint32_t flags_0;
        uint32_t flags_1;
        uint32_t flags_2;
        uint16_t flags_3;
        uint16_t flags_4;
        uint32_t flags_5;
        uint32_t num_children;

        union
        {
            struct swrModel_Node** nodes;
            struct swrModel_Mesh** meshes;
        } children;

        union
        {
            struct
            {
                float transform[12];
                uint32_t unk; // TODO does this field even exist? its not byte swapped.
            } node_d064_data;

            struct
            {
                float transform[12];
                float unk[3];
            } node_d065_data;

            struct
            {
                uint16_t unk1;
                uint16_t unk2;
                uint32_t unk3[3];
                uint32_t unk4;
            } node_d066_data;

            struct
            {
            } node_5064_data;

            struct
            {
                uint32_t unk;
            } node_5065_data;

            struct
            {
                float lods_distances[8];
                float unk[3]; // TODO not sure if actually float
            } node_5066_data;

            struct
            {
                float aabb[6];
                // TODO do unk1, unk2 even exist? they are not byte swapped
                uint32_t unk1;
                uint32_t unk2;
            } node_3064_data;
        } data;
    } swrModel_Node;

    typedef struct swrModel_Mesh
    {
        struct swrModel_MeshMaterial* mesh_material;
        struct swrModel_Light* light;
        float aabb[6];
        uint16_t num_primitives;
        uint16_t primitive_type;
        uint32_t* primitive_sizes;
        uint16_t* unknown_ptr;
        struct swrModel_CollisionVertex* collision_vertices;
        struct swrModel_IndexBuffer* index_buffer;
        struct swrModel_Vertex* vertices;
        uint16_t num_collision_vertices;
        uint16_t num_vertices;
        uint16_t unk1;
        uint16_t unk2;
    } swrModel_Mesh;

    typedef struct swrModel_MeshMaterial
    {
        uint32_t type;
        uint16_t unk1;
        uint16_t unk2;
        struct swrModel_MeshTexture* mesh_texture;
        struct swrModel_Material* material;
    } swrModel_MeshMaterial;

    typedef struct swrModel_MeshTexture
    {
        uint32_t unk0;
        uint16_t w;
        uint16_t h;
        uint16_t unk1[2];
        uint16_t type; // TextureType
        uint16_t num_specs;
        uint16_t width;
        uint16_t height;
        uint16_t unk2;
        uint16_t unk3;
        uint16_t unk4;
        uint16_t unk5;
        struct swrModel_TextureSpec *specs[5];
        uint32_t unk6;
        uint32_t unk7;
        uint32_t texture_index;
        uint32_t unk8;
    } swrModel_MeshTexture;

    typedef struct swrModel_TextureSpec
    {
        uint32_t flags;
        uint32_t unk1;
        uint32_t unk2;
        uint16_t w;
        uint16_t h;
    } swrModel_TextureSpec;

#pragma pack(push, 1)
    // packing on this one
    typedef struct swrModel_Material
    {
        uint32_t unk1;
        uint16_t unk2;
        uint32_t unk3[2];
        uint32_t unk4[2];
        uint16_t unk5;
        uint32_t unk6;
        uint32_t unk7;
    } swrModel_Material;

    // packing on this one
    typedef struct swrModel_Light
    {
        uint16_t unk1;
        uint16_t unk2;
        uint16_t unk3;
        uint16_t unk4;
        uint16_t unk5;
        uint16_t unk6;
        uint16_t unk7;
        uint16_t unk8;
        uint16_t unk9;
        uint16_t unk10;
        uint32_t unk11;
        uint32_t unk12;
        uint32_t unk13;
        uint32_t unk14;
        uint32_t unk15;
        uint32_t unk16;
        uint32_t unk17;
        uint16_t unk18;
        uint16_t unk19;
        uint32_t unk20;
        uint32_t unk21;
        struct swrModel_Light2* light2;
    } swrModel_Light;

    typedef struct swrModel_Light2
    {
        uint32_t unk1[3];
        uint32_t unk2[3];
        uint32_t unk3;
        uint32_t unk4;
        uint16_t unk5;
        uint16_t unk6;
        uint16_t unk7;
        uint16_t unk9;
        struct swrModel_Light2 *next;
    } swrModel_Light2;

#pragma pack(pop)

    typedef struct swrModel_Vertex
    {
        int16_t x,y,z;
        uint16_t padding;
        uint16_t u,v;
        uint8_t r,g,b,a;
    } swrModel_Vertex;

    typedef struct swrModel_CollisionVertex
    {
        int16_t x,y,z;
    } swrModel_CollisionVertex;

#ifdef __cplusplus
}
#endif