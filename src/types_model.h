#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef union swrModel_HeaderEntry
    {
        struct swrModel_Node* node;
        struct swrModel_Animation* animation;
        uint32_t value;
    } swrModel_HeaderEntry;

    typedef struct swrModel_Header
    {
        swrModel_HeaderEntry entries[0];
    } swrModel_Header;

    typedef struct swrModel_Node
    {
        uint32_t flags_0; // 0x4000 if has children
        uint32_t flags_1;
        uint32_t flags_2;
        uint16_t flags_3; // |= 3, if transform was changed.
        uint16_t flags_4;
        uint32_t flags_5;
        uint32_t num_children;

        union
        {
            struct swrModel_Node** child_nodes;
            struct swrModel_Mesh** meshes;
        };

        union
        {
            struct
            {
                float transform[12];
            } node_d064_data;

            struct
            {
                float transform[12];
                float vector[3];
            } node_d065_data;

            struct
            {
                uint16_t unk1;
                uint16_t unk2;
                float vector[3];
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
                uint32_t unk[3];
            } node_5066_data;

            struct
            {
                float aabb[6];
            } node_3064_data;
        };
    } swrModel_Node;

    typedef struct swrModel_Mesh
    {
        struct swrModel_MeshMaterial* mesh_material;
        struct swrModel_Mapping* mapping;
        float aabb[6];
        uint16_t num_primitives;
        uint16_t primitive_type;
        uint32_t* primitive_sizes;
        uint16_t* primitive_indices;
        struct swrModel_CollisionVertex* collision_vertices;
        union
        {
            // this is N64 display list containing draw commands for the GSP
            struct Gfx* vertex_display_list;
            // when the game renders the mesh the first time, it stores a converted rdModel3Mesh* here.
            struct rdModel3Mesh* converted_mesh;
        };
        union Vtx* vertices;
        uint16_t num_collision_vertices;
        uint16_t num_vertices;
        uint16_t unk1;
        int16_t vertex_base_offset;
    } swrModel_Mesh;

#pragma pack(push, 1)
    // every display list command contains 8 bytes, the first byte is the type.
    // on N64 its actually the highest byte of the first 32 bits, but this struct is not byte swapped when loading.
    typedef struct Gfx
    {
        uint8_t type;
        union
        {
            struct
            {
                // http://n64devkit.square7.ch/n64man/gsp/gSPVertex.htm
                uint8_t unk0;
                uint8_t unk1;
                uint8_t num_vertices;
                union Vtx* vertex_offset;
            } gSPVertex; // if type == 1
            struct
            {
                // http://n64devkit.square7.ch/n64man/gsp/gSPCullDisplayList.htm
                uint8_t unk[7];
            } gSPCullDisplayList; // if type == 3
            struct
            {
                // http://n64devkit.square7.ch/n64man/gsp/gSP1Triangle.htm
                uint8_t index0;
                uint8_t index1;
                uint8_t index2;
                uint8_t unused[4];
            } gSP1Triangle; // if type == 5
            struct
            {
                // http://n64devkit.square7.ch/n64man/gsp/gSP2Triangles.htm
                uint8_t index0;
                uint8_t index1;
                uint8_t index2;
                uint8_t unk;
                uint8_t index3;
                uint8_t index4;
                uint8_t index5;
            } gSP2Triangles; // if type == 6
            struct
            {
                // http://n64devkit.square7.ch/n64man/gsp/gSPEndDisplayList.htm
                uint8_t unused[7];
            } gSPEndDisplayList; // if type == 0xdf
        };
    } Gfx;

#pragma pack(pop)

    typedef struct swrModel_MeshMaterial
    {
        uint32_t type; // 0x80 if texture offset is set
        int16_t texture_offset[2];
        struct swrModel_MaterialTexture* material_texture;
        struct swrModel_Material* material;
    } swrModel_MeshMaterial;

    typedef struct swrModel_MaterialTexture
    {
        uint32_t unk0;
        int16_t res[2];
        uint16_t unk1[2];
        uint16_t type; // TextureType
        uint16_t num_children;
        uint16_t width;
        uint16_t height;
        uint16_t unk2;
        uint16_t unk3;
        uint16_t unk4;
        uint16_t unk5;
        struct swrModel_MaterialTextureChild* specs[5];
        uint32_t unk6;
        uint32_t unk7;
        union
        {
            TEXID texture_index; // the file contains texture_index | 0xA000000
            uint8_t* texture_data; // ... the game will then replace it by a pointer to loaded texture data
            swrMaterial* loaded_material; // ... and then create a RdMaterial/swrMaterial that holds the loaded texture data.
        };
        uint8_t* palette_data;
    } swrModel_MaterialTexture;

    typedef struct swrModel_MaterialTextureChild
    {
        uint32_t flags;
        uint32_t unk1;
        uint32_t unk2;
        uint16_t w;
        uint16_t h;
    } swrModel_MaterialTextureChild;

#pragma pack(push, 1)
    // packing on this one
    typedef struct swrModel_Material
    {
        uint32_t unk1;
        uint16_t unk2;
        // combine mode: http://n64devkit.square7.ch/n64man/gdp/gDPSetCombineLERP.htm
        uint32_t color_combine_mode_cycle1;
        uint32_t alpha_combine_mode_cycle1;
        uint32_t color_combine_mode_cycle2;
        uint32_t alpha_combine_mode_cycle2;
        uint16_t unk5;
        // render mode: http://n64devkit.square7.ch/n64man/gdp/gDPSetRenderMode.htm
        uint32_t render_mode_1;
        uint32_t render_mode_2;
        uint16_t unk8;
        uint8_t primitive_color[4];
    } swrModel_Material;

    // packing on this one
    typedef struct swrModel_Mapping
    {
        uint16_t unk1;
        uint8_t fog_flags;
        uint8_t fog_color[3];
        uint16_t fog_start;
        uint16_t fog_end;
        uint16_t light_flags;
        uint8_t ambient_color[3];
        uint8_t light_color[3];
        uint16_t unk10;
        float light_vector[3];
        uint32_t unk14;
        uint32_t unk15;
        uint32_t unk16;
        uint32_t vehicle_reaction;
        uint16_t unk18;
        uint16_t unk19;
        uint32_t unk20;
        uint32_t unk21;
        struct swrModel_MappingChild* subs;
    } swrModel_Mapping;

    typedef struct swrModel_MappingChild
    {
        float vector0[3];
        float vector1[3];
        uint32_t unk3;
        uint32_t unk4;
        uint16_t unk5;
        uint16_t unk6;
        uint16_t unk7;
        uint16_t unk9;
        struct swrModel_MappingChild* next;
    } swrModel_MappingChild;

#pragma pack(pop)
    // vertices are in n64 format
    // see: http://n64devkit.square7.ch/n64man/gsp/gSPVertex.htm
    typedef struct
    {
        int16_t         x,y,z;
        uint16_t        flag;
        int16_t         u,v; // signed 10.5 fixed point
        uint8_t         r,g,b,a;
    } Vtx_t;
    typedef struct
    {
        int16_t         x,y,z;
        uint16_t        flag;
        int16_t         u,v; // signed 10.5 fixed point
        int8_t          nx, ny, nz;
        uint8_t         a;
    } Vtx_tn;
    typedef union Vtx
    {
        Vtx_t           v; // vertex with baked colors
        Vtx_tn          n; // vertex with normals
    } Vtx;

    typedef struct swrModel_CollisionVertex
    {
        int16_t x, y, z;
    } swrModel_CollisionVertex;

    typedef enum swrModel_AnimationFlags
    {
        ANIMATION_LOOP = 0x10, // if set, the animation will loop when it reaches the end. otherwise it just stops there.
        ANIMATION_LOOP_WITH_TRANSITION = 0x40, // if set and looping is enabled, the animation will transition instead of just jumping when looping.
        ANIMATION_RESET = 0x1000000,
        ANIMATION_TRANSITION = 0x20000000, // a transition to a different animation time is planned.
        ANIMATION_TRANSITIONING_NOW = 0x40000000, // an actual transition to a different animation time is ongoing.
        ANIMATION_ENABLED = 0x10000000,
        ANIMATION_DISABLED = 0x80000000,
    } swrModel_AnimationFlags;

    typedef struct swrModel_Animation
    {
        uint8_t unk1[220];
        float loop_transition_speed;
        float transition_speed;
        float transition_interp_factor;
        uint32_t transition_from_this_key_frame_index;
        uint32_t transition_from_this_animation_time;
        float animation_start_time;
        float animation_end_time;
        float animation_duration;
        float duration3;
        union
        {
            struct
            {
                uint32_t type : 4;
                uint32_t flags1 : 28;
            };
            swrModel_AnimationFlags flags;
        };
        uint32_t num_key_frames;
        float duration4;
        float duration5;
        float animation_speed;
        float animation_time;
        int key_frame_index;
        float* key_frame_times;
        union
        {
            float* key_frame_values;
            rdVector4* key_frame_axis_angle_rotations; // type 0x8
            rdVector3* key_frame_translations; // type 0x9
            float* key_frame_uv_x_offsets; // type 0xB
            float* key_frame_uv_y_offsets; // type 0xC
        };
        union
        {
            swrModel_Node* node_ptr; // if type == 0x8 or type == 0x9 or type == 0xA
            swrModel_MeshMaterial* material_ptr; // if type == 0xB or type == 0xC
        };
        uint32_t unk11;
    } swrModel_Animation;

#ifdef __cplusplus
}
#endif