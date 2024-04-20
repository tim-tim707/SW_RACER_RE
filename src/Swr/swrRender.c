#include "swrRender.h"

#include <macros.h>

// 0x00409290
void rdModel3Mesh_CalculateSurfaceNormals(rdModel3Mesh* mesh)
{
    HANG("TODO");
}

// 0x00409380
void rdFace_ConfigureFogStartEnd(int16_t start, int16_t end)
{
    HANG("TODO");
}

// 0x00409450
void Direct3d_ConfigFog2(short r, short g, short b, short a)
{
    HANG("TODO");
}

// 0x004094E0
int rdFace_SetFogEnabled(int)
{
    HANG("TODO");
}

// 0x00409510
void rdCamera_SetLights(int light_index, int num_lights)
{
    HANG("TODO");
}

// 0x00409600
float* SetLightColorsAndDirection(int light_index, short ambient_r, short ambient_g, short ambient_b, short light_r, short light_g, short light_b, short pos_x, short pos_y, short pos_z)
{
    HANG("TODO");
}

// 0x00409700
int SetLightColorsAndDirectionFromPrimaryLight(short light_index)
{
    HANG("TODO");
}

// 0x00409750
float* SetAlternativeLightColorsAndDirection(int light_index, short light_r, short light_g, short light_b, short pos_x, short pos_y, short pos_z)
{
    HANG("TODO");
}

// 0x00432B80
void rdModel3Mesh_ApplySwrModelColors(rdModel3Mesh* rdmesh, swrModel_Mesh* mesh)
{
    HANG("TODO");
}

// 0x00432D30
void rdModel_ConvertSwrModelMesh(Gfx* display_list, rdModel3Mesh* result, swrModel_Mesh* mesh, RdFaceFlag material_flags)
{
    HANG("TODO");
}

// 0x0044C440
char rdModel_ApplyNodeSettings(char, short)
{
    HANG("TODO");
}

// 0x0044C4C0
void rdModel_RevertNodeSettings(char)
{
    HANG("TODO");
}

// 0x0044c510
int16_t AABBFrustumTest(float* aabb, bool full_test)
{
    HANG("TODO");
}

// 0x0044ca00
void rdModel_AddMeshGroupToScene(swrModel_NodeMeshGroup* node)
{
    HANG("TODO");
}

// 0x0044ceb0
void rdModel_AddMeshGroupToScene2(swrModel_NodeMeshGroup* node)
{
    HANG("TODO");
}

// 0x0044d1e0
void NodeTransformedWithPivot_ApplyTransform(rdMatrix34* inout_transform, const rdMatrix34* transform, const rdVector3* pivot)
{
    HANG("TODO");
}

// 0x0044d240
void rdModel_AddTransformedNodeToScene(int a1, rdMatrix34* transform, swrModel_Node* node)
{
    HANG("TODO");
}

// 0x0044d310
void rdModel_NodeTransformedComputedToScene(swrModel_Node* node)
{
    HANG("TODO");
}

// 0x0044d740
int NodeLODSelector_FindLODIndex(swrModel_Node* node)
{
    HANG("TODO");
}

// 0x0044d7c0
void rdModel_AddNodeToScene(swrModel_Node* a1)
{
    HANG("TODO");
}

// 0x0044dae0
void rdModel_AddNodeToScene2(swrModel_Node* a1)
{
    HANG("TODO");
}

// 0x0044E0E0
void SetFogParameters(int fogStart_, int fogEnd_, int fogColorR, int fogColorG, int fogColorB, int fogColorA)
{
    HANG("TODO");
}

// 0x0044E140
void SetPrimaryLightColorsAndDirection(short* ambient_color, short* light_color, short* light_position)
{
    HANG("TODO");
}

// 0x0044E190
void SetSecondaryLightColorsAndDirection(unsigned int light_index, short* ambient_color, short* light_color, short* light_position)
{
    HANG("TODO");
}

// 0x0044E1F0
void SetLightColorsAndDirectionFromPrimraryLight2(unsigned int)
{
    HANG("TODO");
}

// 0x0044E220
void SetAlternativeLightColorsAndDirection2(int light_index, BOOL light_type2, short* light_color, short* light_position)
{
    HANG("TODO");
}

// 0x0044E290
void rdProcEntry_SetCurrentColor(int, int, uint8_t, uint8_t, uint8_t, uint8_t)
{
    HANG("TODO");
}

// 0x00483750
void swrModel_UnkUpdateViewTransforms2(int)
{
    HANG("TODO");
}

// 0x00483840
float* SetLightColorsAndDirection2(int a1, rdVector3* ambient_color, rdVector3* light_color, rdVector3* light_position)
{
    HANG("TODO");
}

// 0x00483960
float* SetAlternativeLightColorsAndDirection3(int light_index, BOOL light_type2, float* light_color, rdVector3* light_position)
{
    HANG("TODO");
}

// 0x00483A40
int SetLightColorsAndDirectionFromPrimaryLight3(unsigned int)
{
    HANG("TODO");
}

// 0x00483A60
short SetClearColor(short, short, short)
{
    HANG("TODO");
}

// 0x00483A90
void swrModel_UnkDraw(int x)
{
    HANG("TODO");
}

// 0x00483BB0
void swrModel_UnkUpdateViewTransforms1(int)
{
    HANG("TODO");
}
