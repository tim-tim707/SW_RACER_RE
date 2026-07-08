#include "swrRender.h"

#include "globals.h"

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
int rdFace_SetFogEnabled(int mode)
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
char rdModel_ApplyNodeSettings(char flags, short light_index)
{
    HANG("TODO");
}

// 0x0044C4C0
void rdModel_RevertNodeSettings(char state)
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
void rdModel_NodeTransformedComputedToScene(swrModel_NodeTransformedComputed* node)
{
    HANG("TODO");
}

// 0x0044d740
int NodeLODSelector_FindLODIndex(swrModel_NodeLODSelector* node)
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
    // a negative component leaves that field unchanged
    if (fogStart_ >= 0) {
        fogStartInt16 = (int16_t) fogStart_;
    }
    if (fogEnd_ >= 0) {
        fogEndInt16 = (int16_t) fogEnd_;
    }
    if (fogColorR >= 0) {
        fogColorInt16[0] = (int16_t) fogColorR;
    }
    if (fogColorG >= 0) {
        fogColorInt16[1] = (int16_t) fogColorG;
    }
    if (fogColorB >= 0) {
        fogColorInt16[2] = (int16_t) fogColorB;
    }
    if (fogColorA >= 0) {
        fogColorInt16[3] = (int16_t) fogColorA;
    }
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
void SetLightColorsAndDirectionFromPrimraryLight2(unsigned int index)
{
    HANG("TODO");
}

// 0x0044E220
void SetAlternativeLightColorsAndDirection2(int light_index, BOOL light_type2, short* light_color, short* light_position)
{
    HANG("TODO");
}

// 0x0044E290
void rdProcEntry_SetCurrentColor(int a1, int a2, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    rdProcEntry_CurrentColor.x = (float) r * oneOver255f;
    rdProcEntry_CurrentColor.y = (float) g * oneOver255f;
    rdProcEntry_CurrentColor.z = (float) b * oneOver255f;
    rdProcEntry_CurrentColor.w = (float) a * oneOver255f;
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
int SetLightColorsAndDirectionFromPrimaryLight3(unsigned int a1)
{
    HANG("TODO");
}

// 0x00483A60
short SetClearColor(short r, short g, short b)
{
    backBufferClearColor[0] = r;
    backBufferClearColor[1] = g;
    backBufferClearColor[2] = b;
    return r;
}
