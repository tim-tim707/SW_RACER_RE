#include "swrRender.h"

#include "globals.h"

#include <Engine/rdCamera.h>
#include <Primitives/rdVector.h>
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

// Push light slot `light_index` from the staging arrays into the active cameras: direction into
// rdCamera_main_ptr's light position, color into the current camera's light, plus ambient. A
// second light (secondary bank) is activated when num_lights > 1, otherwise it is disabled.
// 0x00409510
void rdCamera_SetLights(int light_index, int num_lights)
{
    rdCamera_main_ptr->lightPositions[0].x = lightDirection1[light_index].x;
    rdCamera_main_ptr->lightPositions[0].y = lightDirection1[light_index].y;
    rdCamera_main_ptr->lightPositions[0].z = lightDirection1[light_index].z;
    rdCamera_pCurCamera->lights[0]->color = lightColor1[light_index];
    rdCamera_pCurCamera->lights[0]->active = 1;
    rdCamera_SetAmbientLight(rdCamera_pCurCamera, &lightAmbientColor[light_index]);
    if (num_lights > 1) {
        rdCamera_main_ptr->lightPositions[1].x = lightDirection2[light_index].x;
        rdCamera_main_ptr->lightPositions[1].y = lightDirection2[light_index].y;
        rdCamera_main_ptr->lightPositions[1].z = lightDirection2[light_index].z;
        rdCamera_pCurCamera->lights[1]->color = lightColor2[light_index];
        rdCamera_pCurCamera->lights[1]->active = 1;
    } else {
        rdCamera_pCurCamera->lights[1]->active = 0;
    }
}

// Set primary-bank light `light_index`: direction from the raw position, color + ambient from
// 0-255 components scaled to 0..1 (w = 1.0). The return is the internal light_index*16 byte
// offset left in EAX; callers ignore it.
// 0x00409600
float* SetLightColorsAndDirection(int light_index, short ambient_r, short ambient_g, short ambient_b, short light_r, short light_g, short light_b, short pos_x, short pos_y, short pos_z)
{
    lightDirection1[light_index].x = (float)(int)pos_x;
    lightDirection1[light_index].y = (float)(int)pos_y;
    lightDirection1[light_index].z = (float)(int)pos_z;
    lightColor1[light_index].x = (float)(int)light_r * oneOver255f;
    lightColor1[light_index].y = (float)(int)light_g * oneOver255f;
    lightColor1[light_index].z = (float)(int)light_b * oneOver255f;
    lightColor1[light_index].w = 1.0f;
    lightAmbientColor[light_index].x = (float)(int)ambient_r * oneOver255f;
    lightAmbientColor[light_index].y = (float)(int)ambient_g * oneOver255f;
    lightAmbientColor[light_index].z = (float)(int)ambient_b * oneOver255f;
    lightAmbientColor[light_index].w = 1.0f;
    return (float*)(light_index * 0x10);
}

// Copy the primary light (slot 0)'s direction/color/ambient x,y,z into slot `light_index`.
// 0x00409700
int SetLightColorsAndDirectionFromPrimaryLight(short light_index)
{
    lightDirection1[light_index].x = lightDirection1[0].x;
    lightDirection1[light_index].y = lightDirection1[0].y;
    lightDirection1[light_index].z = lightDirection1[0].z;
    lightColor1[light_index].x = lightColor1[0].x;
    lightColor1[light_index].y = lightColor1[0].y;
    lightColor1[light_index].z = lightColor1[0].z;
    lightAmbientColor[light_index].x = lightAmbientColor[0].x;
    lightAmbientColor[light_index].y = lightAmbientColor[0].y;
    lightAmbientColor[light_index].z = lightAmbientColor[0].z;
    return 0xc;
}

// Set secondary-bank light `light_index`: direction from the raw position, color from 0-255
// components (the secondary bank has no ambient term). Return is the vestigial index offset.
// 0x00409750
float* SetAlternativeLightColorsAndDirection(int light_index, short light_r, short light_g, short light_b, short pos_x, short pos_y, short pos_z)
{
    lightDirection2[light_index].x = (float)(int)pos_x;
    lightDirection2[light_index].y = (float)(int)pos_y;
    lightDirection2[light_index].z = (float)(int)pos_z;
    lightColor2[light_index].x = (float)(int)light_r * oneOver255f;
    lightColor2[light_index].y = (float)(int)light_g * oneOver255f;
    lightColor2[light_index].z = (float)(int)light_b * oneOver255f;
    lightColor2[light_index].w = 1.0f;
    return (float*)(light_index * 0x10);
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

// Primary light (slot 0) from short[3] ambient/color/position arrays; position negated to a direction.
// 0x0044E140
void SetPrimaryLightColorsAndDirection(short* ambient_color, short* light_color, short* light_position)
{
    SetLightColorsAndDirection(0, ambient_color[0], ambient_color[1], ambient_color[2], light_color[0], light_color[1], light_color[2], -light_position[0], -light_position[1], -light_position[2]);
}

// Secondary light `light_index` (stored at slot light_index+1) from short[3] arrays.
// 0x0044E190
void SetSecondaryLightColorsAndDirection(unsigned int light_index, short* ambient_color, short* light_color, short* light_position)
{
    if ((int)light_index >= 0 && (int)light_index < 0xc) {
        SetLightColorsAndDirection(light_index + 1, ambient_color[0], ambient_color[1], ambient_color[2], light_color[0], light_color[1], light_color[2], -light_position[0], -light_position[1], -light_position[2]);
    }
}

// Copy the primary light into slot index+1 and record numEnabledLights[index] = 1.
// 0x0044E1F0
void SetLightColorsAndDirectionFromPrimraryLight2(unsigned int index)
{
    if ((int)index >= 0 && (int)index < 0xc) {
        SetLightColorsAndDirectionFromPrimaryLight((short)index + 1);
        numEnabledLights[index] = 1;
    }
}

// Secondary-bank light `light_index`: light_type2 == 0 -> just record it (numEnabledLights = 1);
// otherwise record numEnabledLights = 2 and set slot light_index+1 from the color/position arrays.
// 0x0044E220
void SetAlternativeLightColorsAndDirection2(int light_index, BOOL light_type2, short* light_color, short* light_position)
{
    if (light_index >= 0 && light_index < 0xc) {
        if (light_type2 == 0) {
            numEnabledLights[light_index] = 1;
            return;
        }
        numEnabledLights[light_index] = 2;
        SetAlternativeLightColorsAndDirection(light_index + 1, light_color[0], light_color[1], light_color[2], -light_position[0], -light_position[1], -light_position[2]);
    }
}

// 0x0044E290
void rdProcEntry_SetCurrentColor(int a1, int a2, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    rdProcEntry_CurrentColor.x = (float) r * oneOver255f;
    rdProcEntry_CurrentColor.y = (float) g * oneOver255f;
    rdProcEntry_CurrentColor.z = (float) b * oneOver255f;
    rdProcEntry_CurrentColor.w = (float) a * oneOver255f;
}

// Float-input primary/secondary light. Normalizes light_position to a length-120 direction
// (straight down when the position is near-zero), truncates the float ambient/color/direction
// to shorts, and dispatches to SetPrimary (a1 == -1) or SetSecondary. Return unused (vestigial).
// 0x00483840
float* SetLightColorsAndDirection2(int a1, rdVector3* ambient_color, rdVector3* light_color, rdVector3* light_position)
{
    float dir_x;
    float dir_y;
    float dir_z;
    float len = rdVector_Len3(light_position);
    if (len < 0.01f) {
        dir_x = 0.0f;
        dir_y = 0.0f;
        dir_z = -1.0f;
    } else {
        float scale = 120.0f / len;
        dir_x = light_position->x * scale;
        dir_y = light_position->y * scale;
        dir_z = light_position->z * scale;
    }
    short ambient[3] = { (short)(int)ambient_color->x, (short)(int)ambient_color->y, (short)(int)ambient_color->z };
    short color[3] = { (short)(int)light_color->x, (short)(int)light_color->y, (short)(int)light_color->z };
    short direction[3] = { (short)(int)dir_x, (short)(int)dir_y, (short)(int)dir_z };
    if (a1 == -1) {
        SetPrimaryLightColorsAndDirection(ambient, color, direction);
    } else {
        SetSecondaryLightColorsAndDirection(a1, ambient, color, direction);
    }
    return NULL;
}

// Float-input secondary-bank variant: when light_type2 is set, normalize light_position the same
// way and truncate the float color to shorts; then defer to SetAlternative...2. Return unused.
// 0x00483960
float* SetAlternativeLightColorsAndDirection3(int light_index, BOOL light_type2, float* light_color, rdVector3* light_position)
{
    short color[3] = { 0, 0, 0 };
    short direction[3] = { 0, 0, 0 };
    if (light_type2 != 0) {
        float dir_x;
        float dir_y;
        float dir_z;
        float len = rdVector_Len3(light_position);
        if (len < 0.01f) {
            dir_x = 0.0f;
            dir_y = 0.0f;
            dir_z = -1.0f;
        } else {
            float scale = 120.0f / len;
            dir_x = light_position->x * scale;
            dir_y = light_position->y * scale;
            dir_z = light_position->z * scale;
        }
        color[0] = (short)(int)light_color[0];
        color[1] = (short)(int)light_color[1];
        color[2] = (short)(int)light_color[2];
        direction[0] = (short)(int)dir_x;
        direction[1] = (short)(int)dir_y;
        direction[2] = (short)(int)dir_z;
    }
    SetAlternativeLightColorsAndDirection2(light_index, light_type2, color, direction);
    return NULL;
}

// Guarded wrapper: copy the primary light into slot a1+1 unless a1 == -1.
// 0x00483A40
int SetLightColorsAndDirectionFromPrimaryLight3(unsigned int a1)
{
    if (a1 != 0xffffffff) {
        SetLightColorsAndDirectionFromPrimraryLight2(a1);
    }
    return a1;
}

// 0x00483A60
short SetClearColor(short r, short g, short b)
{
    backBufferClearColor[0] = r;
    backBufferClearColor[1] = g;
    backBufferClearColor[2] = b;
    return r;
}
