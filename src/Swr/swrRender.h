#ifndef SWRRENDER_H
#define SWRRENDER_H

#include "types.h"

#define rdModel3Mesh_CalculateSurfaceNormals_ADDR (0x00409290)
#define rdFace_ConfigureFogStartEnd_ADDR (0x00409380)
#define Direct3d_ConfigFog2_ADDR (0x00409450)
#define rdFace_SetFogEnabled_ADDR (0x004094E0)
#define rdCamera_SetLights_ADDR (0x00409510)
#define SetLightColorsAndDirection_ADDR (0x00409600)
#define SetLightColorsAndDirectionFromPrimaryLight_ADDR (0x00409700)
#define SetAlternativeLightColorsAndDirection_ADDR (0x00409750)

#define rdModel3Mesh_ApplySwrModelColors_ADDR (0x00432B80)
#define rdModel_ConvertSwrModelMesh_ADDR (0x00432D30)

#define rdModel_ApplyNodeSettings_ADDR (0x0044C440)
#define rdModel_RevertNodeSettings_ADDR (0x0044C4C0)
#define AABBFrustumTest_ADDR (0x0044c510)
#define rdModel_AddMeshGroupToScene_ADDR (0x0044ca00)
#define rdModel_AddMeshGroupToScene2_ADDR (0x0044ceb0)
#define NodeTransformedWithPivot_ApplyTransform_ADDR (0x0044d1e0)
#define rdModel_AddTransformedNodeToScene_ADDR (0x0044d240)
#define rdModel_NodeTransformedComputedToScene_ADDR (0x0044d310)
#define NodeLODSelector_FindLODIndex_ADDR (0x0044d740)
#define rdModel_AddNodeToScene_ADDR (0x0044d7c0)
#define rdModel_AddNodeToScene2_ADDR (0x0044dae0)

#define SetFogParameters_ADDR (0x0044E0E0)
#define SetPrimaryLightColorsAndDirection_ADDR (0x0044E140)
#define SetSecondaryLightColorsAndDirection_ADDR (0x0044E190)
#define SetLightColorsAndDirectionFromPrimraryLight2_ADDR (0x0044E1F0)
#define SetAlternativeLightColorsAndDirection2_ADDR (0x0044E220)
#define rdProcEntry_SetCurrentColor_ADDR (0x0044E290)

#define SetLightColorsAndDirection2_ADDR (0x00483840)
#define SetAlternativeLightColorsAndDirection3_ADDR (0x00483960)
#define SetLightColorsAndDirectionFromPrimaryLight3_ADDR (0x00483A40)
#define SetClearColor_ADDR (0x00483A60)

void rdModel3Mesh_CalculateSurfaceNormals(rdModel3Mesh* mesh);
void rdFace_ConfigureFogStartEnd(int16_t start, int16_t end);
void Direct3d_ConfigFog2(short r, short g, short b, short a);
int rdFace_SetFogEnabled(int);
void rdCamera_SetLights(int light_index, int num_lights);
float* SetLightColorsAndDirection(int light_index, short ambient_r, short ambient_g, short ambient_b, short light_r, short light_g, short light_b, short pos_x, short pos_y, short pos_z);
int SetLightColorsAndDirectionFromPrimaryLight(short light_index);
float* SetAlternativeLightColorsAndDirection(int index, short light_r, short light_g, short light_b, short pos_x, short pos_y, short pos_z);

void rdModel3Mesh_ApplySwrModelColors(rdModel3Mesh* rdmesh, swrModel_Mesh* mesh);
void rdModel_ConvertSwrModelMesh(Gfx* display_list, rdModel3Mesh* result, swrModel_Mesh* mesh, RdFaceFlag material_flags);

char rdModel_ApplyNodeSettings(char flags_5, short light_index);
void rdModel_RevertNodeSettings(char state);
int16_t AABBFrustumTest(float* aabb, bool full_test);
void rdModel_AddMeshGroupToScene(swrModel_NodeMeshGroup* node);
void rdModel_AddMeshGroupToScene2(swrModel_NodeMeshGroup* node);
void NodeTransformedWithPivot_ApplyTransform(rdMatrix34* inout_transform, const rdMatrix34* transform, const rdVector3* pivot);
void rdModel_AddTransformedNodeToScene(int a1, rdMatrix34* transform, swrModel_Node* node);
void rdModel_NodeTransformedComputedToScene(swrModel_Node* node);
int NodeLODSelector_FindLODIndex(swrModel_Node* node);
void rdModel_AddNodeToScene(swrModel_Node* a1);
void rdModel_AddNodeToScene2(swrModel_Node* a1);

void SetFogParameters(int fogStart_, int fogEnd_, int fogColorR, int fogColorG, int fogColorB, int fogColorA);
void SetPrimaryLightColorsAndDirection(short* ambient_color, short* light_color, short* light_position);
void SetSecondaryLightColorsAndDirection(unsigned int light_index, short* ambient_color, short* light_color, short* light_position);
void SetLightColorsAndDirectionFromPrimraryLight2(unsigned int);
void SetAlternativeLightColorsAndDirection2(int light_index, BOOL light_type2, short* light_color, short* light_position);
void rdProcEntry_SetCurrentColor(int, int, uint8_t, uint8_t, uint8_t, uint8_t);

float* SetLightColorsAndDirection2(int a1, rdVector3* ambient_color, rdVector3* light_color, rdVector3* light_position);
float* SetAlternativeLightColorsAndDirection3(int light_index, BOOL light_type2, float* light_color, rdVector3* light_position);
int SetLightColorsAndDirectionFromPrimaryLight3(unsigned int);
short SetClearColor(short, short, short);

#endif // SWRRENDER_H
