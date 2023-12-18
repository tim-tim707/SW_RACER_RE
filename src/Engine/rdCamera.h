#ifndef RDCAMERA_H
#define RDCAMERA_H

#include "types.h"

#define rdCamera_Shutdown_ADDR (0x00409af0)

#define rdCamera_New_ADDR (0x0048fad0)
#define rdCamera_NewEntry_ADDR (0x0048fb20)
#define rdCamera_Free_ADDR (0x0048fc10)
#define rdCamera_FreeEntry_ADDR (0x0048fc30)
#define rdCamera_SetCanvas_ADDR (0x0048fc50)
#define rdCamera_SetCurrent_ADDR (0x0048fc70)
#define rdCamera_SetProjectType_ADDR (0x0048fc90)
#define rdCamera_UpdateProject_ADDR (0x0048fd10)
#define rdCamera_BuildFOV_ADDR (0x0048fdc0)
#define rdCamera_BuildClipFrustum_ADDR (0x0048ffc0)
#define rdCamera_Update_ADDR (0x00490060)
#define rdCamera_OrthoProject_ADDR (0x004900a0)
#define rdCamera_OrthoProjectLst_ADDR (0x004900e0)
#define rdCamera_OrthoProjectSquare_ADDR (0x00490160)
#define rdCamera_OrthoProjectSquareLst_ADDR (0x004901a0)
#define rdCamera_PerspProject_ADDR (0x00490210)
#define rdCamera_PerspProjectLst_ADDR (0x00490250)
#define rdCamera_PerspProjectSquare_ADDR (0x004902d0)
#define rdCamera_PerspProjectSquareLst_ADDR (0x00490310)
#define rdCamera_SetAmbientLight_ADDR (0x004903a0)
#define rdCamera_SetAttenuation_ADDR (0x004903d0)
#define rdCamera_AddLight_ADDR (0x00490450)
#define rdCamera_ClearLights_ADDR (0x004904f0)

void rdCamera_Shutdown(void);

rdCamera* rdCamera_New(float fov, float x, float y, float z, float aspectRatio);
int rdCamera_NewEntry(rdCamera* camera, float fov, float a3, float zNear, float zFar, float aspectRatio);
void rdCamera_Free(rdCamera* camera);
void rdCamera_FreeEntry(rdCamera* camera);
int rdCamera_SetCanvas(rdCamera* camera, rdCanvas* canvas);
int rdCamera_SetCurrent(rdCamera* camera);
int rdCamera_SetProjectType(rdCamera* camera, rdCameraProjectType type);
int rdCamera_UpdateProject(rdCamera* camera, float aspectRatio);
int rdCamera_BuildFOV(rdCamera* camera);
int rdCamera_BuildClipFrustum(rdCamera* camera, rdClipFrustum* outClip, float width, float height);
void rdCamera_Update(rdMatrix34* orthoProj);
void rdCamera_OrthoProject(rdVector3* out, rdVector3* v);
void rdCamera_OrthoProjectLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices);
void rdCamera_OrthoProjectSquare(rdVector3* out, rdVector3* v);
void rdCamera_OrthoProjectSquareLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices);
void rdCamera_PerspProject(rdVector3* out, rdVector3* v);
void rdCamera_PerspProjectLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices);
void rdCamera_PerspProjectSquare(rdVector3* out, rdVector3* v);
void rdCamera_PerspProjectSquareLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices);
void rdCamera_SetAmbientLight(rdCamera* camera, rdVector4* v);
void rdCamera_SetAttenuation(rdCamera* camera, float minVal, float maxVal);
int rdCamera_AddLight(rdCamera* camera, rdLight* light, rdVector3* lightPos);
int rdCamera_ClearLights(rdCamera* camera);

#endif // RDCAMERA_H
