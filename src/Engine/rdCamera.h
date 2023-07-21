#ifndef RDCAMERA_H
#define RDCAMERA_H

#include "types.h"

#define rdCamera_SetProjectType_ADDR (0x0048fc90)

#define rdCamera_BuildFOV_ADDR (0x0048fdc0)

#define rdCamera_BuildClipFrustum_Unk_ADDR (0x0048ffc0)

#define rdCamera_Update_ADDR (0x00490060)
#define rdCamera_OrthoProject_ADDR (0x004900a0)
#define rdCamera_OrthoProjectLst_ADDR (0x004900e0)
#define rdCamera_OrthoProjectSquare_ADDR (0x00490160)
#define rdCamera_OrthoProjectSquareLst_ADDR (0x004901a0)
#define rdCamera_PerspProject_ADDR (0x00490210)
#define rdCamera_PerspProjectLst_ADDR (0x00490250)
#define rdCamera_PerspProjectSquare_ADDR (0x004902d0)
#define rdCamera_PerspProjectSquareLst_ADDR (0x00490310)

int rdCamera_SetProjectType(rdCamera* camera, rdCameraProjectType type);

int rdCamera_BuildFOV(rdCamera* camera);

int rdCamera_BuildClipFrustum_Unk(rdCamera* camera, rdClipFrustum* outClip, float width, float height);

void rdCamera_Update(rdMatrix34* orthoProj);
void rdCamera_OrthoProject(rdVector3* out, rdVector3* v);
void rdCamera_OrthoProjectLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices);
void rdCamera_OrthoProjectSquare(rdVector3* out, rdVector3* v);
void rdCamera_OrthoProjectSquareLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices);
void rdCamera_PerspProject(rdVector3* out, rdVector3* v);
void rdCamera_PerspProjectLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices);
void rdCamera_PerspProjectSquare(rdVector3* out, rdVector3* v);
void rdCamera_PerspProjectSquareLst(rdVector3* vertices_out, rdVector3* vertices_in, unsigned int num_vertices);

#endif // RDCAMERA_H
