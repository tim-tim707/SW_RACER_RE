#ifndef SWRVIEWPORT_H
#define SWRVIEWPORT_H

#include "types.h"

#define swrViewport_SetCameraIndex_ADDR (0x00428B40)
#define swrViewport_SetActiveCamera_ADDR (0x00428bd0)

#define swrViewport_UpdateCameras_ADDR (0x00429540)

#define swrViewport_ProjectToScreen_ADDR (0x0042b710)

#define swrViewport_GetNumViewports_ADDR (0x004318c0)
#define swrViewport_Get_ADDR (0x004318d0)
#define swrViewport_ExtractViewTransform_ADDR (0x00431900)
#define swrViewport_SetMat3_ADDR (0x00431950)
#define swrViewport_SetRootNode_ADDR (0x00431a00)
#define swrViewport_SetNodeFlags_ADDR (0x00431a10)

#define swrViewport_UpdateUnknown_ADDR (0x00482EE0)
#define swrViewport_ComputeClipMatrix_ADDR (0x00482f10)
#define swrViewport_ComputeScreenRect_ADDR (0x004830E0)
#define swrViewport_SetViewport_ADDR (0x004831D0)
#define swrViewport_Enable_ADDR (0x00483230)
#define swrViewport_Init_ADDR (0x00483270)

#define swrViewport_SetCameraParameters_ADDR (0x00483590)

#define swrViewport_Setup_ADDR (0x00483750)

#define swrViewport_Render_ADDR (0x00483A90)
#define swrViewport_Activate_ADDR (0x00483BB0)

#define swrViewport_SetRootNodeForAllViewports_ADDR (0x00483fc0)
#define swrViewport_SetNodeFlagsForAllViewports_ADDR (0x00483ff0)

void swrViewport_SetCameraIndex(short a1, swrViewport* mesh);

// Selects the active viewport camera, clearing the previous selection's flag and setting the new one's.
void swrViewport_SetActiveCamera(short cameraIndex);
void swrViewport_UpdateCameras();

// Projects a world (or camera-relative) point to screen pixels for the given viewport.
// Outputs go to outScreenX / outScreenY (set to -1000.0 if off the projection rect),
// outZ and outDepth. pointIsCameraRelative == 0 means worldPos is absolute world space
// and gets made camera-relative first.
void swrViewport_ProjectToScreen(void* viewport, rdVector4* worldPos, float* outScreenX, float* outScreenY, float* outZ, float* outDepth, int pointIsCameraRelative);

int swrViewport_GetNumViewports();
swrViewport* swrViewport_Get(int index);
void swrViewport_ExtractViewTransform(swrViewport* param_1, rdVector3* translation, rdVector3* rotation);
void swrViewport_SetMat3(swrViewport* a1, const rdMatrix44* a2);
void swrViewport_SetRootNode(swrViewport* a1, swrModel_Node* a2);
void swrViewport_SetNodeFlags(swrViewport* a1, int flag, int value);

void swrViewport_UpdateUnknown(swrViewport*);
void swrViewport_ComputeClipMatrix(swrViewport* unk);
void swrViewport_ComputeScreenRect(swrViewport* a1);
void swrViewport_SetViewport(int viewportIndex, int x1, int y1, int x2, int y2);
void swrViewport_Enable(int viewportIndex, int cameraIndex);
void swrViewport_Init(int);

void swrViewport_SetCameraParameters(int viewportIndex, float fovY, float aspect, float nearClip, float farClip, float param6);

void swrViewport_Setup(int);

void swrViewport_Render(int x);

void swrViewport_Activate(int);

void swrViewport_SetRootNodeForAllViewports(swrModel_Node* unk);
void swrViewport_SetNodeFlagsForAllViewports(int flag, int value);

#endif // SWRVIEWPORT_H
