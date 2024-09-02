#ifndef SWRVIEWPORT_H
#define SWRVIEWPORT_H

#include "types.h"

#define swrViewport_SetCameraIndex_ADDR (0x00428B40)

#define swrViewport_UpdateCameras_ADDR (0x00429540)

#define swrViewport_GetNumViewports_ADDR (0x004318c0)
#define swrViewport_Get_ADDR (0x004318d0)
#define swrViewport_ExtractViewTransform_ADDR (0x00431900)
#define swrViewport_SetMat3_ADDR (0x00431950)
#define swrViewport_SetRootNode_ADDR (0x00431a00)
#define swrViewport_SetNodeFlags_ADDR (0x00431a10)

#define swrViewport_UpdateUnknown_ADDR (0x00482EE0)
#define swrViewport_UpdateClipMatrix_ADDR (0x00482f10)
#define swrViewport_ScaleViewport_ADDR (0x004830E0)
#define swrViewport_SetViewport_ADDR (0x004831D0)
#define swrViewport_Enable_ADDR (0x00483230)
#define swrViewport_Init_ADDR (0x00483270)

#define swrViewport_SetCameraParameters_ADDR (0x00483590)

#define swrViewport_UpdateViewTransforms_ADDR (0x00483750)

#define swrViewport_Render_ADDR (0x00483A90)
#define swrViewport_SetCurrent_ADDR (0x00483BB0)

#define RenderAll_ADDR (0x00483CB0)

#define swrViewport_SetRootNodeForAllViewports_ADDR (0x00483fc0)
#define swrViewport_SetNodeFlagsForAllViewports_ADDR (0x00483ff0)

int swrViewport_GetNumViewports();
swrViewport* swrViewport_Get(int index);
void swrViewport_ExtractViewTransform(swrViewport* param_1, rdVector3* translation, rdVector3* rotation);
void swrViewport_SetMat3(swrViewport* a1, const rdMatrix44* a2);
void swrViewport_SetRootNode(swrViewport* a1, swrModel_Node* a2);
void swrViewport_SetNodeFlags(swrViewport* a1, int flag, int value);

void swrViewport_UpdateUnknown(swrViewport*);
void swrViewport_UpdateClipMatrix(swrViewport* unk);
void swrViewport_ScaleViewport(swrViewport* a1);
void swrViewport_SetViewport(int a1, int a2, int a3, int a4, int a5);
void swrViewport_Enable(int, int);
void swrViewport_Init(int);

void swrViewport_SetCameraParameters(int, float, float, float, float, float);

void swrViewport_UpdateViewTransforms(int);

void swrViewport_Render(int x);

void swrViewport_SetCurrent(int);

void RenderAll();
void swrViewport_SetRootNodeForAllViewports(swrModel_Node* unk);
void swrViewport_SetNodeFlagsForAllViewports(int flag, int value);


#endif //SWRVIEWPORT_H
