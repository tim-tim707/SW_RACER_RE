#ifndef SWRCAM_H
#define SWRCAM_H

#include "types.h"

// Camera-state subsystem. Operates on the camera-state array (swrCamera_unk,
// stride 0x7c) reachable through unkCameraArray (0x004b91c4), and the
// metacamera array (0x00dfb040, stride 0x16c). See also swrObjcMan_* (the
// camera-man entity) in swrObj.h and swrViewport_* in swrViewport.h.

#define swrCam_CamState_InitMatrices_ADDR (0x00428830)
#define swrCam_CamState_SetFlags_ADDR (0x00428a40)
#define swrCam_CamState_InitMainMat4_ADDR (0x00428A60)
#define swrCam_CamState_SetOffset_ADDR (0x00428aa0)
#define swrCam_CamState_SetOffsetSource_ADDR (0x00428b10)
#define swrCam_CamState_GetOffsetTransform_ADDR (0x00428c40)
#define swrCam_CamState_ApplyToViewport_ADDR (0x00428cd0)

// Reset/init the per-camera transform matrices across the camera-state array.
void swrCam_CamState_InitMatrices(void);

// OR flag bits into swrCamera_unk[index].flags.
void swrCam_CamState_SetFlags(int index, unsigned int flags);

// Initializes the per-camera-state entry at index: stores val1 (+4), val2 (+6)
// and a matrix pointer (+8) into swrCamera_unk[index].
void swrCam_CamState_InitMainMat4(uint16_t index, uint16_t val1, rdMatrix44* mat, uint16_t val2);

// Set the camera's position offset (posOffset) and rotation (rotationYPR).
void swrCam_CamState_SetOffset(short index, float posX, float posY, float posZ, float yaw, float pitch, float roll);

// Set the offset-source object (+ offsetMode) the camera tracks.
void swrCam_CamState_SetOffsetSource(short index, void* source, short mode);

// Resolve the offset-source node's transform (mode 2/3 read the node transform).
void swrCam_CamState_GetOffsetTransform(int mode, swrModel_NodeTransformed* node, rdMatrix44* out);

// Compose the camera-state transform and apply it to the viewport.
void swrCam_CamState_ApplyToViewport(swrViewport* viewport);

#endif // SWRCAM_H
