#ifndef SWRCAM_H
#define SWRCAM_H

#include "types.h"

// Camera-state subsystem. Operates on the camera-state array (swrCamera_unk,
// stride 0x7c) reachable through unkCameraArray (0x004b91c4), and the
// metacamera array (0x00dfb040, stride 0x16c). See also swrObjcMan_* (the
// camera-man entity) in swrObj.h and swrViewport_* in swrViewport.h.

#define swrCam_CamState_InitMainMat4_ADDR (0x00428A60)

// Initializes the per-camera-state entry at index: stores val1 (+4), val2 (+6)
// and a matrix pointer (+8) into swrCamera_unk[index].
void swrCam_CamState_InitMainMat4(uint16_t index, uint16_t val1, rdMatrix44* mat, uint16_t val2);

#endif // SWRCAM_H
