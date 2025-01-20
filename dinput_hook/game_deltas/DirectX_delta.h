#pragma once

#include "types.h"

void DirectDraw_InitProgressBar_delta(void);
void DirectDraw_Shutdown_delta(void);
void DirectDraw_BlitProgressBar_delta(int progress);

void DirectDraw_LockZBuffer_delta(uint32_t *bytes_per_depth_value, LONG *pitch, LPVOID *data,
                                  float *near, float *far);
void DirectDraw_UnlockZBuffer_delta(void);

int Direct3d_SetFogMode_delta(void);

int Direct3d_IsLensflareCompatible_delta(void);

void Direct3d_ConfigFog_delta(float r, float g, float b, float near_, float far_);
