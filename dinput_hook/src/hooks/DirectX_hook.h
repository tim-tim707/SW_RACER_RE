#pragma once

#include <Windows.h>
#include <commctrl.h>

#include <cstdint>

void renderer_setLinearFogParameters(float color[4], float start, float end);

void DirectDraw_InitProgressBar_hook(void);
void DirectDraw_Shutdown_hook(void);
void DirectDraw_BlitProgressBar_hook(int progress);
void DirectDraw_LockZBuffer_hook(uint32_t *bytes_per_depth_value, LONG *pitch, LPVOID *data,
                                 float *near_, float *far_);
void DirectDraw_UnlockZBuffer_hook(void);

int Direct3d_SetFogMode_hook(void);
int Direct3d_IsLensflareCompatible_hook(void);
void Direct3d_ConfigFog_hook(float r, float g, float b, float near_, float far_);
