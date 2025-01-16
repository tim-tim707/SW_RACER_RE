#pragma once

#include "types.h"

int stdDisplay_Startup_delta(void);
int stdDisplay_Open_delta(int deviceNum);
void stdDisplay_Close_delta(void);
int stdDisplay_SetMode_delta(int modeNum, int bFullscreen);
void stdDisplay_Refresh_delta(int bReload);
tVBuffer *stdDisplay_VBufferNew_delta(tRasterInfo *texFormat, int create_ddraw_surface,
                                      int use_video_memory);
int stdDisplay_VBufferFill_delta(tVBuffer *pVBuffer, DWORD dwFillColor, LECRECT *pRect);
int stdDisplay_SetWindowMode_delta(HWND hWnd, StdVideoMode *pDisplayMode);
int stdDisplay_SetFullscreenMode_delta(HWND hwnd, StdVideoMode *pDisplayMode);
int stdDisplay_Update_delta(void);
void stdDisplay_FillMainSurface_delta(void);
int stdDisplay_ColorFillSurface_delta(tVSurface *pSurf, DWORD dwFillColor, LECRECT *lpRect);
