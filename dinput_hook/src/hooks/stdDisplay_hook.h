#pragma once

#include "types.h"

#include <Windows.h>
#include <commctrl.h>

int stdDisplay_Startup_hook(void);
int stdDisplay_Open_hook(int deviceNum);
void stdDisplay_Close_hook(void);
int stdDisplay_SetMode_hook(int modeNum, int bFullscreen);
void stdDisplay_Refresh_hook(int bReload);
tVBuffer *stdDisplay_VBufferNew_hook(tRasterInfo *texFormat, int create_ddraw_surface,
                                     int use_video_memory);
int stdDisplay_SetWindowMode_hook(HWND hWnd, StdVideoMode *pDisplayMode);
int stdDisplay_SetFullscreenMode_hook(HWND hwnd, StdVideoMode *pDisplayMode);
int stdDisplay_VBufferFill_hook(tVBuffer *pVBuffer, DWORD dwFillColor, LECRECT *pRect);
int stdDisplay_Update_Hook();
void stdDisplay_FillMainSurface_hook(void);
int stdDisplay_ColorFillSurface_hook(tVSurface *pSurf, DWORD dwFillColor, LECRECT *lpRect);
