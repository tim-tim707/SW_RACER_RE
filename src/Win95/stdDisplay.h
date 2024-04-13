#ifndef STDDISPLAY_H
#define STDDISPLAY_H

#include "types.h"

#define stdDisplay_Startup_ADDR (0x00487d20)
#define stdDisplay_Shutdown_ADDR (0x00487da0)
#define stdDisplay_Open_ADDR (0x00487e00)
#define stdDisplay_Close_ADDR (0x00487e80)
#define stdDisplay_SetMode_ADDR (0x00487f00)
#define stdDisplay_ClearMode_ADDR (0x00488030)

#define stdDisplay_GetNumDevices_ADDR (0x00488070)
#define stdDisplay_GetDevice_ADDR (0x00488080)
#define stdDisplay_Refresh_ADDR (0x00488100)
#define stdDisplay_VBufferNew_ADDR (0x004881c0)
#define stdDisplay_VBufferFree_ADDR (0x00488310)
#define stdDisplay_VBufferLock_ADDR (0x00488370)
#define stdDisplay_VBufferUnlock_ADDR (0x004883c0)
#define stdDisplay_VBufferFill_ADDR (0x00488410)
#define stdDisplay_VBufferConvertColorFormat_ADDR (0x00488670)
#define stdDisplay_FlushText_ADDR (0x004887c0)
#define stdDisplay_VideoModeCompare_ADDR (0x00488850)

#define stdDisplay_CreateZBuffer_ADDR (0x004888d0)

#define stdDisplay_InitDirectDraw_ADDR (0x00488b00)

#define stdDisplay_ReleaseDirectDraw_ADDR (0x00488d10)

#define stdDisplay_GetDirectDraw_ADDR (0x00489260)

#define stdDisplay_SetWindowMode_ADDR (0x00489270)

#define stdDisplay_SetFullscreenMode_ADDR (0x00489790)

#define stdDisplay_ReleaseBuffers_ADDR (0x004899a0)

#define stdDisplay_LockSurface_ADDR (0x00489a00)
#define stdDisplay_UnlockSurface_ADDR (0x00489a60)

#define stdDisplay_Update_ADDR (0x00489ab0)
#define stdDisplay_FillMainSurface_ADDR (0x00489bc0)
#define stdDisplay_ColorFillSurface_ADDR (0x00489bd0)
#define stdDisplay_BackBufferFill_ADDR (0x00489cd0)
#define stdDisplay_SaveScreen_ADDR (0x00489d20)
#define stdDisplay_GetNumVideoModes_ADDR (0x00489d40)
#define stdDisplay_CopyVideoMode_ADDR (0x00489d50)
#define stdDisplay_CopyCurrentVideoMode_ADDR (0x00489d90)

int stdDisplay_Startup(void);
void stdDisplay_Shutdown(void);
int stdDisplay_Open(int deviceNum);
void stdDisplay_Close(void);
int stdDisplay_SetMode(int modeNum, int bFullscreen);
void stdDisplay_ClearMode(void);
int stdDisplay_GetNumDevices(void);
int stdDisplay_GetDevice(unsigned int deviceNum, StdDisplayDevice* pDest);
void stdDisplay_Refresh(int bReload);
tVBuffer* stdDisplay_VBufferNew(tRasterInfo* texFormat, int create_ddraw_surface, int use_video_memory);
void stdDisplay_VBufferFree(tVBuffer* vbuffer);
int stdDisplay_VBufferLock(tVBuffer* vbuffer);
int stdDisplay_VBufferUnlock(tVBuffer* vbuffer);
int stdDisplay_VBufferFill(tVBuffer* pVBuffer, DWORD dwFillColor, LECRECT* pRect);
tVBuffer* stdDisplay_VBufferConvertColorFormat(ColorInfo* texFormat, tVBuffer* src, int colorKey, void* PcolorKey);
int stdDisplay_FlushText(char* output_buffer, int x, int y);

int stdDisplay_VideoModeCompare(const StdVideoMode* pMode1, const StdVideoMode* pMode2);

int stdDisplay_CreateZBuffer(LPDDPIXELFORMAT pPixelFormat, int bSystemMemory, int zBufferlessHSR);

int stdDisplay_InitDirectDraw(HWND wnd);
void stdDisplay_ReleaseDirectDraw(void);

LPDIRECTDRAW4 stdDisplay_GetDirectDraw(void);
int stdDisplay_SetWindowMode(HWND hWnd, StdVideoMode* pDisplayMode);
int stdDisplay_SetFullscreenMode(HWND hwnd, StdVideoMode* pDisplayMode);
void stdDisplay_ReleaseBuffers(void);
BYTE* stdDisplay_LockSurface(tVSurface* pVSurf);
int stdDisplay_UnlockSurface(tVSurface* pSurf);
int stdDisplay_Update(void);
void stdDisplay_FillMainSurface(void);
int stdDisplay_ColorFillSurface(tVSurface* pSurf, DWORD dwFillColor, LECRECT* lpRect);
int stdDisplay_BackBufferFill(uint8_t r, uint8_t b, uint8_t g, LECRECT* lpRect);
int stdDisplay_SaveScreen(char* pFilename);
int stdDisplay_GetNumVideoModes(void);
int stdDisplay_CopyVideoMode(size_t modeNum, StdVideoMode* pDestMode);
int stdDisplay_CopyCurrentVideoMode(StdVideoMode* pDisplayMode);

#endif // STDDISPLAY_H
