#include "stdDisplay_delta.h"

#include <Win95/DirectX.h>
#include <Win95/stdDisplay.h>
#include <Win95/Window.h>
#include "globals.h"

#include <macros.h>
#include <stdPlatform.h>
#include <General/stdBmp.h>

#include <glad/glad.h>
#include <GLFW/glfw3.h>

// 0x00487d20
int stdDisplay_Startup_delta(void) {
    if (stdDisplay_bStartup)
        return 1;

    stdDisplay_g_frontBuffer = (tVBuffer) {0};
    stdDisplay_g_backBuffer = (tVBuffer) {0};
    stdDisplay_zBuffer = (tVSurface) {0};
    stdDisplay_bStartup = 1;
    stdDisplay_numDevices = 0;
    stdDisplay_numDevices = 1;
    StdDisplayDevice *device = &stdDisplay_aDisplayDevices[0];
    snprintf(device->aDeviceName, 128, "OpenGL");
    snprintf(device->aDriverName, 128, "OpenGL");
    device->bHAL = true;
    device->bGuidNotSet = true;
    device->bWindowRenderNotSupported = false;
    device->totalVideoMemory = 1024 * 1024 * 1024;
    device->freeVideoMemory = 1024 * 1024 * 1024;

    stdDisplay_primaryVideoMode.rasterInfo.width = 640;
    stdDisplay_primaryVideoMode.rasterInfo.height = 480;

    return 1;
}

// 0x00487e00
int stdDisplay_Open_delta(int deviceNum) {
    if (stdDisplay_bOpen)
        stdDisplay_Close();

    if (deviceNum >= stdDisplay_numDevices)
        return 0;

    stdDisplay_curDevice = deviceNum;
    stdDisplay_pcurDevice = &stdDisplay_aDisplayDevices[deviceNum];
    glfwSwapInterval(1);
    gladLoadGLLoader((GLADloadproc) glfwGetProcAddress);

    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);

    stdDisplay_numVideoModes = 1;
    stdDisplay_aVideoModes[0] = (StdVideoMode) {
        .aspectRatio = 1.0,
        .rasterInfo =
            {
                .width = w,
                .height = h,
                .size = w * h * 4,
                .rowSize = w * 4,
                .rowWidth = w,
                .colorInfo =
                    {
                        .colorMode = T_STDCOLOR_RGBA,
                        .bpp = 32,
                        .redBPP = 8,
                        .greenBPP = 8,
                        .blueBPP = 8,
                        .redPosShift = 0,
                        .greenPosShift = 8,
                        .bluePosShift = 16,
                        .RedShr = 0,
                        .GreenShr = 0,
                        .BlueShr = 0,
                        .alphaBPP = 8,
                        .alphaPosShift = 24,
                        .AlphaShr = 0,
                    },
            },
    };

    qsort(stdDisplay_aVideoModes, stdDisplay_numVideoModes, sizeof(StdVideoMode),
          (int (*)(const void *, const void *)) stdDisplay_VideoModeCompare);
    stdDisplay_bOpen = 1;
    return 1;
}

// 0x00487e80
void stdDisplay_Close_delta(void) {
    if (!stdDisplay_bStartup || !stdDisplay_bOpen)
        return;

    if (stdDisplay_bModeSet)
        stdDisplay_ClearMode();

    stdDisplay_curDevice = 0;
    memset(&stdDisplay_g_frontBuffer, 0, sizeof(stdDisplay_g_frontBuffer));
    memset(&stdDisplay_g_backBuffer, 0, sizeof(stdDisplay_g_backBuffer));
    memset(&stdDisplay_zBuffer, 0, sizeof(stdDisplay_zBuffer));
    stdDisplay_pcurDevice = 0;
    stdDisplay_FillMainSurface_ptr = (void (*)()) stdPlatform_noop;// parameter count lint error
    stdDisplay_bOpen = 0;
}

// 0x00487f00
int stdDisplay_SetMode_delta(int modeNum, int bFullscreen) {
    stdDisplay_g_frontBuffer.rasterInfo = stdDisplay_aVideoModes[0].rasterInfo;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwWidth =
        stdDisplay_g_frontBuffer.rasterInfo.width;
    stdDisplay_g_frontBuffer.pVSurface.ddSurfDesc.dwHeight =
        stdDisplay_g_frontBuffer.rasterInfo.height;

    stdDisplay_g_backBuffer.rasterInfo = stdDisplay_aVideoModes[0].rasterInfo;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    stdDisplay_g_backBuffer.pVSurface.ddSurfDesc.dwHeight =
        stdDisplay_g_backBuffer.rasterInfo.height;

    stdDisplay_pCurVideMode = &stdDisplay_aVideoModes[0];
    stdDisplay_backbufWidth = stdDisplay_g_backBuffer.rasterInfo.width;
    stdDisplay_backbufHeight = stdDisplay_g_backBuffer.rasterInfo.height;
    stdDisplay_bModeSet = 1;
    stdDisplay_bFullscreen = bFullscreen;
    return 1;
}

// 0x00488100
void stdDisplay_Refresh_delta(int bReload) {
    return;
}

// 0x004881c0
tVBuffer *stdDisplay_VBufferNew_delta(tRasterInfo *texFormat, int create_ddraw_surface,
                                      int use_video_memory) {
    tVBuffer *buffer = (tVBuffer *) stdPlatform_hostServices.alloc(sizeof(tVBuffer));
    if (!buffer)
        return NULL;

    *buffer = (tVBuffer) {0};
    buffer->rasterInfo = *texFormat;

    int bytes_per_pixel = buffer->rasterInfo.colorInfo.bpp / 8;
    buffer->rasterInfo.rowSize = buffer->rasterInfo.width * bytes_per_pixel;
    buffer->rasterInfo.rowWidth = buffer->rasterInfo.width * bytes_per_pixel / bytes_per_pixel;
    buffer->rasterInfo.size =
        buffer->rasterInfo.width * buffer->rasterInfo.height * bytes_per_pixel;

    if (create_ddraw_surface && stdDisplay_bOpen) {
        abort();
    }

    buffer->bSurfaceAllocated = 0;
    buffer->bVideoMemory = 0;
    buffer->pPixels = (BYTE *) stdPlatform_hostServices_ptr->alloc(buffer->rasterInfo.size);
    if (buffer->pPixels) {
        buffer->lockSurfRefCount = 1;
        return buffer;
    }
    return NULL;
}

// 0x00489270
int stdDisplay_SetWindowMode_delta(HWND hWnd, StdVideoMode *pDisplayMode) {
    return 0;
}

// 0x00489790
int stdDisplay_SetFullscreenMode_delta(HWND hwnd, StdVideoMode *pDisplayMode) {
    return 0;
}

// 0x00488410
int stdDisplay_VBufferFill_delta(tVBuffer *pVBuffer, DWORD dwFillColor, LECRECT *pRect) {
    return stdDisplay_ColorFillSurface_delta(&pVBuffer->pVSurface, dwFillColor, pRect);
}

// 0x00489bc0
void stdDisplay_FillMainSurface_delta(void) {
    glDepthMask(GL_TRUE);
    glClear(GL_DEPTH_BUFFER_BIT);
}

// 0x00489bd0
int stdDisplay_ColorFillSurface_delta(tVSurface *pSurf, DWORD dwFillColor, LECRECT *lpRect) {
    if (pSurf == &stdDisplay_g_backBuffer.pVSurface && lpRect == NULL) {
        uint8_t b = ((dwFillColor >> 0) & 0b11111) << 3;
        uint8_t g = ((dwFillColor >> 5) & 0b111111) << 2;
        uint8_t r = ((dwFillColor >> 11) & 0b11111) << 3;
        glClearColor(r / 255.0, g / 255.0, b / 255.0, 255.0);
        glClear(GL_COLOR_BUFFER_BIT);
    }

    return 0;
}
