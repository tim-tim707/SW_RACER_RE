#include "DirectX_hook.h"

#include "../utils/renderer_utils.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <globals.h>

extern "C" {
#include <Win95/stdDisplay.h>
}

float g_fogColor[4];
float g_fogStart;
float g_fogEnd;

void renderer_setLinearFogParameters(float color[4], float start, float end) {
    memcpy(g_fogColor, color, sizeof(g_fogColor));
    g_fogStart = start;
    g_fogEnd = end;
}

void DirectDraw_InitProgressBar_hook(void) {
    // nothing to do here
}

void DirectDraw_Shutdown_hook(void) {
    // nothing to do here
}

void DirectDraw_BlitProgressBar_hook(int progress) {
    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);
    glViewport(0, 0, w, h);

    renderer_drawProgressBar(progress);

    stdDisplay_Update();
}

uint16_t *depth_data = NULL;

// 0x00431C40 HOOK
void DirectDraw_LockZBuffer_hook(uint32_t *bytes_per_depth_value, LONG *pitch, LPVOID *data,
                                 float *near_, float *far_) {
    int w = screen_width;
    int h = screen_height;
    depth_data = (uint16_t *) malloc(w * h * 2);

    glGetError();
    glReadPixels(0, 0, w, h, GL_DEPTH_COMPONENT, GL_UNSIGNED_SHORT, depth_data);
    if (glGetError())
        abort();

    *bytes_per_depth_value = 2;
    *pitch = w * 2;
    *data = depth_data;

    // flip vertically
    uint16_t *src = depth_data;
    uint16_t *dst = &depth_data[w * (h - 1)];
    for (int y = 0; y < h / 2; y++) {
        for (int x = 0; x < w; x++) {
            uint16_t tmp = src[x];
            src[x] = dst[x];
            dst[x] = tmp;
        }
        src += w;
        dst -= w;
    }

    *near_ = rdCamera_pCurCamera->pClipFrustum->zNear;
    *far_ = rdCamera_pCurCamera->pClipFrustum->zFar;
}

void DirectDraw_UnlockZBuffer_hook(void) {
    if (depth_data)
        free(depth_data);

    depth_data = NULL;
}

int Direct3d_SetFogMode_hook(void) {
    return 2;
}

int Direct3d_IsLensflareCompatible_hook(void) {
    return true;
}

void Direct3d_ConfigFog_hook(float r, float g, float b, float near_, float far_) {
    float color[4] = {r, g, b, 1.0};
    renderer_setLinearFogParameters(color, 0.999, 1);
}
