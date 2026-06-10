#include "DirectX_delta.h"

#include <Win95/Window.h>
#include <Win95/stdDisplay.h>
#include "globals.h"

int stdDisplay_Update_Hook();

#include <macros.h>

#include <GLFW/glfw3.h>
#include <glad/glad.h>

extern void renderer_drawProgressBar(int progress);

extern FILE *hook_log;

float g_fogColor[4];
float g_fogStart;
float g_fogEnd;

void renderer_setLinearFogParameters(float color[4], float start, float end) {
    memcpy(g_fogColor, color, sizeof(g_fogColor));
    g_fogStart = start;
    g_fogEnd = end;
}

// 0x00408510
void DirectDraw_InitProgressBar_delta(void) {
    // nothing to do here
}

// 0x00408620
void DirectDraw_Shutdown_delta(void) {
    // nothing to do here
}

// 0x00408640 (canonical name swrUI_UpdateProgressBar; replaces the original blit
// with the HD/widescreen progress bar)
void swrUI_UpdateProgressBar_delta(int progress) {
    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);
    glViewport(0, 0, w, h);

    renderer_drawProgressBar(progress);

    stdDisplay_Update_Hook();
}

uint16_t *depth_data = NULL;
size_t depth_data_size = 0;

// 0x00431C40
void DirectDraw_LockZBuffer_delta(uint32_t *bytes_per_depth_value, LONG *pitch, LPVOID *data,
                                  float *near_, float *far_) {
    int w = screen_width;
    int h = screen_height;
    // allocate one line more for scratch memory
    const size_t new_depth_data_size = w * (h + 1) * 2;
    if (new_depth_data_size != depth_data_size) {
        free(depth_data);
        depth_data = (uint16_t *) malloc(new_depth_data_size);
        depth_data_size = new_depth_data_size;
    }

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
    // use scratch memory for efficient swap
    uint16_t *scratch = &depth_data[w * h];
    for (int y = 0; y < h / 2; y++) {
        memcpy(scratch, src, w * 2);
        memcpy(src, dst, w * 2);
        memcpy(dst, scratch, w * 2);
        src += w;
        dst -= w;
    }

    *near_ = rdCamera_pCurCamera->pClipFrustum->zNear;
    *far_ = rdCamera_pCurCamera->pClipFrustum->zFar;
}

// 0x00431cd0
void DirectDraw_UnlockZBuffer_delta(void) {}

// 0x0048a140
int Direct3d_SetFogMode_delta(void) {
    return 2;
}

// 0x0048a1a0
int Direct3d_IsLensflareCompatible_delta(void) {
    return true;
}

// 0x0048b340
void Direct3d_ConfigFog_delta(float r, float g, float b, float near_, float far_) {
    float color[4] = {r, g, b, 1.0};
    renderer_setLinearFogParameters(color, 0.999, 1);
}
