#include "swrViewport_delta.h"

#include <globals.h>

#include "../imgui_utils.h"
#include "../renderer_utils.h"
#include "../tinygltf/gltf_utils.h"
#include "../tinygltf/stb_image.h"

extern "C" {
#include <Platform/std3D.h>
#include <Swr/swrRender.h>
}

#include <glad/glad.h>
#include <GLFW/glfw3.h>

void debug_render_node(const swrViewport &current_vp, const swrModel_Node *node, int light_index,
                       int num_enabled_lights, bool mirrored, const rdMatrix44 &proj_mat,
                       const rdMatrix44 &view_mat, rdMatrix44 model_mat);

EnvInfos envInfos;
int frameCount = 0;
bool environment_models_drawn = false;

static bool environment_setuped = false;
static bool skybox_initialized = false;

void swrViewport_Render_delta(int x) {
    // fprintf(hook_log, "sub_483A90: %d\n", x);
    // fflush(hook_log);

    if (imgui_state.draw_test_scene) {
        draw_test_scene();
        return;
    }

    uint32_t temp_renderState = std3D_renderState;
    std3D_SetRenderState(Std3DRenderState(0));

    const swrViewport &vp = swrViewport_array[x];
    root_node = vp.model_root_node;

    const int default_light_index = 0;
    const int default_num_enabled_lights = 1;

    int w = screen_width;
    int h = screen_height;

    const bool fog_enabled = (GameSettingFlags & 0x40) == 0;
    if (fog_enabled)
        rdFace_ConfigureFogStartEnd(fogStartInt16, fogEndInt16);

    const bool mirrored = (GameSettingFlags & 0x4000) != 0;

    const auto &frustum = rdCamera_pCurCamera->pClipFrustum;
    float f = frustum->zFar;
    float n = frustum->zNear;
    const float t = 1.0f / tan(0.5 * rdCamera_pCurCamera->fov / 180.0 * 3.14159);
    float a = float(h) / w;
    const rdMatrix44 proj_mat{
        {mirrored ? -t : t, 0, 0, 0},
        {0, t / a, 0, 0},
        {0, 0, -(f + n) / (f - n), -1},
        {0, 0, -2 * f * n / (f - n), 1},
    };

    rdMatrix44 view_mat;
    rdMatrix_Copy44_34(&view_mat, &rdCamera_pCurCamera->view_matrix);

    rdMatrix44 rotation{
        {1, 0, 0, 0},
        {0, 0, -1, 0},
        {0, 1, 0, 0},
        {0, 0, 0, 1},
    };

    rdMatrix44 view_mat_corrected;
    rdMatrix_Multiply44(&view_mat_corrected, &view_mat, &rotation);

    rdMatrix44 model_mat;
    rdMatrix_SetIdentity44(&model_mat);

    // skybox and ibl
    if (!environment_setuped) {
        if (!skybox_initialized) {
            setupSkybox(envInfos.skybox);
            skybox_initialized = true;
        }

        // const char *debug_msg = "Setuping IBL";
        // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(debug_msg), debug_msg);

        // render env to cubemap
        setupIBL(envInfos, envInfos.skybox.GLCubeTexture, frameCount);
        frameCount += 1;

        if (frameCount > 5)
            frameCount = 0;

        glBindFramebuffer(GL_FRAMEBUFFER, envInfos.ibl_framebuffer);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT, GL_TEXTURE_2D,
                               envInfos.skybox.depthTexture, 0);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                               GL_TEXTURE_CUBE_MAP_POSITIVE_X + frameCount,
                               envInfos.skybox.GLCubeTexture, 0);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        glBindFramebuffer(GL_FRAMEBUFFER, 0);
        // environment_setuped = true;

        // glPopDebugGroup();
    }

    // const char *debug_msg = "Scene graph traversal";
    // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(debug_msg), debug_msg);
    environment_models_drawn = false;
    stbi_set_flip_vertically_on_load(false);
    debug_render_node(vp, root_node, default_light_index, default_num_enabled_lights, mirrored,
                      proj_mat, view_mat_corrected, model_mat);
    // glPopDebugGroup();

    // debug
    if (1) {
        GLuint debug_framebuffer;
        glGenFramebuffers(1, &debug_framebuffer);
        size_t ibl_textureSize = 256;
        int w, h;
        glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);

        if (imgui_state.debug_env_cubemap) {
            for (size_t i = 0; i < 6; i++) {
                glBindFramebuffer(GL_FRAMEBUFFER, debug_framebuffer);
                glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                                       GL_TEXTURE_CUBE_MAP_POSITIVE_X + i,
                                       envInfos.skybox.GLCubeTexture, 0);
                size_t start = i * ibl_textureSize;
                size_t end = start + ibl_textureSize;

                glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
                glBindFramebuffer(GL_READ_FRAMEBUFFER, debug_framebuffer);
                glBlitFramebuffer(0, 0, 2048, 2048, start, 0, end, ibl_textureSize,
                                  GL_COLOR_BUFFER_BIT, GL_LINEAR);
            }
        }

        glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
        glDeleteFramebuffers(1, &debug_framebuffer);
    }
    // if (1) {
    //     rdVector3 forward = {-view_mat_corrected.vA.z, -view_mat_corrected.vB.z,
    //                          -view_mat_corrected.vC.z};
    //     // model_mat = vp.model_matrix;
    //     // scaling down
    //     model_mat.vA.x *= 0.001;
    //     model_mat.vB.y *= 0.001;
    //     model_mat.vC.z *= 0.001;

    //     model_mat.vD.x += vp.model_matrix.vD.x;
    //     model_mat.vD.y += vp.model_matrix.vD.y;
    //     model_mat.vD.z += vp.model_matrix.vD.z;
    //     renderer_drawGLTF(proj_mat, view_mat_corrected, model_mat, g_models[5], envInfos);
    // }

    glDisable(GL_CULL_FACE);
    std3D_pD3DTex = 0;
    glUseProgram(0);
    std3D_SetRenderState(Std3DRenderState(temp_renderState));
}
