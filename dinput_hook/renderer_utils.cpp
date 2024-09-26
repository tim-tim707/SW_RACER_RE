#include "renderer_utils.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include <string>
#include <windows.h>
#include <cmath>

#include "globals.h"
#include "types.h"
#include <imgui.h>
#include "imgui_impl_glfw.h"
#include "imgui_utils.h"
#include "meshes.h"

#include "tinygltf/tiny_gltf.h"
#include "tinygltf/gltf_utils.h"
#include "shaders_utils.h"

extern "C" {
#include <Platform/std3D.h>
#include <Primitives/rdMatrix.h>
#include <Swr/swrUI.h>
}

extern "C" FILE *hook_log;

extern ImGuiState imgui_state;

void renderer_setOrtho(rdMatrix44 *m, float left, float right, float bottom, float top,
                       float nearVal, float farVal) {
    float tx = -(right + left) / (right - left);
    float ty = -(top + bottom) / (top - bottom);
    float tz = -(farVal + nearVal) / (farVal - nearVal);

    *m = {{2.0f / (right - left), 0, 0, 0},
          {0, 2 / (top - bottom), 0, 0},
          {0, 0, -2 / (farVal - nearVal), 0},
          {tx, ty, tz, 1}};
}

progressBarShader get_or_compile_drawProgressShader() {
    static bool shaderCompiled = false;
    static progressBarShader shader;
    if (!shaderCompiled) {
        const char *vertex_shader_source = R"(
#version 330 core

out vec2 texcoords; // texcoords are in the normalized [0,1] range for the viewport-filling quad part of the triangle
void main() {
        vec2 vertices[3] = vec2[3](vec2(-1,-1), vec2(3,-1), vec2(-1, 3));
        gl_Position = vec4(vertices[gl_VertexID], 0, 1);
        texcoords = 0.5 * gl_Position.xy + vec2(0.5);
}
)";
        const char *fragment_shader_source = R"(
#version 330 core

in vec2 texcoords;

uniform float progress;

out vec4 fragColor;

void main() {
    // TODO: put a nice texture as a loading bar

    // Progress bar is computed on a [(1/3, 1/8), (2/3, 1/8 + 10px)] rectangle.
    // Later, we want to map [(0, 0), (1, 1)] rectangle back onto [(1/3, 1/8), (2/3, 1/8 + 10px)]
    const float a = 1.0 / 3.0;
    const float b = 1.0 / 8.0;
    const float c = 2.0 / 3.0;
    // original game is 480x640, and the progress bar is offset by 10 pixels.
    // Thats 1 / 48th in height
    const float width_offset = 1.0 / 48.0;
    const float d = 1.0 / 8.0 + width_offset;

    vec2 color = texcoords.xy;

    // Rectangle progress bar clipping
    if (texcoords.x < a || texcoords.x > c ||
        texcoords.y < b || texcoords.y > d) {
        color.x = 0.0;
        color.y = 0.0;
    }

    float xp = (c - a) * (progress / 100.0); // progression distance
    if (texcoords.x > (a + xp)) {
        color.x = 0.0;
        color.y = 0.0;
    }

    // magic part to map [(1/3, 1/8), (2/3, 1/8 + 10px)] rectangle back onto [(0, 0), (1, 1)]
    //                     a,   b,     c,   d                                  e, f,   g, h
    // x' = e + (x - a) * (g - e) / (c - a);
    // y' = f + (y - b) * (h - f) / (d - b);

    color.x = (color.x - 1.0 / 3.0) / (c - a);
    color.y = (color.y - 1.0 / 8.0) / width_offset;

    fragColor = vec4(color, 0.0, 1.0);
}
)";
        std::optional<GLuint> program_opt =
            compileProgram(1, &vertex_shader_source, 1, &fragment_shader_source);
        if (!program_opt.has_value())
            std::abort();
        GLuint program = program_opt.value();

        GLuint VAO;
        glGenVertexArrays(1, &VAO);

        shader = {
            .handle = program,
            .emptyVAO = VAO,
            .progress_pos = glGetUniformLocation(program, "progress"),
        };
        shaderCompiled = true;
    }

    return shader;
}

extern "C" __declspec(dllexport) void renderer_drawProgressBar(int progress) {
    const auto shader = get_or_compile_drawProgressShader();
    glUseProgram(shader.handle);

    glUniform1f(shader.progress_pos, progress);

    glBindVertexArray(shader.emptyVAO);

    glDrawArrays(GL_TRIANGLES, 0, 3);

    glBindVertexArray(0);
}

fullScreenTextureShader get_or_compile_fullscreenTextureShader() {

    static bool shaderCompiled = false;
    static fullScreenTextureShader shader;
    if (!shaderCompiled) {
        const char *vertex_shader_source = R"(
#version 330 core

out vec2 texcoords; // texcoords are in the normalized [0,1] range for the viewport-filling quad part of the triangle
void main() {
        vec2 vertices[3] = vec2[3](vec2(-1,-1), vec2(3,-1), vec2(-1, 3));
        gl_Position = vec4(vertices[gl_VertexID], 0, 1);
        texcoords = 0.5 * gl_Position.xy + vec2(0.5);
}
)";
        const char *fragment_shader_source = R"(
#version 330 core

in vec2 texcoords;

uniform sampler2D tex;

out vec4 fragColor;

void main() {
    fragColor = texture(tex, vec2(texcoords.s, 1.0 - texcoords.t)); // horizontal flip
}
)";
        std::optional<GLuint> program_opt =
            compileProgram(1, &vertex_shader_source, 1, &fragment_shader_source);
        if (!program_opt.has_value())
            std::abort();
        GLuint program = program_opt.value();


        GLuint VAO;
        glGenVertexArrays(1, &VAO);

        GLuint texture;
        glGenTextures(1, &texture);
        glBindTexture(GL_TEXTURE_2D, texture);

        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

        shader = {.handle = program, .emptyVAO = VAO, .texture = texture};

        shaderCompiled = true;
    }

    return shader;
}

extern "C" __declspec(dllexport) void renderer_drawSmushFrame(const SmushImage *image) {
    // fprintf(hook_log, "renderer_drawSmushFrame\n");
    // fflush(hook_log);

    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);

    glViewport(0, 0, w, h);
    glClear(GL_COLOR_BUFFER_BIT);

    const auto shader = get_or_compile_fullscreenTextureShader();
    glUseProgram(shader.handle);

    glBindTexture(GL_TEXTURE_2D, shader.texture);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, image->width, image->height, 0, GL_RGB,
                 GL_UNSIGNED_SHORT_5_6_5, image->data);

    glBindVertexArray(shader.emptyVAO);
    glDrawArrays(GL_TRIANGLES, 0, 3);
    glBindVertexArray(0);
}

renderListShader get_or_compile_renderListShader() {
    static bool shaderCompiled = false;
    static renderListShader shader;

    if (!shaderCompiled) {
        const char *vertex_shader_source = R"(
#version 330 core

layout(location = 0) in vec4 position;
layout(location = 1) in vec4 color;
layout(location = 2) in vec2 uv;

out vec4 passColor;
out vec2 passUV;

uniform mat4 projMatrix;

void main() {
    vec4 posView = position;
    gl_Position = projMatrix * posView;

    passColor = color;
    passUV = uv;
}
)";
        const char *fragment_shader_source = R"(
#version 330 core

in vec4 passColor;
in vec2 passUV;

out vec4 outColor;

uniform sampler2D tex;

void main() {
    vec4 texel = texture(tex, passUV);
    outColor = texel * passColor;
}
)";

        std::optional<GLuint> program_opt =
            compileProgram(1, &vertex_shader_source, 1, &fragment_shader_source);
        if (!program_opt.has_value())
            std::abort();
        GLuint program = program_opt.value();

        GLuint VAO;
        glGenVertexArrays(1, &VAO);
        GLuint VBO;
        glGenBuffers(1, &VBO);
        GLuint EBO;
        glGenBuffers(1, &EBO);

        shader = {
            .handle = program,
            .VAO = VAO,
            .VBO = VBO,
            .EBO = EBO,
            .proj_matrix_pos = glGetUniformLocation(program, "projMatrix"),
        };

        shaderCompiled = true;
    }

    return shader;
}

extern "C" void renderer_drawRenderList(int verticesCount, LPD3DTLVERTEX aVerticies, int indexCount,
                                        LPWORD lpwIndices) {
    // fprintf(hook_log, "renderer_drawRenderList\n");
    // fflush(hook_log);

    if (!imgui_state.draw_renderList || imgui_state.draw_test_scene)
        return;

    const auto shader = get_or_compile_renderListShader();
    glUseProgram(shader.handle);

    int w = screen_width;
    int h = screen_height;

    rdMatrix44 projectionMatrix;
    renderer_setOrtho(&projectionMatrix, 0, screen_width, screen_height, 0, 0, -1);

    glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &projectionMatrix.vA.x);

    glBindVertexArray(shader.VAO);

    glEnableVertexAttribArray(0);
    glEnableVertexAttribArray(1);
    glEnableVertexAttribArray(2);

    glBindBuffer(GL_ARRAY_BUFFER, shader.VBO);
    glBufferData(GL_ARRAY_BUFFER, verticesCount * sizeof(aVerticies[0]), aVerticies,
                 GL_DYNAMIC_DRAW);

    glVertexAttribPointer(0, 4, GL_FLOAT, GL_FALSE, sizeof(aVerticies[0]),
                          reinterpret_cast<void *>(offsetof(D3DTLVERTEX, sx)));
    glVertexAttribPointer(1, 4, GL_UNSIGNED_BYTE, GL_TRUE, sizeof(aVerticies[0]),
                          reinterpret_cast<void *>(offsetof(D3DTLVERTEX, color)));
    glVertexAttribPointer(2, 2, GL_FLOAT, GL_FALSE, sizeof(aVerticies[0]),
                          reinterpret_cast<void *>(offsetof(D3DTLVERTEX, tu)));

    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, shader.EBO);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, indexCount * sizeof(WORD), lpwIndices, GL_DYNAMIC_DRAW);

    glDrawElements(GL_TRIANGLES, indexCount, GL_UNSIGNED_SHORT, 0);

    glDisableVertexAttribArray(0);
    glDisableVertexAttribArray(1);
    glDisableVertexAttribArray(2);
    glBindVertexArray(0);
}

replacementShader get_or_compile_replacement(ImGuiState &state) {
    static bool shaderCompiled = false;
    static replacementShader shader;

    (void) state;

    if (!shaderCompiled) {
        const char *vertex_shader_source = R"(
#version 330 core

layout(location = 0) in vec3 position;

out vec4 passColor;

uniform mat4 projMatrix;
uniform mat4 viewMatrix;
uniform mat4 modelMatrix;

uniform int model_id;

void main() {
    // Yes, precomputing modelView is better and we should do it
    gl_Position = projMatrix * viewMatrix * modelMatrix * vec4(position, 1.0);

    vec4 color = vec4(1.0, 0.0, 1.0, 1.0);
    if (model_id == 1000)
        color = vec4(0.0, 1.0, 1.0, 1.0);
    if (model_id == 1001)
        color = vec4(1.0, 0.0, 0.0, 1.0);
    passColor = color;
}
)";
        const char *fragment_shader_source = R"(
#version 330 core

in vec4 passColor;

out vec4 outColor;

void main() {
    outColor = passColor;
}
)";

        std::optional<GLuint> program_opt =
            compileProgram(1, &vertex_shader_source, 1, &fragment_shader_source);
        if (!program_opt.has_value())
            std::abort();
        GLuint program = program_opt.value();

        GLuint VAO;
        glGenVertexArrays(1, &VAO);
        GLuint VBO;
        glGenBuffers(1, &VBO);

        GLuint EBO;
        glGenBuffers(1, &EBO);

        shader = {
            .handle = program,
            .VAO = VAO,
            .VBO = VBO,
            .EBO = EBO,
            .proj_matrix_pos = glGetUniformLocation(program, "projMatrix"),
            .view_matrix_pos = glGetUniformLocation(program, "viewMatrix"),
            .model_matrix_pos = glGetUniformLocation(program, "modelMatrix"),
            .model_id_pos = glGetUniformLocation(program, "model_id"),
        };

        shaderCompiled = true;
    }

    return shader;
}

void renderer_drawCube(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix) {
    const auto shader = get_or_compile_replacement(imgui_state);
    glUseProgram(shader.handle);

    glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &proj_matrix.vA.x);
    glUniformMatrix4fv(shader.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);
    glUniformMatrix4fv(shader.model_matrix_pos, 1, GL_FALSE, &model_matrix.vA.x);
    glUniform1i(shader.model_id_pos, cube_model_id);
    glBindVertexArray(shader.VAO);

    glEnableVertexAttribArray(0);
    glBindBuffer(GL_ARRAY_BUFFER, shader.VBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(cube_verts), cube_verts, GL_STATIC_DRAW);

    glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 0, 0);

    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, shader.EBO);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(cube_indices), cube_indices, GL_STATIC_DRAW);

    glDrawElements(GL_TRIANGLES, sizeof(cube_indices) / sizeof(unsigned short), GL_UNSIGNED_SHORT,
                   0);

    glDisableVertexAttribArray(0);
    glBindVertexArray(0);
}

void renderer_drawTetrahedron(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                              const rdMatrix44 &model_matrix) {
    const auto shader = get_or_compile_replacement(imgui_state);
    glUseProgram(shader.handle);

    glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &proj_matrix.vA.x);
    glUniformMatrix4fv(shader.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);
    glUniformMatrix4fv(shader.model_matrix_pos, 1, GL_FALSE, &model_matrix.vA.x);
    glUniform1i(shader.model_id_pos, tetrahedron_model_id);
    glBindVertexArray(shader.VAO);

    glEnableVertexAttribArray(0);
    glBindBuffer(GL_ARRAY_BUFFER, shader.VBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(tetrahedron_verts), tetrahedron_verts, GL_STATIC_DRAW);

    glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 0, 0);

    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, shader.EBO);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(tetrahedron_indices), tetrahedron_indices,
                 GL_STATIC_DRAW);

    glDrawElements(GL_TRIANGLE_STRIP, sizeof(tetrahedron_indices) / sizeof(unsigned short),
                   GL_UNSIGNED_SHORT, 0);

    glDisableVertexAttribArray(0);
    glBindVertexArray(0);
}

void renderer_drawGLTF(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix, gltfModel &model) {
    const pbrShader shader = model.shader;
    if (shader.handle == 0) {
        setupModel(model);
    }
    glUseProgram(shader.handle);

    glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &proj_matrix.vA.x);
    glUniformMatrix4fv(shader.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);
    rdMatrix44 model_matrix2;
    memcpy(&model_matrix2, &model_matrix, sizeof(model_matrix2));
    rdMatrix_ScaleBasis44(&model_matrix2, 100, 100, 100, &model_matrix2);

    glUniformMatrix4fv(shader.model_matrix_pos, 1, GL_FALSE, &model_matrix2.vA.x);
    glUniform1i(shader.model_id_pos, gltf_model_id);

    auto baseColorFactor = model.gltf.materials[0].pbrMetallicRoughness.baseColorFactor;
    glUniform4f(shader.baseColorFactor_pos, baseColorFactor[0], baseColorFactor[1],
                baseColorFactor[2], baseColorFactor[3]);
    glUniform1f(shader.metallicFactor_pos,
                model.gltf.materials[0].pbrMetallicRoughness.metallicFactor);

    glBindVertexArray(shader.VAO);

    if (model.gltfFlags & gltfFlags::hasTexCoords)
        glBindTexture(GL_TEXTURE_2D, shader.glTexture);

    if (model.gltfFlags & gltfFlags::isIndexed) {
        const tinygltf::Accessor &indicesAccessor =
            model.gltf.accessors[model.gltf.meshes[0].primitives[0].indices];
        glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, shader.EBO);
        glDrawElements(model.gltf.meshes[0].primitives[0].mode, indicesAccessor.count,
                       indicesAccessor.componentType, 0);
    } else {
        fprintf(hook_log, "Trying to draw a non-indexed mesh. Unsupported yet\n");
        fflush(hook_log);
    }

    glBindVertexArray(0);
}

static void renderer_perspective(rdMatrix44 *mat, float fovY_radian, float aspect_ratio,
                                 float near_value, float far_value) {
    float f = tan(3.141592 * 0.5 - 0.5 * fovY_radian);
    float rangeInv = 1.0 / (near_value - far_value);
    *mat = {
        {f / aspect_ratio, 0, 0, 0},
        {0, f, 0, 0},
        {0, 0, (near_value + far_value) * rangeInv, -1},
        {0, 0, near_value * far_value * rangeInv * 2, 0},
    };
}

static void renderer_lookAtInverse(rdMatrix44 *view_mat, rdVector3 *position, rdVector3 *target,
                                   rdVector3 *up) {
    rdVector3 f;
    rdVector3 s;
    rdVector3 u;
    rdVector_Sub3(&f, target, position);
    rdVector_Normalize3Acc(&f);
    rdVector_Normalize3Acc(up);
    rdVector_Cross3(&s, &f, up);
    rdVector_Normalize3Acc(&s);
    rdVector_Cross3(&u, &s, &f);

    *view_mat = {{s.x, u.x, -f.x, 0},
                 {s.y, u.y, -f.y, 0},
                 {s.z, u.z, -f.z, 0},
                 {-rdVector_Dot3(&s, position), -rdVector_Dot3(&u, position),
                  -rdVector_Dot3(&f, position), 1}};
}

static void renderer_viewFromTransforms(rdMatrix44 *view_mat, rdVector3 *position, float pitch,
                                        float yaw) {
    float sinY = sin(yaw);
    float cosY = cos(yaw);
    float sinP = sin(pitch);
    float cosP = cos(pitch);

    rdVector3 xAxis = {cosY, 0, -sinY};
    rdVector3 yAxis = {sinY * sinP, cosP, cosY * sinP};
    rdVector3 zAxis = {sinY * cosP, -sinP, cosP * cosY};
    // Y UP !
    *view_mat = {
        {xAxis.x, yAxis.x, zAxis.x, 0},
        {xAxis.y, yAxis.y, zAxis.y, 0},
        {xAxis.z, yAxis.z, zAxis.z, 0},
        {-rdVector_Dot3(&xAxis, position), -rdVector_Dot3(&yAxis, position),
         -rdVector_Dot3(&zAxis, position), 1},
    };
}

static int glfw_key_to_dik[349];

static int prev_window_x = 0;
static int prev_window_y = 0;
static int prev_window_width = 0;
static int prev_window_height = 0;

rdVector3 cameraPos = {0, 0, 3};
rdVector3 cameraFront = {0, 0, -1};
rdVector3 cameraUp = {0, 1, 0};
float pitch = 0;
float yaw = 0;
rdVector3 tmp;
float cameraSpeed = 0.1;

static void debug_scene_key_callback(GLFWwindow *window, int key, int scancode, int action,
                                     int mods) {
    // fprintf(hook_log, "got key debug callback\n");
    // fflush(hook_log);
    if (imgui_state.draw_test_scene) {
        if (ImGui::GetIO().WantCaptureKeyboard) {
            ImGui_ImplGlfw_KeyCallback(window, key, scancode, action, mods);
            return;
        }

        if (glfwGetKey(window, GLFW_KEY_W) == GLFW_PRESS) {
            rdVector_Scale3Add3(&cameraPos, &cameraPos, cameraSpeed, &cameraFront);
        }
        if (glfwGetKey(window, GLFW_KEY_A) == GLFW_PRESS) {
            rdVector_Cross3(&tmp, &cameraFront, &cameraUp);
            rdVector_Normalize3Acc(&tmp);
            rdVector_Scale3Add3(&cameraPos, &cameraPos, -cameraSpeed, &tmp);
        }
        if (glfwGetKey(window, GLFW_KEY_S) == GLFW_PRESS) {
            rdVector_Scale3Add3(&cameraPos, &cameraPos, -cameraSpeed, &cameraFront);
        }
        if (glfwGetKey(window, GLFW_KEY_D) == GLFW_PRESS) {
            rdVector_Cross3(&tmp, &cameraFront, &cameraUp);
            rdVector_Normalize3Acc(&tmp);
            rdVector_Scale3Add3(&cameraPos, &cameraPos, cameraSpeed, &tmp);
        }
        if (glfwGetKey(window, GLFW_KEY_SPACE) == GLFW_PRESS) {
            rdVector_Scale3Add3(&cameraPos, &cameraPos, cameraSpeed, &cameraUp);
        }
        if (glfwGetKey(window, GLFW_KEY_LEFT_SHIFT) == GLFW_PRESS) {
            rdVector_Scale3Add3(&cameraPos, &cameraPos, -cameraSpeed, &cameraUp);
        }
        if (glfwGetKey(window, GLFW_KEY_Q) == GLFW_PRESS) {
            pitch += cameraSpeed;
            if (pitch > 90) {
                pitch = 90.0;
            }
        }
        if (glfwGetKey(window, GLFW_KEY_E) == GLFW_PRESS) {
            pitch -= cameraSpeed;
            if (pitch < -90) {
                pitch = -90.0;
            }
        }
        return;
    }

    if (key == GLFW_KEY_ENTER && action == GLFW_PRESS && mods & GLFW_MOD_ALT) {
        bool fullscreen = glfwGetWindowMonitor(window);
        if (!fullscreen) {
            glfwGetWindowPos(window, &prev_window_x, &prev_window_y);
            glfwGetWindowSize(window, &prev_window_width, &prev_window_height);
            GLFWmonitor *monitor = glfwGetPrimaryMonitor();
            const GLFWvidmode *mode = glfwGetVideoMode(monitor);
            glfwSetWindowMonitor(window, monitor, 0, 0, mode->width, mode->height,
                                 mode->refreshRate);
        } else {
            glfwSetWindowMonitor(window, NULL, prev_window_x, prev_window_y, prev_window_width,
                                 prev_window_height, 0);
        }
        return;
    }

    if (glfw_key_to_dik[GLFW_KEY_SPACE] == 0) {
        glfw_key_to_dik[GLFW_KEY_SPACE] = DIK_SPACE;
        glfw_key_to_dik[GLFW_KEY_APOSTROPHE] = DIK_APOSTROPHE;
        glfw_key_to_dik[GLFW_KEY_COMMA] = DIK_COMMA;
        glfw_key_to_dik[GLFW_KEY_MINUS] = DIK_MINUS;
        glfw_key_to_dik[GLFW_KEY_PERIOD] = DIK_PERIOD;
        glfw_key_to_dik[GLFW_KEY_SLASH] = DIK_SLASH;
        glfw_key_to_dik[GLFW_KEY_0] = DIK_0;
        glfw_key_to_dik[GLFW_KEY_1] = DIK_1;
        glfw_key_to_dik[GLFW_KEY_2] = DIK_2;
        glfw_key_to_dik[GLFW_KEY_3] = DIK_3;
        glfw_key_to_dik[GLFW_KEY_4] = DIK_4;
        glfw_key_to_dik[GLFW_KEY_5] = DIK_5;
        glfw_key_to_dik[GLFW_KEY_6] = DIK_6;
        glfw_key_to_dik[GLFW_KEY_7] = DIK_7;
        glfw_key_to_dik[GLFW_KEY_8] = DIK_8;
        glfw_key_to_dik[GLFW_KEY_9] = DIK_9;
        glfw_key_to_dik[GLFW_KEY_SEMICOLON] = DIK_SEMICOLON;
        glfw_key_to_dik[GLFW_KEY_EQUAL] = DIK_EQUALS;
        glfw_key_to_dik[GLFW_KEY_A] = DIK_A;
        glfw_key_to_dik[GLFW_KEY_B] = DIK_B;
        glfw_key_to_dik[GLFW_KEY_C] = DIK_C;
        glfw_key_to_dik[GLFW_KEY_D] = DIK_D;
        glfw_key_to_dik[GLFW_KEY_E] = DIK_E;
        glfw_key_to_dik[GLFW_KEY_F] = DIK_F;
        glfw_key_to_dik[GLFW_KEY_G] = DIK_G;
        glfw_key_to_dik[GLFW_KEY_H] = DIK_H;
        glfw_key_to_dik[GLFW_KEY_I] = DIK_I;
        glfw_key_to_dik[GLFW_KEY_J] = DIK_J;
        glfw_key_to_dik[GLFW_KEY_K] = DIK_K;
        glfw_key_to_dik[GLFW_KEY_L] = DIK_L;
        glfw_key_to_dik[GLFW_KEY_M] = DIK_M;
        glfw_key_to_dik[GLFW_KEY_N] = DIK_N;
        glfw_key_to_dik[GLFW_KEY_O] = DIK_O;
        glfw_key_to_dik[GLFW_KEY_P] = DIK_P;
        glfw_key_to_dik[GLFW_KEY_Q] = DIK_Q;
        glfw_key_to_dik[GLFW_KEY_R] = DIK_R;
        glfw_key_to_dik[GLFW_KEY_S] = DIK_S;
        glfw_key_to_dik[GLFW_KEY_T] = DIK_T;
        glfw_key_to_dik[GLFW_KEY_U] = DIK_U;
        glfw_key_to_dik[GLFW_KEY_V] = DIK_V;
        glfw_key_to_dik[GLFW_KEY_W] = DIK_W;
        glfw_key_to_dik[GLFW_KEY_X] = DIK_X;
        glfw_key_to_dik[GLFW_KEY_Y] = DIK_Y;
        glfw_key_to_dik[GLFW_KEY_Z] = DIK_Z;
        glfw_key_to_dik[GLFW_KEY_LEFT_BRACKET] = DIK_LBRACKET;
        glfw_key_to_dik[GLFW_KEY_BACKSLASH] = DIK_BACKSLASH;
        glfw_key_to_dik[GLFW_KEY_RIGHT_BRACKET] = DIK_RBRACKET;
        glfw_key_to_dik[GLFW_KEY_GRAVE_ACCENT] = DIK_GRAVE;
        glfw_key_to_dik[GLFW_KEY_ESCAPE] = DIK_ESCAPE;
        glfw_key_to_dik[GLFW_KEY_ENTER] = DIK_RETURN;
        glfw_key_to_dik[GLFW_KEY_TAB] = DIK_TAB;
        glfw_key_to_dik[GLFW_KEY_BACKSPACE] = DIK_BACKSPACE;
        glfw_key_to_dik[GLFW_KEY_INSERT] = DIK_INSERT;
        glfw_key_to_dik[GLFW_KEY_DELETE] = DIK_DELETE;
        glfw_key_to_dik[GLFW_KEY_RIGHT] = DIK_RIGHT;
        glfw_key_to_dik[GLFW_KEY_LEFT] = DIK_LEFT;
        glfw_key_to_dik[GLFW_KEY_DOWN] = DIK_DOWN;
        glfw_key_to_dik[GLFW_KEY_UP] = DIK_UP;
        glfw_key_to_dik[GLFW_KEY_PAGE_UP] = DIK_PGUP;
        glfw_key_to_dik[GLFW_KEY_PAGE_DOWN] = DIK_PGDN;
        glfw_key_to_dik[GLFW_KEY_HOME] = DIK_HOME;
        glfw_key_to_dik[GLFW_KEY_END] = DIK_END;
        glfw_key_to_dik[GLFW_KEY_CAPS_LOCK] = DIK_CAPSLOCK;
        glfw_key_to_dik[GLFW_KEY_SCROLL_LOCK] = DIK_SCROLL;
        glfw_key_to_dik[GLFW_KEY_NUM_LOCK] = DIK_NUMLOCK;
        glfw_key_to_dik[GLFW_KEY_PAUSE] = DIK_PAUSE;
        glfw_key_to_dik[GLFW_KEY_F1] = DIK_F1;
        glfw_key_to_dik[GLFW_KEY_F2] = DIK_F2;
        glfw_key_to_dik[GLFW_KEY_F3] = DIK_F3;
        glfw_key_to_dik[GLFW_KEY_F4] = DIK_F4;
        glfw_key_to_dik[GLFW_KEY_F5] = DIK_F5;
        glfw_key_to_dik[GLFW_KEY_F6] = DIK_F6;
        glfw_key_to_dik[GLFW_KEY_F7] = DIK_F7;
        glfw_key_to_dik[GLFW_KEY_F8] = DIK_F8;
        glfw_key_to_dik[GLFW_KEY_F9] = DIK_F9;
        glfw_key_to_dik[GLFW_KEY_F10] = DIK_F10;
        glfw_key_to_dik[GLFW_KEY_F11] = DIK_F11;
        glfw_key_to_dik[GLFW_KEY_F12] = DIK_F12;
        glfw_key_to_dik[GLFW_KEY_F13] = DIK_F13;
        glfw_key_to_dik[GLFW_KEY_F14] = DIK_F14;
        glfw_key_to_dik[GLFW_KEY_F15] = DIK_F15;
        glfw_key_to_dik[GLFW_KEY_KP_0] = DIK_NUMPAD0;
        glfw_key_to_dik[GLFW_KEY_KP_1] = DIK_NUMPAD1;
        glfw_key_to_dik[GLFW_KEY_KP_2] = DIK_NUMPAD2;
        glfw_key_to_dik[GLFW_KEY_KP_3] = DIK_NUMPAD3;
        glfw_key_to_dik[GLFW_KEY_KP_4] = DIK_NUMPAD4;
        glfw_key_to_dik[GLFW_KEY_KP_5] = DIK_NUMPAD5;
        glfw_key_to_dik[GLFW_KEY_KP_6] = DIK_NUMPAD6;
        glfw_key_to_dik[GLFW_KEY_KP_7] = DIK_NUMPAD7;
        glfw_key_to_dik[GLFW_KEY_KP_8] = DIK_NUMPAD8;
        glfw_key_to_dik[GLFW_KEY_KP_9] = DIK_NUMPAD9;
        glfw_key_to_dik[GLFW_KEY_KP_DECIMAL] = DIK_NUMPADCOMMA;
        glfw_key_to_dik[GLFW_KEY_KP_DIVIDE] = DIK_NUMPADSLASH;
        glfw_key_to_dik[GLFW_KEY_KP_MULTIPLY] = DIK_NUMPADSTAR;
        glfw_key_to_dik[GLFW_KEY_KP_SUBTRACT] = DIK_NUMPADMINUS;
        glfw_key_to_dik[GLFW_KEY_KP_ADD] = DIK_NUMPADPLUS;
        glfw_key_to_dik[GLFW_KEY_KP_ENTER] = DIK_NUMPADENTER;
        glfw_key_to_dik[GLFW_KEY_KP_EQUAL] = DIK_NUMPADEQUALS;
        glfw_key_to_dik[GLFW_KEY_LEFT_SHIFT] = DIK_LSHIFT;
        glfw_key_to_dik[GLFW_KEY_LEFT_CONTROL] = DIK_LCONTROL;
        glfw_key_to_dik[GLFW_KEY_LEFT_ALT] = DIK_LALT;
        glfw_key_to_dik[GLFW_KEY_LEFT_SUPER] = DIK_LWIN;
        glfw_key_to_dik[GLFW_KEY_RIGHT_SHIFT] = DIK_RSHIFT;
        glfw_key_to_dik[GLFW_KEY_RIGHT_CONTROL] = DIK_RCONTROL;
        glfw_key_to_dik[GLFW_KEY_RIGHT_ALT] = DIK_RALT;
        glfw_key_to_dik[GLFW_KEY_RIGHT_SUPER] = DIK_RWIN;
        glfw_key_to_dik[GLFW_KEY_MENU] = DIK_RMENU;
    };

    if (key >= ARRAYSIZE(glfw_key_to_dik))
        return;

    int dik_key = glfw_key_to_dik[key];
    if (dik_key == 0)
        return;

    const bool pressed = action != GLFW_RELEASE;

    stdControl_aKeyInfos[dik_key] = pressed;
    stdControl_g_aKeyPressCounter[dik_key] += pressed;

    UINT vk = MapVirtualKeyA(dik_key, MAPVK_VSC_TO_VK);
    if (vk == 0) {
        // TODO hack: for some reason the arrow keys return 0 on MapVirtualKeyA...
        switch (key) {
            case GLFW_KEY_DOWN:
                vk = VK_DOWN;
                break;
            case GLFW_KEY_UP:
                vk = VK_UP;
                break;
            case GLFW_KEY_LEFT:
                vk = VK_LEFT;
                break;
            case GLFW_KEY_RIGHT:
                vk = VK_RIGHT;
                break;
        }
    }

    // Window_AddKeyEvent(vk, 0, pressed); <-- not actually used by the game
    swrUI_HandleKeyEvent(vk, pressed);
}

bool clicking = false;
double lastX = 0.0;
double lastY = 0.0;

static void debug_scene_mouse_button_callback(GLFWwindow *window, int button, int action,
                                              int mods) {
    if (ImGui::GetIO().WantCaptureMouse) {
        ImGui_ImplGlfw_MouseButtonCallback(window, button, action, mods);
        return;
    }
    if (!imgui_state.draw_test_scene) {
        const bool pressed = action != GLFW_RELEASE;
        stdControl_aKeyInfos[512 + button] = pressed;
        stdControl_g_aKeyPressCounter[512 + button] += pressed;
    } else {
        if (button == GLFW_MOUSE_BUTTON_LEFT && action == GLFW_PRESS) {
            if (!clicking) {
                clicking = true;
                glfwGetCursorPos(window, &lastX, &lastY);
            }
        }
        if (button == GLFW_MOUSE_BUTTON_LEFT && action == GLFW_RELEASE) {
            clicking = false;
        }
    }
}

static void debug_mouse_pos_callback(GLFWwindow *window, double xposIn, double yposIn) {
    ImGui_ImplGlfw_CursorPosCallback(window, xposIn, yposIn);

    if (imgui_state.draw_test_scene) {
        if (clicking) {
            double xpos;
            double ypos;
            glfwGetCursorPos(window, &xpos, &ypos);
            float xoffset = lastX - xpos;
            float yoffset = lastY - ypos;
            lastX = xpos;
            lastY = ypos;
            yaw += 0.1 * xoffset;
            pitch += 0.1 * yoffset;

            if (pitch < -90)
                pitch = -90;
            if (pitch > 90)
                pitch = 90;
            // update camera up, front, right
        }
    }
}

void draw_test_scene(void) {
    // Override previous key callbacks to prevent issues with inputs
    auto *glfw_window = glfwGetCurrentContext();
    glfwSetKeyCallback(glfw_window, debug_scene_key_callback);
    glfwSetMouseButtonCallback(glfw_window, debug_scene_mouse_button_callback);
    glfwSetCursorPosCallback(glfw_window, debug_mouse_pos_callback);

    float fov = 45.0;
    float aspect_ratio = float(screen_width) / float(screen_height);

    static rdMatrix44 proj_mat;
    renderer_perspective(&proj_mat, fov * 3.141592 / 180, aspect_ratio, 0.1, 1000.0);
    static rdMatrix44 view_matrix;
    rdMatrix_SetIdentity44(&view_matrix);
    rdVector_Add3(&tmp, &cameraPos, &cameraFront);
    // renderer_lookAtInverse(&view_matrix, &cameraPos, &tmp, &cameraUp);
    renderer_viewFromTransforms(&view_matrix, &cameraPos, pitch * 3.141592 / 180,
                                yaw * 3.141592 / 180);

    static rdMatrix44 model_matrix;
    rdMatrix_SetIdentity44(&model_matrix);
    // reverse scaling factor
    rdMatrix_ScaleBasis44(&model_matrix, 0.005, 0.005, 0.005, &model_matrix);

    gltfModel model = g_models[1];

    // override std3D potential state change
    {
        glEnable(GL_DEPTH_TEST);
        glDepthMask(GL_TRUE);
        glEnable(GL_BLEND);
    }
    renderer_drawGLTF(proj_mat, view_matrix, model_matrix, model);
}
