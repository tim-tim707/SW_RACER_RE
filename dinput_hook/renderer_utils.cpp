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

#include "tinygltf/stb_image.h"
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
        std::string vertex_shader_source_s = readFileAsString("./assets/shaders/fullscreen.vert");
        std::string fragment_shader_source_s =
            readFileAsString("./assets/shaders/progressBar.frag");
        const char *vertex_shader_source = vertex_shader_source_s.c_str();
        const char *fragment_shader_source = fragment_shader_source_s.c_str();

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
        std::string vertex_shader_source_s = readFileAsString("./assets/shaders/fullscreen.vert");
        std::string fragment_shader_source_s = readFileAsString("./assets/shaders/flipUpDown.frag");
        const char *vertex_shader_source = vertex_shader_source_s.c_str();
        const char *fragment_shader_source = fragment_shader_source_s.c_str();

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
        std::string vertex_shader_source_s = readFileAsString("./assets/shaders/renderList.vert");
        std::string fragment_shader_source_s = readFileAsString("./assets/shaders/renderList.frag");
        const char *vertex_shader_source = vertex_shader_source_s.c_str();
        const char *fragment_shader_source = fragment_shader_source_s.c_str();

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
                       const rdMatrix44 &model_matrix, gltfModel &model, envTextures env) {
    if (!model.setuped) {
        setupModel(model);
    }

    for (size_t nodeId = 0; nodeId < model.gltf.nodes.size(); nodeId++) {
        tinygltf::Node node = model.gltf.nodes[nodeId];
        // no hierarchy yet
        if (node.mesh == -1)
            continue;

        size_t meshId = node.mesh;
        const meshInfos meshInfos = model.mesh_infos[meshId];
        const pbrShader shader = model.shader_pool[meshInfos.gltfFlags];
        if (shader.handle == 0)
            continue;
        glUseProgram(shader.handle);

        glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &proj_matrix.vA.x);
        glUniformMatrix4fv(shader.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);
        rdMatrix44 model_matrix2;
        memcpy(&model_matrix2, &model_matrix, sizeof(model_matrix2));
        // build model matrix from node TRS
        rdVector3 translation = {0, 0, 0};
        if (node.translation.size() > 0) {
            translation = {
                static_cast<float>(node.translation[0]),
                static_cast<float>(node.translation[1]),
                static_cast<float>(node.translation[2]),
            };
        }
        rdVector_Add3((rdVector3 *) (&model_matrix2.vD), &translation,
                      (rdVector3 *) (&model_matrix2.vD));

        if (!imgui_state.draw_test_scene) {// the base game need some big coordinates
            rdMatrix_ScaleBasis44(&model_matrix2, 100, 100, 100, &model_matrix2);
        }

        glUniformMatrix4fv(shader.model_matrix_pos, 1, GL_FALSE, &model_matrix2.vA.x);
        glUniform1i(shader.model_id_pos, gltf_model_id);

        int primitiveId = 0;
        tinygltf::Primitive primitive = model.gltf.meshes[meshId].primitives[primitiveId];
        int materialId = primitive.material;
        if (materialId == -1) {
            fprintf(hook_log, "Mesh %d primitive %d has no material, skipping\n", meshId,
                    primitiveId);
            fflush(hook_log);
            continue;
        }

        tinygltf::Material material = model.gltf.materials[materialId];
        std::vector<double> baseColorFactor = material.pbrMetallicRoughness.baseColorFactor;
        glUniform4f(shader.baseColorFactor_pos, baseColorFactor[0], baseColorFactor[1],
                    baseColorFactor[2], baseColorFactor[3]);
        glUniform1f(shader.metallicFactor_pos, material.pbrMetallicRoughness.metallicFactor);
        glUniform1f(shader.roughnessFactor_pos, material.pbrMetallicRoughness.roughnessFactor);

        glUniform3f(shader.cameraWorldPosition_pos, cameraPos.x, cameraPos.y, cameraPos.z);

        glBindVertexArray(meshInfos.VAO);

        // unsigned int
        if (meshInfos.gltfFlags & gltfFlags::HasTexCoords) {
            materialInfos material_infos = model.material_infos[materialId];

            glUniform1i(glGetUniformLocation(shader.handle, "baseColorTexture"), 0);
            glUniform1i(glGetUniformLocation(shader.handle, "metallicRoughnessTexture"), 1);

            glActiveTexture(GL_TEXTURE0);
            glBindTexture(GL_TEXTURE_2D, material_infos.baseColorGLTexture);
            glActiveTexture(GL_TEXTURE1);
            glBindTexture(GL_TEXTURE_2D, material_infos.metallicRoughnessGLTexture);

            // Setup env
            // TODO: We should do it also on non-textured material, using texture slot tracking
            glUniform1i(glGetUniformLocation(shader.handle, "lambertianEnvSampler"), 2);
            glActiveTexture(GL_TEXTURE2);
            glBindTexture(GL_TEXTURE_CUBE_MAP, env.lambertianCubemapID);
            glUniform1i(glGetUniformLocation(shader.handle, "GGXEnvSampler"), 3);
            glActiveTexture(GL_TEXTURE3);
            glBindTexture(GL_TEXTURE_CUBE_MAP, env.ggxCubemapID);
            glUniform1i(glGetUniformLocation(shader.handle, "GGXLUT"), 4);
            glActiveTexture(GL_TEXTURE4);
            glBindTexture(GL_TEXTURE_2D, env.ggxLutTextureID);

            // cleanup
            glActiveTexture(GL_TEXTURE0);
        }

        if (meshInfos.gltfFlags & gltfFlags::IsIndexed) {
            const tinygltf::Accessor &indicesAccessor = model.gltf.accessors[primitive.indices];

            glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, meshInfos.EBO);
            glDrawElements(primitive.mode, indicesAccessor.count, indicesAccessor.componentType, 0);
        } else {
            fprintf(hook_log, "Trying to draw a non-indexed mesh. Unsupported yet\n");
            fflush(hook_log);
        }

        glBindVertexArray(0);
    }
}

bool skybox_initialized = false;
skyboxShader skybox;

void setupSkybox(void) {
    skybox_initialized = true;
    std::string skyboxPath = "./assets/textures/skybox/";
    const char *faces_names[] = {
        "right.jpg", "left.jpg", "top.jpg", "bottom.jpg", "front.jpg", "back.jpg",
    };

    glGenTextures(1, &skybox.GLCubeTexture);
    glBindTexture(GL_TEXTURE_CUBE_MAP, skybox.GLCubeTexture);

    int width;
    int height;
    int nbChannels;
    for (size_t i = 0; i < 6; i++) {
        const char *filepath = (skyboxPath + faces_names[i]).c_str();
        unsigned char *data = stbi_load(filepath, &width, &height, &nbChannels, 0);
        if (data == NULL) {
            fprintf(hook_log, "Couldnt read skybox face %s\n", filepath);
            fflush(hook_log);
            stbi_image_free(data);

            return;
        }
        glTexImage2D(GL_TEXTURE_CUBE_MAP_POSITIVE_X + i, 0, GL_RGB, width, height, 0, GL_RGB,
                     GL_UNSIGNED_BYTE, data);
        stbi_image_free(data);
    }

    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_R, GL_CLAMP_TO_EDGE);

    std::string vertex_shader_source_s = readFileAsString("./assets/shaders/skybox.vert");
    std::string fragment_shader_source_s = readFileAsString("./assets/shaders/skybox.frag");
    const char *vertex_shader_source = vertex_shader_source_s.c_str();
    const char *fragment_shader_source = fragment_shader_source_s.c_str();

    std::optional<GLuint> program_opt =
        compileProgram(1, &vertex_shader_source, 1, &fragment_shader_source);
    if (!program_opt.has_value())
        std::abort();
    skybox.handle = program_opt.value();

    skybox.proj_matrix_pos = glGetUniformLocation(skybox.handle, "projMatrix"),
    skybox.view_matrix_pos = glGetUniformLocation(skybox.handle, "viewMatrix"),

    glGenVertexArrays(1, &skybox.VAO);
    glGenBuffers(1, &skybox.VBO);
    glBindVertexArray(skybox.VAO);
    glBindBuffer(GL_ARRAY_BUFFER, skybox.VBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(skyboxVertices), &skyboxVertices, GL_STATIC_DRAW);
    glEnableVertexArrayAttrib(skybox.VAO, 0);
    glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 3 * sizeof(float), 0);
}

void renderer_drawSkybox(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix) {
    glDepthFunc(GL_LEQUAL);
    glUseProgram(skybox.handle);
    glUniformMatrix4fv(skybox.proj_matrix_pos, 1, GL_FALSE, &proj_matrix.vA.x);
    glUniformMatrix4fv(skybox.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);

    glBindVertexArray(skybox.VAO);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_CUBE_MAP, skybox.GLCubeTexture);
    glDrawArrays(GL_TRIANGLES, 0, 36);
    glBindVertexArray(0);

    // restore state
    glDepthFunc(GL_LESS);
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

static void renderer_viewFromTransforms(rdMatrix44 *view_mat, rdVector3 *position, float pitch_rad,
                                        float yaw_rad) {
    float sinY = sin(yaw_rad);
    float cosY = cos(yaw_rad);
    float sinP = sin(pitch_rad);
    float cosP = cos(pitch_rad);

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

rdVector3 cameraPos = {2.0, 56.003, 4.026};
rdVector3 cameraFront = {-0.99, 0, 0.0};
rdVector3 cameraUp = {0, 1, 0};
float cameraPitch = -86;
float cameraYaw = -270;
float cameraSpeed = 0.001;

// Removes delay of REPEAT by storing the state ourselves
static bool wKeyPressed = false;
static bool aKeyPressed = false;
static bool sKeyPressed = false;
static bool dKeyPressed = false;
static bool spaceKeyPressed = false;
static bool leftShiftKeyPressed = false;
static bool leftCtrKeyPressed = false;

static void debug_scene_key_callback(GLFWwindow *window, int key, int scancode, int action,
                                     int mods) {
    // fprintf(hook_log, "got key debug callback\n");
    // fflush(hook_log);
    if (imgui_state.draw_test_scene) {
        if (ImGui::GetIO().WantCaptureKeyboard) {
            ImGui_ImplGlfw_KeyCallback(window, key, scancode, action, mods);
            return;
        }
        if (action == GLFW_PRESS) {
            switch (key) {
                case GLFW_KEY_W:
                    wKeyPressed = true;
                    break;
                case GLFW_KEY_A:
                    aKeyPressed = true;
                    break;
                case GLFW_KEY_S:
                    sKeyPressed = true;
                    break;
                case GLFW_KEY_D:
                    dKeyPressed = true;
                    break;
                case GLFW_KEY_SPACE:
                    spaceKeyPressed = true;
                    break;
                case GLFW_KEY_LEFT_SHIFT:
                    leftShiftKeyPressed = true;
                    break;
                case GLFW_KEY_LEFT_CONTROL:
                    leftCtrKeyPressed = true;
                    break;
            }
        }
        if (action == GLFW_RELEASE) {
            switch (key) {
                case GLFW_KEY_W:
                    wKeyPressed = false;
                    break;
                case GLFW_KEY_A:
                    aKeyPressed = false;
                    break;
                case GLFW_KEY_S:
                    sKeyPressed = false;
                    break;
                case GLFW_KEY_D:
                    dKeyPressed = false;
                    break;
                case GLFW_KEY_SPACE:
                    spaceKeyPressed = false;
                    break;
                case GLFW_KEY_LEFT_SHIFT:
                    leftShiftKeyPressed = false;
                    break;
                case GLFW_KEY_LEFT_CONTROL:
                    leftCtrKeyPressed = false;
                    break;
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

static bool leftMouseButtonPressed = false;
static double lastX = 0.0;
static double lastY = 0.0;

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
            if (!leftMouseButtonPressed) {
                leftMouseButtonPressed = true;
                glfwGetCursorPos(window, &lastX, &lastY);
            }
        }
        if (button == GLFW_MOUSE_BUTTON_LEFT && action == GLFW_RELEASE) {
            leftMouseButtonPressed = false;
        }
    }
}

static void debug_mouse_pos_callback(GLFWwindow *window, double xposIn, double yposIn) {
    ImGui_ImplGlfw_CursorPosCallback(window, xposIn, yposIn);

    if (imgui_state.draw_test_scene) {
        if (leftMouseButtonPressed) {
            double xpos;
            double ypos;
            glfwGetCursorPos(window, &xpos, &ypos);
            float xoffset = lastX - xpos;
            float yoffset = lastY - ypos;
            lastX = xpos;
            lastY = ypos;

            cameraYaw += 0.1 * xoffset;
            if (cameraYaw > 360)
                cameraYaw -= 360;

            cameraPitch += 0.1 * yoffset;
            if (cameraPitch < -90)
                cameraPitch = -90;
            if (cameraPitch > 90)
                cameraPitch = 90;

            // Update camera front for correct movement
            rdVector3 direction;
            float yaw_rad = cameraYaw * 3.141592 / 180;
            float pitch_rad = cameraPitch * 3.141592 / 180;
            float cosY = cos(yaw_rad);
            float sinY = sin(yaw_rad);
            direction.x = -sinY;
            direction.y = 0;
            direction.z = -cosY;
            rdVector_Normalize3Acc(&direction);
            cameraFront = direction;
        }
    }
}

void debug_scroll_callback(GLFWwindow *window, double xoffset, double yoffset) {
    cameraSpeed += yoffset / 100;
}

static void moveCamera(void) {
    float localCameraSpeed = cameraSpeed;
    if (leftCtrKeyPressed)
        localCameraSpeed *= 100;
    if (wKeyPressed)
        rdVector_Scale3Add3(&cameraPos, &cameraPos, localCameraSpeed, &cameraFront);
    if (aKeyPressed) {
        rdVector3 tmp;
        rdVector_Cross3(&tmp, &cameraFront, &cameraUp);
        rdVector_Normalize3Acc(&tmp);
        rdVector_Scale3Add3(&cameraPos, &cameraPos, -localCameraSpeed, &tmp);
    }
    if (sKeyPressed) {
        rdVector_Scale3Add3(&cameraPos, &cameraPos, -localCameraSpeed, &cameraFront);
    }
    if (dKeyPressed) {
        rdVector3 tmp;
        rdVector_Cross3(&tmp, &cameraFront, &cameraUp);
        rdVector_Normalize3Acc(&tmp);
        rdVector_Scale3Add3(&cameraPos, &cameraPos, localCameraSpeed, &tmp);
    }
    if (spaceKeyPressed) {
        rdVector_Scale3Add3(&cameraPos, &cameraPos, localCameraSpeed, &cameraUp);
    }
    if (leftShiftKeyPressed) {
        rdVector_Scale3Add3(&cameraPos, &cameraPos, -localCameraSpeed, &cameraUp);
    }
}

void draw_test_scene(void) {
    // Override previous key callbacks to prevent issues with inputs
    auto *glfw_window = glfwGetCurrentContext();
    glfwSetKeyCallback(glfw_window, debug_scene_key_callback);
    glfwSetMouseButtonCallback(glfw_window, debug_scene_mouse_button_callback);
    glfwSetCursorPosCallback(glfw_window, debug_mouse_pos_callback);
    glfwSetScrollCallback(glfw_window, debug_scroll_callback);

    moveCamera();

    float fov = 45.0;
    float aspect_ratio = float(screen_width) / float(screen_height);

    static rdMatrix44 proj_mat;
    renderer_perspective(&proj_mat, fov * 3.141592 / 180, aspect_ratio, 0.01, 1000.0);
    static rdMatrix44 view_matrix;
    rdMatrix_SetIdentity44(&view_matrix);
    rdVector3 tmp;
    rdVector_Add3(&tmp, &cameraPos, &cameraFront);
    renderer_viewFromTransforms(&view_matrix, &cameraPos, cameraPitch * 3.141592 / 180,
                                cameraYaw * 3.141592 / 180);

    static rdMatrix44 model_matrix;
    rdMatrix_SetIdentity44(&model_matrix);
    // reverse scaling factor
    // rdMatrix_ScaleBasis44(&model_matrix, 0.005, 0.005, 0.005, &model_matrix);

    // override std3D potential state change
    {
        glEnable(GL_DEPTH_TEST);
        glDepthMask(GL_TRUE);
        glEnable(GL_BLEND);
        glClearColor(0.4, 0.4, 0.4, 1.0);
        glClear(GL_COLOR_BUFFER_BIT);
    }
    if (!skybox_initialized) {
        setupSkybox();
    }

    // Env textures
    static bool environment_setuped = false;
    static envTextures envTextures;
    if (!environment_setuped) {
        envTextures = setupIBL(skybox.GLCubeTexture);
        environment_setuped = true;
    }
    renderer_drawGLTF(proj_mat, view_matrix, model_matrix, g_models[4], envTextures);
    renderer_drawSkybox(proj_mat, view_matrix);

    if (imgui_state.debug_lambertian_cubemap) {}
    if (imgui_state.debug_ggx_cubemap) {}
    if (imgui_state.debug_ggxLut) {}
}
