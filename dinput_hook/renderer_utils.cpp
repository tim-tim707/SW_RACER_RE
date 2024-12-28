#include "renderer_utils.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include <string>
#include <windows.h>
#include <cmath>
#include <algorithm>

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

        std::string loading_textures_path = std::string("./assets/textures/loading_screen/");
        const char *beam_names[16] = {
            "1.png", "2.png",  "3.png",  "4.png",  "5.png",  "6.png",  "7.png",  "8.png",
            "9.png", "10.png", "11.png", "12.png", "13.png", "14.png", "15.png", "16.png",
        };
        GLuint beam_textures[16];
        glGenTextures(16, beam_textures);
        {// read the beam textures
            stbi_set_flip_vertically_on_load(true);

            int width;
            int height;
            int nbChannels;
            for (size_t i = 0; i < 16; i++) {
                glBindTexture(GL_TEXTURE_2D, beam_textures[i]);

                const char *filepath = (loading_textures_path + beam_names[i]).c_str();
                unsigned char *data =
                    stbi_load(filepath, &width, &height, &nbChannels, STBI_rgb_alpha);
                if (data == NULL) {
                    fprintf(hook_log, "Couldnt read beam %s\n", filepath);
                    fflush(hook_log);
                }
                glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE,
                             data);
                setTextureParameters(GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE, GL_LINEAR, GL_LINEAR);
                stbi_image_free(data);
            }
        }

        shader = {
            .handle = program,
            .emptyVAO = VAO,
            .progress_pos = glGetUniformLocation(program, "progress"),
            .beam_texture_pos = glGetUniformLocation(program, "beamTexture"),
        };
        memcpy(shader.beam_textures, beam_textures, sizeof(beam_textures));
        shaderCompiled = true;
    }

    return shader;
}

extern "C" __declspec(dllexport) void renderer_drawProgressBar(int progress) {
    const progressBarShader shader = get_or_compile_drawProgressShader();

    glClearColor(0.0, 0.0, 0.0, 1.0);
    glClear(GL_COLOR_BUFFER_BIT);

    static int callCount = 0;
    glUseProgram(shader.handle);

    glUniform1f(shader.progress_pos, progress);

    glBindTexture(GL_TEXTURE_2D, shader.beam_textures[callCount]);
    glUniform1i(shader.beam_texture_pos, 0);

    glBindVertexArray(shader.emptyVAO);

    glDrawArrays(GL_TRIANGLES, 0, 3);

    callCount += 1;
    if (callCount > 15) {
        callCount = 0;
    }
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

        setTextureParameters(GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE, GL_LINEAR, GL_LINEAR);

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

    const fullScreenTextureShader shader = get_or_compile_fullscreenTextureShader();
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

    // const char *debug_msg = "drawRenderList";
    // glPushDebugGroup(GL_DEBUG_SOURCE_APPLICATION, 0, strlen(debug_msg), debug_msg);

    const renderListShader shader = get_or_compile_renderListShader();
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

    // glPopDebugGroup();
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

uniform vec4 color;

uniform int model_id;

void main() {
    // Yes, precomputing modelView is better and we should do it
    gl_Position = projMatrix * viewMatrix * modelMatrix * vec4(position, 1.0);

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
            .color_pos = glGetUniformLocation(program, "color"),
        };

        shaderCompiled = true;
    }

    return shader;
}

void renderer_drawCube(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix) {
    const replacementShader shader = get_or_compile_replacement(imgui_state);
    glUseProgram(shader.handle);

    glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &proj_matrix.vA.x);
    glUniformMatrix4fv(shader.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);
    glUniformMatrix4fv(shader.model_matrix_pos, 1, GL_FALSE, &model_matrix.vA.x);
    glUniform1i(shader.model_id_pos, cube_model_id);
    glUniform4f(shader.color_pos, 1.0, 0.0, 1.0, 1.0);
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
                              const rdMatrix44 &model_matrix, unsigned char color[4]) {
    const replacementShader shader = get_or_compile_replacement(imgui_state);
    glUseProgram(shader.handle);

    glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &proj_matrix.vA.x);
    glUniformMatrix4fv(shader.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);
    glUniformMatrix4fv(shader.model_matrix_pos, 1, GL_FALSE, &model_matrix.vA.x);
    glUniform1i(shader.model_id_pos, tetrahedron_model_id);
    glUniform4f(shader.color_pos, ((float) color[0] / 255.0), ((float) color[1] / 255.0),
                ((float) color[2] / 255.0), ((float) color[3] / 255.0));
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

static void setupTextureUniform(GLuint programHandle, const char *textureUniformName,
                                GLint textureUnit, GLint target, GLuint glTexture) {
    glUniform1i(glGetUniformLocation(programHandle, textureUniformName), textureUnit);
    glActiveTexture(GL_TEXTURE0 + textureUnit);
    glBindTexture(target, glTexture);
}

void renderer_drawGLTF(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix, gltfModel &model, EnvInfos env,
                       bool mirrored, uint8_t type) {
    if (!model.setuped) {
        setupModel(model);
    }

    for (size_t nodeId = 0; nodeId < model.gltf.nodes.size(); nodeId++) {
        tinygltf::Node node = model.gltf.nodes[nodeId];
        // no hierarchy yet
        if (node.mesh == -1) {
            // fprintf(hook_log, "Skipping hierarchy for model %s node %d (%s)\n",
            //         model.filename.c_str(), nodeId, node.name.c_str());
            // fflush(hook_log);

            continue;
        }

        size_t meshId = node.mesh;
        const meshInfos meshInfos = model.mesh_infos[meshId];

        int primitiveId = 0;
        tinygltf::Primitive primitive = model.gltf.meshes[meshId].primitives[primitiveId];
        int materialId = primitive.material;

        tinygltf::Material material;
        materialInfos material_infos;
        if (materialId == -1) {
            material = default_material;
            material_infos = default_material_infos;
        } else {
            material = model.gltf.materials[materialId];
            material_infos = model.material_infos[materialId];
        }


        const pbrShader shader =
            shader_pool[(meshInfos.gltfFlags << materialFlags::MaterialFlagLast) |
                        material_infos.flags];
        if (shader.handle == 0) {
            fprintf(hook_log, "Failed to get shader for flags gltf %X material %X\n",
                    meshInfos.gltfFlags, material_infos.flags);
            fflush(hook_log);
            continue;
        }

        glEnable(GL_DEPTH_TEST);
        glDepthMask(GL_TRUE);
        glDepthFunc(GL_LEQUAL);

        glEnable(GL_BLEND);

        glEnable(GL_CULL_FACE);
        if (type & 0x8) {
            glEnable(GL_CULL_FACE);
            glCullFace(mirrored ? GL_FRONT : GL_BACK);
        } else if (type & 0x40) {
            // mirrored geometry.
            glEnable(GL_CULL_FACE);
            glCullFace(mirrored ? GL_BACK : GL_FRONT);
        } else {
            // double sided geometry.
            glDisable(GL_CULL_FACE);
        }

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

        std::vector<double> baseColorFactor = material.pbrMetallicRoughness.baseColorFactor;
        glUniform4f(shader.baseColorFactor_pos, baseColorFactor[0], baseColorFactor[1],
                    baseColorFactor[2], baseColorFactor[3]);
        glUniform1f(shader.metallicFactor_pos, material.pbrMetallicRoughness.metallicFactor);
        glUniform1f(shader.roughnessFactor_pos, material.pbrMetallicRoughness.roughnessFactor);

        if (imgui_state.draw_test_scene) {
            glUniform3f(shader.cameraWorldPosition_pos, debugCameraPos.x, debugCameraPos.y,
                        debugCameraPos.z);
        } else {
            const swrViewport &vp = swrViewport_array[1];
            rdVector3 cameraPosition = {
                vp.model_matrix.vD.x,
                vp.model_matrix.vD.y,
                vp.model_matrix.vD.z,
            };

            glUniform3f(shader.cameraWorldPosition_pos, cameraPosition.x, cameraPosition.y,
                        cameraPosition.z);
        }

        glBindVertexArray(meshInfos.VAO);

        if (meshInfos.gltfFlags & gltfFlags::HasTexCoords) {

            setupTextureUniform(shader.handle, "baseColorTexture", 0, GL_TEXTURE_2D,
                                material_infos.baseColorGLTexture);
            setupTextureUniform(shader.handle, "metallicRoughnessTexture", 1, GL_TEXTURE_2D,
                                material_infos.metallicRoughnessGLTexture);

            {// Env
                // TODO: We should do it also on non-textured material, using texture slot tracking
                // TODO: env rotation Matrix

                setupTextureUniform(shader.handle, "lambertianEnvSampler", 2, GL_TEXTURE_CUBE_MAP,
                                    env.lambertianCubemapID);
                setupTextureUniform(shader.handle, "GGXEnvSampler", 3, GL_TEXTURE_CUBE_MAP,
                                    env.ggxCubemapID);
                setupTextureUniform(shader.handle, "GGXLUT", 4, GL_TEXTURE_2D, env.ggxLutTextureID);
                glUniform1f(glGetUniformLocation(shader.handle, "GGXEnvSampler_mipcount"),
                            env.mipmapLevels);
            }

            {// Optional maps
                if (material_infos.flags & materialFlags::HasNormalMap) {
                    setupTextureUniform(shader.handle, "NormalMapSampler", 5, GL_TEXTURE_2D,
                                        material_infos.normalMapGLTexture);
                }

                if (material_infos.flags & materialFlags::HasOcclusionMap) {
                    glUniform1f(glGetUniformLocation(shader.handle, "OcclusionStrength"),
                                material.occlusionTexture.strength);
                    setupTextureUniform(shader.handle, "OcclusionMapSampler", 6, GL_TEXTURE_2D,
                                        material_infos.occlusionMapGLTexture);
                }

                if (material_infos.flags & materialFlags::HasEmissiveMap) {
                    glUniform3f(glGetUniformLocation(shader.handle, "EmissiveFactor"),
                                material.emissiveFactor[0], material.emissiveFactor[1],
                                material.emissiveFactor[2]);
                    setupTextureUniform(shader.handle, "EmissiveMapSampler", 7, GL_TEXTURE_2D,
                                        material_infos.emissiveMapGLTexture);
                }
            }

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

static void applyGltfNodeRotationScale(const tinygltf::Node &node, rdMatrix44 &out_mat,
                                       const rdMatrix44 &in_mat) {
    rdMatrix44 tmp;
    rdMatrix_SetIdentity44(&tmp);

    if (node.rotation.size() > 0) {
        double roll;
        double pitch;
        double yaw;
        quatToEulerAnglesV(node.rotation, roll, pitch, yaw);
        rdMatrix_BuildRotation44(&tmp, yaw, roll, pitch);
    }
    if (node.scale.size() > 0) {
        rdMatrix_ScaleBasis44(&tmp, node.scale[0], node.scale[1], node.scale[2], &tmp);
    }
    rdMatrix_Multiply44(&tmp, &tmp, &in_mat);
    out_mat = tmp;
}

// Note: maybe 3x3 matrices for pod parts ? We should get translation from gltf model hierarchy instead
void renderer_drawGLTFPod(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                          const rdMatrix44 &engineR_model_matrix,
                          const rdMatrix44 &engineL_model_matrix,
                          const rdMatrix44 &cockpit_model_matrix, gltfModel &model, EnvInfos env,
                          bool mirrored, uint8_t type) {
    if (!model.setuped) {
        setupModel(model);
    }

    for (size_t nodeId = 0; nodeId < model.gltf.nodes.size(); nodeId++) {
        tinygltf::Node node = model.gltf.nodes[nodeId];
        // no hierarchy yet
        if (node.mesh == -1) {
            // fprintf(hook_log, "Skipping hierarchy for model %s node %d (%s)\n",
            //         model.filename.c_str(), nodeId, node.name.c_str());
            // fflush(hook_log);

            continue;
        }

        size_t meshId = node.mesh;
        const meshInfos meshInfos = model.mesh_infos[meshId];

        int primitiveId = 0;
        tinygltf::Primitive primitive = model.gltf.meshes[meshId].primitives[primitiveId];
        int materialId = primitive.material;

        tinygltf::Material material;
        materialInfos material_infos;
        if (materialId == -1) {
            material = default_material;
            material_infos = default_material_infos;
        } else {
            material = model.gltf.materials[materialId];
            material_infos = model.material_infos[materialId];
        }


        const pbrShader shader =
            shader_pool[(meshInfos.gltfFlags << materialFlags::MaterialFlagLast) |
                        material_infos.flags];
        if (shader.handle == 0) {
            fprintf(hook_log, "Failed to get shader for flags gltf %X material %X\n",
                    meshInfos.gltfFlags, material_infos.flags);
            fflush(hook_log);
            continue;
        }

        glEnable(GL_DEPTH_TEST);
        glDepthMask(GL_TRUE);
        glDepthFunc(GL_LEQUAL);

        glEnable(GL_BLEND);

        glEnable(GL_CULL_FACE);
        if (type & 0x8) {
            glEnable(GL_CULL_FACE);
            glCullFace(mirrored ? GL_FRONT : GL_BACK);
        } else if (type & 0x40) {
            // mirrored geometry.
            glEnable(GL_CULL_FACE);
            glCullFace(mirrored ? GL_BACK : GL_FRONT);
        } else {
            // double sided geometry.
            glDisable(GL_CULL_FACE);
        }

        glUseProgram(shader.handle);

        glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &proj_matrix.vA.x);
        glUniformMatrix4fv(shader.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);
        rdMatrix44 model_matrix;
        if (node.name == "engineR") {
            applyGltfNodeRotationScale(node, model_matrix, engineR_model_matrix);
        } else if (node.name == "engineL") {
            applyGltfNodeRotationScale(node, model_matrix, engineL_model_matrix);
        } else if (node.name == "cockpit") {
            applyGltfNodeRotationScale(node, model_matrix, cockpit_model_matrix);
        } else {
            fprintf(hook_log,
                    "Unknown node type for replacement pod: %s. Accepted are \"engineR\" | "
                    "\"engineL\" | \"cockpit\"\n",
                    node.name.c_str());
            fflush(hook_log);
            continue;
        }

        glUniformMatrix4fv(shader.model_matrix_pos, 1, GL_FALSE, &model_matrix.vA.x);
        glUniform1i(shader.model_id_pos, gltf_model_id);

        std::vector<double> baseColorFactor = material.pbrMetallicRoughness.baseColorFactor;
        glUniform4f(shader.baseColorFactor_pos, baseColorFactor[0], baseColorFactor[1],
                    baseColorFactor[2], baseColorFactor[3]);
        glUniform1f(shader.metallicFactor_pos, material.pbrMetallicRoughness.metallicFactor);
        glUniform1f(shader.roughnessFactor_pos, material.pbrMetallicRoughness.roughnessFactor);

        if (imgui_state.draw_test_scene) {
            glUniform3f(shader.cameraWorldPosition_pos, debugCameraPos.x, debugCameraPos.y,
                        debugCameraPos.z);
        } else {
            const swrViewport &vp = swrViewport_array[1];
            rdVector3 cameraPosition = {
                vp.model_matrix.vD.x,
                vp.model_matrix.vD.y,
                vp.model_matrix.vD.z,
            };

            glUniform3f(shader.cameraWorldPosition_pos, cameraPosition.x, cameraPosition.y,
                        cameraPosition.z);
        }

        glBindVertexArray(meshInfos.VAO);

        if (meshInfos.gltfFlags & gltfFlags::HasTexCoords) {

            setupTextureUniform(shader.handle, "baseColorTexture", 0, GL_TEXTURE_2D,
                                material_infos.baseColorGLTexture);
            setupTextureUniform(shader.handle, "metallicRoughnessTexture", 1, GL_TEXTURE_2D,
                                material_infos.metallicRoughnessGLTexture);

            {// Env
                // TODO: We should do it also on non-textured material, using texture slot tracking
                // TODO: env rotation Matrix

                setupTextureUniform(shader.handle, "lambertianEnvSampler", 2, GL_TEXTURE_CUBE_MAP,
                                    env.lambertianCubemapID);
                setupTextureUniform(shader.handle, "GGXEnvSampler", 3, GL_TEXTURE_CUBE_MAP,
                                    env.ggxCubemapID);
                setupTextureUniform(shader.handle, "GGXLUT", 4, GL_TEXTURE_2D, env.ggxLutTextureID);
                glUniform1f(glGetUniformLocation(shader.handle, "GGXEnvSampler_mipcount"),
                            env.mipmapLevels);
            }

            {// Optional maps
                if (material_infos.flags & materialFlags::HasNormalMap) {
                    setupTextureUniform(shader.handle, "NormalMapSampler", 5, GL_TEXTURE_2D,
                                        material_infos.normalMapGLTexture);
                }

                if (material_infos.flags & materialFlags::HasOcclusionMap) {
                    glUniform1f(glGetUniformLocation(shader.handle, "OcclusionStrength"),
                                material.occlusionTexture.strength);
                    setupTextureUniform(shader.handle, "OcclusionMapSampler", 6, GL_TEXTURE_2D,
                                        material_infos.occlusionMapGLTexture);
                }

                if (material_infos.flags & materialFlags::HasEmissiveMap) {
                    glUniform3f(glGetUniformLocation(shader.handle, "EmissiveFactor"),
                                material.emissiveFactor[0], material.emissiveFactor[1],
                                material.emissiveFactor[2]);
                    setupTextureUniform(shader.handle, "EmissiveMapSampler", 7, GL_TEXTURE_2D,
                                        material_infos.emissiveMapGLTexture);
                }
            }

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

static inline float lerp(float a, float b, float t) {
    return a + t * (b - a);
}

// https://github.com/KhronosGroup/glTF-Tutorials/blob/main/gltfTutorial/gltfTutorial_007_Animations.md
static inline std::vector<double> slerpV(const std::vector<double> &quat1,
                                         const std::vector<double> &quat2, float t) {
    assert(quat1.size() == 4);
    assert(quat2.size() == 4);
    double q2_tmp[4] = {
        quat2[0],
        quat2[1],
        quat2[2],
        quat2[3],
    };
    std::vector<double> result(4);
    float dotq1q2 =
        quat1[0] * q2_tmp[0] + quat1[1] * q2_tmp[1] + quat1[2] * q2_tmp[2] + quat1[3] * q2_tmp[3];
    if (dotq1q2 < 0.0) {
        q2_tmp[0] *= -1.0;
        q2_tmp[1] *= -1.0;
        q2_tmp[2] *= -1.0;
        q2_tmp[3] *= -1.0;

        dotq1q2 *= -1.0;
    }
    if (dotq1q2 > 0.9995) {
        result[0] = lerp(quat1[0], q2_tmp[0], t);
        result[1] = lerp(quat1[1], q2_tmp[1], t);
        result[2] = lerp(quat1[2], q2_tmp[2], t);
        result[3] = lerp(quat1[3], q2_tmp[3], t);
        return result;
    }
    float theta_0 = std::acos(dotq1q2);
    float theta = t * theta_0;
    float sin_theta = std::sin(theta);
    float sin_theta_0 = std::sin(theta_0);

    float scalePreviousQuat = std::cos(theta) - dotq1q2 * sin_theta / sin_theta_0;
    float scaleNextQuat = sin_theta / sin_theta_0;

    result[0] = scalePreviousQuat * quat1[0] + scaleNextQuat * q2_tmp[0];
    result[1] = scalePreviousQuat * quat1[1] + scaleNextQuat * q2_tmp[1];
    result[2] = scalePreviousQuat * quat1[2] + scaleNextQuat * q2_tmp[2];
    result[3] = scalePreviousQuat * quat1[3] + scaleNextQuat * q2_tmp[3];
    return result;
}

static inline void slerp(std::optional<std::array<float, 4>> &out_quat, const float *quat1,
                         const float *quat2, float t) {
    float q2_tmp[4] = {
        quat2[0],
        quat2[1],
        quat2[2],
        quat2[3],
    };
    float dotq1q2 =
        quat1[0] * q2_tmp[0] + quat1[1] * q2_tmp[1] + quat1[2] * q2_tmp[2] + quat1[3] * q2_tmp[3];
    if (dotq1q2 < 0.0) {
        q2_tmp[0] *= -1.0;
        q2_tmp[1] *= -1.0;
        q2_tmp[2] *= -1.0;
        q2_tmp[3] *= -1.0;

        dotq1q2 *= -1.0;
    }
    if (dotq1q2 > 0.9995) {
        out_quat = {
            lerp(quat1[0], q2_tmp[0], t),
            lerp(quat1[1], q2_tmp[1], t),
            lerp(quat1[2], q2_tmp[2], t),
            lerp(quat1[3], q2_tmp[3], t),
        };
        return;
    }
    float theta_0 = std::acos(dotq1q2);
    float theta = t * theta_0;
    float sin_theta = std::sin(theta);
    float sin_theta_0 = std::sin(theta_0);

    float scalePreviousQuat = std::cos(theta) - dotq1q2 * sin_theta / sin_theta_0;
    float scaleNextQuat = sin_theta / sin_theta_0;

    out_quat = {
        scalePreviousQuat * quat1[0] + scaleNextQuat * q2_tmp[0],
        scalePreviousQuat * quat1[1] + scaleNextQuat * q2_tmp[1],
        scalePreviousQuat * quat1[2] + scaleNextQuat * q2_tmp[2],
        scalePreviousQuat * quat1[3] + scaleNextQuat * q2_tmp[3],
    };
    return;
}


static void interpolateProperty(TRS &trs, const float currentTime, const tinygltf::Model &model,
                                const tinygltf::Accessor &keyframeAccessor,
                                const tinygltf::Accessor &propertyAccessor,
                                const std::string &trsPath) {
    if (trsPath == "weights") {
        fprintf(hook_log, "Weights are not yet supported for animations\n");
        fflush(hook_log);
        return;
    }

    // get buffers
    const tinygltf::BufferView &keyframeBufferView = model.bufferViews[keyframeAccessor.bufferView];
    auto keyframeBuffer = reinterpret_cast<const float *>(
        model.buffers[keyframeBufferView.buffer].data.data() + keyframeAccessor.byteOffset +
        keyframeBufferView.byteOffset);
    unsigned int keyframeCount = keyframeAccessor.count;

    // GLTF Spec: https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#_animation_sampler_input
    assert(keyframeAccessor.type == TINYGLTF_TYPE_SCALAR);
    assert(keyframeAccessor.componentType == TINYGLTF_COMPONENT_TYPE_FLOAT);

    const tinygltf::BufferView &propertyBufferView = model.bufferViews[propertyAccessor.bufferView];
    auto propertyBuffer = reinterpret_cast<const float *>(
        model.buffers[propertyBufferView.buffer].data.data() + keyframeAccessor.byteOffset +
        propertyBufferView.byteOffset);

    // GLTF Spec: https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#_animation_sampler_interpolation
    assert(keyframeCount == propertyAccessor.count);
    // Compute current keyframe index
    ssize_t previousIndex = -1;
    ssize_t nextIndex = 0;

    for (size_t i = 0; i < keyframeCount; i++) {
        if (keyframeBuffer[i] > currentTime) {
            break;
        }
        previousIndex = i;
        nextIndex = i + 1;
    }
    float interpolationValue;
    float *previousQuat_ptr;
    float *nextQuat_ptr;
    if (previousIndex == -1) {// first keyframe
        if (trsPath == "translation") {
            trs.translation = {
                propertyBuffer[0],
                propertyBuffer[1],
                propertyBuffer[2],
            };
        } else if (trsPath == "rotation") {
            trs.rotation = {
                propertyBuffer[0],
                propertyBuffer[1],
                propertyBuffer[2],
                propertyBuffer[3],
            };
        } else if (trsPath == "scale") {
            trs.scale = {
                propertyBuffer[0],
                propertyBuffer[1],
                propertyBuffer[2],
            };
        } else if (trsPath == "weights") {
        }
    } else if (nextIndex == keyframeCount) {// last keyframe
        size_t elemIndex = (keyframeCount - 1) * getComponentCount(propertyAccessor.type);
        if (trsPath == "translation") {
            trs.translation = {
                propertyBuffer[elemIndex + 0],
                propertyBuffer[elemIndex + 1],
                propertyBuffer[elemIndex + 2],
            };
        } else if (trsPath == "rotation") {
            trs.rotation = {
                propertyBuffer[elemIndex + 0],
                propertyBuffer[elemIndex + 1],
                propertyBuffer[elemIndex + 2],
                propertyBuffer[elemIndex + 3],
            };
        } else if (trsPath == "scale") {
            trs.scale = {
                propertyBuffer[elemIndex + 0],
                propertyBuffer[elemIndex + 1],
                propertyBuffer[elemIndex + 2],
            };
        } else if (trsPath == "weights") {
        }
    } else {// In-between two keyframe
        // STEP: apply previousTime
        // interpolationValue = previousTime;
        // CUBICSPLINE: TODO
        // LINEAR:
        interpolationValue = (currentTime - keyframeBuffer[previousIndex]) /
                             (keyframeBuffer[nextIndex] - keyframeBuffer[previousIndex]);
        if (trsPath == "translation") {
            const float *previousTranslation_ptr =
                &propertyBuffer[previousIndex * getComponentCount(propertyAccessor.type)];
            const float *nextTranslation_ptr =
                &propertyBuffer[nextIndex * getComponentCount(propertyAccessor.type)];

            trs.translation = {
                lerp(previousTranslation_ptr[0], nextTranslation_ptr[0], interpolationValue),
                lerp(previousTranslation_ptr[1], nextTranslation_ptr[1], interpolationValue),
                lerp(previousTranslation_ptr[2], nextTranslation_ptr[2], interpolationValue),
            };
        } else if (trsPath == "rotation") {
            const float *previousQuat_ptr =
                &propertyBuffer[previousIndex * getComponentCount(propertyAccessor.type)];
            const float *nextQuat_ptr =
                &propertyBuffer[nextIndex * getComponentCount(propertyAccessor.type)];

            slerp(trs.rotation, previousQuat_ptr, nextQuat_ptr, interpolationValue);
        } else if (trsPath == "scale") {
            const float *previousScale_ptr =
                &propertyBuffer[previousIndex * getComponentCount(propertyAccessor.type)];
            const float *nextScale_ptr =
                &propertyBuffer[nextIndex * getComponentCount(propertyAccessor.type)];

            trs.scale = {
                lerp(previousScale_ptr[0], nextScale_ptr[0], interpolationValue),
                lerp(previousScale_ptr[1], nextScale_ptr[1], interpolationValue),
                lerp(previousScale_ptr[2], nextScale_ptr[2], interpolationValue),
            };
        } else if (trsPath == "weights") {
        }
    }
}

void renderer_drawGLTFAnimated(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                               const rdMatrix44 &model_matrix, gltfModel &model, EnvInfos envInfos,
                               bool mirrored, uint8_t type) {
    // Node - Animated TRS to blend with modelMatrix
    std::map<int, TRS> animatedTRS{};

    // for each animation
    for (size_t animIndex = 0; animIndex < model.gltf.animations.size(); animIndex++) {
        tinygltf::Animation anim = model.gltf.animations[animIndex];
        for (size_t channelIndex = 0; channelIndex < anim.channels.size(); channelIndex++) {
            tinygltf::AnimationChannel channel = anim.channels[channelIndex];
            int node = channel.target_node;
            // if target node is not defined, ignore
            if (!animatedTRS.contains(node)) {
                animatedTRS.emplace(node, TRS{});
            }
            tinygltf::AnimationSampler anim_sampler = anim.samplers[channel.sampler];
            tinygltf::Accessor keyframeAccessor = model.gltf.accessors[anim_sampler.input];
            tinygltf::Accessor propertyAccessor = model.gltf.accessors[anim_sampler.output];

            float currentTime = imgui_state.animationDriver;

            interpolateProperty(animatedTRS[node], currentTime, model.gltf, keyframeAccessor,
                                propertyAccessor, channel.target_path);
        }
    }

    rdMatrix44 animatedMat;
    trsToMatrix(&animatedMat, animatedTRS[0]);
    rdMatrix_Multiply44(&animatedMat, &animatedMat, &model_matrix);

    // hierarchy with animation values
    renderer_drawGLTF(proj_matrix, view_matrix, animatedMat, model, envInfos, mirrored, type);
}

void setupSkybox(skyboxShader &skybox) {
    std::string skyboxPath = "./assets/textures/skybox/";
    const char *faces_names[] = {
        "right.jpg", "left.jpg", "bottom.jpg", "top.jpg", "front.jpg", "back.jpg",
    };

    glGenTextures(1, &skybox.GLCubeTexture);
    glBindTexture(GL_TEXTURE_CUBE_MAP, skybox.GLCubeTexture);

    stbi_set_flip_vertically_on_load(true);
    int width;
    int height;
    int nbChannels;
    for (size_t i = 0; i < 6; i++) {
        const char *filepath = (skyboxPath + faces_names[i]).c_str();
        unsigned char *data = stbi_load(filepath, &width, &height, &nbChannels, STBI_rgb);
        if (data == NULL) {
            fprintf(hook_log, "Couldnt read skybox face %s\n", filepath);
            fflush(hook_log);

            return;
        }
        glTexImage2D(GL_TEXTURE_CUBE_MAP_POSITIVE_X + i, 0, GL_RGB, width, height, 0, GL_RGB,
                     GL_UNSIGNED_BYTE, data);
        stbi_image_free(data);
    }

    // glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_R, GL_CLAMP_TO_EDGE);
    glGenerateMipmap(GL_TEXTURE_CUBE_MAP);

    glGenTextures(1, &skybox.depthTexture);
    glBindTexture(GL_TEXTURE_2D, skybox.depthTexture);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH24_STENCIL8, width, height, 0, GL_DEPTH_STENCIL,
                 GL_UNSIGNED_INT_24_8, NULL);

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

void renderer_drawSkybox(skyboxShader &skybox, const rdMatrix44 &proj_matrix,
                         const rdMatrix44 &view_matrix) {
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

void renderer_lookAtForward(rdMatrix44 *view_mat, rdVector3 *position, rdVector3 *forward,
                            rdVector3 *up) {
    rdVector3 zAxis = *forward;
    rdVector3 xAxis;
    rdVector3 yAxis;
    rdVector_Normalize3Acc(&zAxis);
    rdVector_Cross3(&xAxis, up, &zAxis);
    rdVector_Normalize3Acc(&xAxis);
    rdVector_Cross3(&yAxis, &zAxis, &xAxis);
    rdVector_Normalize3Acc(&yAxis);

    *view_mat = {
        {xAxis.x, xAxis.y, xAxis.z, 0},
        {yAxis.x, yAxis.y, yAxis.z, 0},
        {zAxis.x, zAxis.y, zAxis.z, 0},
        {position->x, position->y, position->z, 1},
    };
}

void renderer_lookAtPosition(rdMatrix44 *view_mat, rdVector3 *position, rdVector3 *position2,
                             rdVector3 *up) {
    rdVector3 zAxis = rdVector3{
        position2->x - position->x,
        position2->y - position->y,
        position2->z - position->z,
    };
    rdVector3 xAxis;
    rdVector3 yAxis;
    rdVector_Normalize3Acc(&zAxis);
    rdVector_Cross3(&xAxis, up, &zAxis);
    rdVector_Normalize3Acc(&xAxis);
    rdVector_Cross3(&yAxis, &zAxis, &xAxis);
    rdVector_Normalize3Acc(&yAxis);

    *view_mat = {
        {xAxis.x, xAxis.y, xAxis.z, 0},
        {yAxis.x, yAxis.y, yAxis.z, 0},
        {zAxis.x, zAxis.y, zAxis.z, 0},
        {position->x, position->y, position->z, 1},
    };
}

void renderer_inverse4(rdMatrix44 *out, rdMatrix44 *in) {
    float m00 = in->vA.x;
    float m01 = in->vA.y;
    float m02 = in->vA.z;
    float m03 = in->vA.w;
    float m10 = in->vB.x;
    float m11 = in->vB.y;
    float m12 = in->vB.z;
    float m13 = in->vB.w;
    float m20 = in->vC.x;
    float m21 = in->vC.y;
    float m22 = in->vC.z;
    float m23 = in->vC.w;
    float m30 = in->vD.x;
    float m31 = in->vD.y;
    float m32 = in->vD.z;
    float m33 = in->vD.w;

    float tmp_0 = m22 * m33;
    float tmp_1 = m32 * m23;
    float tmp_2 = m12 * m33;
    float tmp_3 = m32 * m13;
    float tmp_4 = m12 * m23;
    float tmp_5 = m22 * m13;
    float tmp_6 = m02 * m33;
    float tmp_7 = m32 * m03;
    float tmp_8 = m02 * m23;
    float tmp_9 = m22 * m03;
    float tmp_10 = m02 * m13;
    float tmp_11 = m12 * m03;
    float tmp_12 = m20 * m31;
    float tmp_13 = m30 * m21;
    float tmp_14 = m10 * m31;
    float tmp_15 = m30 * m11;
    float tmp_16 = m10 * m21;
    float tmp_17 = m20 * m11;
    float tmp_18 = m00 * m31;
    float tmp_19 = m30 * m01;
    float tmp_20 = m00 * m21;
    float tmp_21 = m20 * m01;
    float tmp_22 = m00 * m11;
    float tmp_23 = m10 * m01;

    float t0 =
        (tmp_0 * m11 + tmp_3 * m21 + tmp_4 * m31) - (tmp_1 * m11 + tmp_2 * m21 + tmp_5 * m31);
    float t1 =
        (tmp_1 * m01 + tmp_6 * m21 + tmp_9 * m31) - (tmp_0 * m01 + tmp_7 * m21 + tmp_8 * m31);
    float t2 =
        (tmp_2 * m01 + tmp_7 * m11 + tmp_10 * m31) - (tmp_3 * m01 + tmp_6 * m11 + tmp_11 * m31);
    float t3 =
        (tmp_5 * m01 + tmp_8 * m11 + tmp_11 * m21) - (tmp_4 * m01 + tmp_9 * m11 + tmp_10 * m21);

    float d = 1.0 / (m00 * t0 + m10 * t1 + m20 * t2 + m30 * t3);

    out->vA.x = d * t0;
    out->vA.y = d * t1;
    out->vA.z = d * t2;
    out->vA.w = d * t3;
    out->vB.x =
        d * ((tmp_1 * m10 + tmp_2 * m20 + tmp_5 * m30) - (tmp_0 * m10 + tmp_3 * m20 + tmp_4 * m30));
    out->vB.y =
        d * ((tmp_0 * m00 + tmp_7 * m20 + tmp_8 * m30) - (tmp_1 * m00 + tmp_6 * m20 + tmp_9 * m30));
    out->vB.z = d * ((tmp_3 * m00 + tmp_6 * m10 + tmp_11 * m30) -
                     (tmp_2 * m00 + tmp_7 * m10 + tmp_10 * m30));
    out->vB.w = d * ((tmp_4 * m00 + tmp_9 * m10 + tmp_10 * m20) -
                     (tmp_5 * m00 + tmp_8 * m10 + tmp_11 * m20));
    out->vC.x = d * ((tmp_12 * m13 + tmp_15 * m23 + tmp_16 * m33) -
                     (tmp_13 * m13 + tmp_14 * m23 + tmp_17 * m33));
    out->vC.y = d * ((tmp_13 * m03 + tmp_18 * m23 + tmp_21 * m33) -
                     (tmp_12 * m03 + tmp_19 * m23 + tmp_20 * m33));
    out->vC.z = d * ((tmp_14 * m03 + tmp_19 * m13 + tmp_22 * m33) -
                     (tmp_15 * m03 + tmp_18 * m13 + tmp_23 * m33));
    out->vC.w = d * ((tmp_17 * m03 + tmp_20 * m13 + tmp_23 * m23) -
                     (tmp_16 * m03 + tmp_21 * m13 + tmp_22 * m23));
    out->vD.x = d * ((tmp_14 * m22 + tmp_17 * m32 + tmp_13 * m12) -
                     (tmp_16 * m32 + tmp_12 * m12 + tmp_15 * m22));
    out->vD.y = d * ((tmp_20 * m32 + tmp_12 * m02 + tmp_19 * m22) -
                     (tmp_18 * m22 + tmp_21 * m32 + tmp_13 * m02));
    out->vD.z = d * ((tmp_18 * m12 + tmp_23 * m32 + tmp_15 * m02) -
                     (tmp_22 * m32 + tmp_14 * m02 + tmp_19 * m12));
    out->vD.w = d * ((tmp_22 * m22 + tmp_16 * m02 + tmp_21 * m12) -
                     (tmp_20 * m12 + tmp_23 * m22 + tmp_17 * m02));
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

rdVector3 debugCameraPos = {2.0, 56.003, 4.026};
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
    if (cameraSpeed < 0.0)
        cameraSpeed = 0.0;
}

static void moveCamera(void) {
    float localCameraSpeed = cameraSpeed;
    if (leftCtrKeyPressed)
        localCameraSpeed *= 100;
    if (wKeyPressed)
        rdVector_Scale3Add3(&debugCameraPos, &debugCameraPos, localCameraSpeed, &cameraFront);
    if (aKeyPressed) {
        rdVector3 tmp;
        rdVector_Cross3(&tmp, &cameraFront, &cameraUp);
        rdVector_Normalize3Acc(&tmp);
        rdVector_Scale3Add3(&debugCameraPos, &debugCameraPos, -localCameraSpeed, &tmp);
    }
    if (sKeyPressed) {
        rdVector_Scale3Add3(&debugCameraPos, &debugCameraPos, -localCameraSpeed, &cameraFront);
    }
    if (dKeyPressed) {
        rdVector3 tmp;
        rdVector_Cross3(&tmp, &cameraFront, &cameraUp);
        rdVector_Normalize3Acc(&tmp);
        rdVector_Scale3Add3(&debugCameraPos, &debugCameraPos, localCameraSpeed, &tmp);
    }
    if (spaceKeyPressed) {
        rdVector_Scale3Add3(&debugCameraPos, &debugCameraPos, localCameraSpeed, &cameraUp);
    }
    if (leftShiftKeyPressed) {
        rdVector_Scale3Add3(&debugCameraPos, &debugCameraPos, -localCameraSpeed, &cameraUp);
    }
}

static bool environment_setuped = false;
static EnvInfos envInfos;

void draw_test_scene() {
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
    rdVector_Add3(&tmp, &debugCameraPos, &cameraFront);
    renderer_viewFromTransforms(&view_matrix, &debugCameraPos, cameraPitch * 3.141592 / 180,
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

    // Env textures

    if (!environment_setuped) {
        setupSkybox(envInfos.skybox);
        setupIBL(envInfos, envInfos.skybox.GLCubeTexture, -1);
        environment_setuped = true;
    }
    renderer_drawGLTF(proj_mat, view_matrix, model_matrix, g_models[5], envInfos, false, 0);

    model_matrix.vD.x += 5.0;
    model_matrix.vD.y += 5.0;
    // renderer_drawGLTF(proj_mat, view_matrix, model_matrix, g_models[6], envInfos, false, 0);

    renderer_drawGLTFAnimated(proj_mat, view_matrix, model_matrix, g_models[7], envInfos, false, 0);

    renderer_drawSkybox(envInfos.skybox, proj_mat, view_matrix);

    {// Debug only
        GLuint debug_framebuffer;
        glGenFramebuffers(1, &debug_framebuffer);
        size_t ibl_textureSize = 256;
        if (imgui_state.debug_lambertian_cubemap) {
            for (size_t i = 0; i < 6; i++) {
                glBindFramebuffer(GL_FRAMEBUFFER, debug_framebuffer);
                glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                                       GL_TEXTURE_CUBE_MAP_POSITIVE_X + i,
                                       envInfos.lambertianCubemapID, 0);
                size_t start = i * ibl_textureSize;
                size_t end = start + ibl_textureSize;

                glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
                glBindFramebuffer(GL_READ_FRAMEBUFFER, debug_framebuffer);
                glBlitFramebuffer(0, 0, ibl_textureSize, ibl_textureSize, start, 0, end,
                                  ibl_textureSize, GL_COLOR_BUFFER_BIT, GL_LINEAR);
            }
        }
        if (imgui_state.debug_ggx_cubemap) {
            {// debug draw ggx as skybox
                glDepthFunc(GL_LEQUAL);
                glUseProgram(envInfos.skybox.handle);
                glUniformMatrix4fv(envInfos.skybox.proj_matrix_pos, 1, GL_FALSE, &proj_mat.vA.x);
                glUniformMatrix4fv(envInfos.skybox.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);

                glBindVertexArray(envInfos.skybox.VAO);
                glActiveTexture(GL_TEXTURE0);
                glBindTexture(GL_TEXTURE_CUBE_MAP, envInfos.ggxCubemapID);
                glDrawArrays(GL_TRIANGLES, 0, 36);
                glBindVertexArray(0);

                // restore state
                glDepthFunc(GL_LESS);
            }

            for (size_t i = 0; i < 6; i++) {
                glBindFramebuffer(GL_FRAMEBUFFER, debug_framebuffer);
                glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                                       GL_TEXTURE_CUBE_MAP_POSITIVE_X + i, envInfos.ggxCubemapID,
                                       0);
                size_t start = i * ibl_textureSize;
                size_t end = start + ibl_textureSize;

                glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
                glBindFramebuffer(GL_READ_FRAMEBUFFER, debug_framebuffer);
                glBlitFramebuffer(0, 0, ibl_textureSize, ibl_textureSize, start, 0, end,
                                  ibl_textureSize, GL_COLOR_BUFFER_BIT, GL_LINEAR);
            }
        }
        if (imgui_state.debug_ggxLut) {
            size_t ibl_lutResolution = 1024;
            glBindFramebuffer(GL_FRAMEBUFFER, debug_framebuffer);
            glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                                   envInfos.ggxLutTextureID, 0);

            glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
            glBindFramebuffer(GL_READ_FRAMEBUFFER, debug_framebuffer);
            glBlitFramebuffer(0, 0, ibl_lutResolution, ibl_lutResolution, 0, 0, ibl_textureSize,
                              ibl_textureSize, GL_COLOR_BUFFER_BIT, GL_LINEAR);
        }

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
        glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
        glDeleteFramebuffers(1, &debug_framebuffer);
    }
}
