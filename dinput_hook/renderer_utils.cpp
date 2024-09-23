#include "renderer_utils.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include <string>
#include <windows.h>
#include <cmath>

#include "globals.h"
#include "types.h"
#include "imgui_utils.h"
#include "meshes.h"

#include "tinygltf/tiny_gltf.h"
#include "tinygltf/gltf_utils.h"

extern "C" {
#include <Platform/std3D.h>
#include <Primitives/rdMatrix.h>
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

std::optional<GLuint> compileProgram(GLsizei vertexCount, const GLchar **vertexShaderSource,
                                     GLsizei fragmentCount, const GLchar **fragmentShaderSource) {

    GLuint program = glCreateProgram();

    GLuint vertex_shader = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(vertex_shader, vertexCount, vertexShaderSource, nullptr);
    glCompileShader(vertex_shader);
    GLint status = 0;
    glGetShaderiv(vertex_shader, GL_COMPILE_STATUS, &status);
    if (status != GL_TRUE) {
        int length = 0;
        glGetShaderiv(vertex_shader, GL_INFO_LOG_LENGTH, &length);
        std::string error(length, '\0');
        glGetShaderInfoLog(vertex_shader, error.size(), nullptr, error.data());

        fprintf(hook_log, "%s\n", error.c_str());
        fflush(hook_log);

        return std::nullopt;
    }

    GLuint fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(fragment_shader, fragmentCount, fragmentShaderSource, nullptr);
    glCompileShader(fragment_shader);
    glGetShaderiv(fragment_shader, GL_COMPILE_STATUS, &status);
    if (status != GL_TRUE) {
        int length = 0;
        glGetShaderiv(fragment_shader, GL_INFO_LOG_LENGTH, &length);

        std::string error(length, '\0');
        glGetShaderInfoLog(fragment_shader, error.size(), nullptr, error.data());

        fprintf(hook_log, "%s\n", error.c_str());
        fflush(hook_log);

        return std::nullopt;
    }

    glAttachShader(program, vertex_shader);
    glAttachShader(program, fragment_shader);
    glLinkProgram(program);

    glGetProgramiv(program, GL_LINK_STATUS, &status);
    if (status != GL_TRUE)
        return std::nullopt;

    return program;
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

    if (!imgui_state.draw_renderList)
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

pbrShader get_or_compile_pbr(ImGuiState &state, const tinygltf::Material &material) {
    static bool shaderCompiled = false;
    static pbrShader shader;

    (void) state;

    if (!shaderCompiled) {
        const char *vertex_shader_source = R"(
#version 330 core

layout(location = 0) in vec3 position;
layout(location = 1) in vec3 normal;
// if texture
layout(location = 2) in vec2 texcoords;
// endif

uniform mat4 projMatrix;
uniform mat4 viewMatrix;
uniform mat4 modelMatrix;

uniform int model_id;

out vec2 passTexcoords;

void main() {
    // Yes, precomputing modelView is better and we should do it
    gl_Position = projMatrix * viewMatrix * modelMatrix * vec4(position, 1.0);
    passTexcoords = texcoords;
}
)";
        const char *fragment_shader_source = R"(
#version 330 core

in vec2 passTexcoords;

uniform vec4 pbrMetallicRoughness;
// useful with punctual light or IBL
uniform float metallicFactor;

uniform sampler2D baseColorTexture;

out vec4 outColor;

void main() {
    // outColor = vec4(1.0, 0.0, 1.0, 0.0);
    // outColor = pbrMetallicRoughness;
    // outColor = vec4(passTexcoords, 0.0, 1.0);
    outColor = texture(baseColorTexture, passTexcoords);
}
)";

        std::optional<GLuint> program_opt =
            compileProgram(1, &vertex_shader_source, 1, &fragment_shader_source);
        if (!program_opt.has_value())
            std::abort();
        GLuint program = program_opt.value();

        GLuint VAO;
        glGenVertexArrays(1, &VAO);
        GLuint VBOs[3];
        glGenBuffers(3, VBOs);

        GLuint EBO;
        glGenBuffers(1, &EBO);

        unsigned int glTexture;
        glGenTextures(1, &glTexture);

        shader = {
            .handle = program,
            .VAO = VAO,
            .PositionBO = VBOs[0],
            .NormalBO = VBOs[1],
            .TexCoordsBO = VBOs[2],
            .EBO = EBO,
            .glTexture = glTexture,
            .proj_matrix_pos = glGetUniformLocation(program, "projMatrix"),
            .view_matrix_pos = glGetUniformLocation(program, "viewMatrix"),
            .model_matrix_pos = glGetUniformLocation(program, "modelMatrix"),
            .pbrMetallicRoughness_pos = glGetUniformLocation(program, "pbrMetallicRoughness"),
            .metallicFactor_pos = glGetUniformLocation(program, "metallicFactor"),
            .model_id_pos = glGetUniformLocation(program, "model_id"),
        };

        shaderCompiled = true;
    }

    return shader;
}

void renderer_drawGLTF(const rdMatrix44 &proj_matrix, const rdMatrix44 &view_matrix,
                       const rdMatrix44 &model_matrix, tinygltf::Model &model) {
    // TODO: material pbrMetallicRoughness baseColorFactor vec4 metallicFactor float
    const auto shader = get_or_compile_pbr(imgui_state, model.materials[0]);
    glUseProgram(shader.handle);

    glUniformMatrix4fv(shader.proj_matrix_pos, 1, GL_FALSE, &proj_matrix.vA.x);
    glUniformMatrix4fv(shader.view_matrix_pos, 1, GL_FALSE, &view_matrix.vA.x);
    rdMatrix44 model_matrix2;
    memcpy(&model_matrix2, &model_matrix, sizeof(model_matrix2));
    rdMatrix_ScaleBasis44(&model_matrix2, 100, 100, 100, &model_matrix2);

    glUniformMatrix4fv(shader.model_matrix_pos, 1, GL_FALSE, &model_matrix2.vA.x);
    glUniform1i(shader.model_id_pos, gltf_model_id);

    // Metallic uniforms
    // if have base color
    auto roughness = model.materials[0].pbrMetallicRoughness;
    glUniform4f(shader.pbrMetallicRoughness_pos, roughness.baseColorFactor[0],
                roughness.baseColorFactor[1], roughness.baseColorFactor[2],
                roughness.baseColorFactor[3]);
    // else "index": 0 for texture
    // endif
    glUniform1f(shader.metallicFactor_pos, roughness.metallicFactor);

    if (model.meshes.size() > 1) {
        fprintf(hook_log, "Multiples meshes per object not yet supported in renderer\n");
        fflush(hook_log);
        std::abort();
    }
    if (model.meshes[0].primitives.size() > 1) {
        fprintf(hook_log, "Multiples primitives per mesh not yet supported in renderer\n");
        fflush(hook_log);
        std::abort();
    }
    if (model.meshes[0].primitives[0].indices == -1) {
        fprintf(hook_log, "Un-indexed topology not yet supported in renderer\n");
        fflush(hook_log);
        std::abort();
    }
    int indicesAccessorId = model.meshes[0].primitives[0].indices;

    GLint drawMode = model.meshes[0].primitives[0].mode;
    if (drawMode == -1) {
        fprintf(hook_log, "Unsupported draw mode %d in renderer\n", drawMode);
        fflush(hook_log);
        std::abort();
    }
    int materialIndex = model.meshes[0].primitives[0].material;
    if (materialIndex == -1) {
        fprintf(hook_log, "Material-less model not yet supported in renderer\n");
        fflush(hook_log);
        std::abort();
    }

    int positionAccessorId = -1;
    int normalAccessorId = -1;
    int texcoordAccessorId = -1;
    for (const auto &[key, value]: model.meshes[0].primitives[0].attributes) {
        if (key == "POSITION")
            positionAccessorId = value;
        if (key == "NORMAL")
            normalAccessorId = value;
        if (key == "TEXCOORD_0")
            texcoordAccessorId = value;
    }
    if (positionAccessorId == -1) {
        fprintf(hook_log, "Unsupported mesh without position attribute in renderer\n");
        fflush(hook_log);
        std::abort();
    }
    if (normalAccessorId == -1) {
        fprintf(hook_log, "Unsupported mesh without position attribute in renderer\n");
        fflush(hook_log);
        std::abort();
    }

    // Accessors

    if (model.accessors[indicesAccessorId].type != TINYGLTF_TYPE_SCALAR) {
        fprintf(hook_log, "Error: indices accessor does not have type scalar in renderer\n");
        fflush(hook_log);
        std::abort();
    }
    const tinygltf::Accessor &indicesAccessor = model.accessors[indicesAccessorId];

    if (indicesAccessor.componentType != GL_UNSIGNED_SHORT)// 0x1403
    {
        fprintf(hook_log, "Unsupported type for indices buffer in renderer\n");
        fflush(hook_log);
        std::abort();
    }

    // BufferView
    const tinygltf::BufferView &indicesBufferView = model.bufferViews[indicesAccessor.bufferView];

    auto indexBuffer = reinterpret_cast<const unsigned short *>(
        model.buffers[indicesBufferView.buffer].data.data() + indicesAccessor.byteOffset +
        indicesBufferView.byteOffset);


    // Draw call
    glBindVertexArray(shader.VAO);

    glEnableVertexAttribArray(0);// pos
    glEnableVertexAttribArray(1);// normal
    glEnableVertexAttribArray(2);// texcoords

    // Position is mandatory attribute
    const tinygltf::Accessor &positionAccessor = model.accessors[positionAccessorId];
    const tinygltf::BufferView &positionBufferView = model.bufferViews[positionAccessor.bufferView];
    auto positionBuffer = reinterpret_cast<const float *>(
        model.buffers[positionBufferView.buffer].data.data() + positionAccessor.byteOffset +
        positionBufferView.byteOffset);
    glBindBuffer(positionBufferView.target, shader.PositionBO);
    glBufferData(positionBufferView.target,
                 positionAccessor.count * getComponentCount(positionAccessor.type) *
                     getComponentByteSize(positionAccessor.componentType),
                 positionBuffer, GL_STATIC_DRAW);

    glVertexAttribPointer(0, getComponentCount(positionAccessor.type),
                          positionAccessor.componentType, GL_FALSE, positionBufferView.byteStride,
                          0);

    // Has Normals
    if (normalAccessorId != -1) {
        const tinygltf::Accessor &normalAccessor = model.accessors[normalAccessorId];
        const tinygltf::BufferView &normalBufferView =
            model.bufferViews[positionAccessor.bufferView];
        auto normalBuffer = reinterpret_cast<const float *>(
            model.buffers[normalBufferView.buffer].data.data() + normalAccessor.byteOffset +
            normalBufferView.byteOffset);
        glBindBuffer(normalBufferView.target, shader.NormalBO);
        glBufferData(normalBufferView.target,
                     normalAccessor.count * getComponentCount(normalAccessor.type) *
                         getComponentByteSize(normalAccessor.componentType),
                     normalBuffer, GL_STATIC_DRAW);

        glVertexAttribPointer(1, getComponentCount(normalAccessor.type),
                              normalAccessor.componentType, GL_FALSE, normalBufferView.byteStride,
                              0);
    }

    // Has TexCoords
    if (texcoordAccessorId != -1) {
        const tinygltf::Accessor &texcoordAccessor = model.accessors[texcoordAccessorId];
        const tinygltf::BufferView &texcoordBufferView =
            model.bufferViews[texcoordAccessor.bufferView];

        auto texcoordBuffer = reinterpret_cast<const float *>(
            model.buffers[texcoordBufferView.buffer].data.data() + texcoordAccessor.byteOffset +
            texcoordBufferView.byteOffset);
        glBindBuffer(texcoordBufferView.target, shader.TexCoordsBO);
        glBufferData(texcoordBufferView.target,
                     texcoordAccessor.count * getComponentCount(texcoordAccessor.type) *
                         getComponentByteSize(texcoordAccessor.componentType),
                     texcoordBuffer, GL_STATIC_DRAW);
        glVertexAttribPointer(
            2, getComponentCount(positionAccessor.type), texcoordAccessor.componentType, GL_FALSE,
            texcoordBufferView.byteStride,
            reinterpret_cast<void *>(texcoordAccessor.byteOffset / texcoordBufferView.byteStride));

        // Setup texture
        auto image = model.images[0];
        auto texels = image.image.data();

        glBindTexture(GL_TEXTURE_2D, shader.glTexture);
        GLint internalFormat = GL_RGBA;
        glTexImage2D(GL_TEXTURE_2D, 0, internalFormat, image.width, image.height, 0, internalFormat,
                     image.pixel_type, image.image.data());
        glGenerateMipmap(GL_TEXTURE_2D);
        // activate texture TEXTURE0 + texslot
        // uniform1i loc texslot
        auto texture =
            model.textures[model.materials[0].pbrMetallicRoughness.baseColorTexture.index];
        auto sampler = model.samplers[texture.sampler];

        // Sampler parameters. TODO: Should use glSamplerParameter here
        // if not exist, use defaults wrapS wrapT, auto filtering
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, sampler.wrapS);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, sampler.wrapT);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, sampler.minFilter);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, sampler.magFilter);
    }

    glBindBuffer(indicesBufferView.target, shader.EBO);
    glBufferData(indicesBufferView.target, indicesBufferView.byteLength, indexBuffer,
                 GL_STATIC_DRAW);

    glDrawElements(drawMode, indicesAccessor.count, indicesAccessor.componentType, 0);

    glDisableVertexAttribArray(0);
    glDisableVertexAttribArray(1);
    glDisableVertexAttribArray(2);
    glBindVertexArray(0);
}
