#include "renderer_utils.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include <string>
#include <windows.h>
#include <cmath>

#include "globals.h"
#include "types.h"

extern "C" {
#include <Platform/std3D.h>
}

extern "C" FILE *hook_log;

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

GLuint compileProgram(GLsizei vertexCount, const GLchar **vertexShaderSource, GLsizei fragmentCount,
                      const GLchar **fragmentShaderSource) {

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

        std::abort();
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

        std::abort();
    }

    glAttachShader(program, vertex_shader);
    glAttachShader(program, fragment_shader);
    glLinkProgram(program);

    glGetProgramiv(program, GL_LINK_STATUS, &status);
    if (status != GL_TRUE)
        std::abort();

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
        GLuint program = compileProgram(1, &vertex_shader_source, 1, &fragment_shader_source);

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
        GLuint program = compileProgram(1, &vertex_shader_source, 1, &fragment_shader_source);

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
        GLuint program = glCreateProgram();
        GLuint vertex_shader = glCreateShader(GL_VERTEX_SHADER);
        glShaderSource(vertex_shader, 1, &vertex_shader_source, nullptr);
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

            std::abort();
        }

        GLuint fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);
        glShaderSource(fragment_shader, 1, &fragment_shader_source, nullptr);
        glCompileShader(fragment_shader);
        glGetShaderiv(fragment_shader, GL_COMPILE_STATUS, &status);
        if (status != GL_TRUE) {
            int length = 0;
            glGetShaderiv(fragment_shader, GL_INFO_LOG_LENGTH, &length);
            std::string error(length, '\0');
            glGetShaderInfoLog(fragment_shader, error.size(), nullptr, error.data());

            fprintf(hook_log, "%s\n", error.c_str());
            fflush(hook_log);

            std::abort();
        }

        glAttachShader(program, vertex_shader);
        glAttachShader(program, fragment_shader);
        glLinkProgram(program);

        glGetProgramiv(program, GL_LINK_STATUS, &status);
        if (status != GL_TRUE)
            std::abort();

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
