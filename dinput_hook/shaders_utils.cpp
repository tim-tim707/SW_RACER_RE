#include "shaders_utils.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <optional>
#include <string>
#include <fstream>
#include <sstream>

extern "C" FILE *hook_log;

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

        fprintf(hook_log, "vertex shader: %s\n", error.c_str());
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

        fprintf(hook_log, "fragment shader: %s\n", error.c_str());
        fflush(hook_log);

        return std::nullopt;
    }

    glAttachShader(program, vertex_shader);
    glAttachShader(program, fragment_shader);
    glLinkProgram(program);

    glGetProgramiv(program, GL_LINK_STATUS, &status);
    if (status != GL_TRUE) {
        int length = 0;
        glGetProgramiv(program, GL_INFO_LOG_LENGTH, &length);

        std::string error(length, '\0');
        glGetProgramInfoLog(program, error.size(), nullptr, error.data());

        fprintf(hook_log, "shader linking: %s\n", error.c_str());
        fflush(hook_log);
        return std::nullopt;
    }

    return program;
}

std::string readFileAsString(const char *filepath) {
    std::ifstream stream(filepath);
    if (!stream.is_open()) {
        fprintf(hook_log, "Cannot open %s. Does the file exist ?\n", filepath);
        fflush(hook_log);
        std::abort;
    }
    std::stringstream buffer;
    buffer << stream.rdbuf();

    return buffer.str();
}
