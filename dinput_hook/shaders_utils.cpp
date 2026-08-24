#include "shaders_utils.h"

#include "embedded_shaders.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <optional>
#include <string>
#include <fstream>
#include <sstream>
#include <cstring>

#include <windows.h>

extern "C" FILE *hook_log;

// How much of the driver's compiler log to put in the modal. Enough to show the offending line and
// message; the rest stays in hook.log.
static constexpr size_t kMaxReportedShaderLogChars = 600;

// Shader failures are driver-specific, and every caller treats them as fatal -- but they were also
// invisible. The process died before a window existed, so the user saw the game fail to start with
// no dialog and no hint that hook.log held the reason; one report cost a tester days of blaming
// wrapper and driver settings. Put the driver's own message in front of them. Once only: the first
// failure is the actionable one, and hook.log has the rest.
static void reportShaderFailureOnce(const char *stage, const char *compiler_log) {
    static bool reported = false;
    if (reported)
        return;
    reported = true;

    std::string excerpt(compiler_log ? compiler_log : "(no message from the driver)");
    if (excerpt.size() > kMaxReportedShaderLogChars) {
        excerpt.resize(kMaxReportedShaderLogChars);
        excerpt += "\n[...]";
    }

    const std::string message =
        "An OpenGL " + std::string(stage) + " failed to compile on this graphics driver.\n\n" +
        excerpt +
        "\n\nThe full message was written to hook.log next to the game executable. Please include "
        "that file when reporting this.";
    MessageBoxA(nullptr, message.c_str(), "Star Wars Episode I Racer - shader error",
                MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND);
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

        fprintf(hook_log, "vertex shader: %s\n", error.c_str());
        fflush(hook_log);

        reportShaderFailureOnce("vertex shader", error.c_str());
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

        reportShaderFailureOnce("fragment shader", error.c_str());
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
        reportShaderFailureOnce("shader program", error.c_str());
        return std::nullopt;
    }

    return program;
}

std::string readFileAsString(const char *filepath) {
    std::ifstream stream(filepath);
    if (!stream.is_open()) {
        // The assets/ directory may be absent (issue #236). Every caller loads a
        // shader from assets/shaders/, so fall back to the copy embedded in the
        // executable at build time, keyed by file name.
        const char *name = filepath;
        if (const char *slash = std::strrchr(filepath, '/')) {
            name = slash + 1;
        }
        if (const char *embedded = embedded_shaders::find(name)) {
            fprintf(hook_log, "Using embedded shader for %s (not found on disk).\n", name);
            fflush(hook_log);
            return embedded;
        }
        fprintf(hook_log, "Cannot open %s. Does the file exist ?\n", filepath);
        fflush(hook_log);
        // Returning empty rather than aborting hands the problem to compileProgram, which reports
        // it to the user and lets callers that have a fallback keep going. The line above is what
        // actually names the missing file.
        return "";
    }
    std::stringstream buffer;
    buffer << stream.rdbuf();

    return buffer.str();
}
