#pragma once

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <optional>
#include <string>

std::optional<GLuint> compileProgram(GLsizei vertexCount, const GLchar **vertexShaderSource,
                                     GLsizei fragmentCount, const GLchar **fragmentShaderSource);

std::string readFileAsString(const char *filepath);
