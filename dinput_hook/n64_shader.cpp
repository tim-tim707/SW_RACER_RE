//
// Created by tly on 25.03.2024.
//

#include "n64_shader.h"
#include <format>
#include <glad/glad.h>
#include <map>

const static std::map<uint8_t, const char *> cc_mode_strings{
    {G_CCMUX_COMBINED, "COMBINED.rgb"},
    {G_CCMUX_TEXEL0, "TEXEL0.rgb"},
    {G_CCMUX_TEXEL1, "TEXEL1.rgb"},
    {G_CCMUX_PRIMITIVE, "PRIMITIVE.rgb"},
    {G_CCMUX_SHADE, "SHADE.rgb"},
    {G_CCMUX_ENVIRONMENT, "ENVIRONMENT.rgb"},
    {G_CCMUX_CENTER, "CENTER.rgb"},
    {G_CCMUX_SCALE, "SCALE.rgb"},
    {G_CCMUX_COMBINED_ALPHA, "COMBINED.aaa"},
    {G_CCMUX_TEXEL0_ALPHA, "TEXEL0.aaa"},
    {G_CCMUX_TEXEL1_ALPHA, "TEXEL1.aaa"},
    {G_CCMUX_PRIMITIVE_ALPHA, "PRIMITIVE.aaa"},
    {G_CCMUX_SHADE_ALPHA, "SHADE.aaa"},
    {G_CCMUX_ENV_ALPHA, "ENV.aaa"},
    {G_CCMUX_LOD_FRACTION, "vec3(LOD_FRACTION)"},
    {G_CCMUX_PRIM_LOD_FRAC, "vec3(PRIM_LOD_FRAC)"},
    {G_CCMUX_NOISE, "vec3(NOISE)"},
    {G_CCMUX_K4, "vec3(K4)"},
    {G_CCMUX_K5, "vec3(K5)"},
    {G_CCMUX_1, "vec3(1)"},
    {G_CCMUX_0, "vec3(0)"},
};

const std::map<uint8_t, const char *> ac_mode_strings{
    {G_ACMUX_COMBINED, "COMBINED.a"},
    {G_ACMUX_TEXEL0, "TEXEL0.a"},
    {G_ACMUX_TEXEL1, "TEXEL1.a"},
    {G_ACMUX_PRIMITIVE, "PRIMITIVE.a"},
    {G_ACMUX_SHADE, "SHADE.a"},
    {G_ACMUX_ENVIRONMENT, "ENVIRONMENT.a"},
    {G_ACMUX_LOD_FRACTION, "LOD_FRACTION"},
    {G_ACMUX_PRIM_LOD_FRAC, "PRIM_LOD_FRAC"},
    {G_ACMUX_1, "1"},
    {G_ACMUX_0, "0"},
};

void set_render_mode(uint32_t mode) {
    const auto &rm = (const RenderMode &) mode;
    if (rm.z_compare)
        glEnable(GL_DEPTH_TEST);
    else
        glDisable(GL_DEPTH_TEST);

    glDepthMask(rm.z_update);

    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
}


std::string CombineMode::to_string() const {
    const auto &s = is_alpha ? ac_mode_strings : cc_mode_strings;
    return std::format("({}-{})*{}+{}", s.at(a), s.at(b), s.at(c), s.at(d));
}

ColorCombineShader
get_or_compile_color_combine_shader(const std::array<CombineMode, 4> &combiners) {
    static std::map<std::array<CombineMode, 4>, ColorCombineShader> shader_map;
    if (shader_map.contains(combiners))
        return shader_map.at(combiners);

    const std::string defines = std::format("#define COLOR_CYCLE_1 {}\n"
                                            "#define ALPHA_CYCLE_1 {}\n"
                                            "#define COLOR_CYCLE_2 {}\n"
                                            "#define ALPHA_CYCLE_2 {}\n",
                                            combiners[0].to_string(), combiners[1].to_string(),
                                            combiners[2].to_string(), combiners[3].to_string());

    const char *vertex_shader_source = R"(
#version 330 core
layout(location = 0) in vec3 position;
layout(location = 1) in vec4 color;
layout(location = 2) in vec2 uv;

out vec4 passColor;
out vec2 passUV;

uniform float nearPlane;
uniform mat4 mvpMatrix;
uniform vec2 uvOffset;
uniform vec2 uvScale;

void main() {
    gl_Position = mvpMatrix *  vec4(position, 1);
    passColor = color;
    passUV = uv / (uvScale * 4096.0) + uvOffset;
}
)";

    const char *fragment_shader_source = R"(
in vec4 passColor;
in vec2 passUV;

uniform sampler2D diffuseTex;
uniform vec4 primitiveColor;

out vec4 color;
void main() {
    vec4 TEXEL0 = texture(diffuseTex, passUV);
    vec4 TEXEL1 = texture(diffuseTex, passUV);
    vec4 PRIMITIVE = primitiveColor;
    vec4 SHADE = passColor;
    vec4 ENVIRONMENT = vec4(1);
    vec4 CENTER = vec4(1);
    vec4 SCALE = vec4(1);
    float LOD_FRACTION = 1;
    float PRIM_LOD_FRAC = 1;
    float NOISE = 1;
    float K4 = 1;
    float K5 = 1;

    vec4 COMBINED = vec4(0);
    COMBINED = vec4(COLOR_CYCLE_1, ALPHA_CYCLE_1);
    color = vec4(COLOR_CYCLE_2, ALPHA_CYCLE_2);
}
)";

    GLuint program = glCreateProgram();

    GLuint vertex_shader = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(vertex_shader, 1, &vertex_shader_source, nullptr);
    glCompileShader(vertex_shader);
    GLint status = 0;
    glGetShaderiv(vertex_shader, GL_COMPILE_STATUS, &status);
    if (status != GL_TRUE)
        std::abort();

    GLuint fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);
    const char *fragment_sources[]{"#version 330 core\n", defines.c_str(), fragment_shader_source};
    glShaderSource(fragment_shader, std::size(fragment_sources), std::data(fragment_sources),
                   nullptr);
    glCompileShader(fragment_shader);
    glGetShaderiv(fragment_shader, GL_COMPILE_STATUS, &status);
    if (status != GL_TRUE) {
        int length = 0;
        glGetShaderiv(fragment_shader, GL_INFO_LOG_LENGTH, &length);

        std::string error(length, '\0');
        glGetShaderInfoLog(fragment_shader, error.size(), nullptr, error.data());

        std::abort();
    }


    glAttachShader(program, vertex_shader);
    glAttachShader(program, fragment_shader);
    glLinkProgram(program);

    glGetProgramiv(program, GL_LINK_STATUS, &status);
    if (status != GL_TRUE)
        std::abort();

    ColorCombineShader shader{
        .handle = program,
        .mvp_pos = glGetUniformLocation(program, "mvpMatrix"),
        .uv_offset_pos = glGetUniformLocation(program, "uvOffset"),
        .uv_scale_pos = glGetUniformLocation(program, "uvScale"),
        .primitive_color_pos = glGetUniformLocation(program, "primitiveColor"),
    };

    shader_map.emplace(combiners, shader);
    return shader;
}