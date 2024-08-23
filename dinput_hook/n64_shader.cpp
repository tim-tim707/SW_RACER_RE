//
// Created by tly on 25.03.2024.
//

#include "n64_shader.h"
#include <format>
#include <glad/glad.h>
#include <map>

#include "renderer_utils.h"

extern FILE *hook_log;

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

std::string dump_blend_mode(const RenderMode &mode, bool mode2) {
    const auto p = mode2 ? mode.mode2_p_mux : mode.mode1_p_mux;
    const auto m = mode2 ? mode.mode2_m_mux : mode.mode1_m_mux;
    const auto a = mode2 ? mode.mode2_a_mux : mode.mode1_a_mux;
    const auto b = mode2 ? mode.mode2_b_mux : mode.mode1_b_mux;

    const std::string pm_mux_strings[]{
        "CLR_IN",
        "CLR_MEM",
        "CLR_BL",
        "CLR_FOG",
    };
    const std::string a_mux_strings[]{
        "A_IN",
        "A_FOG",
        "A_SHADE",
        "0",
    };
    const std::string b_mux_strings[]{
        "(1 - AMUX)",
        "A_MEM",
        "1",
        "0",
    };
    return std::format("{}*{} + {}*{}", pm_mux_strings[p], a_mux_strings[a], pm_mux_strings[m],
                       b == ONE_MINUS_AMUX ? std::format("(1 - {})", a_mux_strings[a])
                                           : b_mux_strings[b]);
}

void set_render_mode(uint32_t mode) {
    const auto &rm = (const RenderMode &) mode;
    if (rm.z_compare) {
        glEnable(GL_DEPTH_TEST);
    } else {
        glDisable(GL_DEPTH_TEST);
    }

    if (rm.alpha_compare) {
        renderer_setAlphaMask(true);
    } else {
        renderer_setAlphaMask(false);
    }

    glDepthMask(rm.z_update);

    const auto p = rm.mode2_p_mux;
    const auto a = rm.mode2_a_mux;
    const auto m = rm.mode2_m_mux;
    const auto b = rm.mode2_b_mux;

    if (p == CLR_IN && a == A_IN && m == CLR_MEM && b == ONE_MINUS_AMUX) {
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    } else if (p == CLR_IN && a == A_IN && m == CLR_MEM && b == A_MEM) {
        // this seems like a blend mode but is actually a mode for antialiasing using coverage values.
        if (rm.z_mode != ZMODE_OPA)
            std::abort();

        glDisable(GL_BLEND);
    } else if (p == CLR_IN && a == ZEROA && m == CLR_IN && b == ONE) {
        glDisable(GL_BLEND);
    } else {
        std::abort();
    }
}


std::string CombineMode::to_string() const {
    const auto &s = is_alpha ? ac_mode_strings : cc_mode_strings;
    return std::format("({}-{})*{}+{}", s.at(a), s.at(b), s.at(c), s.at(d));
}

ColorCombineShader
get_or_compile_color_combine_shader(ImGuiState &state,
                                    const std::array<CombineMode, 4> &combiners) {
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
layout(location = 3) in vec3 normal;

out vec4 passColor;
out vec2 passUV;
out vec3 passNormal;
out float passZ;

uniform float nearPlane;
uniform mat4 projMatrix;
uniform mat4 viewMatrix;
uniform mat4 modelMatrix;
uniform vec2 uvOffset;
uniform vec2 uvScale;

void main() {
    vec4 posView = viewMatrix * modelMatrix * vec4(position, 1);
    gl_Position = projMatrix * posView;
    passColor = color;
    passUV = uv / (uvScale * 4096.0) + uvOffset;
    passNormal = normalize(transpose(inverse(mat3(modelMatrix))) * normal);
    passZ = -posView.z;
}
)";

    const char *fragment_shader_source = R"(
in vec4 passColor;
in vec2 passUV;
in vec3 passNormal;
in float passZ;

uniform sampler2D diffuseTex;
uniform vec4 primitiveColor;

uniform bool enableGouraudShading;
uniform vec3 ambientColor;
uniform vec3 lightColor;
uniform vec3 lightDir;

uniform bool fogEnabled;
uniform float fogStart;
uniform float fogEnd;
uniform vec4 fogColor;

out vec4 color;
void main() {
    vec4 TEXEL0 = texture(diffuseTex, passUV);
    vec4 TEXEL1 = texture(diffuseTex, passUV);
    vec4 PRIMITIVE = primitiveColor;
    vec4 SHADE = passColor;
    if (enableGouraudShading)
        SHADE.xyz = lightColor * max(dot(lightDir / 128.0, passNormal), 0.0) + ambientColor;

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
    if (fogEnabled)
        color.xyz = mix(color.xyz, fogColor.xyz, clamp((passZ - fogStart) / (fogEnd - fogStart), 0, 1));
}
)";

    const char *fragment_sources[]{"#version 330 core\n", defines.c_str(), fragment_shader_source};
    GLuint program = compileProgram(1, &vertex_shader_source, std::size(fragment_sources),
                                    std::data(fragment_sources));

    GLuint VAO;
    glGenVertexArrays(1, &VAO);
    GLuint VBO;
    glGenBuffers(1, &VBO);

    ColorCombineShader shader{
        .handle = program,
        .VAO = VAO,
        .VBO = VBO,
        .proj_matrix_pos = glGetUniformLocation(program, "projMatrix"),
        .view_matrix_pos = glGetUniformLocation(program, "viewMatrix"),
        .model_matrix_pos = glGetUniformLocation(program, "modelMatrix"),
        .uv_offset_pos = glGetUniformLocation(program, "uvOffset"),
        .uv_scale_pos = glGetUniformLocation(program, "uvScale"),
        .primitive_color_pos = glGetUniformLocation(program, "primitiveColor"),
        .enable_gouraud_shading_pos = glGetUniformLocation(program, "enableGouraudShading"),
        .ambient_color_pos = glGetUniformLocation(program, "ambientColor"),
        .light_color_pos = glGetUniformLocation(program, "lightColor"),
        .light_dir_pos = glGetUniformLocation(program, "lightDir"),
        .fog_enabled_pos = glGetUniformLocation(program, "fogEnabled"),
        .fog_start_pos = glGetUniformLocation(program, "fogStart"),
        .fog_end_pos = glGetUniformLocation(program, "fogEnd"),
        .fog_color_pos = glGetUniformLocation(program, "fogColor"),
    };

    shader_map.emplace(combiners, shader);
    return shader;
}
