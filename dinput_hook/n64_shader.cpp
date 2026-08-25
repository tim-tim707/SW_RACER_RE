//
// Created by tly on 25.03.2024.
//

#include "n64_shader.h"
#include <format>
#include <glad/glad.h>
#include <map>
#include <optional>

#include "renderer_utils.h"
#include "shaders_utils.h"

extern "C" {
#include <Primitives/rdMatrix.h>
#include <globals.h> // swrWeather_enabled (translucent-terrain depth-write while weather is on)
#include "./game_deltas/std3D_delta.h"
}

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
    const uint32_t p = mode2 ? mode.mode2_p_mux : mode.mode1_p_mux;
    const uint32_t m = mode2 ? mode.mode2_m_mux : mode.mode1_m_mux;
    const uint32_t a = mode2 ? mode.mode2_a_mux : mode.mode1_a_mux;
    const uint32_t b = mode2 ? mode.mode2_b_mux : mode.mode1_b_mux;

    std::string additional_flags = "";
    if (mode.z_compare)
        additional_flags += "z_compare";

    if (mode.z_update) {
        if (!additional_flags.empty())
            additional_flags += ",";

        additional_flags += "z_update";
    }

    if (mode.alpha_compare) {
        if (!additional_flags.empty())
            additional_flags += ",";

        additional_flags += "alpha_compare";
    }

    if (!additional_flags.empty())
        additional_flags = " " + additional_flags;

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
                                           : b_mux_strings[b]) +
           additional_flags;
}

bool g_cutout_alpha_to_coverage = false;

void set_render_mode(uint32_t mode) {
    const RenderMode &rm = (const RenderMode &) mode;
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

    const uint32_t p = rm.mode2_p_mux;
    const uint32_t a = rm.mode2_a_mux;
    const uint32_t m = rm.mode2_m_mux;
    const uint32_t b = rm.mode2_b_mux;
    const bool alpha_blend = (p == CLR_IN && a == A_IN && m == CLR_MEM && b == ONE_MINUS_AMUX);

    bool blend_enabled = false;

    // Faithfully, alpha-blended world surfaces don't write depth (rm.z_update == 0). While weather is
    // active that lets rain/snow particles show through translucent TRACK terrain (frozen lakes,
    // swamps), because the depth buffer then holds the opaque geometry behind the surface. Force only
    // those depth-tested translucent surfaces -- scoped by g_weather_terrain_depth to the static track
    // subtree -- to write depth, so the particle depth-occlusion (and rain-splash impact test) sees the
    // real surface. Excludes translucent entity FX (pod energy binders, engine glow), which must keep
    // blending without writing depth. Non-weather tracks are untouched -> byte-identical to faithful.
    glDepthMask(rm.z_update ||
                (swrWeather_enabled && g_weather_terrain_depth && rm.z_compare && alpha_blend));

    if (alpha_blend) {
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        blend_enabled = true;
    } else if (p == CLR_IN && a == A_IN && m == CLR_MEM && b == A_MEM) {
        // this seems like a blend mode but is actually a mode for antialiasing using coverage values.
        if (rm.z_mode != ZMODE_OPA)
            std::abort();

        glDisable(GL_BLEND);
        blend_enabled = false;
    } else if (p == CLR_IN && a == ZEROA && m == CLR_IN && b == ONE) {
        glDisable(GL_BLEND);
        blend_enabled = false;
    } else {
        std::abort();
    }

    // Alpha-to-coverage for cutout materials (alpha drives coverage, or an explicit alpha_compare)
    // that are not alpha-blended: let MSAA turn the texture alpha into multisample coverage, which
    // antialiases the cutout edge the way the N64's coverage x alpha did while keeping correct depth
    // (unlike alpha blending). Only meaningful when rendering to a multisample target; the draw path
    // reads g_cutout_alpha_to_coverage to drop the shader's hard cutoff in this case.
    // Cutout = explicit alpha test or coverage-from-alpha. alpha_cvg_sel is excluded on purpose: it
    // rides on ordinary opaque AA geometry and is not a cutout signal (matches the draw path).
    const bool is_cutout = rm.cvg_x_alpha || rm.alpha_compare;
    g_cutout_alpha_to_coverage = is_cutout && !blend_enabled && imgui_state.msaa_samples > 1;
    if (g_cutout_alpha_to_coverage) {
        glEnable(GL_SAMPLE_ALPHA_TO_COVERAGE);
    } else {
        glDisable(GL_SAMPLE_ALPHA_TO_COVERAGE);
    }
}


// Last-resort shader pair, used when the generated combiner shader will not compile. Kept
// deliberately plain -- GLSL 3.30, no integer math, no combiner defines, no picking -- and built
// into the DLL rather than read from assets/shaders, so it survives both the driver quirks that
// reject the generated shader and a missing or stale shader file. Rendering is visibly wrong (no
// color combiner, no lighting, no fog), but the game boots and stays playable, which is what lets
// a user reach the options and the log instead of staring at a process that vanished.
static const char *const kFallbackVertexShader = R"(#version 330 core
layout(location = 0) in vec3 position;
layout(location = 1) in vec4 color;
layout(location = 2) in vec2 uv;

uniform mat4 projMatrix;
uniform mat4 viewMatrix;
uniform mat4 modelMatrix;
uniform vec2 uvOffset;
uniform vec2 uvScale;

out vec4 passColor;
out vec2 passUV;

void main() {
    gl_Position = projMatrix * viewMatrix * modelMatrix * vec4(position, 1);
    passColor = color;
    passUV = uv / (uvScale * 4096.0) + uvOffset;
}
)";

static const char *const kFallbackFragmentShader = R"(#version 330 core
in vec4 passColor;
in vec2 passUV;

uniform sampler2D diffuseTex;

out vec4 color;

void main() {
    color = texture(diffuseTex, passUV) * passColor;
}
)";

// Compiled at most once and shared by every combiner that fails to build.
static std::optional<GLuint> get_fallback_program() {
    static std::optional<GLuint> fallback;
    static bool attempted = false;
    if (!attempted) {
        attempted = true;
        const char *vertex_shader_source = kFallbackVertexShader;
        const char *fragment_shader_source = kFallbackFragmentShader;
        fallback = compileProgram(1, &vertex_shader_source, 1, &fragment_shader_source);
    }
    return fallback;
}

// Uniforms the fallback shader doesn't declare resolve to -1, and glUniform* on -1 is a documented
// no-op, so the draw path needs no special case for it.
static ColorCombineShader make_color_combine_shader(GLuint program) {
    return ColorCombineShader{
        .handle = program,
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
        .num_lights_pos = glGetUniformLocation(program, "numLights"),
        .light_color2_pos = glGetUniformLocation(program, "lightColor2"),
        .light_dir2_pos = glGetUniformLocation(program, "lightDir2"),
        .fog_enabled_pos = glGetUniformLocation(program, "fogEnabled"),
        .fog_start_pos = glGetUniformLocation(program, "fogStart"),
        .fog_end_pos = glGetUniformLocation(program, "fogEnd"),
        .fog_color_pos = glGetUniformLocation(program, "fogColor"),
        .model_id_pos = glGetUniformLocation(program, "modelId"),
        .mouse_position_pos = glGetUniformLocation(program, "mousePosition"),
        .alpha_compare_mode_pos = glGetUniformLocation(program, "alphaCompareMode"),
        .alpha_is_coverage_pos = glGetUniformLocation(program, "alphaIsCoverage"),
        .alpha_cutoff_pos = glGetUniformLocation(program, "alphaCutoff"),
        .alpha_to_coverage_pos = glGetUniformLocation(program, "alphaToCoverage"),
    };
}

std::string CombineMode::to_string() const {
    const std::map<uint8_t, const char *> &s = is_alpha ? ac_mode_strings : cc_mode_strings;
    return std::format("({}-{})*{}+{}", s.at(a), s.at(b), s.at(c), s.at(d));
}

uint32_t CombineMode::to_big_endian_u32() const {
    return (a << 24) | (b << 16) | (c << 8) | (d << 0);
}

ColorCombineShader &
get_or_compile_color_combine_shader(ImGuiState &state,
                                    const std::array<CombineMode, 4> &combiners) {
    static std::map<std::array<CombineMode, 4>, ColorCombineShader> shader_map;
    if (auto it = shader_map.find(combiners); it != shader_map.end())
        return it->second;

    const std::string defines = std::format("#define COLOR_CYCLE_1 {}\n"
                                            "#define ALPHA_CYCLE_1 {}\n"
                                            "#define COLOR_CYCLE_2 {}\n"
                                            "#define ALPHA_CYCLE_2 {}\n",
                                            combiners[0].to_string(), combiners[1].to_string(),
                                            combiners[2].to_string(), combiners[3].to_string());

    fprintf(hook_log, "Generating n64 shader with defines:\n%s", defines.c_str());
    fflush(hook_log);

    std::string vertex_shader_source_s = readFileAsString("./assets/shaders/n64_shader.vert");
    std::string fragment_shader_source_s = readFileAsString("./assets/shaders/n64_shader.frag");
    const char *vertex_shader_source = vertex_shader_source_s.c_str();
    const char *fragment_shader_source = fragment_shader_source_s.c_str();

    const char *fragment_sources[]{"#version 450 core\n", defines.c_str(), fragment_shader_source};

    std::optional<GLuint> program_opt = compileProgram(
        1, &vertex_shader_source, std::size(fragment_sources), std::data(fragment_sources));
    if (!program_opt.has_value()) {
        // compileProgram has already logged the driver's message and shown it to the user. Carry on
        // with the built-in shader instead of killing the process: a wrong-looking game the user can
        // navigate beats one that never opens a window.
        fprintf(hook_log, "Combiner shader failed to compile, falling back to the built-in plain "
                          "shader. Rendering will be incorrect.\n");
        fflush(hook_log);

        program_opt = get_fallback_program();
        if (!program_opt.has_value()) {
            // Plain GLSL 3.30 won't compile either, so the context is unusable and there is nothing
            // left to try. The user has seen the error by now.
            fprintf(hook_log, "The built-in fallback shader failed to compile too, aborting.\n");
            fflush(hook_log);
            std::abort();
        }
    }

    return shader_map
        .insert_or_assign(combiners, make_color_combine_shader(program_opt.value()))
        .first->second;
}
