//
// Created by tly on 25.03.2024.
//

#pragma once
#include <array>
#include <cstdint>
#include <glad/glad.h>
#include <string>


enum AlphaCompare {
    AC_NONE = 0,
    AC_THRESHOLD = 1,
    AC_DITHER = 3,
};

enum ZSelect {
    ZS_PIXEL = 0,
    ZS_PRIM = 1,
};

enum CoverageMode {
    CVG_DST_CLAMP = 0,
    CVG_DST_WRAP = 1,
    CVG_DST_FULL = 2,
    CVG_DST_SAVE = 3,
};

enum ZMode {
    ZMODE_OPA = 0,
    ZMODE_INTER = 1,
    ZMODE_XLU = 2,
    ZMODE_DEC = 3,
};

enum BlendPMMux {
    CLR_IN = 0,
    CLR_MEM = 1,
    CLR_BL = 2,
    CLR_FOG = 3,
};

enum BlendAMux {
    A_IN = 0,
    A_FOG = 1,
    A_SHADE = 2,
    ZEROA = 3,
};

enum BlendBMux {
    ONE_MINUS_AMUX = 0,
    A_MEM = 1,
    ONE = 2,
    ZEROB = 3,
};

#pragma pack(push, 1)
struct RenderMode {
    // https://wiki.cloudmodding.com/oot/F3DZEX2#Cycle-Independent_Blender_Settings
    uint32_t alpha_compare : 2;
    uint32_t z_source_select : 1;
    uint32_t aa_enable : 1;
    uint32_t z_compare : 1;
    uint32_t z_update : 1;
    uint32_t im_rd : 1;
    uint32_t clr_on_cvg : 1;
    uint32_t cvg_mode : 2;
    uint32_t z_mode : 2;
    uint32_t cvg_x_alpha : 1;
    uint32_t alpha_cvg_sel : 1;
    uint32_t force_bl : 1;
    uint32_t unusued : 1;
    // https://wiki.cloudmodding.com/oot/F3DZEX2#Cycle-Dependent_Blender_Settings
    uint32_t mode2_b_mux : 2;
    uint32_t mode1_b_mux : 2;
    uint32_t mode2_m_mux : 2;
    uint32_t mode1_m_mux : 2;
    uint32_t mode2_a_mux : 2;
    uint32_t mode1_a_mux : 2;
    uint32_t mode2_p_mux : 2;
    uint32_t mode1_p_mux : 2;
};
static_assert(sizeof(RenderMode) == sizeof(uint32_t));
#pragma pack(pop)

#define G_CCMUX_COMBINED 0
#define G_CCMUX_TEXEL0 1
#define G_CCMUX_TEXEL1 2
#define G_CCMUX_PRIMITIVE 3
#define G_CCMUX_SHADE 4
#define G_CCMUX_ENVIRONMENT 5
#define G_CCMUX_CENTER 6
#define G_CCMUX_SCALE 6
#define G_CCMUX_COMBINED_ALPHA 7
#define G_CCMUX_TEXEL0_ALPHA 8
#define G_CCMUX_TEXEL1_ALPHA 9
#define G_CCMUX_PRIMITIVE_ALPHA 10
#define G_CCMUX_SHADE_ALPHA 11
#define G_CCMUX_ENV_ALPHA 12
#define G_CCMUX_LOD_FRACTION 13
#define G_CCMUX_PRIM_LOD_FRAC 14
#define G_CCMUX_NOISE 7
#define G_CCMUX_K4 7
#define G_CCMUX_K5 15
#define G_CCMUX_1 6
#define G_CCMUX_0 31

/* Alpha combiner constants: */
#define G_ACMUX_COMBINED 0
#define G_ACMUX_TEXEL0 1
#define G_ACMUX_TEXEL1 2
#define G_ACMUX_PRIMITIVE 3
#define G_ACMUX_SHADE 4
#define G_ACMUX_ENVIRONMENT 5
#define G_ACMUX_LOD_FRACTION 0
#define G_ACMUX_PRIM_LOD_FRAC 6
#define G_ACMUX_1 6
#define G_ACMUX_0 7

void set_render_mode(uint32_t mode);

struct CombineMode {
    CombineMode(uint32_t m, bool is_alpha)
        : a((m >> 24) & 0xFF), b((m >> 16) & 0xFF), c((m >> 8) & 0xFF), d((m >> 0) & 0xFF),
          is_alpha(is_alpha){};

    uint8_t a, b, c, d;
    bool is_alpha;

    std::string to_string() const;
    constexpr auto operator<=>(const CombineMode &) const = default;
};

struct ColorCombineShader {
    GLuint handle;
    GLuint VAO;
    GLuint VBO;
    GLint proj_matrix_pos;
    GLint view_matrix_pos;
    GLint model_matrix_pos;
    GLint uv_offset_pos;
    GLint uv_scale_pos;
    GLint primitive_color_pos;
    GLint enable_gouraud_shading_pos;
    GLint ambient_color_pos;
    GLint light_color_pos;
    GLint light_dir_pos;
    GLint fog_enabled_pos;
    GLint fog_start_pos;
    GLint fog_end_pos;
    GLint fog_color_pos;
};

std::string dump_blend_mode(const RenderMode &mode, bool mode2);

ColorCombineShader get_or_compile_color_combine_shader(const std::array<CombineMode, 4> &combiners);
