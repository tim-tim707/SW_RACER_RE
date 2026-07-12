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
uniform uint modelId;
uniform ivec2 mousePosition;

// N64 render mode alpha_compare field: 0 = AC_NONE, 1 = AC_THRESHOLD, 3 = AC_DITHER.
uniform int alphaCompareMode;
// Non-zero when the material drives coverage from texture alpha (N64 cvg_x_alpha / alpha_cvg_sel):
// a hard cutout (fences, foliage, grates) the RDP resolved as an antialiased edge.
uniform int alphaIsCoverage;
// Alpha test cutoff for cutout materials. ~0.5 gives a crisp binary edge that ignores the fringe
// magnification/mipmapping introduce; the CPU drops it to ~0 when alpha-to-coverage is active.
uniform float alphaCutoff;
// Non-zero when MSAA alpha-to-coverage is antialiasing this cutout's edge, so the shader keeps the
// real alpha (coverage source) instead of forcing surviving pixels opaque.
uniform int alphaToCoverage;

vec3 HSV_to_RGB(float h, float s, float v) {
    h = fract(h) * 6.0;
    int i = int(h);
    float f = h - float(i);
    float p = v * (1.0 - s);
    float q = v * (1.0 - s * f);
    float t = v * (1.0 - s * (1.0 - f));

    switch(i) {
        case 0: return vec3(v, t, p);
        case 1: return vec3(q, v, p);
        case 2: return vec3(p, v, t);
        case 3: return vec3(p, q, v);
        case 4: return vec3(t, p, v);

        default:
        break;
    }
    return vec3(v, p, q);
}

vec3 identifying_color(uint index) {
    float f = index * 0.618033988749895;
    return HSV_to_RGB(f - 1.0 * floor(f), 0.5, 1.0);
}

out vec4 color;
void main() {
    if (ivec2(gl_FragCoord.xy) == mousePosition) {
        color = unpackUnorm4x8(modelId);
        return;
    }

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

    // Cutout materials: those that enable alpha_compare, and the coverage-from-alpha materials
    // (cvg_x_alpha / alpha_cvg_sel) the N64 RDP resolved as an antialiased hard cutout. Opaque
    // materials (neither flag) are never tested, so near-zero-alpha texels on them don't punch
    // holes (issue #193, e.g. Sebulba). A ~0.5 cutoff yields a crisp binary edge that ignores the
    // interpolated alpha fringe magnification and mipmapping introduce (the fringe used to survive
    // the old ~0 test, write depth, and occlude meshes behind it).
    bool isCutout = (alphaCompareMode != 0 || alphaIsCoverage != 0);
    if (isCutout && color.a < alphaCutoff)
        discard;
    // A cutout is binary on the N64, not a blend. Force surviving pixels fully opaque so that if the
    // material also has a blend mode enabled, the edge doesn't blend translucently against the
    // framebuffer -- that partial blend was the faint "x-ray" rim around opaque features (e.g.
    // Anakin's goggles) that leaked the background through. When alpha-to-coverage is active we keep
    // the real alpha instead, so multisample coverage antialiases the edge.
    if (isCutout && alphaToCoverage == 0)
        color.a = 1.0;
}
