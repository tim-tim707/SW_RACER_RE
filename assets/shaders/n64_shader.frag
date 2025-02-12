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
uniform int model_id;

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

    if (color.a < 0.01)
        discard;
}
