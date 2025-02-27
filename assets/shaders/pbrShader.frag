// Taken from https://github.com/KhronosGroup/glTF-Sample-Renderer

in vec3 worldPosition;
in vec3 vReflect;
#ifdef HAS_NORMALS
in vec3 passNormal;
#endif // HAS_NORMALS
#ifdef HAS_TEXCOORDS
in vec2 passTexcoords;
#endif // HAS_TEXCOORDS
#ifdef HAS_VERTEXCOLOR // only vec3 for the moment
in vec3 passVertexColor;
#endif // HAS_VERTEXCOLOR

uniform vec4 baseColorFactor;
uniform float metallicFactor;
uniform float roughnessFactor;
uniform vec3 cameraWorldPosition;

#ifdef HAS_TEXCOORDS
layout(binding = 0) uniform sampler2D baseColorTexture;
layout(binding = 1) uniform sampler2D metallicRoughnessTexture;
#endif // HAS_TEXCOORDS

// Environnment
// #ifdef USE_IBL
layout(binding = 2) uniform samplerCube lambertianEnvSampler;
layout(binding = 3) uniform samplerCube GGXEnvSampler;
layout(binding = 4) uniform sampler2D GGXLUT;
// #endif

#ifdef HAS_NORMAL_MAP
layout(binding = 5) uniform sampler2D NormalMapSampler;
#endif // HAS_NORMAL_MAP
#ifdef HAS_OCCLUSION_MAP
layout(binding = 6) uniform sampler2D OcclusionMapSampler;
#endif // HAS_OCCLUSION_MAP
#ifdef HAS_EMISSIVE_MAP
layout(binding = 7) uniform sampler2D EmissiveMapSampler;
#endif // HAS_EMISSIVE_MAP

uniform float OcclusionStrength;
uniform vec3 EmissiveFactor;
uniform int GGXEnvSampler_mipCount;

// Spot light
struct Light
{
    vec3 color;
    float intensity;

    vec3 position;
};
const Light light = Light(vec3(1.0, 1.0, 0.0), 0.2, vec3(0, 0.30, 0.40));

out vec4 outColor;

// Utils
float clampedDot(vec3 x, vec3 y)
{
    return clamp(dot(x, y), 0.0, 1.0);
}

const float GAMMA = 2.2;
const float INV_GAMMA = 1.0 / GAMMA;

vec3 linearTosRGB(vec3 color)
{
    return pow(color, vec3(INV_GAMMA));
}

vec3 toneMap(vec3 color)
{
    return linearTosRGB(color);
}

struct NormalInfo
{
    vec3 normal;
    vec3 tangent;
    vec3 bitangent;
};

NormalInfo getNormalInfo()
{
#ifdef HAS_TEXCOORDS
    // TODO: second set of UVs for normal map
    vec2 uv = passTexcoords;
#else
    vec2 uv = vec2(0.0, 0.0);
#endif // HAS_TEXCOORDS

    vec2 uv_dx = dFdx(uv);
    vec2 uv_dy = dFdy(uv);

    if (length(uv_dx) <= 1e-2)
    {
        uv_dx = vec2(1.0, 0.0);
    }

    if (length(uv_dy) <= 1e-2)
    {
        uv_dy = vec2(0.0, 1.0);
    }

    vec3 t_ = (uv_dy.t * dFdx(worldPosition) - uv_dx.t * dFdy(worldPosition)) / (uv_dx.s * uv_dy.t - uv_dy.s * uv_dx.t);

    vec3 normal = normalize(passNormal);
    vec3 tangent = normalize(t_ - normal * dot(normal, t_));
    vec3 bitangent = cross(normal, tangent);

#ifdef HAS_NORMAL_MAP

    vec3 texNormal = texture(NormalMapSampler, uv).rgb * 2.0 - vec3(1.0, 1.0, 1.0);

    normal = normalize(mat3(tangent, bitangent, normal) * texNormal);
#endif // HAS_NORMAL_MAP

    NormalInfo normalInfo;
    normalInfo.normal = normal;
    normalInfo.tangent = tangent;
    normalInfo.bitangent = bitangent;

    return normalInfo;
}

// IBL Functions

const mat3 EnvRotation = mat3(
    vec3(1.0, 0.0, 0.0),
    vec3(0.0, 1.0, 0.0),
    vec3(0.0, 0.0, 1.0)
);
const float envIntensity = 1.0;
vec3 getDiffuseLight(vec3 n)
{
    vec4 textureSample = texture(lambertianEnvSampler, EnvRotation * n);
    textureSample.rgb *= envIntensity;
    return textureSample.rgb;
}

vec4 getSpecularSample(vec3 reflection, float lod)
{
    vec4 textureSample = textureLod(GGXEnvSampler, EnvRotation * reflection, lod);
    textureSample.rgb *= envIntensity;
    return textureSample;
}

vec3 getIBLRadianceGGX(vec3 n, vec3 v, float roughness)
{
    float lod = roughness * float(GGXEnvSampler_mipCount - 1);

    vec3 reflection = normalize(vReflect);
    // vec3 reflection = normalize(reflect(-v, n));
    vec4 specularSample = getSpecularSample(reflection, lod);

    vec3 specularLight = specularSample.rgb;

    return specularLight;
}

vec3 getIBLGGXFresnel(vec3 n, vec3 v, float roughness, vec3 F0, float specularWeight)
{
    // see https://bruop.github.io/ibl/#single_scattering_results at Single Scattering Results
    // Roughness dependent fresnel, from Fdez-Aguera
    float NdotV = clampedDot(n, v);
    vec2 brdfSamplePoint = clamp(vec2(NdotV, roughness), vec2(0.0, 0.0), vec2(1.0, 1.0));
    vec2 f_ab = texture(GGXLUT, brdfSamplePoint).rg;
    vec3 Fr = max(vec3(1.0 - roughness), F0) - F0;
    vec3 k_S = F0 + Fr * pow(1.0 - NdotV, 5.0);
    vec3 FssEss = specularWeight * (k_S * f_ab.x + f_ab.y);

    // Multiple scattering, from Fdez-Aguera
    float Ems = (1.0 - (f_ab.x + f_ab.y));
    vec3 F_avg = specularWeight * (F0 + (1.0 - F0) / 21.0);
    vec3 FmsEms = Ems * FssEss * F_avg / (1.0 - F_avg * Ems);

    return FssEss + FmsEms;
}

// Light BRDF

vec3 getLightIntensity(Light light, vec3 pointToLight)
{
    float rangeAttenuation = 1.0 / pow(length(pointToLight), 2.0); // unlimited
    float spotAttenuation = 1.0;

    return rangeAttenuation * spotAttenuation * light.intensity * light.color;
}

vec3 F_Schlick(vec3 f0, vec3 f90, float VdotH)
{
    return f0 + (f90 - f0) * pow(clamp(1.0 - VdotH, 0.0, 1.0), 5.0);
}

const float M_PI = 3.141592653589793;

vec3 BRDF_lambertian(vec3 diffuseColor)
{
    return (diffuseColor / M_PI);
}

// Smith Joint GGX
// Note: Vis = G / (4 * NdotL * NdotV)
// see Eric Heitz. 2014. Understanding the Masking-Shadowing Function in Microfacet-Based BRDFs. Journal of Computer Graphics Techniques, 3
// see Real-Time Rendering. Page 331 to 336.
// see https://google.github.io/filament/Filament.md.html#materialsystem/specularbrdf/geometricshadowing(specularg)

float V_GGX(float NdotL, float NdotV, float alphaRoughness)
{
    float alphaRoughnessSq = alphaRoughness * alphaRoughness;

    float GGXV = NdotL * sqrt(NdotV * NdotV * (1.0 - alphaRoughnessSq) + alphaRoughnessSq);
    float GGXL = NdotV * sqrt(NdotL * NdotL * (1.0 - alphaRoughnessSq) + alphaRoughnessSq);

    float GGX = GGXV + GGXL;
    if (GGX > 0.0)
    {
        return 0.5 / GGX;
    }
    return 0.0;
}

// The following equation(s) model the distribution of microfacet normals across the area being drawn (aka D())
// Implementation from "Average Irregularity Representation of a Roughened Surface for Ray Reflection" by T. S. Trowbridge, and K. P. Reitz
// Follows the distribution function recommended in the SIGGRAPH 2013 course notes from EPIC Games [1], Equation 3.

float D_GGX(float NdotH, float alphaRoughness)
{
    float alphaRoughnessSq = alphaRoughness * alphaRoughness;
    float f = (NdotH * NdotH) * (alphaRoughnessSq - 1.0) + 1.0;
    return alphaRoughnessSq / (M_PI * f * f);
}

vec3 BRDF_specularGGX(float alphaRoughness, float NdotL, float NdotV, float NdotH)
{
    float Vis = V_GGX(NdotL, NdotV, alphaRoughness);
    float D = D_GGX(NdotH, alphaRoughness);

    return vec3(Vis * D);
}

struct PhysicalMaterial {
    vec3 diffuseColor;
    float roughness;
    vec3 specularColor;
    float specularF90;
};

void main()
{
    vec4 baseColor;

#ifdef HAS_TEXCOORDS
    vec4 texColor = texture(baseColorTexture, passTexcoords);
    baseColor = baseColorFactor * texColor;
#else
    baseColor = baseColorFactor;
#endif // HAS_TEXCOORDS
#ifdef HAS_VERTEXCOLOR
    baseColor *= vec4(passVertexColor, 1.0);
#endif // HAS_VERTEXCOLOR

    vec3 outgoingLight;

#ifndef MATERIAL_UNLIT
#ifdef HAS_TEXCOORDS
    vec4 metallicRoughnessTexel = texture(metallicRoughnessTexture, passTexcoords);
    float metallic = metallicFactor * metallicRoughnessTexel.b;
    float perceptualRoughness = roughnessFactor * metallicRoughnessTexel.g;
#else
    float metallic = metallicFactor;
    float perceptualRoughness = roughnessFactor;
#endif // HAS_TEXCOORDS
    float alphaRoughness = perceptualRoughness * perceptualRoughness;

    NormalInfo normalInfo = getNormalInfo();

    vec3 v = normalize(cameraWorldPosition - worldPosition);
    vec3 n = normalInfo.normal;

    vec3 f0_dielectric = vec3(0.04);
    float specularWeight = 1.0;
    vec3 f90_dielectric = vec3(1.0);

    // #ifdef USE_IBL
    vec3 f_diffuse = getDiffuseLight(n) * baseColor.rgb;
    vec3 f_specular_metal = getIBLRadianceGGX(n, v, perceptualRoughness);
    vec3 f_specular_dieletric = f_specular_metal;

    vec3 f_metal_fresnel_ibl = getIBLGGXFresnel(n, v, perceptualRoughness, baseColor.rgb, 1.0);
    vec3 f_metal_brdf_ibl = f_metal_fresnel_ibl * f_specular_metal;

    vec3 f_dieletric_fresnel_ibl = getIBLGGXFresnel(n, v, perceptualRoughness, f0_dielectric, specularWeight);
    vec3 f_dieletric_brdf_ibl = mix(f_diffuse, f_specular_dieletric, f_dieletric_fresnel_ibl);

    outgoingLight = mix(f_dieletric_brdf_ibl, f_metal_brdf_ibl, metallic);
#ifdef HAS_OCCLUSION_MAP
    float ao = 1.0;
    ao = texture(OcclusionMapSampler, passTexcoords).r;
    outgoingLight = outgoingLight * (1.0 + OcclusionStrength * (ao - 1.0));
#endif // HAS_OCCLUSION_MAP
    // #endif // USE_IBL

    // #ifdef USE_PUNCTUAL
    // FOR EACH LIGHT
    vec3 pointToLight = light.position - worldPosition;
    vec3 l = normalize(pointToLight);
    vec3 h = normalize(l + v);
    float NdotL = clampedDot(n, l);
    float NdotV = clampedDot(n, v);
    float NdotH = clampedDot(n, h);
    float LdotH = clampedDot(l, h);
    float VdotH = clampedDot(v, h);

    vec3 dielectric_fresnel = F_Schlick(f0_dielectric * specularWeight, f90_dielectric, abs(VdotH));
    vec3 metal_fresnel = F_Schlick(baseColor.rgb, vec3(1.0), abs(VdotH));

    vec3 lightIntensity = getLightIntensity(light, pointToLight);
    vec3 l_diffuse = lightIntensity * NdotL * BRDF_lambertian(baseColor.rgb);
    vec3 l_specular_metal = lightIntensity * NdotL * BRDF_specularGGX(alphaRoughness, NdotL, NdotV, NdotH);
    vec3 l_specular_dielectric = l_specular_metal;
    vec3 l_metal_brdf = metal_fresnel * l_specular_metal;
    vec3 l_dielectric_brdf = mix(l_diffuse, l_specular_dielectric, dielectric_fresnel);
    vec3 l_color = mix(l_dielectric_brdf, l_metal_brdf, metallic);
    outgoingLight += l_color;
    // END FOR EACH
    // #endif // USE_PUNCTUAL

#ifdef HAS_EMISSIVE_MAP
    vec3 f_emissive = EmissiveFactor;
    f_emissive *= texture(EmissiveMapSampler, passTexcoords).rgb;
    outgoingLight = outgoingLight + f_emissive;
#endif // HAS_EMISSIVE_MAP

#else // MATERIAL_UNLIT
    outgoingLight = baseColor.rgb;
#endif // MATERIAL_UNLIT
    // outColor = vec4(1.0, 0.0, 1.0, 0.0);
    outColor = vec4(toneMap(outgoingLight), baseColor.a);
}
