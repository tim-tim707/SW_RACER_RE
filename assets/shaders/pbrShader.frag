// Taken from https://github.com/KhronosGroup/glTF-Sample-Renderer

in vec3 worldPosition;
#ifdef HAS_NORMALS
in vec3 passNormal;
#endif
#ifdef HAS_TEXCOORDS
in vec2 passTexcoords;
#endif

uniform vec4 baseColorFactor;
// useful with punctual light or IBL
uniform float metallicFactor;
uniform float roughnessFactor;
uniform vec3 cameraWorldPosition;

#ifdef HAS_TEXCOORDS
layout(binding = 0) uniform sampler2D baseColorTexture;
layout(binding = 1) uniform sampler2D metallicRoughnessTexture;
// Environnment
layout(binding = 2) uniform samplerCube lambertianEnvSampler;
layout(binding = 3) uniform samplerCube GGXEnvSampler;
layout(binding = 4) uniform sampler2D GGXLUT;
#endif

// Spot light
struct Light
{
    vec3 color;
    float intensity;

    vec3 position;
};
const Light light = Light(vec3(1), 100.0, vec3(0, 0.03, 0.40));

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
// IBL Functions

// lambertianEnvSampler
// GGXEnvSampler
// const envRotation
// u_envIntensity
// u_mipCount
// GGXLUT
vec3 getDiffuseLight(vec3 n)
{
    // vec4 textureSample = texture(u_LambertianEnvSampler, u_EnvRotation * n);
    // textureSample.rgb *= u_EnvIntensity;
    // return textureSample.rgb;
    return vec3(0);
}

vec4 getSpecularSample(vec3 reflection, float lod)
{
    // vec4 textureSample = textureLod(u_GGXEnvSampler, u_EnvRotation * reflection, lod);
    // textureSample.rgb *= u_EnvIntensity;
    // return textureSample;
    return vec4(0);
}

vec3 getIBLRadianceGGX(vec3 n, vec3 v, float roughness)
{
    // float NdotV = clampedDot(n, v);
    // float lod = roughness * float(u_MipCount - 1);
    // vec3 reflection = normalize(reflect(-v, n));
    // vec4 specularSample = getSpecularSample(reflection, lod);

    // vec3 specularLight = specularSample.rgb;

    // return specularLight;
    return vec3(0);
}

vec3 getIBLGGXFresnel(vec3 n, vec3 v, float roughness, vec3 F0, float specularWeight)
{
    // see https://bruop.github.io/ibl/#single_scattering_results at Single Scattering Results
    // Roughness dependent fresnel, from Fdez-Aguera
    // float NdotV = clampedDot(n, v);
    // vec2 brdfSamplePoint = clamp(vec2(NdotV, roughness), vec2(0.0, 0.0), vec2(1.0, 1.0));
    // vec2 f_ab = texture(u_GGXLUT, brdfSamplePoint).rg;
    // vec3 Fr = max(vec3(1.0 - roughness), F0) - F0;
    // vec3 k_S = F0 + Fr * pow(1.0 - NdotV, 5.0);
    // vec3 FssEss = specularWeight * (k_S * f_ab.x + f_ab.y);

    // // Multiple scattering, from Fdez-Aguera
    // float Ems = (1.0 - (f_ab.x + f_ab.y));
    // vec3 F_avg = specularWeight * (F0 + (1.0 - F0) / 21.0);
    // vec3 FmsEms = Ems * FssEss * F_avg / (1.0 - F_avg * Ems);

    // return FssEss + FmsEms;
    return vec3(0);
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

void main()
{
    vec4 baseColor;

#ifdef HAS_TEXCOORDS
    vec4 texColor = texture(baseColorTexture, passTexcoords);
    baseColor = baseColorFactor * texColor;
#else
    baseColor = baseColorFactor;
#endif

    vec3 color;
#ifndef MATERIAL_UNLIT
    vec3 v = normalize(cameraWorldPosition - worldPosition);
    vec3 n = passNormal;
    vec3 f0_dielectric = vec3(0.04);
    float specularWeight = 1.0;
    vec3 f90_dielectric = vec3(1.0);

    vec4 metallicRoughnessTexel = texture(metallicRoughnessTexture, passTexcoords);
    float metallic = metallicFactor * metallicRoughnessTexel.r;
    float perceptualRoughness = roughnessFactor * metallicRoughnessTexel.g;
    float alphaRoughness = perceptualRoughness * perceptualRoughness;

    // USE_IBL
    // getDiffuseLight();
    // getIBLRadianceGGX();
    // getIBLGGXFresnel();

    // END USE_IBL

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
    color = l_color;
// # END FOR EACH
#else
    // MATERIAL_UNLIT
    color = baseColor.rgb;
#endif
    // outColor = vec4(1.0, 0.0, 1.0, 0.0);
    outColor = vec4(toneMap(color), baseColor.a);
}
