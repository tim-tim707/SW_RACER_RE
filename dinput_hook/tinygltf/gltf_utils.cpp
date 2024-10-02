#include "gltf_utils.h"

// Define these only in *one* .cc file.
#define TINYGLTF_IMPLEMENTATION
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define TINYGLTF_NOEXCEPTION// optional. disable exception handling.
#include "tiny_gltf.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include <format>

#include "../imgui_utils.h"
#include "../shaders_utils.h"

extern "C" FILE *hook_log;

extern ImGuiState imgui_state;

std::vector<gltfModel> g_models;

void load_gltf_models() {
    fprintf(hook_log, "[load_gltf_models]\n");
    tinygltf::TinyGLTF loader;

    std::vector<std::string> asset_names = {"Box.gltf", "BoxTextured.gltf", "box_textured_red.gltf",
                                            "MetalRoughSpheresNoTextures.gltf"};
    std::string asset_dir = "./assets/gltf/";

    for (auto name: asset_names) {
        std::string err;
        std::string warn;
        tinygltf::Model model;
        bool ret = loader.LoadASCIIFromFile(&model, &err, &warn, asset_dir + name);
        //bool ret = loader.LoadBinaryFromFile(&model, &err, &warn, argv[1]); // for binary glTF(.glb)

        if (!warn.empty()) {
            fprintf(hook_log, "Warn: %s\n", warn.c_str());
        }

        if (!err.empty()) {
            fprintf(hook_log, "Err: %s\n", err.c_str());
        }

        if (!ret) {
            fprintf(hook_log, "Failed to parse %s glTF\n", name.c_str());
        }
        fflush(hook_log);

        g_models.push_back(
            gltfModel{.setuped = false, .gltf = model, .mesh_infos = {}, .shader_pool = {}});
        fprintf(hook_log, "Loaded %s\n", name.c_str());
    }
}

static unsigned int getComponentCount(int tinygltfType) {
    switch (tinygltfType) {
        case TINYGLTF_TYPE_SCALAR:
            return 1;
        case TINYGLTF_TYPE_VEC2:
            return 2;
        case TINYGLTF_TYPE_VEC3:
            return 3;
        case TINYGLTF_TYPE_VEC4:
            return 4;
        case TINYGLTF_TYPE_MAT2:
            return 4;
        case TINYGLTF_TYPE_MAT3:
            return 9;
        case TINYGLTF_TYPE_MAT4:
            return 16;
    }

    fprintf(hook_log, "Unrecognized tinygltfType %d", tinygltfType);
    fflush(hook_log);
    assert(false);
}

static unsigned int getComponentByteSize(int componentType) {
    switch (componentType) {
        case TINYGLTF_COMPONENT_TYPE_BYTE:         //GL_BYTE
        case TINYGLTF_COMPONENT_TYPE_UNSIGNED_BYTE:// GL_UNSIGNED_BYTE
            return 1;
        case TINYGLTF_COMPONENT_TYPE_SHORT:         // GL_SHORT
        case TINYGLTF_COMPONENT_TYPE_UNSIGNED_SHORT:// GL_UNSIGNED_SHORT
            return 2;
            // No GL equivalent ?
            // TINYGLTF_COMPONENT_TYPE_INT
        case TINYGLTF_COMPONENT_TYPE_UNSIGNED_INT:// GL_UNSIGNED_INT
        case TINYGLTF_COMPONENT_TYPE_FLOAT:       // GL_FLOAT
            return 4;
    }

    fprintf(hook_log, "Unrecognized glType %d", componentType);
    fflush(hook_log);
    assert(false);
}

static void setupAttribute(unsigned int bufferObject, tinygltf::Model &model, int accessorId,
                           unsigned int location) {
    const tinygltf::Accessor &accessor = model.accessors[accessorId];
    const tinygltf::BufferView &bufferView = model.bufferViews[accessor.bufferView];
    auto buffer = reinterpret_cast<const float *>(model.buffers[bufferView.buffer].data.data() +
                                                  accessor.byteOffset + bufferView.byteOffset);

    glBindBuffer(bufferView.target, bufferObject);
    glBufferData(bufferView.target,
                 accessor.count * getComponentCount(accessor.type) *
                     getComponentByteSize(accessor.componentType),
                 buffer, GL_STATIC_DRAW);

    glVertexAttribPointer(location, getComponentCount(accessor.type), accessor.componentType,
                          GL_FALSE, bufferView.byteStride, 0);
}

static void setupTexture(unsigned int textureObject, tinygltf::Model &model,
                         int textureId /*TODO: , int textureSlot default to texture 0 */) {
    auto texture = model.textures[textureId];
    auto image = model.images[texture.source];

    glBindTexture(GL_TEXTURE_2D, textureObject);
    GLint internalFormat = GL_RGBA;
    glTexImage2D(GL_TEXTURE_2D, 0, internalFormat, image.width, image.height, 0, internalFormat,
                 image.pixel_type, image.image.data());
    glGenerateMipmap(GL_TEXTURE_2D);
    // activate texture TEXTURE0 + texslot
    // uniform1i loc texslot
    auto sampler = model.samplers[texture.sampler];

    // Sampler parameters. TODO: Should use glSamplerParameter here
    // if not exist, use defaults wrapS wrapT, auto filtering
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, sampler.wrapS);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, sampler.wrapT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, sampler.minFilter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, sampler.magFilter);
}

pbrShader compile_pbr(ImGuiState &state, int gltfFlags) {
    pbrShader shader;
    bool hasNormals = gltfFlags & gltfFlags::hasNormals;
    bool hasTexCoords = gltfFlags & gltfFlags::hasTexCoords;
    fprintf(hook_log, "Compiling shader %s,%s...", hasNormals ? "NORMALS" : "",
            hasTexCoords ? "TEXCOORDS" : "");
    fflush(hook_log);

    (void) state;

    const std::string defines = std::format("{}{}", hasNormals ? "#define HAS_NORMALS\n" : "",
                                            hasTexCoords ? "#define HAS_TEXCOORDS\n" : "");

    const char *vertex_shader_source = R"(
layout(location = 0) in vec3 position;
#ifdef HAS_NORMALS
layout(location = 1) in vec3 normal;
#endif
#ifdef HAS_TEXCOORDS
layout(location = 2) in vec2 texcoords;
#endif

uniform mat4 projMatrix;
uniform mat4 viewMatrix;
uniform mat4 modelMatrix;

uniform int model_id;

out vec3 worldPosition;
#ifdef HAS_NORMALS
out vec3 passNormal;
#endif
#ifdef HAS_TEXCOORDS
out vec2 passTexcoords;
#endif

void main() {
    vec4 pos = modelMatrix * vec4(position, 1.0);
    worldPosition = vec3(pos.xyz) / pos.w;

    // Yes, precomputing modelView is better and we should do it
    gl_Position = projMatrix * viewMatrix * pos;

#ifdef HAS_NORMALS
    passNormal = normal;
#endif
#ifdef HAS_TEXCOORDS
    passTexcoords = texcoords;
#endif
}
)";
    const char *fragment_shader_source = R"(
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
uniform sampler2D baseColorTexture;
#endif

out vec4 outColor;

// Spot light
struct Light {
    vec3 color;
    vec3 position;
};
const Light light = Light(vec3(1), vec3(0, 0.03, 0.40));

vec3 getLightIntensity(Light light, vec3 pointToLight) {
    float rangeAttenuation = 1.0 / pow(length(pointToLight), 2.0); // unlimited
    float spotAttenuation = 1.0;

    return rangeAttenuation * spotAttenuation * light.color;
}

float clampedDot(vec3 x, vec3 y) {
    return clamp(dot(x, y), 0.0, 1.0);
}

const float GAMMA = 2.2;
const float INV_GAMMA = 1.0 / GAMMA;

vec3 linearTosRGB(vec3 color) {
    return pow(color, vec3(INV_GAMMA));
}

vec3 toneMap(vec3 color) {
    return linearTosRGB(color);
}

vec3 F_Schlick(vec3 f0, vec3 f90, float VdotH) {
    return f0 + (f90 - f0) * pow(clamp(1.0 - VdotH, 0.0, 1.0), 5.0);
}

const float M_PI = 3.141592653589793;

vec3 BRDF_lambertian(vec3 diffuseColor) {
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

vec3 BRDF_specularGGX(float alphaRoughness, float NdotL, float NdotV, float NdotH) {
    float Vis = V_GGX(NdotL, NdotV, alphaRoughness);
    float D = D_GGX(NdotH, alphaRoughness);

    return vec3(Vis * D);
}

void main() {

vec4 baseColor;

#ifdef HAS_TEXCOORDS
    vec4 texColor = texture(baseColorTexture, passTexcoords);
    baseColor = baseColorFactor * texColor;
#else
    baseColor = baseColorFactor;
#endif

    vec3 v = normalize(cameraWorldPosition - worldPosition);
    vec3 n = passNormal;
    vec3 f0_dielectric = vec3(0.04);
    float specularWeight = 1.0;
    vec3 f90_dielectric = vec3(1.0);

    float perceptualRoughness = roughnessFactor;
    float alphaRoughness = perceptualRoughness * perceptualRoughness;

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
    vec3 l_color = mix(l_dielectric_brdf, l_metal_brdf, metallicFactor);
    vec3 color = l_color;
// # END FOR EACH

    // outColor = vec4(1.0, 0.0, 1.0, 0.0);
    outColor = vec4(toneMap(color), baseColor.a);
}
)";

    const char *vertex_sources[]{"#version 330 core\n", defines.c_str(), vertex_shader_source};
    const char *fragment_sources[]{"#version 330 core\n", defines.c_str(), fragment_shader_source};

    std::optional<GLuint> program_opt = compileProgram(
        std::size(vertex_sources), vertex_sources, std::size(fragment_sources), fragment_sources);
    if (!program_opt.has_value())
        std::abort();
    GLuint program = program_opt.value();

    shader = {
        .handle = program,
        .proj_matrix_pos = glGetUniformLocation(program, "projMatrix"),
        .view_matrix_pos = glGetUniformLocation(program, "viewMatrix"),
        .model_matrix_pos = glGetUniformLocation(program, "modelMatrix"),
        .baseColorFactor_pos = glGetUniformLocation(program, "baseColorFactor"),
        .metallicFactor_pos = glGetUniformLocation(program, "metallicFactor"),
        .roughnessFactor_pos = glGetUniformLocation(program, "roughnessFactor"),
        .model_id_pos = glGetUniformLocation(program, "model_id"),
    };

    fprintf(hook_log, "Done\n");
    fflush(hook_log);

    return shader;
}

void setupModel(gltfModel &model) {
    fprintf(hook_log, "Setuping model...\n");
    fflush(hook_log);

    model.setuped = true;

    for (size_t meshId = 0; meshId < model.gltf.meshes.size(); meshId++) {
        meshInfos mesh_infos{};
        if (model.gltf.meshes[meshId].primitives.size() > 1) {
            fprintf(hook_log, "Multiples primitives for mesh %zu not yet supported in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }

        int primitiveId = 0;
        tinygltf::Primitive primitive = model.gltf.meshes[meshId].primitives[primitiveId];
        int indicesAccessorId = primitive.indices;
        if (indicesAccessorId == -1) {
            fprintf(hook_log, "Un-indexed topology not yet supported for mesh %zu in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }
        mesh_infos.gltfFlags |= gltfFlags::isIndexed;

        GLint drawMode = primitive.mode;
        if (drawMode == -1) {
            fprintf(hook_log, "Unsupported draw mode %d in renderer\n", drawMode);
            fflush(hook_log);
            continue;
        }
        int materialIndex = primitive.material;
        if (materialIndex == -1) {
            fprintf(hook_log, "Material-less model not yet supported in renderer\n");
            fflush(hook_log);
            continue;
        }

        int positionAccessorId = -1;
        int normalAccessorId = -1;
        int texcoordAccessorId = -1;
        for (const auto &[key, value]: primitive.attributes) {
            if (key == "POSITION")
                positionAccessorId = value;
            if (key == "NORMAL") {
                mesh_infos.gltfFlags |= gltfFlags::hasNormals;
                normalAccessorId = value;
            }
            if (key == "TEXCOORD_0") {
                mesh_infos.gltfFlags |= gltfFlags::hasTexCoords;
                texcoordAccessorId = value;
            }
        }

        if (positionAccessorId == -1) {
            fprintf(hook_log, "Unsupported mesh %zu without position attribute in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }
        if (mesh_infos.gltfFlags & gltfFlags::hasNormals == 0) {
            fprintf(hook_log, "Unsupported mesh %zu without normal attribute in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }

        if (model.gltf.accessors[indicesAccessorId].type != TINYGLTF_TYPE_SCALAR) {
            fprintf(hook_log,
                    "Error: indices accessor does not have type scalar in renderer for mesh %zu\n",
                    meshId);
            fflush(hook_log);
            continue;
        }
        const tinygltf::Accessor &indicesAccessor = model.gltf.accessors[indicesAccessorId];

        if (indicesAccessor.componentType != GL_UNSIGNED_SHORT)// 0x1403
        {
            fprintf(hook_log, "Unsupported type for indices buffer of mesh %zu in renderer\n",
                    meshId);
            fflush(hook_log);
            continue;
        }

        // compile shader with options
        // https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#appendix-b-brdf-implementation
        if (!model.shader_pool.contains(mesh_infos.gltfFlags)) {
            model.shader_pool[mesh_infos.gltfFlags] =
                compile_pbr(imgui_state, mesh_infos.gltfFlags);
        }

        // create GL objects
        GLuint VAO;
        glGenVertexArrays(1, &VAO);
        GLuint VBOs[3];
        glGenBuffers(3, VBOs);

        GLuint EBO;
        glGenBuffers(1, &EBO);

        unsigned int glTexture;
        glGenTextures(1, &glTexture);

        mesh_infos.VAO = VAO;
        mesh_infos.PositionBO = VBOs[0];
        mesh_infos.NormalBO = VBOs[1];
        mesh_infos.TexCoordsBO = VBOs[2];
        mesh_infos.EBO = EBO;
        mesh_infos.glTexture = glTexture;

        model.mesh_infos[meshId] = mesh_infos;

        // Setup VAO
        pbrShader shader = model.shader_pool[mesh_infos.gltfFlags];
        glUseProgram(shader.handle);

        glBindVertexArray(mesh_infos.VAO);

        // Position is mandatory attribute
        setupAttribute(mesh_infos.PositionBO, model.gltf, positionAccessorId, 0);
        glEnableVertexArrayAttrib(mesh_infos.VAO, 0);

        if (mesh_infos.gltfFlags & gltfFlags::hasNormals) {
            setupAttribute(mesh_infos.NormalBO, model.gltf, normalAccessorId, 1);
            glEnableVertexArrayAttrib(mesh_infos.VAO, 1);
        }

        if (mesh_infos.gltfFlags & gltfFlags::hasTexCoords) {
            setupAttribute(mesh_infos.TexCoordsBO, model.gltf, texcoordAccessorId, 2);
            glEnableVertexArrayAttrib(mesh_infos.VAO, 2);

            int textureId =
                model.gltf.materials[materialIndex].pbrMetallicRoughness.baseColorTexture.index;
            setupTexture(mesh_infos.glTexture, model.gltf, textureId);
        }

        // is indexed geometry
        const tinygltf::BufferView &indicesBufferView =
            model.gltf.bufferViews[indicesAccessor.bufferView];
        auto indexBuffer = reinterpret_cast<const unsigned short *>(
            model.gltf.buffers[indicesBufferView.buffer].data.data() + indicesAccessor.byteOffset +
            indicesBufferView.byteOffset);

        glBindBuffer(indicesBufferView.target, mesh_infos.EBO);
        glBufferData(indicesBufferView.target, indicesBufferView.byteLength, indexBuffer,
                     GL_STATIC_DRAW);

        glBindVertexArray(0);
    }
    fprintf(hook_log, "Model setup Done\n");
    fflush(hook_log);
}
