// glTF / glb replacement models are untrusted input (assets/gltf, community model packs). Parse
// with the game's options, validate, then read everything setupModel / setupTexture /
// interpolateProperty would: a validated asset must never read out of bounds.
#include "gltf_validate.h"

#include <cstddef>
#include <cstdint>

#include <fastgltf/core.hpp>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

static volatile uint32_t g_sink;

static void touch(const std::optional<GltfByteSpan> &span) {
    if (!span)
        __builtin_trap();// validated, yet the renderer would read an unchecked range
    uint32_t h = 0;
    for (size_t i = 0; i < span->size; i++)
        h = h * 31 + (uint8_t) span->data[i];
    g_sink = g_sink + h;
}

static void decode_texture(const fastgltf::Asset &asset, size_t textureId) {
    const fastgltf::Texture &texture = asset.textures[textureId];
    if (std::optional<GltfByteSpan> bytes = gltf_embedded_image_bytes(asset, texture.imageIndex.value())) {
        int w, h, n;
        stbi_uc *pixels = stbi_load_from_memory((const stbi_uc *) bytes->data, (int) bytes->size, &w, &h, &n, 4);
        stbi_image_free(pixels);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    auto buffer = fastgltf::GltfDataBuffer::FromBytes(reinterpret_cast<const std::byte *>(data), size);
    if (buffer.error() != fastgltf::Error::None)
        return 0;
    fastgltf::Parser parser(fastgltf::Extensions::KHR_materials_unlit | fastgltf::Extensions::KHR_texture_transform);
    // load_gltf_asset's options minus the external files (the fuzzer has no model folder).
    auto asset = parser.loadGltf(buffer.get(), "",
                                 fastgltf::Options::DontRequireValidAssetMember | fastgltf::Options::DecomposeNodeMatrices);
    if (asset.error() != fastgltf::Error::None || gltf_validate_model(asset.get()))
        return 0;
    const fastgltf::Asset &a = asset.get();

    for (const fastgltf::Node &node: a.nodes) {
        if (!node.meshIndex)
            continue;
        for (const fastgltf::Primitive &primitive: a.meshes[*node.meshIndex].primitives) {
            for (const auto &[name, accessorId]: primitive.attributes) {
                if (gltf_attribute_uploaded(name))
                    touch(gltf_accessor_bytes(a, accessorId));
            }
            if (primitive.indicesAccessor)
                touch(gltf_accessor_bytes(a, *primitive.indicesAccessor));
            if (!primitive.materialIndex)
                continue;
            const fastgltf::Material &m = a.materials[*primitive.materialIndex];
            if (m.pbrData.baseColorTexture)
                decode_texture(a, m.pbrData.baseColorTexture->textureIndex);
            if (m.normalTexture)
                decode_texture(a, m.normalTexture->textureIndex);
        }
    }
    for (const fastgltf::Animation &anim: a.animations) {
        for (const fastgltf::AnimationChannel &channel: anim.channels) {
            const fastgltf::AnimationSampler &sampler = anim.samplers[channel.samplerIndex];
            touch(gltf_accessor_data(a, sampler.inputAccessor));
            if (channel.path != fastgltf::AnimationPath::Weights)
                touch(gltf_accessor_data(a, sampler.outputAccessor));
        }
    }
    return 0;
}
