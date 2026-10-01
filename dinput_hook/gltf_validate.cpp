#include "gltf_validate.h"

#include <cstdint>
#include <variant>

#include <fastgltf/tools.hpp>

static std::optional<GltfByteSpan> buffer_bytes(const fastgltf::Buffer &buffer) {
    std::optional<GltfByteSpan> span;
    std::visit(fastgltf::visitor{
                   [](const auto &) {},
                   [&](const fastgltf::sources::Array &a) { span = GltfByteSpan{a.bytes.data(), a.bytes.size()}; },
                   [&](const fastgltf::sources::Vector &v) { span = GltfByteSpan{v.bytes.data(), v.bytes.size()}; },
                   [&](const fastgltf::sources::ByteView &bv) { span = GltfByteSpan{bv.bytes.data(), bv.bytes.size()}; },
               },
               buffer.data);
    return span;
}

// [offset, offset + size) of `span`, in 64-bit so a file-supplied offset or count can't wrap.
static std::optional<GltfByteSpan> sub_span(GltfByteSpan span, uint64_t offset, uint64_t size) {
    if (offset > span.size || size > span.size - offset)
        return std::nullopt;
    return GltfByteSpan{span.data + offset, (size_t) size};
}

static std::optional<GltfByteSpan> accessor_span(const fastgltf::Asset &asset, size_t accessorId,
                                                 bool needsTarget) {
    if (accessorId >= asset.accessors.size())
        return std::nullopt;
    const fastgltf::Accessor &accessor = asset.accessors[accessorId];
    // Sparse accessors without a view are not supported by the renderer.
    if (!accessor.bufferViewIndex.has_value() || accessor.bufferViewIndex.value() >= asset.bufferViews.size())
        return std::nullopt;
    const fastgltf::BufferView &view = asset.bufferViews[accessor.bufferViewIndex.value()];
    if ((needsTarget && !view.target.has_value()) || view.bufferIndex >= asset.buffers.size())
        return std::nullopt;
    const std::optional<GltfByteSpan> buffer = buffer_bytes(asset.buffers[view.bufferIndex]);
    if (!buffer)
        return std::nullopt;

    const uint64_t element = fastgltf::getElementByteSize(accessor.type, accessor.componentType);
    if (element == 0)
        return std::nullopt;
    return sub_span(*buffer, (uint64_t) view.byteOffset + accessor.byteOffset, (uint64_t) accessor.count * element);
}

std::optional<GltfByteSpan> gltf_accessor_bytes(const fastgltf::Asset &asset, size_t accessorId) {
    return accessor_span(asset, accessorId, true);
}

std::optional<GltfByteSpan> gltf_accessor_data(const fastgltf::Asset &asset, size_t accessorId) {
    return accessor_span(asset, accessorId, false);
}

std::optional<GltfByteSpan> gltf_embedded_image_bytes(const fastgltf::Asset &asset, size_t imageId) {
    if (imageId >= asset.images.size())
        return std::nullopt;
    std::optional<GltfByteSpan> span;
    std::visit(fastgltf::visitor{
                   [](const auto &) {},
                   [&](const fastgltf::sources::Array &a) { span = GltfByteSpan{a.bytes.data(), a.bytes.size()}; },
                   [&](const fastgltf::sources::BufferView &bv) {
                       if (bv.bufferViewIndex >= asset.bufferViews.size())
                           return;
                       const fastgltf::BufferView &view = asset.bufferViews[bv.bufferViewIndex];
                       if (view.bufferIndex >= asset.buffers.size())
                           return;
                       if (const std::optional<GltfByteSpan> buffer = buffer_bytes(asset.buffers[view.bufferIndex]))
                           span = sub_span(*buffer, view.byteOffset, view.byteLength);
                   },
               },
               asset.images[imageId].data);
    return span;
}

static bool image_source_ok(const fastgltf::Asset &asset, size_t imageId) {
    if (imageId >= asset.images.size())
        return false;
    const auto &data = asset.images[imageId].data;
    // External files are read by stb_image from disk; embedded ones must lie inside their buffer.
    if (std::holds_alternative<fastgltf::sources::URI>(data))
        return true;
    return gltf_embedded_image_bytes(asset, imageId).has_value();
}

static std::optional<std::string> texture_error(const fastgltf::Asset &asset, size_t textureId) {
    if (textureId >= asset.textures.size())
        return "texture index out of range";
    const fastgltf::Texture &texture = asset.textures[textureId];
    // setupModel aborts on a texture with no image.
    if (!texture.imageIndex.has_value())
        return "texture without an image";
    if (!image_source_ok(asset, texture.imageIndex.value()))
        return "texture image missing or out of range";
    if (texture.samplerIndex.has_value() && texture.samplerIndex.value() >= asset.samplers.size())
        return "sampler index out of range";
    return std::nullopt;
}

static std::optional<std::string> material_error(const fastgltf::Asset &asset, size_t materialId) {
    if (materialId >= asset.materials.size())
        return "material index out of range";
    const fastgltf::Material &m = asset.materials[materialId];
    std::optional<std::string> error;
    if (m.pbrData.baseColorTexture && (error = texture_error(asset, m.pbrData.baseColorTexture->textureIndex)))
        return error;
    if (m.pbrData.metallicRoughnessTexture &&
        (error = texture_error(asset, m.pbrData.metallicRoughnessTexture->textureIndex)))
        return error;
    if (m.normalTexture && (error = texture_error(asset, m.normalTexture->textureIndex)))
        return error;
    if (m.occlusionTexture && (error = texture_error(asset, m.occlusionTexture->textureIndex)))
        return error;
    if (m.emissiveTexture && (error = texture_error(asset, m.emissiveTexture->textureIndex)))
        return error;
    return std::nullopt;
}

bool gltf_attribute_uploaded(std::string_view name) {
    return name == "POSITION" || name == "NORMAL" || name == "TEXCOORD_0" || name == "TEXCOORD_1" ||
           name == "COLOR_0" || name == "WEIGHTS_0" || name == "JOINTS_0";
}

static bool float_accessor(const fastgltf::Asset &asset, size_t accessorId, fastgltf::AccessorType type) {
    const fastgltf::Accessor &a = asset.accessors[accessorId];
    return a.type == type && a.componentType == fastgltf::ComponentType::Float;
}

// What renderer_utils' computeAnimatedTRS / interpolateProperty read: the channel's node and
// sampler, float keyframes whose max (the animation length) is positive, and one float vec3 / vec4
// output per keyframe.
static std::optional<std::string> animation_error(const fastgltf::Asset &asset, const fastgltf::Animation &anim) {
    for (const fastgltf::AnimationChannel &channel: anim.channels) {
        if (channel.samplerIndex >= anim.samplers.size())
            return "animation sampler index out of range";
        if (!channel.nodeIndex.has_value() || channel.nodeIndex.value() >= asset.nodes.size())
            return "animation channel without a valid node";
        const fastgltf::AnimationSampler &sampler = anim.samplers[channel.samplerIndex];
        if (!gltf_accessor_data(asset, sampler.inputAccessor) ||
            !float_accessor(asset, sampler.inputAccessor, fastgltf::AccessorType::Scalar))
            return "animation keyframes out of range or not float";
        const auto *max = std::get_if<FASTGLTF_STD_PMR_NS::vector<double>>(&asset.accessors[sampler.inputAccessor].max);
        if (max == nullptr || max->empty() || !(max->back() > 0.0))
            return "animation without a positive length";
        if (channel.path == fastgltf::AnimationPath::Weights)
            continue;// skipped by the renderer
        const fastgltf::AccessorType type = channel.path == fastgltf::AnimationPath::Rotation
                                                ? fastgltf::AccessorType::Vec4
                                                : fastgltf::AccessorType::Vec3;
        if (!gltf_accessor_data(asset, sampler.outputAccessor) || !float_accessor(asset, sampler.outputAccessor, type))
            return "animation output out of range or wrong type";
        if (asset.accessors[sampler.outputAccessor].count != asset.accessors[sampler.inputAccessor].count)
            return "animation output count differs from its keyframes";
    }
    return std::nullopt;
}

std::optional<std::string> gltf_validate_model(const fastgltf::Asset &asset) {
    for (const fastgltf::Animation &anim: asset.animations) {
        if (std::optional<std::string> error = animation_error(asset, anim))
            return error;
    }
    for (const fastgltf::Node &node: asset.nodes) {
        if (!node.meshIndex.has_value())
            continue;
        if (node.meshIndex.value() >= asset.meshes.size())
            return "node mesh index out of range";
        for (const fastgltf::Primitive &primitive: asset.meshes[node.meshIndex.value()].primitives) {
            for (const auto &[name, accessorId]: primitive.attributes) {
                if (gltf_attribute_uploaded(name) && !gltf_accessor_bytes(asset, accessorId))
                    return "vertex attribute " + std::string(name) + " out of range";
            }
            if (primitive.indicesAccessor.has_value() && !gltf_accessor_bytes(asset, primitive.indicesAccessor.value()))
                return "index accessor out of range";
            if (primitive.materialIndex.has_value()) {
                if (std::optional<std::string> error = material_error(asset, primitive.materialIndex.value()))
                    return error;
            }
        }
    }
    return std::nullopt;
}
