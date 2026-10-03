#pragma once

// Checks for user-supplied glTF models (assets/gltf) before setupModel walks them. Pure -- fastgltf
// only, no GL -- so fuzz/ links it standalone. Every index and byte range setupModel / setupTexture
// dereferences comes from the file; a model that fails here is not loaded.

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include <fastgltf/types.hpp>

struct GltfByteSpan {
    const std::byte *data;
    size_t size;
};

// The vertex / index bytes setupModel uploads for an accessor, or nullopt if any index or range is
// out of bounds. Requires bufferView.target, which the upload binds.
std::optional<GltfByteSpan> gltf_accessor_bytes(const fastgltf::Asset &asset, size_t accessorId);

// Same, for data read on the CPU (animation keyframes), which has no bind target.
std::optional<GltfByteSpan> gltf_accessor_data(const fastgltf::Asset &asset, size_t accessorId);

// An embedded image's encoded bytes (glb / data URI), nullopt for external files or bad ranges.
std::optional<GltfByteSpan> gltf_embedded_image_bytes(const fastgltf::Asset &asset, size_t imageId);

// The vertex attributes setupModel uploads (the rest are ignored).
bool gltf_attribute_uploaded(std::string_view name);

// nullopt if setupModel can walk the asset; otherwise why not.
std::optional<std::string> gltf_validate_model(const fastgltf::Asset &asset);
