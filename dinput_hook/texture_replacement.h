#pragma once

#include "glad/glad.h"
#include <filesystem>
#include <cstdint>
#include <map>

extern "C" {
#include <types.h>
}

struct ReplacementTexture {
    std::filesystem::path path;
    uint32_t hash;
    GLuint handle;
};

extern bool enable_texture_replacement;
extern std::map<TEXID, ReplacementTexture> replacement_textures;

void refresh_replacement_textures();

void begin_texture_replacement();
void end_texture_replacement();

// True if handle is a loaded user-replacement texture (already correct, must not be deswizzled).
bool is_replacement_texture_handle(GLuint handle);
