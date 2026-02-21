#include "texture_replacement.h"

#include "imgui_internal.h"
#include "imgui_utils.h"
#include "nv_dds/nv_dds.h"

extern "C" FILE *hook_log;

extern "C" {
#include "globals.h"
}

#include <regex>

bool enable_texture_replacement = true;
std::map<TEXID, ReplacementTexture> replacement_textures;

uint32_t hash_file_contents(const std::filesystem::path &file) {
    FILE *f = fopen(file.generic_string().c_str(), "rb");
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<char> data(size);
    fread(data.data(), 1, data.size(), f);
    fclose(f);

    return ImHashData(data.data(), data.size());
}

void create_or_refresh_replacement_texture(ReplacementTexture &tex,
                                           const std::filesystem::path &path) {
    const uint32_t file_hash = hash_file_contents(path);
    if (tex.handle != 0 && file_hash == tex.hash)
        return;

    tex.path = path;
    tex.hash = file_hash;
    if (tex.handle == 0)
        glGenTextures(1, &tex.handle);

    glBindTexture(GL_TEXTURE_2D, tex.handle);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);

    nv_dds::CDDSImage image;
    image.load(path.generic_string());
#if 0
    // TODO: loading mipmaps is somehow broken, image lines are skewed
    image.upload_texture2D();
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, image.get_num_mipmaps());
#else
    glCompressedTexImage2D(GL_TEXTURE_2D, 0, image.get_format(), image.get_width(),
                           image.get_height(), 0, image.get_size(), image);
    glGenerateMipmap(GL_TEXTURE_2D);
#endif

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_ANISOTROPY, imgui_state.anisotropy);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
    glBindTexture(GL_TEXTURE_2D, 0);
}

static bool loaded_replacement_textures_at_least_once = false;

void refresh_replacement_textures() {
    loaded_replacement_textures_at_least_once = true;

    const static std::regex file_regex("([0-9]+)\\.dds");
    if (!std::filesystem::is_directory("./assets/replacement_textures/")) {
        fprintf(hook_log,
                "[swrModel_LoadModelTexture] texture replacement folder "
                "./assets/replacement_textures/ does not exist, cannot load any replacements.\n");
        fflush(hook_log);
        return;
    }

    erase_if(replacement_textures, [](const auto &tex) {
        if (exists(tex.second.path))
            return false;

        glDeleteTextures(1, &tex.second.handle);
        return true;
    });

    for (const auto &entry:
         std::filesystem::recursive_directory_iterator("./assets/replacement_textures/")) {
        if (!entry.is_regular_file())
            continue;

        const std::string filename = entry.path().filename().generic_string();
        std::smatch match;
        if (std::regex_match(filename, match, file_regex)) {
            const TEXID id = (TEXID) std::stod(match.str(1));
            create_or_refresh_replacement_texture(replacement_textures[id], entry.path());
        }
    }
}

extern void **texture_buffer_replacement;
static std::vector<std::pair<GLuint*, GLuint>> replacement_backup;

void begin_texture_replacement() {
    if (!loaded_replacement_textures_at_least_once)
        refresh_replacement_textures();

    if (enable_texture_replacement && texture_buffer_replacement) {
        // replace loaded texture opengl handles
        replacement_backup.clear();
        for (const auto& [tex_id, replacement] : replacement_textures) {
            RdMaterial** mat_ptr = (RdMaterial **)texture_buffer_replacement[tex_id];
            if (!mat_ptr)
                continue;

            GLuint* to_replace = (GLuint*)&(**mat_ptr).aTextures->pD3DSrcTexture;
            replacement_backup.emplace_back(to_replace, *to_replace);
            *to_replace = replacement.handle;
        }
    }
}

void end_texture_replacement() {
    for (const auto& [to_replace, backup] : replacement_backup)
        *to_replace = backup;

    replacement_backup.clear();
}