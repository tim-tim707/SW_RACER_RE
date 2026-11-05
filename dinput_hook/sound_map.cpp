#include "sound_map.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <vector>

#include <windows.h>

extern "C" {
#include <Swr/swrSound.h>// swrSound_RegisterSound
#include <globals.h>     // swrSound_Initted
#include <types.h>       // swrSoundDescriptor

extern FILE *hook_log;
}

namespace {
    const char *MAP_PATH = "./data/Sounds.map";
    const char *CONTENT_DIR = "./assets/content";
    const char *CUSTOM_DIR = "./data/wavs/Music";
    // "cs_" + 24 hex + ".wav" = 31 characters: the most a descriptor's name field holds, and the
    // name is what the streaming loader reopens the file by.
    constexpr size_t CUSTOM_HASH_CHARS = 24;

    std::vector<std::string> names;// index = bank index
    bool loaded = false;
    std::map<std::string, int> custom_by_hash;// sha256 -> bank index, once registered

    std::string lowered_stem(const char *text, size_t length) {
        std::string out;
        for (size_t i = 0; i < length; i++) {
            const unsigned char c = (unsigned char) text[i];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
                break;
            out.push_back((char) tolower(c));
        }
        if (out.size() > 4 && out.compare(out.size() - 4, 4, ".wav") == 0)
            out.resize(out.size() - 4);
        return out;
    }

    void load() {
        loaded = true;
        FILE *f = fopen(MAP_PATH, "rb");
        if (!f) {
            fprintf(hook_log, "[sound_map] %s is not readable; sounds cannot be named\n", MAP_PATH);
            fflush(hook_log);
            return;
        }
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            const char *p = line;
            while (*p == ' ' || *p == '\t')
                p++;
            if (*p == '#' || *p == '\r' || *p == '\n' || *p == '\0' || strncmp(p, "NUM", 3) == 0)
                continue;
            names.push_back(lowered_stem(p, strlen(p)));
        }
        fclose(f);
    }
}

int sound_map_IndexOf(const std::string &name) {
    if (!loaded)
        load();
    const std::string wanted = lowered_stem(name.c_str(), name.size());
    for (size_t i = 0; i < names.size(); i++) {
        if (names[i] == wanted)
            return (int) i;
    }
    return -1;
}

std::string sound_map_NameOf(int index) {
    if (!loaded)
        load();
    if (index < 0 || (size_t) index >= names.size())
        return std::string();
    return names[index];
}

int sound_map_RegisterCustom(const std::string &sha256, const std::string &label) {
    if (!loaded)
        load();
    const auto known = custom_by_hash.find(sha256);
    if (known != custom_by_hash.end())
        return known->second;
    if (swrSound_Initted == 0 || sha256.size() < CUSTOM_HASH_CHARS)
        return -1;

    const std::string file_name = "cs_" + sha256.substr(0, CUSTOM_HASH_CHARS) + ".wav";
    const std::string link_path = std::string(CUSTOM_DIR) + "/" + file_name;
    const std::string blob_path =
        std::string(CONTENT_DIR) + "/" + sha256.substr(0, 2) + "/" + sha256;
    if (GetFileAttributesA(link_path.c_str()) == INVALID_FILE_ATTRIBUTES &&
        !CreateHardLinkA(link_path.c_str(), blob_path.c_str(), nullptr) &&
        !CopyFileA(blob_path.c_str(), link_path.c_str(), FALSE)) {
        fprintf(hook_log, "[sound_map] cannot place %s next to the game's wavs (error %lu)\n",
                sha256.c_str(), GetLastError());
        fflush(hook_log);
        return -1;
    }

    const swrSoundDescriptor *entry =
        (const swrSoundDescriptor *) swrSound_RegisterSound((char *) file_name.c_str(), 0);
    if (entry == nullptr) {
        fprintf(hook_log, "[sound_map] the sound bank refused %s (%s): full, or not a wav\n",
                file_name.c_str(), label.c_str());
        fflush(hook_log);
        return -1;
    }

    const int index = (int) entry->index;
    custom_by_hash[sha256] = index;
    if ((size_t) index >= names.size())
        names.resize((size_t) index + 1);
    names[index] = label;
    fprintf(hook_log, "[sound_map] custom sound '%s' = bank %d (%s, %u bytes%s)\n", label.c_str(),
            index, file_name.c_str(), entry->dataSize,
            (entry->flags & swrSoundDescriptor_STREAMED) ? ", streamed" : "");
    fflush(hook_log);
    return index;
}
