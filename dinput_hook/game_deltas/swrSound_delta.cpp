#include "swrSound_delta.h"

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>

#include "../hook_helper.h"

extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);

extern "C" {
#include <Swr/swrSound.h>
#include <engine_config.h>
#include <globals.h>
}

// Stock RegisterSound fopen-probes every search dir per sound then reads the RIFF header: ~2300
// opens per boot, several seconds when the files aren't cached. Instead each dir is listed once and
// headers are cached on disk, keyed by path + size + mtime from the listing.

namespace {

    const char *const CACHE_PATH = "wav_header_cache.bin";
    const uint32_t CACHE_MAGIC = 0x31484157;// "WAH1"

    // Header of the descriptor bank swrSound_bank points at.
    struct SoundBank {
        uint8_t unk00[0x20];
        uint32_t count;
        uint32_t capacity;
        swrSoundDescriptor *entries;
    };
    static_assert(offsetof(SoundBank, entries) == 0x28);
    static_assert(sizeof(swrSoundDescriptor) == 0x4c);

    struct WavHeader {
        uint64_t size;
        uint64_t mtime;
        int32_t rate;
        int32_t bits;
        uint32_t stereo;
        uint32_t data_offset;
        uint32_t data_size;
    };

    struct DirEntry {
        uint64_t size;
        uint64_t mtime;
    };

    // lowercase dir -> (lowercase file name -> entry)
    std::unordered_map<std::string, std::unordered_map<std::string, DirEntry>> g_dirs;
    // lowercase full path -> header
    std::unordered_map<std::string, WavHeader> g_headers;
    bool g_headers_loaded = false;
    bool g_headers_dirty = false;

    std::string lower(const char *s) {
        std::string out(s);
        for (char &c: out)
            c = (char) tolower((unsigned char) c);
        return out;
    }

    const std::unordered_map<std::string, DirEntry> &list_dir(const std::string &dir) {
        const std::string key = lower(dir.c_str());
        auto it = g_dirs.find(key);
        if (it != g_dirs.end())
            return it->second;

        auto &files = g_dirs[key];
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    continue;
                files[lower(fd.cFileName)] = DirEntry{
                    ((uint64_t) fd.nFileSizeHigh << 32) | fd.nFileSizeLow,
                    ((uint64_t) fd.ftLastWriteTime.dwHighDateTime << 32) |
                        fd.ftLastWriteTime.dwLowDateTime,
                };
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
        return files;
    }

    void load_headers() {
        g_headers_loaded = true;
        FILE *f = fopen(CACHE_PATH, "rb");
        if (!f)
            return;
        uint32_t magic = 0, count = 0;
        if (fread(&magic, 4, 1, f) == 1 && magic == CACHE_MAGIC && fread(&count, 4, 1, f) == 1) {
            for (uint32_t i = 0; i < count; i++) {
                uint16_t len;
                char path[MAX_PATH];
                WavHeader hdr;
                if (fread(&len, 2, 1, f) != 1 || len >= sizeof(path) ||
                    fread(path, len, 1, f) != 1 || fread(&hdr, sizeof(hdr), 1, f) != 1)
                    break;
                path[len] = '\0';
                g_headers[path] = hdr;
            }
        }
        fclose(f);
    }

    void save_headers() {
        FILE *f = fopen(CACHE_PATH, "wb");
        if (!f)
            return;
        const uint32_t count = (uint32_t) g_headers.size();
        fwrite(&CACHE_MAGIC, 4, 1, f);
        fwrite(&count, 4, 1, f);
        for (const auto &[path, hdr]: g_headers) {
            const uint16_t len = (uint16_t) path.size();
            fwrite(&len, 2, 1, f);
            fwrite(path.data(), len, 1, f);
            fwrite(&hdr, sizeof(hdr), 1, f);
        }
        fclose(f);
    }

    // Same search path as stock ("%s;%s%s;%s%s" @0x004b74e4, split on ';').
    std::string search_path() {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s;%s%s;%s%s",
                 Main_hiRes_sound
                     ? ".\\data\\wavs\\22K;.\\data\\wavs\\22K\\Voice"
                     : ".\\data\\wavs\\11K;.\\data\\wavs\\11K\\Voice;.\\data\\wavs\\22K\\Voice",
                 rootPathName, ".\\data\\wavs\\Music", wuRegistry_lpClass, ".\\data\\wavs\\Voice");
        return buf;
    }

    bool find_wav(const char *name, std::string &path, const DirEntry *&entry) {
        const std::string sp = search_path();
        const std::string key = lower(name);
        size_t start = 0;
        while (start <= sp.size()) {
            size_t end = sp.find(';', start);
            if (end == std::string::npos)
                end = sp.size();
            const std::string dir = sp.substr(start, end - start);
            start = end + 1;
            if (dir.empty())
                continue;
            const auto &files = list_dir(dir);
            auto it = files.find(key);
            if (it != files.end()) {
                path = dir + "\\" + name;
                entry = &it->second;
                return true;
            }
        }
        return false;
    }

    bool read_header(const std::string &path, const DirEntry &entry, WavHeader &hdr) {
        const std::string key = lower(path.c_str());
        auto it = g_headers.find(key);
        if (it != g_headers.end() && it->second.size == entry.size &&
            it->second.mtime == entry.mtime) {
            hdr = it->second;
            return true;
        }

        HostServices *hs = stdPlatform_hostServices_ptr;
        stdFile_t file = hs->fileOpen(path.c_str(), "rb");
        if (!file)
            return false;
        hdr.size = entry.size;
        hdr.mtime = entry.mtime;
        hdr.data_size =
            swrSound_ParseWave(file, &hdr.rate, &hdr.bits, &hdr.stereo, (char *) &hdr.data_offset);
        hs->fileClose(file);
        g_headers[key] = hdr;
        g_headers_dirty = true;
        return true;
    }

    typedef void *(__cdecl *swrSound_RegisterSound_t)(char *name, int load);

    void *register_original(char *name, int load) {
        return hook_call_original((swrSound_RegisterSound_t) swrSound_RegisterSound_ADDR, name,
                                  load);
    }

}// namespace

// 0x004227e0
extern "C" void *__cdecl swrSound_RegisterSound_delta(char *name, int load) {
    // Aliases and anything the listing can't place keep the stock path.
    if (!swrSound_Initted || strcmp(name, "none") == 0 || swrSound_Find(name) != nullptr ||
        strpbrk(name, "\\/:") != nullptr)
        return register_original(name, load);

    std::string path;
    const DirEntry *entry;
    if (!find_wav(name, path, entry))
        return register_original(name, load);

    SoundBank *bank = (SoundBank *) swrSound_bank;
    const uint32_t count = bank->count;
    if (count >= bank->capacity)
        return nullptr;

    WavHeader hdr;
    if (!read_header(path, *entry, hdr))
        return register_original(name, load);

    swrSoundDescriptor *desc = &bank->entries[count];
    desc->index = count;
    strncpy(desc->name, name, sizeof(desc->name) - 1);
    desc->name[sizeof(desc->name) - 1] = '\0';
    desc->sampleRate = hdr.rate;
    desc->bits = hdr.bits;
    desc->channels = hdr.stereo;
    desc->dataOffset = (void *) (uintptr_t) hdr.data_offset;
    desc->dataSize = hdr.data_size;
    if (hdr.data_size == 0)
        return nullptr;

    desc->durationMs =
        (uint32_t) ((uint64_t) hdr.data_size / ((uint64_t) (uint32_t) hdr.rate / 1000));
    if (hdr.bits == 16)
        desc->durationMs >>= 1;
    if (hdr.stereo != 0)
        desc->durationMs >>= 1;
    desc->flags = hdr.data_size > SWR_SOUND_STREAM_THRESHOLD ? swrSoundDescriptor_STREAMED
                                                             : (swrSoundDescriptor_FLAG) 0;
    desc->unk44 = 1;
    swrSound_Add((char *) desc);
    bank->count = count + 1;
    return desc;
}

void swrSound_delta_BeginStartup(void) {
    // Startup re-runs on a sound / hi-res toggle; re-list in case files changed.
    g_dirs.clear();
    if (!g_headers_loaded)
        load_headers();
}

void swrSound_delta_EndStartup(void) {
    if (g_headers_dirty) {
        save_headers();
        g_headers_dirty = false;
    }
}

void swrSound_delta_RegisterHooks(void) {
    hook_function("swrSound_RegisterSound", (uint32_t) swrSound_RegisterSound_ADDR,
                  (uint8_t *) swrSound_RegisterSound_delta);
}
