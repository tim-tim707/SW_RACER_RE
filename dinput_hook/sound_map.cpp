#include "sound_map.h"

#include <cstdio>
#include <cstring>
#include <vector>

extern "C" FILE *hook_log;

namespace {
    const char *MAP_PATH = "./data/Sounds.map";
    std::vector<std::string> names;// index = bank index
    bool loaded = false;

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
