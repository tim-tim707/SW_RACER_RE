//
// Round-trip INI parser for the mod/delta layer (modding API, issue #153). See config.h.
//
#include "config.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <vector>

#include <windows.h>
#include <filesystem>

namespace {
    // One parsed line. Comments, blank lines and `[section]` headers are kept verbatim in `raw`;
    // `key=value` lines carry the parsed key/value so they can be looked up and rewritten in place.
    // Every entry records its owning `section` (lowercased) so a new key lands in the right block.
    struct Entry {
        bool is_kv = false;
        bool is_header = false;
        std::string section;// owning section, lowercased ("" before the first header)
        std::string key;    // lowercased, kv lines only
        std::string value;  // kv lines only
        std::string raw;    // verbatim text for non-kv lines (comment / blank / "[section]")
    };

    std::vector<Entry> g_entries;
    bool g_loaded = false;

    std::wstring resolve_path() {
        wchar_t buff[1024];
        GetModuleFileNameW(nullptr, buff, (DWORD) std::size(buff));
        return (std::filesystem::path(buff).parent_path() / "SW_RACER_RE.ini").wstring();
    }

    std::string to_lower(std::string s) {
        for (char &c: s)
            c = (char) std::tolower((unsigned char) c);
        return s;
    }

    std::string trim(const std::string &s) {
        const size_t a = s.find_first_not_of(" \t\r\n");
        if (a == std::string::npos)
            return "";
        const size_t b = s.find_last_not_of(" \t\r\n");
        return s.substr(a, b - a + 1);
    }

    void ensure_loaded() {
        if (!g_loaded)
            config::reload();
    }

    Entry *find_kv(const std::string &section, const std::string &key) {
        for (Entry &e: g_entries)
            if (e.is_kv && e.section == section && e.key == key)
                return &e;
        return nullptr;
    }

    const char *find_value(const char *section, const char *key) {
        ensure_loaded();
        const Entry *e = find_kv(to_lower(section), to_lower(key));
        return e ? e->value.c_str() : nullptr;
    }
}

const std::wstring &config::path() {
    static const std::wstring p = resolve_path();
    return p;
}

void config::reload() {
    g_entries.clear();
    g_loaded = true;

    FILE *f = _wfopen(path().c_str(), L"rb");
    if (!f)
        return;// no file yet -> empty model; save() will create it

    std::string text;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        text.append(buf, n);
    fclose(f);

    std::istringstream stream(text);
    std::string line;
    std::string cur_section;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();// CRLF files

        const std::string t = trim(line);
        Entry e;
        if (t.empty() || t[0] == ';' || t[0] == '#') {
            e.raw = line;// blank / comment
        } else if (t.front() == '[' && t.back() == ']') {
            cur_section = to_lower(trim(t.substr(1, t.size() - 2)));
            e.is_header = true;
            e.raw = line;
        } else {
            const size_t eq = line.find('=');
            if (eq == std::string::npos) {
                e.raw = line;// not a key=value line, keep verbatim
            } else {
                e.is_kv = true;
                e.key = to_lower(trim(line.substr(0, eq)));
                e.value = trim(line.substr(eq + 1));
            }
        }
        e.section = cur_section;
        g_entries.push_back(e);
    }
}

int config::get_int(const char *section, const char *key, int fallback) {
    const char *v = find_value(section, key);
    if (!v || !*v)
        return fallback;
    char *end = nullptr;
    const long parsed = std::strtol(v, &end, 10);
    return end == v ? fallback : (int) parsed;
}

float config::get_float(const char *section, const char *key, float fallback) {
    const char *v = find_value(section, key);
    if (!v || !*v)
        return fallback;
    char *end = nullptr;
    const float parsed = std::strtof(v, &end);
    return end == v ? fallback : parsed;
}

std::string config::get_string(const char *section, const char *key, const char *fallback) {
    const char *v = find_value(section, key);
    return v ? std::string(v) : std::string(fallback ? fallback : "");
}

void config::set_string(const char *section, const char *key, const std::string &value) {
    ensure_loaded();
    const std::string s = to_lower(section);
    const std::string k = to_lower(key);

    if (Entry *e = find_kv(s, k)) {
        e->value = value;
        return;
    }

    // New key: insert after the last entry in the section so it joins that block. If the section is
    // absent, append a blank separator + a "[section]" header and start it.
    Entry kv;
    kv.is_kv = true;
    kv.section = s;
    kv.key = k;
    kv.value = value;

    size_t insert_at = g_entries.size();
    bool section_seen = false;
    for (size_t i = 0; i < g_entries.size(); i++) {
        if (g_entries[i].section == s) {
            section_seen = true;
            insert_at = i + 1;// keep advancing to the section's last line
        }
    }

    if (!section_seen) {
        if (!g_entries.empty()) {
            Entry blank;
            blank.section = s;
            g_entries.push_back(blank);
        }
        Entry header;
        header.is_header = true;
        header.section = s;
        header.raw = "[" + std::string(section) + "]";
        g_entries.push_back(header);
        g_entries.push_back(kv);
    } else {
        g_entries.insert(g_entries.begin() + insert_at, kv);
    }
}

void config::set_int(const char *section, const char *key, int value) {
    set_string(section, key, std::to_string(value));
}

void config::set_bool(const char *section, const char *key, bool value) {
    set_string(section, key, value ? "1" : "0");
}

void config::set_float(const char *section, const char *key, float value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%g", value);
    set_string(section, key, buf);
}

void config::save() {
    ensure_loaded();
    FILE *f = _wfopen(path().c_str(), L"wb");
    if (!f)
        return;
    for (const Entry &e: g_entries) {
        if (e.is_kv)
            std::fprintf(f, "%s=%s\r\n", e.key.c_str(), e.value.c_str());
        else
            std::fprintf(f, "%s\r\n", e.raw.c_str());
    }
    fclose(f);
}
