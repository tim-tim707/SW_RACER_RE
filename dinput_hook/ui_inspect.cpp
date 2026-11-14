#include "ui_inspect.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <tuple>
#include <vector>

namespace {

struct SiteRecord {
    std::string kind;
    uintptr_t site;
    int id, x, y;
    std::string text;
    int count;
};

bool g_active = false;
DWORD g_end_ms = 0;
std::map<std::pair<std::string, uintptr_t>, SiteRecord> g_sites;
std::string g_status = "No capture yet.";

void write_capture() {
    std::vector<SiteRecord> rows;
    rows.reserve(g_sites.size());
    for (const auto &kv : g_sites)
        rows.push_back(kv.second);
    std::sort(rows.begin(), rows.end(), [](const SiteRecord &a, const SiteRecord &b) {
        return std::tie(a.site, a.kind) < std::tie(b.site, b.kind);
    });
    static int capture_index = 0;
    FILE *f = std::fopen("ui_callsites.txt", capture_index == 0 ? "w" : "a");
    if (f == NULL) {
        g_status = "Could not write ui_callsites.txt.";
        return;
    }
    std::fprintf(f, "=== capture %d ===\n# site(return addr)  kind      id     x     y  count  text\n",
                 ++capture_index);
    for (const SiteRecord &r : rows) {
        std::fprintf(f, "0x%08x  %-8s %5d %5d %5d %6d  %s\n", (unsigned) r.site, r.kind.c_str(), r.id,
                     r.x, r.y, r.count, r.text.c_str());
    }
    std::fclose(f);
    g_status = "Capture " + std::to_string(capture_index) + ": " + std::to_string(rows.size()) +
               " call sites appended to ui_callsites.txt.";
}

void finish_if_due() {
    if (g_active && (LONG) (GetTickCount() - g_end_ms) >= 0) {
        g_active = false;
        write_capture();
        g_sites.clear();
    }
}

} // namespace

void ui_inspect_start(float seconds) {
    g_sites.clear();
    g_active = true;
    g_end_ms = GetTickCount() + (DWORD) (seconds * 1000.0f);
    g_status = "Capturing...";
}

bool ui_inspect_active(void) {
    finish_if_due();
    return g_active;
}

const char *ui_inspect_status(void) {
    finish_if_due();
    return g_status.c_str();
}

void ui_inspect_note(const char *kind, uintptr_t site, int id, int x, int y, const char *text) {
    if (!g_active)
        return;
    finish_if_due();
    if (!g_active)
        return;
    SiteRecord &r = g_sites[{kind, site}];
    if (r.count == 0) {
        r.kind = kind;
        r.site = site;
    }
    r.id = id;
    r.x = x;
    r.y = y;
    if (text != NULL) {
        r.text.assign(text, strnlen(text, 60));
        for (char &c : r.text) {
            if (c == '\n' || c == '\r')
                c = ' ';
        }
    }
    r.count++;
}
