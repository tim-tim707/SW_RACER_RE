//
// Pod edits from the HTML pod editor -- see pod_edits.h.
//
#include <glad/glad.h>

#include "pod_edits.h"
#include "pod_fx.h"// pod_fx_auto_points (export)
#include <array>

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <imgui.h>
#include <shlobj.h>// SHGetFolderPathW (Desktop)

extern "C" {
#include <Swr/swrEvent.h>// swrEvent_GetEventCount / swrEvent_GetItem
#include <Swr/swrModel.h>// swrModel_LoadAnimation
#include <globals.h>
#include <types_enums.h>// swrObjTest_FLAG0_*
extern FILE* hook_log;
}

#include "../config.h"
#include "../debug_ui.h"
#include "../node_utils.h"
#include "../replacements.h"// modelid_cstr
#include "../model_replacement.h"// refresh_replacement_models

const std::filesystem::path& pod_workspace() {
    static std::filesystem::path dir;
    static bool done = false;
    if (done)
        return dir;
    done = true;
    wchar_t docs[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, SHGFP_TYPE_CURRENT, docs)))
        return dir;
    std::filesystem::path d = std::filesystem::path(docs) / L"SWEP1R Pod Editor";
    std::error_code ec;
    for (const wchar_t* sub: {L"replacement_models", L"pod_edits", L"export"})
        std::filesystem::create_directories(d / sub, ec);
    if (ec)
        return dir;
    // The bake's input: the game's STOCK model block (the backup once baked models were written
    // into the game's block), refreshed when it changes.
    std::error_code bec;
    const std::filesystem::path src = std::filesystem::exists(MODELBLOCK_ORIGINAL_PATH, bec)
                                              ? std::filesystem::path(MODELBLOCK_ORIGINAL_PATH)
                                              : std::filesystem::path(MODELBLOCK_PATH),
                                dst = d / L"out_modelblock.bin";
    std::error_code e1, e2;
    const auto ssize = std::filesystem::file_size(src, e1), dsize = std::filesystem::file_size(dst, e2);
    if (!e1 && (e2 || ssize != dsize ||
                std::filesystem::last_write_time(src, e1) > std::filesystem::last_write_time(dst, e2)))
        std::filesystem::copy_file(src, dst, std::filesystem::copy_options::overwrite_existing, ec);
    const std::filesystem::path readme = d / L"README.txt";
    if (!std::filesystem::exists(readme, ec)) {
        if (FILE* r = _wfopen(readme.c_str(), L"wb")) {
            fputs("SW_RACER_RE pod editor workspace (made by the mod).\r\n\r\n"
                  "In tools/pod_editor/pod_editor.html, \"Build & install\" asks for a folder: pick this one.\r\n"
                  "It reads out_modelblock.bin (a copy of the game's) and writes:\r\n"
                  "  replacement_models\\<id>.bin   baked pod models (spinning parts, extra cables)\r\n"
                  "  pod_edits\\<Pod>.txt          in-game edits (hides, cables, binder)\r\n"
                  "  pod_edits\\source\\<Pod>.txt   the full edits, to reopen in the editor\r\n"
                  "The mod uses these before the game folder's assets\\replacement_models and assets\\pod_edits.\r\n"
                  "Delete a file here to undo it.\r\n",
                  r);
            fclose(r);
        }
    }
    dir = d;
    fprintf(hook_log, "[PodEdits] workspace %ls\n", d.c_str());
    fflush(hook_log);
    return dir;
}

namespace {
    const char* kDir = "./assets/pod_edits/";
    const char* kExportDir = "./assets/pod_edits/export/";

    // swrRacer_PodVisualData fields the layout lines set (floats from the row start).
    constexpr int kFieldCableCockpit = 9, kFieldCableEngine = 12, kFieldBinder = 15, kFieldExhaust = 21;
    struct ModelEdits {
        bool found = false;
        // Mesh edits by key. "<model>:<offset>" keys (current exports) are byte offsets in the model
        // file; plain hex keys (older exports) are asset-buffer offsets of the file's own model.
        std::unordered_map<uint32_t, PodMeshEdit> meshes_file;
        std::unordered_map<uint32_t, PodMeshEdit> meshes;
        bool layout_set[4] = {};// cable cockpit, cable engine, binder, exhaust trail
        float layout[4][3] = {};
        // "trailnode <model>:<offset> R|L <x> <y> <z>": an extra exhaust trail the bake added (a copy of
        // the stock exhaust node, sharing its trail), placed by the mod at that engine-frame point.
        struct TrailNodeLine {
            uint32_t off;
            int side;// 0 = right engine, 1 = left
            float pos[3];
            float scale[3];// along the exhaust's x (width), y (length), z (height)
        };
        std::vector<TrailNodeLine> trail_nodes;
        // "exhaustscale <sx> <sy> <sz>": the stock exhaust trails scaled about their anchor.
        bool cable_stiff_set = false;// "cablestiff <k>"
        float cable_stiff = 0.3f;
        bool cable_out_set = false;// "cableout <cockpit z> <engine z>"
        float cable_out[2] = {};
        bool exhaust_light_set = false;// "exhaustlight <aim> <reach> <width> <strength>"
        float exhaust_light[4] = {0.7f, 1.0f, 1.0f, 1.0f};
        bool exhaust_scale_set = false;
        float exhaust_scale[3] = {1.0f, 1.0f, 1.0f};
        bool cable2_set[2] = {};// extra cable pair: cockpit end, engine end
        float cable2[2][3] = {};
        // "spinnode <model>:<offset> <rpm> <ax> <ay> <az>": a baked pivot node in an alt model, which
        // the mod turns (alt models' animations never run).
        struct SpinNodeLine {
            uint32_t off;
            float rpm;
            float axis[3];
        };
        std::vector<SpinNodeLine> spin_nodes;
        // Engine effect points: [kind: nozzle, fire spot, dust spot][side: right, left].
        bool fx_set[4] = {};
        std::vector<std::array<float, 4>> fx[4][2];
        bool gamefire_streak_set = false;// "gamefirestreak <length> <rx> <ry> <rz>"
        float gamefire_streak[4] = {1.0f, 0.0f, 0.0f, 0.0f};
        bool cable_rot_set = false;// "cablerot <cockpit rx ry rz> <engine rx ry rz>"
        float cable_rot[6] = {};
        // Per cable ("owncable1".."owncable4"; older files "cable1".."cable4"): own ends and turns.
        bool cable_end_set[4][2] = {};
        float cable_end[4][2][3] = {};
        bool cable_own_rot_set[4] = {};
        float cable_own_rot[4][6] = {};
    };
    std::unordered_map<int, ModelEdits> g_models;
    bool g_apply = true;
    bool g_cable_clear = false;    // push cables out of the engines / cockpit
    float g_cable_margin = 0.12f;  // how far (game units)
    bool g_cable_stiff = true;     // stiff cables: straight out of each end, then a curve
    float g_cable_stiffness = 0.3f;// the straight run, as a share of the cable's length
    // Baked spins: share of the baked RPM while idle, and the speed that reaches the full RPM.
    float g_idle_spin = 0.25f;
    float g_full_spin_speed = 600.0f;
    bool g_any_files = false;// any edit file present (fast path off when not)
    bool g_scanned = false;
    std::string g_status;

    const auto g_t0 = std::chrono::steady_clock::now();

    void load_file(const std::filesystem::path& path, int file_model);

    // Every edit file, from the game folder's assets/pod_edits and the workspace's pod_edits (which
    // wins for a file of the same name). Each file is named after a model; its lines can still edit
    // meshes of other models ("<model>:<offset>" keys -- a pod is drawn from two models).
    void scan_dir() {
        g_scanned = true;
        g_any_files = false;
        g_models.clear();
        std::map<std::string, std::filesystem::path> files;
        std::error_code ec;
        for (const std::filesystem::path& d: {std::filesystem::path(kDir), pod_workspace() / L"pod_edits"}) {
            if (d.empty() || !std::filesystem::is_directory(d, ec))
                continue;
            for (const auto& e: std::filesystem::directory_iterator(d, ec))
                if (e.is_regular_file() && e.path().extension() == ".txt")
                    files[e.path().stem().string()] = e.path();
        }
        for (const auto& [stem, path]: files) {
            int file_model = -1;
            for (int id = 0; id < 323; id++)
                if (modelid_cstr[id] && stem == modelid_cstr[id])
                    file_model = id;
            g_any_files = true;
            load_file(path, file_model);
        }
    }

    bool parse_ranges(const std::string& s, std::vector<PodEditRange>& out) {
        std::stringstream ss(s);
        std::string part;
        while (std::getline(ss, part, ',')) {
            if (part.empty())
                continue;
            unsigned a = 0, b = 0;
            const int n = sscanf(part.c_str(), "%u-%u", &a, &b);
            if (n == 1)
                b = a;
            else if (n != 2 || b < a)
                return false;
            out.push_back({a, b - a + 1});
        }
        return !out.empty();
    }

    // A mesh key: "<model>:<hex offset>" (file offset in that model) or "<hex offset>" (older: asset
    // offset in the file's own model). The edit entry it names, or nullptr.
    PodMeshEdit* mesh_entry(const std::string& key, int file_model) {
        const size_t colon = key.find(':');
        try {
            if (colon != std::string::npos) {
                ModelEdits& me = g_models[std::stoi(key.substr(0, colon))];
                me.found = true;
                return &me.meshes_file[(uint32_t) std::stoul(key.substr(colon + 1), nullptr, 16)];
            }
            if (file_model < 0)
                return nullptr;
            ModelEdits& me = g_models[file_model];
            me.found = true;
            return &me.meshes[(uint32_t) std::stoul(key, nullptr, 16)];
        } catch (...) {
            return nullptr;
        }
    }

    void load_file(const std::filesystem::path& file, int file_model) {
        std::ifstream f(file);
        if (!f)
            return;
        const std::string path = file.string();
        // Layout lines (cables / binder) belong to the pod the file is named after.
        ModelEdits dummy;
        ModelEdits& m = file_model >= 0 ? g_models[file_model] : dummy;
        int n_lines = 0;
        std::string line;
        int lineno = 0, bad = 0;
        while (std::getline(f, line)) {
            lineno++;
            const size_t hash = line.find('#');
            if (hash != std::string::npos)
                line.resize(hash);
            std::istringstream in(line);
            std::string cmd;
            if (!(in >> cmd))
                continue;
            if (cmd == "spin") {
                std::string mesh, ranges;
                PodEditSpin sp{};
                if (in >> mesh >> sp.rpm >> sp.pivot[0] >> sp.pivot[1] >> sp.pivot[2] >> sp.axis[0] >> sp.axis[1] >>
                    sp.axis[2] >> ranges &&
                    parse_ranges(ranges, sp.tris)) {
                    float o[3];
                    if (in >> o[0] >> o[1] >> o[2]) {// optional move, then optional scale
                        sp.offset[0] = o[0], sp.offset[1] = o[1], sp.offset[2] = o[2];
                        float sc;
                        if (in >> sc && sc > 0.0f)
                            sp.scale = sc;
                    }
                    if (PodMeshEdit* e = mesh_entry(mesh, file_model)) {
                        e->spins.push_back(std::move(sp));
                        n_lines++;
                        continue;
                    }
                }
            } else if (cmd == "spinnode") {
                std::string key;
                ModelEdits::SpinNodeLine sl{};
                const size_t colon = (in >> key) ? key.find(':') : std::string::npos;
                if (colon != std::string::npos && in >> sl.rpm >> sl.axis[0] >> sl.axis[1] >> sl.axis[2]) {
                    try {
                        ModelEdits& me = g_models[std::stoi(key.substr(0, colon))];
                        sl.off = (uint32_t) std::stoul(key.substr(colon + 1), nullptr, 16);
                        const float l = std::sqrt(sl.axis[0] * sl.axis[0] + sl.axis[1] * sl.axis[1] + sl.axis[2] * sl.axis[2]);
                        if (l > 1e-6f) {
                            for (float& a: sl.axis)
                                a /= l;
                            me.spin_nodes.push_back(sl);
                            me.found = true;
                            n_lines++;
                            continue;
                        }
                    } catch (...) {
                    }
                }
            } else if (((cmd.size() == 6 && cmd.compare(0, 5, "cable") == 0) ||
                        (cmd.size() == 9 && cmd.compare(0, 8, "owncable") == 0)) &&
                       cmd.back() >= '1' && cmd.back() <= '4' &&
                       !(cmd == "cable2" && (line.find(" cockpit") != std::string::npos ||
                                             line.find(" engine") != std::string::npos))) {
                // ("cable2 cockpit / engine" is the extra pair's line, handled below.)
                const int idx = cmd.back() - '1';
                std::string what;
                float v[6];
                if (in >> what && (what == "cockpit" || what == "engine") && in >> v[0] >> v[1] >> v[2]) {
                    const int end = what == "cockpit" ? 0 : 1;
                    m.cable_end_set[idx][end] = true;
                    for (int j = 0; j < 3; j++)
                        m.cable_end[idx][end][j] = v[j];
                    m.found = true;
                    continue;
                }
                if (what == "rot" && in >> v[0] >> v[1] >> v[2] >> v[3] >> v[4] >> v[5]) {
                    m.cable_own_rot_set[idx] = true;
                    for (int j = 0; j < 6; j++)
                        m.cable_own_rot[idx][j] = v[j];
                    m.found = true;
                    continue;
                }
            } else if (cmd == "gamefirestreak" || cmd == "cablerot") {
                const bool streak = cmd == "gamefirestreak";
                float v[6];
                const int n = streak ? 4 : 6;
                bool ok = true;
                for (int j = 0; j < n && ok; j++)
                    ok = (bool) (in >> v[j]);
                if (ok) {
                    m.found = true;
                    if (streak) {
                        m.gamefire_streak_set = true;
                        for (int j = 0; j < 4; j++)
                            m.gamefire_streak[j] = v[j];
                    } else {
                        m.cable_rot_set = true;
                        for (int j = 0; j < 6; j++)
                            m.cable_rot[j] = v[j];
                    }
                    continue;
                }
            } else if (cmd == "nozzle" || cmd == "firespot" || cmd == "dustspot" || cmd == "gamefire") {
                const int kind = cmd == "nozzle" ? 0 : cmd == "firespot" ? 1 : cmd == "dustspot" ? 2 : 3;
                std::string side;
                std::array<float, 4> v{};
                if (in >> side >> v[0] >> v[1] >> v[2] && (side == "R" || side == "L") && (kind != 0 || in >> v[3])) {
                    m.fx_set[kind] = true;
                    m.found = true;
                    m.fx[kind][side == "R" ? 0 : 1].push_back(v);
                    continue;
                }
            } else if (cmd == "cables") {// "cables extra": a bake option, nothing to do here
                std::string what;
                if (in >> what && what == "extra")
                    continue;
            } else if (cmd == "cable2") {
                std::string which;
                float v[3];
                if (in >> which >> v[0] >> v[1] >> v[2] && (which == "cockpit" || which == "engine")) {
                    const int k = which == "cockpit" ? 0 : 1;
                    m.cable2_set[k] = true;
                    m.found = true;
                    for (int j = 0; j < 3; j++)
                        m.cable2[k][j] = v[j];
                    continue;
                }
            } else if (cmd == "trail") {// an extra trail for the bake; its node comes as "trailnode"
                continue;
            } else if (cmd == "cableout") {
                float v[2];
                if (in >> v[0] >> v[1]) {
                    m.cable_out_set = true;
                    m.found = true;
                    m.cable_out[0] = v[0];
                    m.cable_out[1] = v[1];
                    continue;
                }
            } else if (cmd == "exhaustlight") {
                float v[4];
                if (in >> v[0] >> v[1] >> v[2] >> v[3]) {
                    m.exhaust_light_set = true;
                    m.found = true;
                    for (int j = 0; j < 4; j++)
                        m.exhaust_light[j] = v[j];
                    continue;
                }
            } else if (cmd == "cablestiff") {
                float k;
                if (in >> k) {
                    m.cable_stiff_set = true;
                    m.cable_stiff = k;
                    m.found = true;
                    continue;
                }
            } else if (cmd == "exhaustscale") {
                float v[3];
                if (in >> v[0] >> v[1] >> v[2]) {
                    m.exhaust_scale_set = true;
                    m.found = true;
                    for (int j = 0; j < 3; j++)
                        m.exhaust_scale[j] = v[j];
                    continue;
                }
            } else if (cmd == "trailnode") {
                std::string key, side;
                ModelEdits::TrailNodeLine tl{};
                const size_t colon = (in >> key) ? key.find(':') : std::string::npos;
                if (colon != std::string::npos && in >> side >> tl.pos[0] >> tl.pos[1] >> tl.pos[2] &&
                    (side == "R" || side == "L")) {
                    if (!(in >> tl.scale[0] >> tl.scale[1] >> tl.scale[2]))
                        tl.scale[0] = tl.scale[1] = tl.scale[2] = 1.0f;// optional
                    try {
                        ModelEdits& me = g_models[std::stoi(key.substr(0, colon))];
                        tl.off = (uint32_t) std::stoul(key.substr(colon + 1), nullptr, 16);
                        tl.side = side == "R" ? 0 : 1;
                        me.trail_nodes.push_back(tl);
                        me.found = true;
                        n_lines++;
                        continue;
                    } catch (...) {
                    }
                }
            } else if (cmd == "cable" || cmd == "binder" || cmd == "exhaust") {
                std::string which = cmd;
                if (cmd == "cable")
                    in >> which;
                const int k = which == "cockpit" ? 0 : which == "engine" ? 1 : which == "binder" ? 2 : which == "exhaust" ? 3 : -1;
                float v[3];
                if (k >= 0 && (cmd == "cable") == (k < 2) && in >> v[0] >> v[1] >> v[2]) {
                    m.layout_set[k] = true;
                    m.found = true;
                    for (int j = 0; j < 3; j++)
                        m.layout[k][j] = v[j];
                    continue;
                }
            } else if (cmd == "hide") {
                std::string mesh, ranges;
                std::vector<PodEditRange> r;
                if (in >> mesh >> ranges && parse_ranges(ranges, r)) {
                    if (PodMeshEdit* e = mesh_entry(mesh, file_model)) {
                        e->hidden.insert(e->hidden.end(), r.begin(), r.end());
                        n_lines++;
                        continue;
                    }
                }
            }
            bad++;
            fprintf(hook_log, "[PodEdits] %s line %d not understood\n", path.c_str(), lineno);
        }
        fprintf(hook_log, "[PodEdits] loaded %s (%d mesh edit lines, %d bad lines)\n", path.c_str(), n_lines, bad);
        fflush(hook_log);
    }

    ModelEdits* model_edits(int id) {
        if (!g_scanned)
            scan_dir();
        auto it = g_models.find(id);
        return it != g_models.end() && it->second.found ? &it->second : nullptr;
    }

    // ---- export ----------------------------------------------------------------------------
    struct ExMesh {
        uint32_t key;     // asset offset (dedupe within this export)
        int model;        // the mesh's own model
        int64_t file_off; // offset in that model's file data (-1: unknown)
        int part;
        unsigned tex;
        bool textured;
        rdMatrix44 matrix;
        std::vector<float> pos, uv;
        // Other places the same mesh is drawn (e.g. the left engine: the right engine's meshes
        // under a mirrored transform): part + model matrix of each.
        std::vector<std::pair<int, rdMatrix44>> instances;
    };
    bool g_export_armed = false;
    int g_export_frames = 0;
    std::vector<ExMesh> g_ex;
    std::unordered_set<uint64_t> g_ex_seen;// model << 32 | asset offset
    const swrRace* g_ex_racer = nullptr;
    int g_ex_model = -1;

    bool inv_affine(const rdMatrix44& m, rdMatrix44& out) {
        const float a = m.vA.x, b = m.vA.y, c = m.vA.z;
        const float d = m.vB.x, e = m.vB.y, f = m.vB.z;
        const float g = m.vC.x, h = m.vC.y, i = m.vC.z;
        const float det = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
        if (std::fabs(det) < 1e-12f)
            return false;
        const float k = 1.0f / det;
        out.vA = {(e * i - f * h) * k, (c * h - b * i) * k, (b * f - c * e) * k, 0.0f};
        out.vB = {(f * g - d * i) * k, (a * i - c * g) * k, (c * d - a * f) * k, 0.0f};
        out.vC = {(d * h - e * g) * k, (b * g - a * h) * k, (a * e - b * d) * k, 0.0f};
        const float tx = m.vD.x, ty = m.vD.y, tz = m.vD.z;
        out.vD = {-(tx * out.vA.x + ty * out.vB.x + tz * out.vC.x), -(tx * out.vA.y + ty * out.vB.y + tz * out.vC.y),
                  -(tx * out.vA.z + ty * out.vB.z + tz * out.vC.z), 1.0f};
        return true;
    }
    rdMatrix44 mul(const rdMatrix44& a, const rdMatrix44& b) {
        const float* A = &a.vA.x;
        const float* B = &b.vA.x;
        rdMatrix44 o;
        float* O = &o.vA.x;
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                O[r * 4 + c] = A[r * 4] * B[c] + A[r * 4 + 1] * B[4 + c] + A[r * 4 + 2] * B[8 + c] + A[r * 4 + 3] * B[12 + c];
        return o;
    }
    void xf(const rdMatrix44& m, const float* p, float* out) {
        out[0] = p[0] * m.vA.x + p[1] * m.vB.x + p[2] * m.vC.x + m.vD.x;
        out[1] = p[0] * m.vA.y + p[1] * m.vB.y + p[2] * m.vC.y + m.vD.y;
        out[2] = p[0] * m.vA.z + p[1] * m.vB.z + p[2] * m.vC.z + m.vD.z;
    }

    std::string base64(const unsigned char* d, size_t n) {
        static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string o;
        o.reserve((n + 2) / 3 * 4);
        for (size_t i = 0; i < n; i += 3) {
            const unsigned v = (d[i] << 16) | ((i + 1 < n ? d[i + 1] : 0) << 8) | (i + 2 < n ? d[i + 2] : 0);
            o += t[(v >> 18) & 63];
            o += t[(v >> 12) & 63];
            o += i + 1 < n ? t[(v >> 6) & 63] : '=';
            o += i + 2 < n ? t[v & 63] : '=';
        }
        return o;
    }

    void write_floats(FILE* f, const float* v, size_t n) {
        fputc('[', f);
        for (size_t i = 0; i < n; i++)
            fprintf(f, i ? ",%.5g" : "%.5g", v[i]);
        fputc(']', f);
    }

    // Stock swrRacer_PodVisualData rows, saved before a layout edit first changes a pilot's row.
    float g_stock_rows[23][27];
    bool g_stock_saved[23] = {};
    const float* layout_stock_row(int pilot) {
        return g_stock_saved[pilot] ? g_stock_rows[pilot] : (const float*) &swrRacer_PodVisualData[pilot];
    }

    void write_export() {
        const swrRace* r = g_ex_racer;
        rdMatrix44 inv_pod;
        if (r == nullptr || !inv_affine(r->transform, inv_pod)) {
            g_status = "Export failed: no pod transform.";
            return;
        }
        std::error_code ec;
        std::filesystem::create_directories(kExportDir, ec);
        const char* name = (g_ex_model >= 0 && g_ex_model < 323) ? modelid_cstr[g_ex_model] : "unknown_pod";
        const std::string path = std::string(kExportDir) + name + ".json";
        FILE* f = fopen(path.c_str(), "wb");
        if (f == nullptr) {
            g_status = "Export failed: cannot write " + path;
            return;
        }
        fprintf(f, "{\"format\":\"swr-pod-export-1\",\"model\":\"%s\",", name);
        auto local = [&](const rdMatrix44& m, float out[3]) {
            const float p[3] = {m.vD.x, m.vD.y, m.vD.z};
            xf(inv_pod, p, out);
        };
        float eR[3], eL[3], ck[3];
        local(r->engineXfR, eR);
        local(r->engineXfL, eL);
        local(r->cockpitXf, ck);
        fprintf(f, "\"engineR\":[%.5g,%.5g,%.5g],\"engineL\":[%.5g,%.5g,%.5g],\"cockpit\":[%.5g,%.5g,%.5g],", eR[0], eR[1],
                eR[2], eL[0], eL[1], eL[2], ck[0], ck[1], ck[2]);
        fprintf(f, "\"fourEngines\":%s,", (r->partNodes && r->partNodes[3] && r->partNodes[4]) ? "true" : "false");
        // Pod layout: the pilot's row of the pod table (as the game has it now, and stock), and the
        // cockpit / engine frames (in the pod frame) the cable and binder offsets are in.
        const int pilot = (r->score_ptr && r->score_ptr->pilotId) ? *r->score_ptr->pilotId : -1;
        if (pilot >= 0 && pilot < 23) {
            fprintf(f, "\"pilot\":%d,\"visual\":", pilot);
            write_floats(f, (const float*) &swrRacer_PodVisualData[pilot], 27);
            fputs(",\"visualStock\":", f);
            write_floats(f, layout_stock_row(pilot), 27);
            fputs(",\"frames\":{", f);
            const rdMatrix44* frames[5] = {&r->cockpitXf, &r->engineXfR, &r->engineXfL, &r->engineXfR2, &r->engineXfL2};
            const char* names[5] = {"cockpit", "engineR", "engineL", "engineR2", "engineL2"};
            for (int i = 0; i < 5; i++) {
                const rdMatrix44 m = mul(*frames[i], inv_pod);
                fprintf(f, "%s\"%s\":", i ? "," : "", names[i]);
                write_floats(f, &m.vA.x, 16);
            }
            fputs("},", f);
            // The engine effects' automatic points (engine frames): the editor's starting points.
            fputs("\"fxAuto\":{", f);
            for (int side = 0; side < 2; side++) {
                std::vector<std::array<float, 4>> pts[4];
                pod_fx_auto_points(r, side, pts[0], pts[1], pts[2]);
                {
                    // The game's overheat fire emitter: 2 units behind the engine's origin.
                    const rdMatrix44& e = side == 0 ? r->engineXfR : r->engineXfL;
                    const float d2[3] = {e.vB.x * -2.0f, e.vB.y * -2.0f, e.vB.z * -2.0f};
                    const float* rows[3] = {&e.vA.x, &e.vB.x, &e.vC.x};
                    std::array<float, 4> p{};
                    for (int j = 0; j < 3; j++) {
                        const float l2 = rows[j][0] * rows[j][0] + rows[j][1] * rows[j][1] + rows[j][2] * rows[j][2];
                        p[j] = l2 > 1e-12f ? (d2[0] * rows[j][0] + d2[1] * rows[j][1] + d2[2] * rows[j][2]) / l2 : 0.0f;
                    }
                    pts[3].push_back(p);
                }
                fprintf(f, "%s\"%s\":{", side ? "," : "", side == 0 ? "R" : "L");
                const char* kinds[4] = {"nozzle", "firespot", "dustspot", "gamefire"};
                for (int k = 0; k < 4; k++) {
                    fprintf(f, "%s\"%s\":[", k ? "," : "", kinds[k]);
                    for (size_t i = 0; i < pts[k].size(); i++) {
                        if (i)
                            fputc(',', f);
                        write_floats(f, pts[k][i].data(), 4);
                    }
                    fputc(']', f);
                }
                fputc('}', f);
            }
            fputs("},", f);
        }

        // Textures: raw RGBA, base64.
        fputs("\"textures\":{", f);
        std::unordered_set<unsigned> done;
        GLint prev_tex = 0;
        glGetIntegerv(GL_TEXTURE_BINDING_2D, &prev_tex);
        bool first = true;
        std::vector<unsigned char> px;
        for (const ExMesh& m: g_ex) {
            if (!m.textured || m.tex == 0 || !done.insert(m.tex).second)
                continue;
            glBindTexture(GL_TEXTURE_2D, m.tex);
            GLint w = 0, h = 0;
            glGetTexLevelParameteriv(GL_TEXTURE_2D, 0, GL_TEXTURE_WIDTH, &w);
            glGetTexLevelParameteriv(GL_TEXTURE_2D, 0, GL_TEXTURE_HEIGHT, &h);
            if (w <= 0 || h <= 0 || w > 4096 || h > 4096)
                continue;
            GLint wrap_s = GL_REPEAT, wrap_t = GL_REPEAT;
            glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, &wrap_s);
            glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, &wrap_t);
            px.assign((size_t) w * h * 4, 0);
            glPixelStorei(GL_PACK_ALIGNMENT, 1);
            glGetTexImage(GL_TEXTURE_2D, 0, GL_RGBA, GL_UNSIGNED_BYTE, px.data());
            fprintf(f, "%s\"%u\":{\"w\":%d,\"h\":%d,\"clampS\":%s,\"clampT\":%s,\"rgba\":\"", first ? "" : ",", m.tex, w, h,
                    wrap_s == GL_CLAMP_TO_EDGE ? "true" : "false", wrap_t == GL_CLAMP_TO_EDGE ? "true" : "false");
            const std::string b = base64(px.data(), px.size());
            fwrite(b.data(), 1, b.size(), f);
            fputs("\"}", f);
            first = false;
        }
        glBindTexture(GL_TEXTURE_2D, (GLuint) prev_tex);
        fputs("},", f);

        // Meshes: positions in the pod's frame, plus the mesh->pod matrix (row-vector convention:
        // p_pod = p_mesh * localToPod) so the editor can store pivots in the mesh's own frame.
        fputs("\"meshes\":[", f);
        for (size_t i = 0; i < g_ex.size(); i++) {
            const ExMesh& m = g_ex[i];
            const rdMatrix44 to_pod = mul(m.matrix, inv_pod);
            // "<model>:<file offset>" keys: stable, and they say which model the mesh is in.
            char key[32];
            if (m.file_off >= 0)
                snprintf(key, sizeof(key), "%d:%x", m.model, (unsigned) m.file_off);
            else
                snprintf(key, sizeof(key), "%x", m.key);
            fprintf(f, "%s{\"key\":\"%s\",\"part\":%d,\"texture\":%s%u%s,\"localToPod\":", i ? "," : "", key, m.part,
                    m.textured ? "\"" : "", m.textured ? m.tex : 0u, m.textured ? "\"" : "");
            write_floats(f, &to_pod.vA.x, 16);
            std::vector<float> p(m.pos.size());
            for (size_t v = 0; v + 2 < m.pos.size(); v += 3)
                xf(inv_pod, &m.pos[v], &p[v]);
            fputs(",\"pos\":", f);
            write_floats(f, p.data(), p.size());
            fputs(",\"uv\":", f);
            write_floats(f, m.uv.data(), m.uv.size());
            if (!m.instances.empty()) {
                fputs(",\"instances\":[", f);
                for (size_t k = 0; k < m.instances.size(); k++) {
                    const rdMatrix44 inst = mul(m.instances[k].second, inv_pod);
                    fprintf(f, "%s{\"part\":%d,\"localToPod\":", k ? "," : "", m.instances[k].first);
                    write_floats(f, &inst.vA.x, 16);
                    fputc('}', f);
                }
                fputc(']', f);
            }
            fputc('}', f);
        }
        fputs("]}", f);
        fclose(f);
        std::string where = path;
        if (!pod_workspace().empty()) {
            std::error_code cec;
            const std::filesystem::path ws = pod_workspace() / L"export" / (std::string(name) + ".json");
            if (std::filesystem::copy_file(path, ws, std::filesystem::copy_options::overwrite_existing, cec))
                where = ws.string();
        }
        char buf[768];
        snprintf(buf, sizeof(buf), "Exported %zu meshes, %zu textures to %s", g_ex.size(), done.size(), where.c_str());
        g_status = buf;
        fprintf(hook_log, "[PodEdits] %s\n", buf);
        fflush(hook_log);
    }

    // ---- panel -------------------------------------------------------------------------------
    void draw_panel() {
        ImGui::TextWrapped("Edit pod models in tools/pod_editor/pod_editor.html: export your pod during a race, "
                           "open the JSON in the editor, edit it, then Build & install into the workspace folder "
                           "Desktop\\SWEP1R Pod Editor (the editor can't write into Program Files).");
        if (ImGui::Button(g_export_armed ? "Exporting..." : "Export my pod") && !g_export_armed) {
            g_export_armed = true;
            g_export_frames = 0;
            g_ex.clear();
            g_ex_seen.clear();
            g_ex_racer = nullptr;
            g_ex_model = -1;
            g_status = "Waiting for a race frame...";
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Writes assets/pod_edits/export/<Pod>_pod.json from the next race frame. Best at the "
                              "start line, with nothing hidden or blown off.");
        if (ImGui::Checkbox("Apply pod edits", &g_apply))
            config::set_int("pod_edits", "apply", g_apply ? 1 : 0);
        if (ImGui::Checkbox("Stiff cables", &g_cable_stiff))
            config::set_int("pod_edits", "cable_stiff", g_cable_stiff ? 1 : 0);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Each cable leaves its attach point straight out from the cockpit / engine, then curves\n"
                              "to the other end, like a stiff hose. A pod's own \"cablestiff\" edit overrides the amount.");
        if (g_cable_stiff) {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(120);
            if (ImGui::SliderFloat("##cablestiff", &g_cable_stiffness, 0.0f, 0.6f, "straight %.2f"))
                config::set_float("pod_edits", "cable_stiffness", g_cable_stiffness);
        }
        if (ImGui::Checkbox("Push cables out of the pod", &g_cable_clear))
            config::set_int("pod_edits", "cable_clear", g_cable_clear ? 1 : 0);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Also pushes any bit of a cable that still runs through an engine or the cockpit out of it.");
        if (g_cable_clear) {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(120);
            if (ImGui::SliderFloat("##cablemargin", &g_cable_margin, 0.0f, 1.0f, "gap %.2f"))
                config::set_float("pod_edits", "cable_margin", g_cable_margin);
        }
        if (ImGui::SliderFloat("Baked spin when idle", &g_idle_spin, 0.0f, 1.0f, "%.2f x RPM"))
            config::set_float("pod_edits", "idle_spin", g_idle_spin);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Baked spinning parts turn at this share of their RPM while the pod idles and reach the "
                              "full RPM at the speed below.");
        if (ImGui::SliderFloat("Full spin at speed", &g_full_spin_speed, 100.0f, 1000.0f, "%.0f"))
            config::set_float("pod_edits", "full_spin_speed", g_full_spin_speed);
        ImGui::SameLine();
        if (ImGui::Button("Reload edits")) {
            g_models.clear();
            scan_dir();
            refresh_replacement_models();// newly built models are used from the next model load
            g_status = g_any_files ? "Edits reloaded." : "No edit files in assets/pod_edits/.";
        }
        ImGui::SeparatorText("Game data");
        {
            const auto& repl = current_replacement_models();
            std::string ids;
            for (const auto& [id, path]: repl)
                ids += (ids.empty() ? "" : ", ") + std::to_string(id);
            std::error_code ec;
            const bool written = std::filesystem::exists(MODELBLOCK_ORIGINAL_PATH, ec);
            ImGui::TextWrapped("Baked / replacement models: %s", repl.empty() ? "none" : ids.c_str());
            ImGui::TextDisabled(written ? "out_modelblock.bin holds written models (stock copy kept)."
                                        : "out_modelblock.bin is the stock one.");
            if (ImGui::Button("Write into out_modelblock.bin")) {
                std::string msg;
                write_replacements_into_modelblock(msg);
                g_status = msg;
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Builds the baked models into the game's data/lev01/out_modelblock.bin, so the game\n"
                                  "loads them itself (and the file can be shared). The stock file is kept as\n"
                                  "out_modelblock.original.bin, and every write starts from it: write again after\n"
                                  "each new build. Restart the race to load the models.");
            ImGui::SameLine();
            ImGui::BeginDisabled(!written);
            if (ImGui::Button("Restore original")) {
                std::string msg;
                restore_original_modelblock(msg);
                g_status = msg;
            }
            ImGui::EndDisabled();
        }
        int n = 0;
        for (const auto& [id, m]: g_models)
            if (m.found) {
                ImGui::BulletText("%s: %zu meshes edited", (id >= 0 && id < 323 && modelid_cstr[id]) ? modelid_cstr[id] : "?",
                                  m.meshes.size() + m.meshes_file.size());
                n++;
            }
        if (n == 0)
            ImGui::TextDisabled(g_any_files ? "Edit files found, but nothing in them applies (see the log)."
                                            : "No edit files in assets/pod_edits/ or the workspace's pod_edits.");
        if (!g_status.empty())
            ImGui::TextWrapped("%s", g_status.c_str());
    }
    DebugPanel g_panel = {.category = "Mods", .name = "Pod Editor", .draw = draw_panel, .dev_only = false};
}// namespace

const PodMeshEdit* pod_edits_find(const swrModel_Mesh* mesh) {
    if (!g_scanned)
        scan_dir();
    if (!g_apply || !g_any_files || mesh == nullptr)
        return nullptr;
    MODELID id;
    uint32_t off;
    if (!find_asset_offset(mesh, &id, &off))
        return nullptr;
    ModelEdits* m = model_edits((int) id);
    if (m == nullptr)
        return nullptr;
    MODELID fid;
    uint32_t foff;
    if (!m->meshes_file.empty() && find_model_offset(mesh, &fid, &foff)) {
        auto it = m->meshes_file.find(foff);
        if (it != m->meshes_file.end())
            return &it->second;
    }
    auto it = m->meshes.find(off);
    return it == m->meshes.end() ? nullptr : &it->second;
}

float pod_edits_time() {
    return std::chrono::duration<float>(std::chrono::steady_clock::now() - g_t0).count();
}

bool pod_edits_export_armed() {
    return g_export_armed;
}

void pod_edits_export_mesh(const swrRace* racer, int part, const swrModel_Mesh* mesh, const rdMatrix44& model_matrix,
                           const std::vector<float>& world_pos, const std::vector<float>& uv, unsigned texture,
                           bool textured) {
    if (!g_export_armed || racer == nullptr || (racer->flags0 & swrObjTest_FLAG0_LOCAL) == 0)
        return;
    MODELID id;
    uint32_t off;
    if (!find_asset_offset(mesh, &id, &off))
        return;
    if (!g_ex_seen.insert(((uint64_t) id << 32) | off).second) {
        // Drawn again: keep each distinct placement (one record per mesh, the edits are per mesh).
        for (ExMesh& m: g_ex) {
            if (m.key != off || m.model != (int) id)
                continue;
            auto same = [&](const rdMatrix44& a) {
                const float* x = &a.vA.x;
                const float* y = &model_matrix.vA.x;
                for (int i = 0; i < 16; i++)
                    if (std::fabs(x[i] - y[i]) > 1e-4f)
                        return false;
                return true;
            };
            if (same(m.matrix))
                return;
            for (const auto& [p, mat]: m.instances)
                if (same(mat))
                    return;
            m.instances.push_back({part, model_matrix});
            return;
        }
        return;
    }
    g_ex_racer = racer;
    g_ex_model = (int) id;
    MODELID fid;
    uint32_t foff;
    const int64_t file_off = find_model_offset(mesh, &fid, &foff) ? (int64_t) foff : -1;
    g_ex.push_back({off, (int) id, file_off, part, texture, textured, model_matrix, world_pos, uv});
}

void pod_edits_export_end_frame(bool in_race) {
    if (!g_export_armed)
        return;
    if (!g_ex.empty()) {
        write_export();
        g_export_armed = false;
        g_ex.clear();
        g_ex_seen.clear();
        return;
    }
    (void) in_race;
    if (++g_export_frames > 600) {
        g_export_armed = false;
        g_status = "Nothing exported: start a race (your pod must be on screen), then press Export.";
    }
}

// ---- baked spinning parts: pod model animations, run only during races ----------------------
namespace {
    struct PodAnim {
        swrModel_Animation* anim;
        const char* begin;// owning model's asset start (dropped when the buffer rewinds past it)
        const char* end;  // and end: a racer whose part nodes lie in [begin, end) drives it
        float rate = -1.0f;// smoothed playback rate (< 0: not started)
    };
    std::vector<PodAnim> g_pod_anims;
    constexpr uint32_t kTagPodd = 0x506f6464, kTagData = 0x44617461, kTagAnim = 0x416e696d;

    // Spinning parts baked into an alt model ("spinnode" lines): the game runs no animations in
    // alt models, so the mod turns these pivot nodes itself, keeping their baked scale and move.
    struct SpinNode {
        swrModel_NodeTransformed* node;
        const char* begin;
        const char* end;
        float rpm;
        float axis[3];
        float scale;          // baked scale (the node's matrix rows' length)
        rdVector3 translation;// baked move
        float angle = 0.0f;   // degrees
        float rate = -1.0f;
    };
    std::vector<SpinNode> g_spin_nodes;

    // Extra exhaust trails ("trailnode" lines): copies of a stock exhaust node (partNodes[0x43] right,
    // [0x44] left) sharing its children (the trail ribbon the game scales), placed at their own
    // engine-frame point the way the game places the stock one.
    struct TrailNode {
        swrModel_NodeTransformed* node;
        const char* begin;
        const char* end;
        int side;
        float pos[3];
        float scale[3];
        // On a four-engine pod: which engine on its side the trail sits on (0 = main, 1 = second
        // pair, -1 = not decided yet), and its point in that engine's frame.
        int engine = -1;
        float local[3] = {};
    };
    std::vector<TrailNode> g_trail_nodes;

    // a then b (row vectors).
    rdMatrix44 mat_then(const rdMatrix44& a, const rdMatrix44& b) {
        rdMatrix44 o;
        const rdVector4* ra[4] = {&a.vA, &a.vB, &a.vC, &a.vD};
        rdVector4* ro[4] = {&o.vA, &o.vB, &o.vC, &o.vD};
        for (int i = 0; i < 4; i++) {
            const rdVector4& r = *ra[i];
            *ro[i] = {r.x * b.vA.x + r.y * b.vB.x + r.z * b.vC.x + r.w * b.vD.x, r.x * b.vA.y + r.y * b.vB.y + r.z * b.vC.y + r.w * b.vD.y,
                      r.x * b.vA.z + r.y * b.vB.z + r.z * b.vC.z + r.w * b.vD.z, r.x * b.vA.w + r.y * b.vB.w + r.z * b.vC.w + r.w * b.vD.w};
        }
        return o;
    }
    // Inverse of an affine row-vector matrix; false if singular.
    bool invert_affine(const rdMatrix44& m, rdMatrix44& out) {
        const float a = m.vA.x, b = m.vA.y, c = m.vA.z, d = m.vB.x, e = m.vB.y, f = m.vB.z, g = m.vC.x, h = m.vC.y, i = m.vC.z;
        const float det = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
        if (std::fabs(det) < 1e-12f)
            return false;
        const float k = 1.0f / det;
        out.vA = {(e * i - f * h) * k, (c * h - b * i) * k, (b * f - c * e) * k, 0.0f};
        out.vB = {(f * g - d * i) * k, (a * i - c * g) * k, (c * d - a * f) * k, 0.0f};
        out.vC = {(d * h - e * g) * k, (b * g - a * h) * k, (a * e - b * d) * k, 0.0f};
        const float tx = m.vD.x, ty = m.vD.y, tz = m.vD.z;
        out.vD = {-(tx * out.vA.x + ty * out.vB.x + tz * out.vC.x), -(tx * out.vA.y + ty * out.vB.y + tz * out.vC.y),
                  -(tx * out.vA.z + ty * out.vB.z + tz * out.vC.z), 1.0f};
        return true;
    }
    rdVector3 xf_point(const rdMatrix44& m, const float p[3]) {
        return {m.vD.x + m.vA.x * p[0] + m.vB.x * p[1] + m.vC.x * p[2], m.vD.y + m.vA.y * p[0] + m.vB.y * p[1] + m.vC.y * p[2],
                m.vD.z + m.vA.z * p[0] + m.vB.z * p[1] + m.vC.z * p[2]};
    }
}// namespace

void pod_edits_note_model(swrModel_Header* header, const char* asset_begin, const char* asset_end, int model_id) {
    if (header == nullptr)
        return;
    // Extra exhaust trails listed for this model.
    if (ModelEdits* me = model_edits(model_id)) {
        const char* data = (const char*) header - 4;
        for (const ModelEdits::TrailNodeLine& tl: me->trail_nodes) {
            if (data + tl.off + sizeof(swrModel_NodeTransformed) > asset_end)
                continue;
            auto* node = (swrModel_NodeTransformed*) (data + tl.off);
            if (node->node.type != NODE_TRANSFORMED_WITH_PIVOT && node->node.type != NODE_TRANSFORMED)
                continue;
            g_trail_nodes.push_back({node, asset_begin, asset_end, tl.side, {tl.pos[0], tl.pos[1], tl.pos[2]},
                                     {tl.scale[0], tl.scale[1], tl.scale[2]}});
        }
    }
    // Alt-model spinning parts listed for this model: their nodes, by file offset.
    if (ModelEdits* me = model_edits(model_id)) {
        const char* data = (const char*) header - 4;// the type tag: the model file's first byte
        for (const ModelEdits::SpinNodeLine& sl: me->spin_nodes) {
            if (data + sl.off + sizeof(swrModel_NodeTransformed) > asset_end)
                continue;
            auto* node = (swrModel_NodeTransformed*) (data + sl.off);
            if (node->node.type != NODE_TRANSFORMED_WITH_PIVOT && node->node.type != NODE_TRANSFORMED) {
                fprintf(hook_log, "[PodEdits] spinnode %d:%x is not a transformed node (type %x), skipped\n", model_id,
                        sl.off, node->node.type);
                continue;
            }
            const rdVector3& a = node->transform.rvec;
            SpinNode sn{node, asset_begin, asset_end, sl.rpm, {sl.axis[0], sl.axis[1], sl.axis[2]},
                        std::sqrt(a.x * a.x + a.y * a.y + a.z * a.z), node->transform.scale};
            g_spin_nodes.push_back(sn);
        }
    }
    const uint32_t* words = (const uint32_t*) header;
    if (words[-1] != kTagPodd)// the loader skips the type tag: header points just past it
        return;
    const swrModel_HeaderEntry* e = header->entries;
    while (e->value != 0xFFFFFFFF)
        e++;
    e++;
    if (e->value == kTagData)
        e += 2 + e[1].value;
    if (e->value != kTagAnim)
        return;
    for (e++; e->animation != nullptr; e++)
        g_pod_anims.push_back({e->animation, asset_begin, asset_end});
}

void pod_edits_drop_models_from(const char* asset_begin) {
    std::erase_if(g_pod_anims, [&](const PodAnim& a) { return a.begin >= asset_begin; });
    std::erase_if(g_spin_nodes, [&](const SpinNode& s) { return s.begin >= asset_begin; });
    std::erase_if(g_trail_nodes, [&](const TrailNode& t) { return t.begin >= asset_begin; });
}

namespace {
    constexpr int kEventTest = 0x54657374;// 'Test': one swrRace per racer

    // The racer flying the pod model at [begin, end): its part nodes live in the model.
    const swrRace* racer_of(const char* begin, const char* end) {
        const int n = swrEvent_GetEventCount(kEventTest);
        for (int i = 0; i < n; i++) {
            const swrRace* r = (const swrRace*) swrEvent_GetItem(kEventTest, i);
            if (r == nullptr || r->partNodes == nullptr)
                continue;
            for (int part = 0; part < 75; part++) {// any part (an alt model fills some of the slots)
                const char* p = (const char*) r->partNodes[part];
                if (p != nullptr && p >= begin && p < end)
                    return r;
            }
        }
        return nullptr;
    }
}// namespace

void pod_edits_animations_frame(bool in_race) {
    for (PodAnim& pa: g_pod_anims) {
        swrModel_Animation* a = pa.anim;
        if (!in_race) {
            a->flags = (swrModel_AnimationFlags) (a->flags & ~ANIMATION_ENABLED);
            continue;
        }
        bool registered = false;
        for (int i = 0; i < swrScene_animations_count && !registered; i++)
            registered = swrScene_animations[i] == a;
        if (!registered && swrScene_animations_count < 1000)
            swrModel_LoadAnimation(a);
        a->flags = (swrModel_AnimationFlags) ((a->flags | ANIMATION_ENABLED | ANIMATION_LOOP) & ~ANIMATION_DISABLED);

        // Slow while idling, full baked RPM at speed (eased so throttle blips don't snap it).
        const swrRace* r = racer_of(pa.begin, pa.end);
        float k = 0.0f;
        if (r != nullptr && g_full_spin_speed > 1.0f)
            k = std::fmin(std::fmax(r->speedValue / g_full_spin_speed, 0.0f), 1.25f);
        const float target = g_idle_spin + (1.0f - g_idle_spin) * k;
        const float dt = std::fmin(std::fmax(swrRace_deltaTimeSecs, 0.0f), 0.1f);
        pa.rate = pa.rate < 0.0f ? target : pa.rate + (target - pa.rate) * (1.0f - std::exp(-dt / 0.25f));
        a->animation_speed = pa.rate;
    }

    // Alt-model spinning parts: turned here, at the same speed rule; at rest outside races.
    typedef void(__cdecl * NodeSetTransform_t)(swrModel_NodeTransformed * node, const rdMatrix44* m);
    const auto set_transform = (NodeSetTransform_t) swrModel_NodeSetTransform_ADDR;
    const float dt = std::fmin(std::fmax(swrRace_deltaTimeSecs, 0.0f), 0.1f);
    for (SpinNode& sn: g_spin_nodes) {
        if (!in_race) {
            sn.angle = 0.0f;
            sn.rate = -1.0f;
        } else {
            const swrRace* r = racer_of(sn.begin, sn.end);
            float k = 0.0f;
            if (r != nullptr && g_full_spin_speed > 1.0f)
                k = std::fmin(std::fmax(r->speedValue / g_full_spin_speed, 0.0f), 1.25f);
            const float target = g_idle_spin + (1.0f - g_idle_spin) * k;
            sn.rate = sn.rate < 0.0f ? target : sn.rate + (target - sn.rate) * (1.0f - std::exp(-dt / 0.25f));
            sn.angle = std::fmod(sn.angle + sn.rpm * 6.0f * sn.rate * dt, 360.0f);// rpm * 360 / 60
        }
        // Rows = the basis vectors turned about the axis (Rodrigues), scaled; then the move.
        const float* ax = sn.axis;
        const float t = sn.angle * 3.14159265f / 180.0f, c = std::cos(t), s = std::sin(t);
        rdMatrix44 m{};
        float* rows[3] = {&m.vA.x, &m.vB.x, &m.vC.x};
        for (int i = 0; i < 3; i++) {
            const float v[3] = {i == 0 ? 1.0f : 0.0f, i == 1 ? 1.0f : 0.0f, i == 2 ? 1.0f : 0.0f};
            const float d = ax[0] * v[0] + ax[1] * v[1] + ax[2] * v[2];
            const float cr[3] = {ax[1] * v[2] - ax[2] * v[1], ax[2] * v[0] - ax[0] * v[2], ax[0] * v[1] - ax[1] * v[0]};
            for (int j = 0; j < 3; j++)
                rows[i][j] = (v[j] * c + cr[j] * s + ax[j] * d * (1.0f - c)) * sn.scale;
        }
        m.vD = {sn.translation.x, sn.translation.y, sn.translation.z, 1.0f};
        set_transform(sn.node, &m);
    }
}

namespace {
    // The edits of a pilot's pod that `has` accepts: an edit file may be named after either of
    // its model ids.
    template<class Pred>
    const ModelEdits* pilot_edits(int pilot, Pred has) {
        if (!g_apply || !g_any_files || pilot < 0 || pilot >= 23)
            return nullptr;
        for (const MODELID id: {swrRacer_PodData[pilot].pod_alt_modelID, swrRacer_PodData[pilot].pod_modelID}) {
            const ModelEdits* me = model_edits((int) id);
            if (me && has(*me))
                return me;
        }
        return nullptr;
    }
}// namespace

void pod_edits_extra_cable_values(int pilot, float cockpit[3], float engine[3]) {
    if (!g_scanned)
        scan_dir();
    const float* row = (const float*) &swrRacer_PodVisualData[pilot < 0 || pilot >= 23 ? 0 : pilot];
    for (int j = 0; j < 3; j++) {
        cockpit[j] = row[kFieldCableCockpit + j];
        engine[j] = row[kFieldCableEngine + j];
    }
    engine[2] = -engine[2];// default: the stock engine end mirrored vertically
    const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.cable2_set[0] || m.cable2_set[1]; });
    if (e == nullptr)
        return;
    for (int j = 0; j < 3; j++) {
        if (e->cable2_set[0])
            cockpit[j] = e->cable2[0][j];
        if (e->cable2_set[1])
            engine[j] = e->cable2[1][j];
    }
}

const std::vector<std::array<float, 4>>* pod_edits_fx_points(int pilot, int kind, int side) {
    if (kind < 0 || kind > 3 || side < 0 || side > 1)
        return nullptr;
    if (!g_scanned)
        scan_dir();
    const ModelEdits* e = pilot_edits(pilot, [kind](const ModelEdits& m) { return m.fx_set[kind]; });
    return e ? &e->fx[kind][side] : nullptr;
}

void pod_edits_place_trails(swrRace* player) {
    if (player == nullptr || player->partNodes == nullptr)
        return;
    typedef void(__cdecl * NodeSetTransform_t)(swrModel_NodeTransformed * node, const rdMatrix44* m);
    const auto set_transform = (NodeSetTransform_t) swrModel_NodeSetTransform_ADDR;
    auto scale_rows = [](rdMatrix44& m, const float s[3]) {
        m.vA.x *= s[0], m.vA.y *= s[0], m.vA.z *= s[0];
        m.vB.x *= s[1], m.vB.y *= s[1], m.vB.z *= s[1];
        m.vC.x *= s[2], m.vC.y *= s[2], m.vC.z *= s[2];
    };
    // The stock trails scaled about their anchor (the exhaust node the game just placed).
    const int pilot = (player->score_ptr && player->score_ptr->pilotId) ? *player->score_ptr->pilotId : -1;
    if (const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.exhaust_scale_set; })) {
        for (int side = 0; side < 2; side++) {
            auto* stock = (swrModel_NodeTransformed*) player->partNodes[0x43 + side];
            if (stock == nullptr)
                continue;
            rdMatrix44 m = side == 0 ? player->engineExhaustXfR : player->engineExhaustXfL;
            scale_rows(m, e->exhaust_scale);
            set_transform(stock, &m);
        }
    }
    const bool four = player->partNodes[3] && player->partNodes[4];
    for (TrailNode& t: g_trail_nodes) {
        swrModel_Node* stock = player->partNodes[0x43 + t.side];
        if (stock == nullptr || (const char*) stock < t.begin || (const char*) stock >= t.end)
            continue;// another racer's pod
        // The game's exhaust matrix for that engine (orientation), moved to this trail's point.
        rdMatrix44 m = t.side == 0 ? player->engineExhaustXfR : player->engineExhaustXfL;
        const rdMatrix44& e = t.side == 0 ? player->engineXfR : player->engineXfL;
        const rdMatrix44& e2 = t.side == 0 ? player->engineXfR2 : player->engineXfL2;
        rdVector3 p = xf_point(e, t.pos);
        if (four) {
            // The trail follows the engine it sits on: the main one or the second pair's (which
            // moves on its own). Decided once, from where the point sits the first time.
            if (t.engine < 0) {
                rdMatrix44 inv2;
                const float d1 = (p.x - e.vD.x) * (p.x - e.vD.x) + (p.y - e.vD.y) * (p.y - e.vD.y) + (p.z - e.vD.z) * (p.z - e.vD.z);
                const float d2 = (p.x - e2.vD.x) * (p.x - e2.vD.x) + (p.y - e2.vD.y) * (p.y - e2.vD.y) + (p.z - e2.vD.z) * (p.z - e2.vD.z);
                t.engine = 0;
                if (d2 < d1 && invert_affine(e2, inv2)) {
                    const float w[3] = {p.x, p.y, p.z};
                    const rdVector3 l = xf_point(inv2, w);
                    t.local[0] = l.x, t.local[1] = l.y, t.local[2] = l.z;
                    t.engine = 1;
                }
            }
            if (t.engine == 1) {
                rdMatrix44 inv;
                if (invert_affine(e, inv))
                    m = mat_then(mat_then(m, inv), e2);// the exhaust's orientation, carried by the second engine
                p = xf_point(e2, t.local);
            }
        }
        m.vD.x = p.x;
        m.vD.y = p.y;
        m.vD.z = p.z;
        scale_rows(m, t.scale);
        set_transform(t.node, &m);
        // Shown / hidden with the stock trail (e.g. the engine blown off).
        t.node->node.flags_1 = (t.node->node.flags_1 & ~0x2u) | (stock->flags_1 & 0x2u);
    }
}

void pod_edits_layout_frame() {
    if (!g_scanned)
        scan_dir();
    for (int pilot = 0; pilot < 23; pilot++) {
        float* row = (float*) &swrRacer_PodVisualData[pilot];
        const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) {
            return m.layout_set[0] || m.layout_set[1] || m.layout_set[2] || m.layout_set[3];
        });
        if (e == nullptr) {
            if (g_stock_saved[pilot]) {// edits gone: put the stock values back
                memcpy(row, g_stock_rows[pilot], sizeof(g_stock_rows[pilot]));
                g_stock_saved[pilot] = false;
            }
            continue;
        }
        if (!g_stock_saved[pilot]) {
            memcpy(g_stock_rows[pilot], row, sizeof(g_stock_rows[pilot]));
            g_stock_saved[pilot] = true;
        }
        const int fields[4] = {kFieldCableCockpit, kFieldCableEngine, kFieldBinder, kFieldExhaust};
        for (int k = 0; k < 4; k++)
            for (int j = 0; j < 3; j++)
                row[fields[k] + j] = e->layout_set[k] ? e->layout[k][j] : g_stock_rows[pilot][fields[k] + j];
    }
}

float pod_edits_cable_clearance() {
    return g_cable_clear ? g_cable_margin : -1.0f;
}

bool pod_edits_gamefire_streak(int pilot, float out[4]) {
    const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.gamefire_streak_set; });
    if (e == nullptr)
        return false;
    for (int j = 0; j < 4; j++)
        out[j] = e->gamefire_streak[j];
    return true;
}

bool pod_edits_cable_end(int pilot, int index, int end, float out[3]) {
    if (index < 0 || index > 3 || end < 0 || end > 1)
        return false;
    const ModelEdits* e =
        pilot_edits(pilot, [index, end](const ModelEdits& m) { return m.cable_end_set[index][end]; });
    if (e == nullptr)
        return false;
    for (int j = 0; j < 3; j++)
        out[j] = e->cable_end[index][end][j];
    return true;
}

bool pod_edits_cable_own_rot(int pilot, int index, float out[6]) {
    if (index < 0 || index > 3)
        return false;
    const ModelEdits* e = pilot_edits(pilot, [index](const ModelEdits& m) { return m.cable_own_rot_set[index]; });
    if (e == nullptr)
        return false;
    for (int j = 0; j < 6; j++)
        out[j] = e->cable_own_rot[index][j];
    return true;
}

bool pod_edits_cable_rot(int pilot, float out[6]) {
    for (int j = 0; j < 6; j++)
        out[j] = 0.0f;
    const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.cable_rot_set; });
    if (e == nullptr)
        return false;
    for (int j = 0; j < 6; j++)
        out[j] = e->cable_rot[j];
    return true;
}

void pod_edits_cable_out(int pilot, float out[2]) {
    out[0] = out[1] = 0.0f;
    if (const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.cable_out_set; })) {
        out[0] = e->cable_out[0];
        out[1] = e->cable_out[1];
    }
}

bool pod_edits_exhaust_light(int pilot, float out[4]) {
    const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.exhaust_light_set; });
    if (e == nullptr)
        return false;
    for (int j = 0; j < 4; j++)
        out[j] = e->exhaust_light[j];
    return true;
}

float pod_edits_cable_stiffness(int pilot) {
    if (!g_cable_stiff)
        return -1.0f;
    if (const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.cable_stiff_set; }))
        return e->cable_stiff;
    return g_cable_stiffness;
}

void pod_edits_register_panel() {
    pod_workspace();// create it (and copy the model block) at startup
    g_apply = config::get_int("pod_edits", "apply", 1) != 0;
    g_idle_spin = config::get_float("pod_edits", "idle_spin", 0.25f);
    g_cable_clear = config::get_int("pod_edits", "cable_clear", 0) != 0;
    g_cable_stiff = config::get_int("pod_edits", "cable_stiff", 1) != 0;
    g_cable_stiffness = config::get_float("pod_edits", "cable_stiffness", 0.3f);
    g_cable_margin = config::get_float("pod_edits", "cable_margin", 0.12f);
    g_full_spin_speed = config::get_float("pod_edits", "full_spin_speed", 600.0f);
    debug_ui_register(&g_panel);
}
