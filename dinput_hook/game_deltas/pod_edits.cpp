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
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <imgui.h>
#include <simdjson.h>// edits files (JSON)
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
#include "../camera/player_camera.h"// playercam_FovOffset (export: the camera preview's FOV)
#include "../imgui_utils.h"         // imgui_state.fov_scale (export: the camera preview's FOV)
#include "../node_utils.h"
#include "../replacements.h"// modelid_cstr
#include "../model_replacement.h"// refresh_replacement_models
#include "../math_manipulation.h"

using math_manipulation::invert_affine;
using math_manipulation::mat_then;
using math_manipulation::v3;
using math_manipulation::xf_point;

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
        // Camera offsets (further, higher), game units: [0] chase near (pod.chaseCamNear), [1] chase
        // far (pod.chaseCamFar), [2] looking behind with Tab (pod.rearCam).
        bool cam_set[3] = {};
        float cam[3][2] = {};
        bool height_set = false;// pod.height dz: the drawn pod raised / lowered (visual only)
        float height = 0.0f;
        bool engine_gap_set = false;// pod.engineGap k: the engines' sideways spacing, x the stock one
        float engine_gap = 1.0f;
        bool cockpit_gap_set = false;// "cockpitgap <k>": the cockpit's distance from the engines, x stock
        float cockpit_gap = 1.0f;
        bool cockpit_move_set = false;// "cockpitmove <x> <y> <z>": the cockpit moved (pod frame: right, forward, up)
        float cockpit_move[3] = {};
        // trailNodes { node: "<model>:<offset>", side, pos, scale }: an extra exhaust trail the bake added (a copy of
        // the stock exhaust node, sharing its trail), placed by the mod at that engine-frame point.
        struct TrailNodeLine {
            uint32_t off;
            int side;// 0 = right engine, 1 = left
            float pos[3];
            float scale[3];// along the exhaust's x (width), y (length), z (height)
        };
        std::vector<TrailNodeLine> trail_nodes;
        // "exhaustscale <sx> <sy> <sz>": the stock exhaust trails scaled about their anchor.
        bool exhaust_light_set = false;// effects.exhaustLight { aim, reach, width, strength }
        float exhaust_light[4] = {0.7f, 1.0f, 1.0f, 1.0f};
        bool nozzle_flame_set = false;// effects.nozzleFlame { width, length, height }: the nozzle flame cones' size (x stock)
        float nozzle_flame[3] = {1.0f, 1.0f, 1.0f};
        bool exhaust_scale_set = false;
        float exhaust_scale[3] = {1.0f, 1.0f, 1.0f};
        bool cable2_set[2] = {};// extra cable pair: cockpit end, engine end
        float cable2[2][3] = {};
        // spinNodes { node: "<model>:<offset>", rpm, axis }: a baked pivot node in an alt model, which
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
        bool gamefire_streak_set = false;// effects.gameFireStreak { length, turn }
        float gamefire_streak[4] = {1.0f, 0.0f, 0.0f, 0.0f};
        std::vector<float> nozzle_len[2];// per edited nozzle (same order as fx[0]): its flame's length (x stock)
        std::vector<float> nozzle_hgt[2];// ... its height (vertical size, x its radius: 1 = round)
        std::vector<float> nozzle_wid[2];// ... and its width (horizontal size, x its radius: 1 = round)
        // Per cable (layout.ownCables, cable 1..4): own ends.
        bool cable_end_set[4][2] = {};
        float cable_end[4][2][3] = {};
    };
    std::unordered_map<int, ModelEdits> g_models;
    bool g_apply = true;
    bool g_cable_clear = false;    // push cables out of the engines / cockpit
    float g_cable_margin = 0.12f;  // how far (game units)
    // Baked spins: share of the baked RPM while idle, and the speed that reaches the full RPM.
    float g_idle_spin = 0.25f;
    float g_full_spin_speed = 600.0f;
    bool g_any_files = false;// any edit file present (fast path off when not)
    bool g_scanned = false;
    std::string g_status;

    const auto g_t0 = std::chrono::steady_clock::now();

    void load_file(const std::filesystem::path& path, int file_model);
    void load_edits(const std::string& text, const std::string& path, int file_model);

    // Edits a model carries inside its own data: Build appends the pod's in-game edits to the model it
    // writes, so a .bin passed to another player brings its cables, binder, exhaust, effects and
    // cameras with it (and they survive "Write into out_modelblock.bin"). Read when the model loads
    // (pod_edits_note_model); used like an edit file named after that model, unless such a file is
    // newer. `when`: the time of the file the model came from (its .bin, or out_modelblock.bin).
    struct EmbeddedEdits {
        std::string text;
        std::filesystem::file_time_type when{};
        std::string source;
    };
    std::map<int, EmbeddedEdits> g_embedded;

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
                if (e.is_regular_file() && e.path().extension() == ".json")
                    files[e.path().stem().string()] = e.path();
        }
        std::set<int> from_file;
        for (const auto& [stem, path]: files) {
            int file_model = -1;
            for (int id = 0; id < 323; id++)
                if (modelid_cstr[id] && stem == modelid_cstr[id])
                    file_model = id;
            // The model carries its own edits, written after this file: those win (a .bin someone
            // sent over is newer than an old edit file of the same pod here).
            if (file_model >= 0) {
                const auto it = g_embedded.find(file_model);
                std::error_code tec;
                const auto t = std::filesystem::last_write_time(path, tec);
                if (it != g_embedded.end() && (tec || t < it->second.when)) {
                    fprintf(hook_log, "[PodEdits] %s is older than the edits model %d carries: using those\n",
                            path.string().c_str(), file_model);
                    continue;
                }
                from_file.insert(file_model);
            }
            g_any_files = true;
            load_file(path, file_model);
        }
        for (const auto& [id, e]: g_embedded) {
            if (from_file.count(id))
                continue;
            g_any_files = true;
            load_edits(e.text, e.source, id);
        }
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
        std::ifstream f(file, std::ios::binary);
        if (f)
            load_edits(std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()), file.string(), file_model);
    }

    // ---- reading an edits document (JSON; written by tools/pod_editor, see bake.js "edits documents")
    using simdjson::dom::array;
    using simdjson::dom::element;
    using simdjson::dom::object;

    bool json_float(element e, float& out) {
        double d;
        if (e.get(d) == simdjson::SUCCESS) {
            out = (float) d;
            return true;
        }
        int64_t i;
        if (e.get(i) == simdjson::SUCCESS) {
            out = (float) i;
            return true;
        }
        return false;
    }
    // obj[key] as a number; false if missing or not a number.
    bool json_float(object o, const char* key, float& out) {
        element e;
        return o[key].get(e) == simdjson::SUCCESS && json_float(e, out);
    }
    // obj[key] (or the element itself when key is null) as n numbers.
    bool json_floats(element e, float* out, size_t n) {
        array a;
        if (e.get(a) != simdjson::SUCCESS || a.size() < n)
            return false;
        size_t i = 0;
        for (element v: a) {
            if (i == n)
                break;
            if (!json_float(v, out[i++]))
                return false;
        }
        return i == n;
    }
    bool json_floats(object o, const char* key, float* out, size_t n) {
        element e;
        return o[key].get(e) == simdjson::SUCCESS && json_floats(e, out, n);
    }
    std::string json_string(object o, const char* key) {
        std::string_view s;
        return o[key].get(s) == simdjson::SUCCESS ? std::string(s) : std::string();
    }
    // [[first, last], ...] face ranges.
    bool json_faces(object o, std::vector<PodEditRange>& out) {
        array a;
        if (o["faces"].get(a) != simdjson::SUCCESS)
            return false;
        for (element r: a) {
            float v[2];
            if (!json_floats(r, v, 2) || v[0] < 0.0f || v[1] < v[0])
                return false;
            out.push_back({(uint32_t) v[0], (uint32_t) (v[1] - v[0]) + 1});
        }
        return !out.empty();
    }
    // A "<model>:<hex offset>" node key; false if it isn't one.
    bool json_node_key(const std::string& key, int& model, uint32_t& off) {
        const size_t colon = key.find(':');
        if (colon == std::string::npos)
            return false;
        try {
            model = std::stoi(key.substr(0, colon));
            off = (uint32_t) std::stoul(key.substr(colon + 1), nullptr, 16);
            return true;
        } catch (...) {
            return false;
        }
    }

    void load_edits(const std::string& text, const std::string& path, int file_model) {
        simdjson::dom::parser parser;
        element root_el;
        object root;
        if (parser.parse(text).get(root_el) != simdjson::SUCCESS || root_el.get(root) != simdjson::SUCCESS ||
            json_string(root, "format") != "swr-pod-edits") {
            fprintf(hook_log, "[PodEdits] %s is not a pod edits file (JSON, \"format\": \"swr-pod-edits\"): skipped\n", path.c_str());
            fflush(hook_log);
            return;
        }
        // Layout, pod and effect settings belong to the pod the file is named after.
        ModelEdits dummy;
        ModelEdits& m = file_model >= 0 ? g_models[file_model] : dummy;
        int n_lines = 0, bad = 0;

        // Spin / hide groups: one line per mesh, in that mesh's own frame.
        array groups;
        if (root["groups"].get(groups) == simdjson::SUCCESS)
            for (element g_el: groups) {
                object g;
                array lines;
                if (g_el.get(g) != simdjson::SUCCESS || g["lines"].get(lines) != simdjson::SUCCESS)
                    continue;
                const std::string type = json_string(g, "type");
                for (element l_el: lines) {
                    object l;
                    std::vector<PodEditRange> faces;
                    if (l_el.get(l) != simdjson::SUCCESS || !json_faces(l, faces)) {
                        bad++;
                        continue;
                    }
                    PodMeshEdit* e = mesh_entry(json_string(l, "mesh"), file_model);
                    if (e == nullptr) {
                        bad++;
                        continue;
                    }
                    if (type == "hide") {
                        e->hidden.insert(e->hidden.end(), faces.begin(), faces.end());
                        n_lines++;
                    } else if (type == "spin") {
                        PodEditSpin sp{};
                        if (!json_float(l, "rpm", sp.rpm) || !json_floats(l, "pivot", sp.pivot, 3) ||
                            !json_floats(l, "axis", sp.axis, 3)) {
                            bad++;
                            continue;
                        }
                        sp.tris = std::move(faces);
                        json_floats(l, "offset", sp.offset, 3);// optional move, mesh frame
                        float sc;
                        if (json_float(l, "scale", sc) && sc > 0.0f)
                            sp.scale = sc;
                        e->spins.push_back(std::move(sp));
                        n_lines++;
                    }
                }
            }

        // Nodes Build added to a model, which the mod drives: alt-model spinning parts and extra trails.
        array nodes;
        if (root["spinNodes"].get(nodes) == simdjson::SUCCESS)
            for (element n_el: nodes) {
                object n;
                ModelEdits::SpinNodeLine sl{};
                int model;
                if (n_el.get(n) != simdjson::SUCCESS || !json_node_key(json_string(n, "node"), model, sl.off) ||
                    !json_float(n, "rpm", sl.rpm) || !json_floats(n, "axis", sl.axis, 3)) {
                    bad++;
                    continue;
                }
                const float l = std::sqrt(sl.axis[0] * sl.axis[0] + sl.axis[1] * sl.axis[1] + sl.axis[2] * sl.axis[2]);
                if (l <= 1e-6f) {
                    bad++;
                    continue;
                }
                for (float& a: sl.axis)
                    a /= l;
                ModelEdits& me = g_models[model];
                me.spin_nodes.push_back(sl);
                me.found = true;
                n_lines++;
            }
        if (root["trailNodes"].get(nodes) == simdjson::SUCCESS)
            for (element n_el: nodes) {
                object n;
                ModelEdits::TrailNodeLine tl{};
                int model;
                const std::string side = n_el.get(n) == simdjson::SUCCESS ? json_string(n, "side") : std::string();
                if ((side != "R" && side != "L") || !json_node_key(json_string(n, "node"), model, tl.off) ||
                    !json_floats(n, "pos", tl.pos, 3)) {
                    bad++;
                    continue;
                }
                if (!json_floats(n, "scale", tl.scale, 3))
                    tl.scale[0] = tl.scale[1] = tl.scale[2] = 1.0f;
                tl.side = side == "R" ? 0 : 1;
                ModelEdits& me = g_models[model];
                me.trail_nodes.push_back(tl);
                me.found = true;
                n_lines++;
            }

        // Cable / binder ends and the exhaust trails' anchor (swrRacer_PodVisualData), per-cable ends,
        // the extra cable pair.
        object layout;
        if (root["layout"].get(layout) == simdjson::SUCCESS) {
            const char* names[4] = {"cableCockpit", "cableEngine", "binder", "exhaust"};
            for (int k = 0; k < 4; k++)
                if (json_floats(layout, names[k], m.layout[k], 3))
                    m.layout_set[k] = m.found = true;
            if (json_floats(layout, "exhaustScale", m.exhaust_scale, 3))
                m.exhaust_scale_set = m.found = true;
            array own;
            if (layout["ownCables"].get(own) == simdjson::SUCCESS)
                for (element c_el: own) {
                    object c;
                    float idx;
                    if (c_el.get(c) != simdjson::SUCCESS || !json_float(c, "cable", idx) || idx < 1.0f || idx > 4.0f)
                        continue;
                    const int i = (int) idx - 1;
                    if (json_floats(c, "cockpit", m.cable_end[i][0], 3))
                        m.cable_end_set[i][0] = m.found = true;
                    if (json_floats(c, "engine", m.cable_end[i][1], 3))
                        m.cable_end_set[i][1] = m.found = true;
                }
            object extra;
            if (layout["extraCables"].get(extra) == simdjson::SUCCESS) {
                if (json_floats(extra, "cockpit", m.cable2[0], 3))
                    m.cable2_set[0] = m.found = true;
                if (json_floats(extra, "engine", m.cable2[1], 3))
                    m.cable2_set[1] = m.found = true;
            }
        }

        // The whole pod (visual / camera only): height, engine / cockpit spacing, cameras.
        object pod;
        if (root["pod"].get(pod) == simdjson::SUCCESS) {
            if (json_float(pod, "height", m.height))
                m.height_set = m.found = true;
            float k;
            if (json_float(pod, "engineGap", k) && k > 0.0f)
                m.engine_gap = k, m.engine_gap_set = m.found = true;
            if (json_float(pod, "cockpitGap", k) && k > 0.0f)
                m.cockpit_gap = k, m.cockpit_gap_set = m.found = true;
            if (json_floats(pod, "cockpitMove", m.cockpit_move, 3))
                m.cockpit_move_set = m.found = true;
            const char* cams[3] = {"chaseCamNear", "chaseCamFar", "rearCam"};
            for (int c = 0; c < 3; c++)
                if (json_floats(pod, cams[c], m.cam[c], 2))
                    m.cam_set[c] = m.found = true;
        }

        // Engine effects: the points of each kind (in its engine's frame) and the effect settings.
        object fx;
        if (root["effects"].get(fx) == simdjson::SUCCESS) {
            const char* kinds[4] = {"nozzles", "fireSpots", "dustSpots", "gameFire"};
            for (int kind = 0; kind < 4; kind++) {
                object pts;
                if (fx[kinds[kind]].get(pts) != simdjson::SUCCESS)
                    continue;
                m.fx_set[kind] = m.found = true;
                for (int side = 0; side < 2; side++) {
                    array list;
                    if (pts[side == 0 ? "R" : "L"].get(list) != simdjson::SUCCESS)
                        continue;
                    for (element p_el: list) {
                        object p;
                        std::array<float, 4> v{};
                        if (p_el.get(p) != simdjson::SUCCESS || !json_floats(p, "pos", v.data(), 3)) {
                            bad++;
                            continue;
                        }
                        if (kind == 0) {// a nozzle: its size, and its flame's length / height / width (x stock)
                            float f[3] = {1.0f, 1.0f, 1.0f};
                            json_float(p, "size", v[3]);
                            const char* keys[3] = {"length", "height", "width"};
                            for (int j = 0; j < 3; j++)
                                if (!json_float(p, keys[j], f[j]) || !(f[j] > 0.0f))
                                    f[j] = 1.0f;
                            m.nozzle_len[side].push_back(f[0]);
                            m.nozzle_hgt[side].push_back(f[1]);
                            m.nozzle_wid[side].push_back(f[2]);
                        }
                        m.fx[kind][side].push_back(v);
                    }
                }
            }
            object o;
            if (fx["nozzleFlame"].get(o) == simdjson::SUCCESS) {
                const char* keys[3] = {"width", "length", "height"};
                for (int j = 0; j < 3; j++)
                    if (!json_float(o, keys[j], m.nozzle_flame[j]) || !(m.nozzle_flame[j] > 0.0f))
                        m.nozzle_flame[j] = 1.0f;
                m.nozzle_flame_set = m.found = true;
            }
            if (fx["exhaustLight"].get(o) == simdjson::SUCCESS) {
                const char* keys[4] = {"aim", "reach", "width", "strength"};
                for (int j = 0; j < 4; j++)
                    json_float(o, keys[j], m.exhaust_light[j]);
                m.exhaust_light_set = m.found = true;
            }
            if (fx["gameFireStreak"].get(o) == simdjson::SUCCESS) {
                json_float(o, "length", m.gamefire_streak[0]);
                json_floats(o, "turn", m.gamefire_streak + 1, 3);
                m.gamefire_streak_set = m.found = true;
            }
        }
        fprintf(hook_log, "[PodEdits] loaded %s (%d mesh / node edits, %d not understood)\n", path.c_str(), n_lines, bad);
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
    // The pod's ride height (physics: never changed here), exported so the editor can show the ground.
    float hover_stock(int pilot) {
        return swrRacer_PodHandlingData[pilot].hoverHeight;
    }

    void write_export() {
        const swrRace* r = g_ex_racer;
        rdMatrix44 inv_pod;
        if (r == nullptr || !invert_affine(r->transform, inv_pod)) {
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
        // Baked models in use while exporting: their meshes sit at other offsets than the stock
        // models the editor's Build reads, so the editor warns and won't build from this export.
        {
            fputs("\"baked\":[", f);
            bool first = true;
            for (const auto& [id, path]: current_replacement_models()) {
                fprintf(f, "%s%d", first ? "" : ",", id);
                first = false;
            }
            std::error_code bec;
            fprintf(f, "],\"bakedBlock\":%s,", std::filesystem::exists(MODELBLOCK_ORIGINAL_PATH, bec) ? "true" : "false");
        }
        auto local = [&](const rdMatrix44& m, float out[3]) {
            const rdVector3 p = xf_point(inv_pod, v3(m.vD));
            out[0] = p.x, out[1] = p.y, out[2] = p.z;
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
            fprintf(f, ",\"hover\":[%.5g,%.5g]", r->podStats.hoverHeight, hover_stock(pilot));
            // The look-behind (Tab) camera's size: the racer float right after its stats (0xa8); the
            // chase camera puts the camera 2x it ahead of the pod and 0.2x it up while looking back.
            float rear_cam;
            memcpy(&rear_cam, (const char*) r + 0xa8, sizeof(rear_cam));
            fprintf(f, ",\"rearCam\":%.5g", rear_cam);
            // How the game draws its view, for the editor's camera preview: the race cameras' FOV
            // (100 degrees horizontal at 4:3, plus the player camera's FOV offset), the user FOV
            // scale the renderer applies (Hor+), and the window's aspect.
            const float aspect = swrDisplay_screenHeight > 0 ? (float) swrDisplay_screenWidth / (float) swrDisplay_screenHeight
                                                             : 4.0f / 3.0f;
            fprintf(f, ",\"view\":{\"fov\":%.5g,\"fovScale\":%.5g,\"aspect\":%.5g}", 100.0f + playercam_FovOffset(),
                    imgui_state.fov_scale > 0.0f ? imgui_state.fov_scale : 1.0f, aspect);
            fputs(",\"frames\":{", f);
            const rdMatrix44* frames[5] = {&r->cockpitXf, &r->engineXfR, &r->engineXfL, &r->engineXfR2, &r->engineXfL2};
            const char* names[5] = {"cockpit", "engineR", "engineL", "engineR2", "engineL2"};
            for (int i = 0; i < 5; i++) {
                const rdMatrix44 m = mat_then(*frames[i], inv_pod);
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
        // The base models (the stock block's entries, as the editor's Build reads them) the meshes
        // below sit in: Build bakes against these, so it never disagrees with the export.
        {
            std::set<int> ids;
            for (const ExMesh& m: g_ex)
                if (m.file_off >= 0)
                    ids.insert(m.model);
            fputs("\"baseModels\":{", f);
            bool first_base = true;
            // As loaded: a baked replacement (or a model written into the game's block) is what the
            // meshes above come from, so Build can rebuild on top of it (e.g. an older .bin put back).
            // stockFp: the game's own base model, which Build stamps the result with.
            for (const int id: ids) {
                std::vector<uint8_t> mask, data, smask, sdata;
                if (!read_loaded_model(id, mask, data))
                    continue;
                const std::string fp = model_fingerprint(mask, data);
                const std::string stock_fp = read_base_model(id, smask, sdata) ? model_fingerprint(smask, sdata) : fp;
                fprintf(f, "%s\"%d\":{\"fp\":\"%s\",\"stockFp\":\"%s\",\"mask\":\"%s\",\"data\":\"%s\"}",
                        first_base ? "" : ",", id, fp.c_str(), stock_fp.c_str(), base64(mask.data(), mask.size()).c_str(),
                        base64(data.data(), data.size()).c_str());
                first_base = false;
            }
            fputs("},", f);
            // The edits text each model is driven by now (carried in the model, else the winning edit
            // file): a .bin without carried edits still brings its spinning parts, cables, ... to the editor.
            fputs("\"edits\":{", f);
            bool first_edit = true;
            for (const int id: ids) {
                std::string text;
                const auto it = g_embedded.find(id);
                if (it != g_embedded.end())
                    text = it->second.text;
                else if (modelid_cstr[id]) {
                    for (const std::filesystem::path& d: {pod_workspace() / L"pod_edits", std::filesystem::path(kDir)}) {
                        std::ifstream in(d / (std::string(modelid_cstr[id]) + ".json"), std::ios::binary);
                        if (!in)
                            continue;
                        text.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
                        break;
                    }
                }
                if (text.empty())
                    continue;
                std::string esc;
                for (const char c: text) {
                    if (c == '"' || c == '\\') { esc += '\\'; esc += c; }
                    else if (c == '\n') esc += "\\n";
                    else if (c == '\r') {}
                    else if (c == '\t') esc += "\\t";
                    else esc += c;
                }
                fprintf(f, "%s\"%d\":\"%s\"", first_edit ? "" : ",", id, esc.c_str());
                first_edit = false;
            }
            fputs("},", f);
        }
        fputs("\"meshes\":[", f);
        for (size_t i = 0; i < g_ex.size(); i++) {
            const ExMesh& m = g_ex[i];
            const rdMatrix44 to_pod = mat_then(m.matrix, inv_pod);
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
            for (size_t v = 0; v + 2 < m.pos.size(); v += 3) {
                const rdVector3 q = xf_point(inv_pod, {m.pos[v], m.pos[v + 1], m.pos[v + 2]});
                p[v] = q.x, p[v + 1] = q.y, p[v + 2] = q.z;
            }
            fputs(",\"pos\":", f);
            write_floats(f, p.data(), p.size());
            fputs(",\"uv\":", f);
            write_floats(f, m.uv.data(), m.uv.size());
            if (!m.instances.empty()) {
                fputs(",\"instances\":[", f);
                for (size_t k = 0; k < m.instances.size(); k++) {
                    const rdMatrix44 inst = mat_then(m.instances[k].second, inv_pod);
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

    // ---- motion recording: the pod editor's Idle / Top speed preview replays these -----------------
    // For a few seconds, 30 times a second: the cockpit's and each engine's frame in the pod's frame
    // (idle: the pod's frame when recording started, so its own hover bob is in it; top speed: the pod's
    // frame each moment). Written to export/<Pod>_idle.motion.json / <Pod>_top.motion.json.
    struct MotionRec {
        int kind = -1;// 0 idle, 1 top speed; -1 = not recording
        bool waiting = false;// top speed: until the pod is flat out
        float t = 0.0f, next = 0.0f;
        rdMatrix44 inv_ref{};
        std::vector<float> frames;// per sample: 5 parts x 16 floats
        std::string name;
    } g_rec;
    constexpr float kRecSecs = 4.0f, kRecStep = 1.0f / 30.0f;

    // Scrolling textures (binder beam, exhaust dust, flames ...): the game moves a mesh material's
    // texture_offset itself (swrModel_MeshMaterialSetTextureUVOffset / scroll animations). Every mesh the
    // export lists is watched while a motion is recorded, and its measured scroll rate (texture widths /
    // heights per second) goes into the motion file for the editor to animate. Pointers are only used
    // while a recording runs in a race, and dropped when it ends.
    struct ScrollProbe {
        std::string key;
        const swrModel_MeshMaterial* mat;
        int16_t last[2];
        bool have = false;
        double acc[2] = {0, 0};
    };
    std::vector<ScrollProbe> g_probes;
    double g_probe_secs = 0.0;

    // Where each exported mesh is while a motion records (mesh -> pod frame, per sample): parts the game
    // moves itself (steering flaps, spinning fans, pistons) need their own frames, not just the main
    // parts'. Filled by the renderer (pod_edits_record_mesh), sampled by tick_recording.
    struct MeshMotion {
        std::string key;
        int part;
        rdMatrix44 cur{};
        bool seen = false;     // drawn since the last sample
        bool have_last = false;// has frames
        size_t lead = 0;       // samples before its first sighting (filled in with the first frame)
        std::vector<float> frames;
    };
    std::vector<MeshMotion> g_mmot;
    std::unordered_map<const swrModel_Mesh*, size_t> g_mmot_idx;

    void probe_reset() {
        for (MeshMotion& mo: g_mmot) {
            mo.frames.clear();
            mo.have_last = false;
            mo.lead = 0;
        }
        for (ScrollProbe& pr: g_probes) {
            pr.have = false;
            pr.acc[0] = pr.acc[1] = 0.0;
        }
        g_probe_secs = 0.0;
    }
    void probe_sample(float dt) {
        for (ScrollProbe& pr: g_probes) {
            const swrModel_MaterialTexture* mt = pr.mat->material_texture;
            if (mt == nullptr)
                continue;
            for (int c = 0; c < 2; c++) {
                const int res = mt->res[c];
                const int16_t cur = pr.mat->texture_offset[c];
                if (pr.have && res > 1) {
                    int d = (int) cur - (int) pr.last[c];
                    if (d > res / 2)
                        d -= res;
                    if (d < -res / 2)
                        d += res;
                    pr.acc[c] += (double) d / res;
                }
                pr.last[c] = cur;
            }
            pr.have = true;
        }
        g_probe_secs += dt;
    }
    // "Export my pod" also records the idle motion (right away: the pod sits on the start line) and then
    // the top-speed motion (once the pod is flat out), so no extra buttons are needed.
    bool g_auto_motion = true;
    bool g_rec_chain = false;// the idle recording running now is followed by the top-speed one

    swrRace* local_racer() {
        const int n = swrEvent_GetEventCount(0x54657374);// 'Test': one per racer
        for (int i = 0; i < n; i++) {
            swrRace* r = (swrRace*) swrEvent_GetItem(0x54657374, i);
            if (r != nullptr && (r->flags0 & swrObjTest_FLAG0_LOCAL) != 0 && r->partNodes != nullptr)
                return r;
        }
        return nullptr;
    }

    void start_recording(int kind) {
        swrRace* r = local_racer();
        const int pilot = (r && r->score_ptr && r->score_ptr->pilotId) ? *r->score_ptr->pilotId : -1;
        if (r == nullptr || pilot < 0 || pilot >= 23) {
            g_status = "Start a race first (your pod must be on track).";
            return;
        }
        MODELID id = swrRacer_PodData[pilot].pod_alt_modelID;
        if ((int) id < 0 || (int) id >= 323 || modelid_cstr[id] == nullptr)
            id = swrRacer_PodData[pilot].pod_modelID;
        g_rec = MotionRec{};
        g_rec.kind = kind;
        g_rec.waiting = kind == 1;
        g_rec.name = ((int) id >= 0 && (int) id < 323 && modelid_cstr[id]) ? modelid_cstr[id] : "unknown_pod";
        g_status = kind == 0 ? "Recording idle motion (keep still)..." : "Waiting for top speed...";
    }

    void write_motion() {
        std::error_code ec;
        std::filesystem::create_directories(kExportDir, ec);
        const std::string file = g_rec.name + (g_rec.kind == 0 ? "_idle" : "_top") + ".motion.json";
        const std::string path = std::string(kExportDir) + file;
        FILE* f = fopen(path.c_str(), "wb");
        if (f == nullptr) {
            g_status = "Recording failed: cannot write " + path;
            return;
        }
        fprintf(f, "{\"format\":\"swr-pod-motion-1\",\"model\":\"%s\",\"kind\":\"%s\",\"dt\":%.6g,\"parts\":{", g_rec.name.c_str(),
                g_rec.kind == 0 ? "idle" : "top", kRecStep);
        const char* names[5] = {"cockpit", "engineR", "engineL", "engineR2", "engineL2"};
        const size_t n = g_rec.frames.size() / 80;
        for (int part = 0; part < 5; part++) {
            fprintf(f, "%s\"%s\":[", part ? "," : "", names[part]);
            for (size_t i = 0; i < n; i++) {
                if (i)
                    fputc(',', f);
                write_floats(f, &g_rec.frames[i * 80 + part * 16], 16);
            }
            fputc(']', f);
        }
        fputs("},\"scroll\":{", f);
        {
            bool first_scroll = true;
            for (const ScrollProbe& pr: g_probes) {
                if (g_probe_secs <= 0.0 || (std::fabs(pr.acc[0]) < 1e-6 && std::fabs(pr.acc[1]) < 1e-6))
                    continue;
                fprintf(f, "%s\"%s\":[%.6g,%.6g]", first_scroll ? "" : ",", pr.key.c_str(), pr.acc[0] / g_probe_secs,
                        pr.acc[1] / g_probe_secs);
                first_scroll = false;
            }
        }
        fputs("},\"meshes\":{", f);
        {
            // Meshes the main parts' frames above don't explain: any that moved, other than the engines' and
            // cockpit's own (and their glows / exhaust), the binder, cables and shadows.
            const auto main_part = [](int p) {
                return (p >= 1 && p <= 13) || p == 0x1c || p == 0x1d || p == 0x2a || p == 0x2b || (p >= 0x3d && p <= 0x46);
            };
            bool first_mesh = true;
            int written = 0;
            for (const MeshMotion& mo: g_mmot) {
                if (!mo.have_last || mo.frames.size() != n * 16 || main_part(mo.part))
                    continue;
                float dev = 0.0f;
                for (size_t i = 1; i < n; i++)
                    for (int c = 0; c < 16; c++)
                        dev = std::fmax(dev, std::fabs(mo.frames[i * 16 + c] - mo.frames[c]));
                if (dev < 1e-3f)
                    continue;
                fprintf(f, "%s\"%s\":[", first_mesh ? "" : ",", mo.key.c_str());
                for (size_t i = 0; i < n; i++) {
                    if (i)
                        fputc(',', f);
                    write_floats(f, &mo.frames[i * 16], 16);
                }
                fputc(']', f);
                first_mesh = false;
                written++;
            }
            fprintf(hook_log, "[PodEdits] motion: %d moving mesh(es) recorded\n", written);
        }
        fputs("}}", f);
        fclose(f);
        std::string where = path;
        if (!pod_workspace().empty()) {
            const std::filesystem::path ws = pod_workspace() / L"export" / file;
            if (std::filesystem::copy_file(path, ws, std::filesystem::copy_options::overwrite_existing, ec))
                where = ws.string();
        }
        g_status = "Recorded " + std::to_string(n) + " frames to " + where + " (open it in the editor after the pod's export).";
    }

    void tick_recording() {
        if (g_rec.kind < 0)
            return;
        swrRace* r = local_racer();
        if (r != g_ex_racer) {
            g_probes.clear();// from another race / pod: their material pointers are stale
            g_mmot.clear();
            g_mmot_idx.clear();
        }
        if (r == nullptr) {
            g_rec.kind = -1;
            g_status = "Recording stopped: the race ended.";
            return;
        }
        const float dt = (float) std::fmin(std::fmax(swrRace_deltaTimeSecs, 0.0), 0.1);
        if (dt <= 0.0f)
            return;// paused
        if (g_rec.waiting) {
            if (r->speedValue < 0.60f * r->podStats.maxSpeed)
                return;
            g_rec.waiting = false;
            g_status = "Recording top-speed motion (hold top speed)...";
        }
        if (g_rec.frames.empty() && g_rec.kind == 0 && !invert_affine(r->transform, g_rec.inv_ref)) {
            g_rec.kind = -1;
            return;
        }
        if (g_rec.t == 0.0f)
            probe_reset();
        probe_sample(dt);
        g_rec.t += dt;
        while (g_rec.t >= g_rec.next && g_rec.next <= kRecSecs) {
            rdMatrix44 ref = g_rec.inv_ref;
            if (g_rec.kind == 1 && !invert_affine(r->transform, ref))
                return;
            const rdMatrix44* parts[5] = {&r->cockpitXf, &r->engineXfR, &r->engineXfL, &r->engineXfR2, &r->engineXfL2};
            for (const rdMatrix44* m: parts) {
                const rdMatrix44 rel = mat_then(*m, ref);
                g_rec.frames.insert(g_rec.frames.end(), &rel.vA.x, &rel.vA.x + 16);
            }
            for (MeshMotion& mo: g_mmot) {
                if (mo.seen) {
                    const rdMatrix44 rel = mat_then(mo.cur, ref);
                    for (size_t i = 0; i <= mo.lead; i++)// (earlier samples it wasn't drawn in: its first frame)
                        mo.frames.insert(mo.frames.end(), &rel.vA.x, &rel.vA.x + 16);
                    mo.lead = 0;
                    mo.have_last = true;
                    mo.seen = false;
                } else if (mo.have_last) {
                    float last[16];
                    std::copy(mo.frames.end() - 16, mo.frames.end(), last);
                    mo.frames.insert(mo.frames.end(), last, last + 16);
                } else
                    mo.lead++;
            }
            g_rec.next += kRecStep;
        }
        if (g_rec.next > kRecSecs) {
            write_motion();
            const bool chain = g_rec_chain && g_rec.kind == 0;
            g_rec.kind = -1;
            g_rec_chain = false;
            if (chain) {
                const std::string done = g_status;
                start_recording(1);
                g_status = done + " Now waiting for top speed...";
            }
        }
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
            g_probes.clear();
            g_mmot.clear();
            g_mmot_idx.clear();
            g_ex_racer = nullptr;
            g_ex_model = -1;
            g_status = "Waiting for a race frame...";
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Writes assets/pod_edits/export/<Pod>_pod.json from the next race frame. Best at the "
                              "start line, with nothing hidden or blown off.");
        ImGui::BeginDisabled(g_rec.kind >= 0);
        if (ImGui::Button(g_rec.kind == 0 ? "Recording..." : "Record idle motion"))
            start_recording(0);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Records 4 seconds of how the pod's cockpit and engines move while it sits still (e.g. on the\n"
                              "start line), for the editor's Idle preview: open the .motion.json after the pod's export.");
        ImGui::SameLine();
        if (ImGui::Button(g_rec.kind == 1 ? (g_rec.waiting ? "Waiting for top speed..." : "Recording...") : "Record top-speed motion"))
            start_recording(1);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Waits until you are flat out, then records 4 seconds of how the pod's cockpit and engines\n"
                              "move, for the editor's Top speed preview.");
        ImGui::EndDisabled();
        ImGui::Checkbox("Export also records idle + top-speed motion", &g_auto_motion);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("After the export, records 4 s of idle motion at once (keep the pod still), then 4 s at\n"
                              "top speed once you are flat out. Open the export and both .motion.json files together\n"
                              "in the editor.");
        if (ImGui::Checkbox("Apply pod edits", &g_apply))
            config::set_int("pod_edits", "apply", g_apply ? 1 : 0);
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
            ImGui::TextDisabled("Loaded: %zu spinning part(s) the mod turns (alt models), %zu baked pod animation(s)",
                                pod_edits_spin_node_count(), pod_edits_baked_anim_count());
            for (const auto& [id, why]: skipped_replacement_models())
                ImGui::TextColored(ImVec4(1.0f, 0.65f, 0.3f, 1.0f), "Model %d ignored: %s", id, why.c_str());
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
    {
        char mkey[32];
        if (file_off >= 0)
            snprintf(mkey, sizeof(mkey), "%d:%x", (int) id, (unsigned) file_off);
        else
            snprintf(mkey, sizeof(mkey), "%x", off);
        g_mmot_idx[mesh] = g_mmot.size();
        g_mmot.push_back(MeshMotion{mkey, part});
        if (mesh->mesh_material != nullptr)
            g_probes.push_back({mkey, mesh->mesh_material, {0, 0}});
    }
}

bool pod_edits_recording() {
    return g_rec.kind >= 0 && !g_mmot.empty();
}

void pod_edits_record_mesh(const swrRace* racer, int part, const swrModel_Mesh* mesh, const rdMatrix44& model_matrix) {
    (void) part;
    if (g_rec.kind < 0 || racer == nullptr || racer != g_ex_racer)
        return;
    const auto it = g_mmot_idx.find(mesh);
    if (it == g_mmot_idx.end())
        return;
    MeshMotion& mo = g_mmot[it->second];
    if (mo.seen)
        return;// (the first placement it is drawn at)
    mo.cur = model_matrix;
    mo.seen = true;
}

void pod_edits_export_end_frame(bool in_race) {
    if (!g_export_armed)
        return;
    if (!g_ex.empty()) {
        write_export();
        g_export_armed = false;
        g_ex.clear();
        g_ex_seen.clear();
        if (g_auto_motion && g_rec.kind < 0) {
            start_recording(0);
            g_rec_chain = g_rec.kind == 0;
        }
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

    // Spinning parts baked into an alt model (spinNodes): the game runs no animations in
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

    // Extra exhaust trails (trailNodes): copies of a stock exhaust node (partNodes[0x43] right,
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
}// namespace

namespace {
    swrModel_Node* parent_of(swrModel_Node* n, const swrModel_Node* target, int depth) {
        if (n == nullptr || depth > 48 || n->type == NODE_MESH_GROUP || !(n->type & 0x4000))
            return nullptr;
        for (uint32_t i = 0; i < n->num_children && i < 256; i++) {
            swrModel_Node* c = n->children.nodes[i];
            if (c == target)
                return n;
            if (swrModel_Node* p = parent_of(c, target, depth + 1))
                return p;
        }
        return nullptr;
    }
    // Neva Kee's pod model (fused engines) puts each engine's nozzle ring and star glow on the other
    // side: the node above each sits 126 units out to the far side (other pods: 0), so the right
    // engine's branch carries the left ring and the other way round. Intact, that looks the same; but
    // when an engine comes off, its ring goes with it and the one left behind floats where the lost
    // engine was. Turning that offset round puts each ring and glow on its own engine.
    void fix_neva_kee_nozzles(swrModel_Header* header) {
        int count = 0;
        while (count < 128 && header->entries[count].value != 0xFFFFFFFFu)
            count++;
        if (count <= 0x2b)
            return;
        std::set<swrModel_Node*> done;
        for (const int part: {0x1c, 0x1d, 0x2a, 0x2b}) {
            const swrModel_Node* target = header->entries[part].node;
            if (target == nullptr)
                continue;
            swrModel_Node* parent = nullptr;
            for (int i = 0; i < count && parent == nullptr; i++)
                if (header->entries[i].node != nullptr && header->entries[i].node != target)
                    parent = parent_of(header->entries[i].node, target, 0);
            if (parent == nullptr || !done.insert(parent).second ||
                (parent->type != NODE_TRANSFORMED && parent->type != NODE_TRANSFORMED_WITH_PIVOT))
                continue;
            float& x = ((swrModel_NodeTransformed*) parent)->transform.scale.x;
            if (std::fabs(x) > 1.0f) {
                x = -x;
                parent->flags_3 |= 3;
            }
        }
    }
}// namespace

void pod_edits_note_model(swrModel_Header* header, const char* asset_begin, const char* asset_end, int model_id) {
    if (header == nullptr)
        return;
    if (model_id == MODELID_neva_kee_pod)
        fix_neva_kee_nozzles(header);
    // Edits the model carries: Build appends them at the very end of the model data as
    //   <text> <zero padding> <u32 text length, little-endian> "SWRPEDT1"
    // (padded so the whole trailer is a multiple of 8 bytes). The loader reads the model data as it
    // is and only fixes up the words its mask marks, so these bytes reach memory unchanged. They are
    // not at the end of the load's range, though: the model's textures are loaded after its data (and
    // the buffer may be aligned), so the trailer is looked for from the model data onward.
    const char* trailer = nullptr;
    uint32_t len = 0;
    if (model_id >= 0) {
        const char* data = std::max((const char*) header - 4, asset_begin);
        for (const char* p = data + 12; p + 8 <= asset_end; p++) {
            if (*p != 'S' || memcmp(p, "SWRPEDT1", 8) != 0)
                continue;
            uint32_t l = 0;
            memcpy(&l, p - 4, 4);
            uint32_t pd = l;
            while ((pd + 12) % 8 != 0)
                pd++;
            if (l == 0 || l >= (1u << 20) || p - 4 - pd < data)
                continue;
            const char* t = p - 4 - pd;
            if (memchr(t, 0, l) != nullptr)// the text has no zero bytes: not the trailer
                continue;
            trailer = t, len = l;
            break;
        }
    }
    if (trailer != nullptr) {
        {
            std::string text(trailer, len);
            // Its time: the file it came from (its replacement .bin, or the game's model block).
            const auto& repl = current_replacement_models();
            const auto it = repl.find(model_id);
            const std::filesystem::path src = it != repl.end() ? it->second : std::filesystem::path(MODELBLOCK_PATH);
            std::error_code tec;
            const auto when = std::filesystem::last_write_time(src, tec);
            EmbeddedEdits& slot = g_embedded[model_id];
            if (slot.text != text || slot.when != when) {
                slot = {std::move(text), when, src.string() + " (edits carried in model " + std::to_string(model_id) + ")"};
                fprintf(hook_log, "[PodEdits] model %d carries its own edits (%u bytes)\n", model_id, len);
                fflush(hook_log);
                scan_dir();// apply them (or keep a newer edit file)
            }
        }
    }
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
    int registered_spin = 0;
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
            registered_spin++;
            fprintf(hook_log, "[PodEdits] spinnode %d:%x registered (%.0f rpm, axis %.2f %.2f %.2f)\n", model_id, sl.off, sl.rpm,
                    sl.axis[0], sl.axis[1], sl.axis[2]);
        }
    }
    // A baked replacement of an alt model (not a Podd model: those turn through their own baked
    // animations) with nothing the mod will turn: say why, since the pod would just sit there.
    if (registered_spin == 0 && ((const uint32_t*) header)[-1] != kTagPodd && current_replacement_models().count(model_id)) {
        fprintf(hook_log,
                "[PodEdits] model %d is a baked replacement but %s: any spinning parts baked into it will not turn "
                "(Build writes the spinNodes into pod_edits/<Pod>.json; Mods > Pod Editor > Reload edits)\n",
                model_id, model_edits(model_id) ? "its pod_edits file has no spinNodes" : "no pod_edits file for it was found");
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

size_t pod_edits_spin_node_count() {
    return g_spin_nodes.size();
}
size_t pod_edits_baked_anim_count() {
    return g_pod_anims.size();
}

void pod_edits_drop_models_from(const char* asset_begin) {
    // Anything that reaches past asset_begin is overwritten by the new load (an old model overlapping
    // the new one too): stale pointers there would turn parts of other models (e.g. the pit droids).
    std::erase_if(g_pod_anims, [&](const PodAnim& a) { return a.end > asset_begin; });
    // (Rebuilt rather than erase_if'd: these small trivially-copyable entries are only ever
    // copy-constructed, never assigned.)
    const auto keep = [](auto& list, auto drop) {
        std::remove_reference_t<decltype(list)> kept;
        kept.reserve(list.size());
        for (const auto& e: list)
            if (!drop(e))
                kept.push_back(e);
        list.swap(kept);
    };
    keep(g_spin_nodes, [&](const SpinNode& s) { return s.end > asset_begin; });
    keep(g_trail_nodes, [&](const TrailNode& t) { return t.begin >= asset_begin; });
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

const std::vector<float>* pod_edits_nozzle_lengths(int pilot, int side) {
    if (side < 0 || side > 1)
        return nullptr;
    if (!g_scanned)
        scan_dir();
    const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.fx_set[0]; });
    return e ? &e->nozzle_len[side] : nullptr;
}

const std::vector<float>* pod_edits_nozzle_heights(int pilot, int side) {
    if (side < 0 || side > 1)
        return nullptr;
    if (!g_scanned)
        scan_dir();
    const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.fx_set[0]; });
    return e ? &e->nozzle_hgt[side] : nullptr;
}

const std::vector<float>* pod_edits_nozzle_widths(int pilot, int side) {
    if (side < 0 || side > 1)
        return nullptr;
    if (!g_scanned)
        scan_dir();
    const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.fx_set[0]; });
    return e ? &e->nozzle_wid[side] : nullptr;
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
        rdVector3 p = xf_point(e, {t.pos[0], t.pos[1], t.pos[2]});
        if (four) {
            // The trail follows the engine it sits on: the main one or the second pair's (which
            // moves on its own). Decided once, from where the point sits the first time.
            if (t.engine < 0) {
                rdMatrix44 inv2;
                const float d1 = (p.x - e.vD.x) * (p.x - e.vD.x) + (p.y - e.vD.y) * (p.y - e.vD.y) + (p.z - e.vD.z) * (p.z - e.vD.z);
                const float d2 = (p.x - e2.vD.x) * (p.x - e2.vD.x) + (p.y - e2.vD.y) * (p.y - e2.vD.y) + (p.z - e2.vD.z) * (p.z - e2.vD.z);
                t.engine = 0;
                if (d2 < d1 && invert_affine(e2, inv2)) {
                    const rdVector3 l = xf_point(inv2, p);
                    t.local[0] = l.x, t.local[1] = l.y, t.local[2] = l.z;
                    t.engine = 1;
                }
            }
            if (t.engine == 1) {
                rdMatrix44 inv;
                if (invert_affine(e, inv))
                    m = mat_then(mat_then(m, inv), e2);// the exhaust's orientation, carried by the second engine
                p = xf_point(e2, {t.local[0], t.local[1], t.local[2]});
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
    tick_recording();
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

bool pod_edits_camera_offset(int pilot, int which, float out[2]) {
    if (which < 0 || which > 2)
        return false;
    const ModelEdits* e = pilot_edits(pilot, [which](const ModelEdits& m) { return m.cam_set[which]; });
    if (e == nullptr)
        return false;
    out[0] = e->cam[which][0], out[1] = e->cam[which][1];
    return true;
}

void pod_edits_apply_gaps(swrRace* p) {
    if (p == nullptr || p->partNodes == nullptr || !p->score_ptr || !p->score_ptr->pilotId)
        return;
    if (g_rec.kind >= 0 && (p->flags0 & swrObjTest_FLAG0_LOCAL) != 0)
        return;// recording the pod's motion: as the game moves it, without the edits
    const ModelEdits* e = pilot_edits(*p->score_ptr->pilotId,
                                      [](const ModelEdits& m) {
                                          return m.engine_gap_set || m.cockpit_gap_set || m.height_set || m.cockpit_move_set;
                                      });
    if (e == nullptr)
        return;
    // Sideways = the pod's right axis; the middle = halfway between the main engine pair.
    const rdVector4& ra = p->transform.vA;
    const float rl = std::sqrt(ra.x * ra.x + ra.y * ra.y + ra.z * ra.z);
    if (rl < 1e-6f)
        return;
    const float rx = ra.x / rl, ry = ra.y / rl, rz = ra.z / rl;
    const float cx = (p->engineXfR.vD.x + p->engineXfL.vD.x) * 0.5f, cy = (p->engineXfR.vD.y + p->engineXfL.vD.y) * 0.5f,
                cz = (p->engineXfR.vD.z + p->engineXfL.vD.z) * 0.5f;
    if (e->engine_gap_set) {
        const bool four = p->partNodes[3] && p->partNodes[4];
        rdMatrix44* engines[4] = {&p->engineXfR, &p->engineXfL, four ? &p->engineXfR2 : nullptr, four ? &p->engineXfL2 : nullptr};
        for (rdMatrix44* m: engines) {
            if (m == nullptr)
                continue;
            const float side = (m->vD.x - cx) * rx + (m->vD.y - cy) * ry + (m->vD.z - cz) * rz;
            const float d = side * (e->engine_gap - 1.0f);
            m->vD.x += rx * d, m->vD.y += ry * d, m->vD.z += rz * d;
        }
    }
    if (e->cockpit_gap_set) {
        rdVector4& c = p->cockpitXf.vD;
        c.x = cx + (c.x - cx) * e->cockpit_gap, c.y = cy + (c.y - cy) * e->cockpit_gap, c.z = cz + (c.z - cz) * e->cockpit_gap;
    }
    if (e->cockpit_move_set) {// moved freely, along the pod's own right / forward / up
        const rdVector4* ax[3] = {&p->transform.vA, &p->transform.vB, &p->transform.vC};
        rdVector4& c = p->cockpitXf.vD;
        for (int j = 0; j < 3; j++) {
            const rdVector4& a = *ax[j];
            const float l = std::sqrt(a.x * a.x + a.y * a.y + a.z * a.z);
            if (l < 1e-6f)
                continue;
            const float k = e->cockpit_move[j] / l;
            c.x += a.x * k, c.y += a.y * k, c.z += a.z * k;
        }
    }
    // The whole drawn pod raised / lowered along the pod's up axis (the cables, binder and exhaust
    // are built from these afterwards). The pod's own transform -- its physics, collision and ground
    // contact -- is left alone.
    if (e->height_set && e->height != 0.0f) {
        const rdVector4& ua = p->transform.vC;
        const float ul = std::sqrt(ua.x * ua.x + ua.y * ua.y + ua.z * ua.z);
        if (ul > 1e-6f) {
            const float k = e->height / ul;
            const bool four = p->partNodes[3] && p->partNodes[4];
            rdMatrix44* parts[5] = {&p->cockpitXf, &p->engineXfR, &p->engineXfL, four ? &p->engineXfR2 : nullptr,
                                    four ? &p->engineXfL2 : nullptr};
            for (rdMatrix44* m: parts)
                if (m != nullptr)
                    m->vD.x += ua.x * k, m->vD.y += ua.y * k, m->vD.z += ua.z * k;
        }
    }
}

bool pod_edits_apply_display_gaps(swrModel_Node** nodes, int pilot) {
    if (nodes == nullptr || nodes[1] == nullptr || nodes[2] == nullptr || nodes[5] == nullptr)
        return false;
    const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) {
        return m.engine_gap_set || m.cockpit_gap_set || m.height_set || m.cockpit_move_set;
    });
    if (e == nullptr)
        return false;
    typedef void(__cdecl * NodeGetTransform_t)(const swrModel_Node* node, rdMatrix44* out);
    typedef void(__cdecl * NodeSetTransform_t)(swrModel_Node* node, const rdMatrix44* m);
    const auto get = (NodeGetTransform_t) swrModel_NodeGetTransform_ADDR;
    const auto set = (NodeSetTransform_t) swrModel_NodeSetTransform_ADDR;
    // The display pod is posed in world space, scaled (x 2.6 on the racer-select turntable) and
    // turning: the pod's right / forward / up are the cockpit node's axes, and their length is the
    // display's scale, so moves along them (in race units) come out the same as in a race.
    rdMatrix44 m[6];
    for (int i = 1; i <= 5; i++)
        if (nodes[i])
            get(nodes[i], &m[i]);
    const rdVector4 right = m[5].vA, fwd = m[5].vB, up = m[5].vC;
    const float rl2 = right.x * right.x + right.y * right.y + right.z * right.z;
    const float cx = (m[1].vD.x + m[2].vD.x) * 0.5f, cy = (m[1].vD.y + m[2].vD.y) * 0.5f, cz = (m[1].vD.z + m[2].vD.z) * 0.5f;
    if (e->engine_gap_set && rl2 > 1e-12f)
        for (int i = 1; i <= 4; i++) {
            if (!nodes[i])
                continue;
            rdVector4& v = m[i].vD;
            const float side = ((v.x - cx) * right.x + (v.y - cy) * right.y + (v.z - cz) * right.z) / rl2;// along the pod's right
            const float d = side * (e->engine_gap - 1.0f);
            v.x += right.x * d, v.y += right.y * d, v.z += right.z * d;
        }
    rdVector4& c = m[5].vD;
    if (e->cockpit_gap_set)
        c.x = cx + (c.x - cx) * e->cockpit_gap, c.y = cy + (c.y - cy) * e->cockpit_gap, c.z = cz + (c.z - cz) * e->cockpit_gap;
    if (e->cockpit_move_set) {
        const float* mv = e->cockpit_move;
        c.x += right.x * mv[0] + fwd.x * mv[1] + up.x * mv[2];
        c.y += right.y * mv[0] + fwd.y * mv[1] + up.y * mv[2];
        c.z += right.z * mv[0] + fwd.z * mv[1] + up.z * mv[2];
    }
    if (e->height_set)
        for (int i = 1; i <= 5; i++)
            m[i].vD.x += up.x * e->height, m[i].vD.y += up.y * e->height, m[i].vD.z += up.z * e->height;
    for (int i = 1; i <= 5; i++)
        if (nodes[i])
            set(nodes[i], &m[i]);
    return true;
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

bool pod_edits_nozzle_flame(int pilot, float out[3]) {
    const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.nozzle_flame_set; });
    if (e == nullptr)
        return false;
    out[0] = e->nozzle_flame[0];
    out[1] = e->nozzle_flame[1];
    out[2] = e->nozzle_flame[2];
    return true;
}

bool pod_edits_exhaust_light(int pilot, float out[4]) {
    const ModelEdits* e = pilot_edits(pilot, [](const ModelEdits& m) { return m.exhaust_light_set; });
    if (e == nullptr)
        return false;
    for (int j = 0; j < 4; j++)
        out[j] = e->exhaust_light[j];
    return true;
}

void pod_edits_register_panel() {
    pod_workspace();// create it (and copy the model block) at startup
    g_apply = config::get_int("pod_edits", "apply", 1) != 0;
    g_idle_spin = config::get_float("pod_edits", "idle_spin", 0.25f);
    g_cable_clear = config::get_int("pod_edits", "cable_clear", 0) != 0;
    g_cable_margin = config::get_float("pod_edits", "cable_margin", 0.12f);
    g_full_spin_speed = config::get_float("pod_edits", "full_spin_speed", 600.0f);
    debug_ui_register(&g_panel);
}
