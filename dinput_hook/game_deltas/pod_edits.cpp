//
// Pod editor support -- see pod_edits.h.
//
#include <glad/glad.h>

#include "pod_edits.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>

#include <imgui.h>
#include <shlobj.h>// SHGetFolderPathW (Desktop)

extern "C" {
#include <Swr/swrModel.h>// swrModel_LoadAnimation
#include <globals.h>
#include <types_enums.h>// swrObjTest_FLAG0_*
extern FILE* hook_log;
}

#include "../debug_ui.h"
#include "../node_utils.h"
#include "../replacements.h"      // modelid_cstr
#include "../model_replacement.h" // write_replacements_into_modelblock

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
                  "  replacement_models\\<id>.bin   baked pod models\r\n"
                  "  pod_edits\\source\\<Pod>.txt   the edits, to reopen in the editor\r\n"
                  "The mod loads the baked models from here (before the game folder's assets\\replacement_models);\r\n"
                  "Mods > Pod Editor > Write into out_modelblock.bin builds them into the game's data.\r\n"
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
    const char* kExportDir = "./assets/pod_edits/export/";
    std::string g_status_export;

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

    void write_export() {
        const swrRace* r = g_ex_racer;
        rdMatrix44 inv_pod;
        if (r == nullptr || !inv_affine(r->transform, inv_pod)) {
            g_status_export = "Export failed: no pod transform.";
            return;
        }
        std::error_code ec;
        std::filesystem::create_directories(kExportDir, ec);
        const char* name = (g_ex_model >= 0 && g_ex_model < 323) ? modelid_cstr[g_ex_model] : "unknown_pod";
        const std::string path = std::string(kExportDir) + name + ".json";
        FILE* f = fopen(path.c_str(), "wb");
        if (f == nullptr) {
            g_status_export = "Export failed: cannot write " + path;
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
            write_floats(f, (const float*) &swrRacer_PodVisualData[pilot], 27);
            fputs(",\"frames\":{", f);
            const rdMatrix44* frames[5] = {&r->cockpitXf, &r->engineXfR, &r->engineXfL, &r->engineXfR2, &r->engineXfL2};
            const char* names[5] = {"cockpit", "engineR", "engineL", "engineR2", "engineL2"};
            for (int i = 0; i < 5; i++) {
                const rdMatrix44 m = mul(*frames[i], inv_pod);
                fprintf(f, "%s\"%s\":", i ? "," : "", names[i]);
                write_floats(f, &m.vA.x, 16);
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
        g_status_export = buf;
        fprintf(hook_log, "[PodEdits] %s\n", buf);
        fflush(hook_log);
    }

    // ---- panel -------------------------------------------------------------------------------
    std::string g_status;

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
            g_status.clear();
            g_status_export = "Waiting for a race frame...";
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Writes the pod as seen in the next race frame to the workspace's export folder\n"
                              "(and assets/pod_edits/export/). Best at the start line, with nothing blown off.");
        ImGui::SeparatorText("Game data");
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
        if (!g_status.empty())
            ImGui::TextWrapped("%s", g_status.c_str());
        else if (!g_status_export.empty())
            ImGui::TextWrapped("%s", g_status_export.c_str());
    }
    DebugPanel g_panel = {.category = "Mods", .name = "Pod Editor", .draw = draw_panel, .dev_only = false};
}// namespace

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
        g_status_export = "Nothing exported: start a race (your pod must be on screen), then press Export.";
    }
}

// ---- baked spinning parts: the pod models' animations, kept running in races ----------------
namespace {
    struct PodAnim {
        swrModel_Animation* anim;
        const char* begin;// the owning model's asset range (dropped when the buffer rewinds past it)
    };
    std::vector<PodAnim> g_pod_anims;
    constexpr uint32_t kTagPodd = 0x506f6464, kTagData = 0x44617461, kTagAnim = 0x416e696d;
    constexpr int kMaxSceneAnimations = 300;// swrScene_animations[300]
}// namespace

void pod_edits_note_model(swrModel_Header* header, const char* asset_begin, const char* asset_end) {
    (void) asset_end;
    if (header == nullptr)
        return;
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
        g_pod_anims.push_back({e->animation, asset_begin});
}

void pod_edits_drop_models_from(const char* asset_begin) {
    std::erase_if(g_pod_anims, [&](const PodAnim& a) { return a.begin >= asset_begin; });
}

void pod_edits_animations_frame(bool in_race) {
    for (const PodAnim& pa: g_pod_anims) {
        swrModel_Animation* a = pa.anim;
        if (!in_race) {// still in menus (the racer-select preview)
            a->flags = (swrModel_AnimationFlags) (a->flags & ~ANIMATION_ENABLED);
            continue;
        }
        if (a->node_ptr == nullptr)
            continue;// an alt-model part's animation not linked (its alt model wasn't merged in)
        bool registered = false;
        for (int i = 0; i < swrScene_animations_count && !registered; i++)
            registered = swrScene_animations[i] == a;
        if (!registered && swrScene_animations_count < kMaxSceneAnimations)
            swrModel_LoadAnimation(a);
        a->flags = (swrModel_AnimationFlags) ((a->flags | ANIMATION_ENABLED | ANIMATION_LOOP) & ~ANIMATION_DISABLED);
    }
}

void pod_edits_register_panel() {
    pod_workspace();// create it (and copy the model block) at startup
    debug_ui_register(&g_panel);
}
