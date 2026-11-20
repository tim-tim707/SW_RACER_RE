#include <glad/glad.h>

#include "pod_fx.h"

#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include <string>
#include <cstdio>

#include <imgui.h>

extern "C" {
#include <Platform/std3D.h>
#include <Primitives/rdMatrix.h>
#include <Swr/swrEvent.h>// swrEvent_GetEventCount / swrEvent_GetItem
#include <Swr/swrObj.h>  // NumLocalPlayers
#include <Win95/DirectX.h>
#include <globals.h>    // pauseState, swrDisplay_screenWidth/Height
#include <types_enums.h>// swrObjTest_FLAG0_*
#include "std3D_delta.h"
extern FILE* hook_log;
}

#include "../config.h"
#include "../debug_ui.h"
#include "../shadows.h"// SceneLight
#include "pod_edits.h"// pod_edits_fx_points (the pod editor's effect points)
#include "pod_wreck.h"// pod_wreck_side_gone (an engine knocked off the pod)

// Drawing follows swrWeather_delta.cpp: particles live in world space (z up), are projected
// through the scene view/projection handed in by the renderer, and are emitted as screen-space
// quads into render-list batches: one alpha-blended (smoke, dust) and one additive (sparks,
// flames, embers, exhaust), both depth-tested without depth writes. Everything is scaled by the
// pod's own length (cockpit to engine midpoint) so it reads the same on every pod.

namespace {
    using Clock = std::chrono::steady_clock;
    float clampf_(float x, float lo, float hi) { return x < lo ? lo : (x > hi ? hi : x); }

    // ---- settings --------------------------------------------------------------------------
    struct Settings {
        bool enabled = true;
        bool ai_pods = true;
        // damage
        bool damage = true;
        float threshold = 0.40f;// fallback "orange" damage level, until learned from the HUD
        float sparks = 1.0f;
        float flames = 1.0f;
        float smoke = 1.0f;
        float fade_secs = 2.0f;// wind-down after repairs
        bool swap_sides = false;
        // dust
        bool dust = true;
        bool hide_stock_dust = true;// particle dust replaces the stock dust-kick models
        float dust_amount = 1.0f;
        float air_trails = 1.0f;    // exhaust air/vapour trail amount
        float dust_color[3] = {0.78f, 0.66f, 0.50f};
        // exhaust
        bool exhaust = true;
        float exhaust_glow = 1.0f;
        float exhaust_flame = 1.0f;
        float exhaust_embers = 0.4f;
        int nozzle_source = 0;    // 0 = auto (per-nozzle glows), 1 = per-nozzle discs, 2 = engine exhaust, 3 = engine glow
        bool show_nozzles = false;// debug markers on every detected nozzle
        float top_speed = 600.0f;
        // physics
        float turbulence = 1.0f;
        bool ground_bounce = true;
        float size = 1.0f;
        float smoke_opacity = 1.0f;// smoke + smoke trail density
        float flame_opacity = 1.0f;// flame transparency (exhaust + damage fire)
        float exhaust_light = 1.0f; // directional exhaust light (beam + ground pool)
        float binder_light = 1.0f;  // energy binder glow + omni light
        bool hide_stock_binder_glow = true;// drop the game's binder glow card (texture #1411)
    };
    Settings s;
    const Settings kDefaults;

    // The HUD's "orange" damage level, learned by watching the local player's HUD segment colours:
    // the highest damage seen while a segment was still green/yellow, and the lowest seen once it
    // was orange or worse. The threshold sits between them. Used for pods with no HUD (AI).
    float g_learn_lo = -1.0f, g_learn_hi = 2.0f;
    bool g_learn_dirty = false;
    float orange_threshold() {
        if (g_learn_lo >= 0.0f && g_learn_hi <= 1.0f)
            return clampf_(0.5f * (g_learn_lo + g_learn_hi), 0.0f, 0.95f);
        if (g_learn_hi <= 1.0f)
            return clampf_(g_learn_hi - 0.02f, 0.0f, 0.95f);
        if (g_learn_lo >= 0.0f)
            return clampf_(g_learn_lo + 0.02f > s.threshold ? g_learn_lo + 0.02f : s.threshold, 0.0f, 0.95f);
        return s.threshold;
    }

    // ---- small math ------------------------------------------------------------------------
    rdVector3 v3(const rdVector4& v) { return {v.x, v.y, v.z}; }
    rdVector3 add(rdVector3 a, rdVector3 b) { return {a.x + b.x, a.y + b.y, a.z + b.z}; }
    rdVector3 sub(rdVector3 a, rdVector3 b) { return {a.x - b.x, a.y - b.y, a.z - b.z}; }
    rdVector3 mul(rdVector3 a, float k) { return {a.x * k, a.y * k, a.z * k}; }
    float dot(rdVector3 a, rdVector3 b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
    float len(rdVector3 a) { return std::sqrt(dot(a, a)); }
    rdVector3 norm(rdVector3 a) {
        const float l = len(a);
        return l > 1e-6f ? mul(a, 1.0f / l) : rdVector3{0, 0, 0};
    }
    float clampf(float x, float lo, float hi) { return x < lo ? lo : (x > hi ? hi : x); }

    uint32_t g_rng = 0x9e3779b9u;
    float frand() {
        g_rng ^= g_rng << 13;
        g_rng ^= g_rng >> 17;
        g_rng ^= g_rng << 5;
        return (float) (g_rng >> 8) * (1.0f / 16777216.0f);
    }
    float frand_sym() { return frand() * 2.0f - 1.0f; }
    rdVector3 rand_vec() { return {frand_sym(), frand_sym(), frand_sym()}; }

    // ---- particles -------------------------------------------------------------------------
    enum Kind : uint8_t { kSpark, kEmber, kFlame, kSmoke, kDust, kTrail, kExFire };
    struct Particle {
        rdVector3 pos, vel, carrier;// carrier = pod velocity at spawn (streak direction)
        float age, life, size, unit;// unit = pod length at spawn (physics scale)
        float shade;                // smoke darkness 0..1 / generic tint factor
        float ground_z;             // bounce plane (NAN = none)
        Kind kind;
        bool active;
    };
    constexpr int kMaxParticles = 8192;
    Particle g_parts[kMaxParticles];
    int g_next = 0;

    Particle& alloc() {
        Particle& p = g_parts[g_next];
        g_next = (g_next + 1) % kMaxParticles;// oldest recycled when full
        p = Particle{};
        p.active = true;
        p.ground_z = NAN;
        return p;
    }

    // One exhaust nozzle, in its engine's local frame (so it follows the engine wherever pod
    // motion moves it), with its radius in the same units.
    struct Nozzle {
        rdVector3 local;
        float radius;
    };

    struct PodFx {
        bool has_pos = false;
        rdVector3 prev_pos{}, vel{};
        float shown[6] = {};
        float acc[6][4] = {};// spawn accumulators: spark, flame, smoke, (unused)
        float dust_acc = 0.0f, ember_acc = 0.0f;
        float trail_acc[2] = {};
        float fire_acc[2] = {};
        float throttle = 0.0f;// smoothed exhaust intensity
        float moving = 0.0f;  // 0 = stopped .. 1 = under way (gates smoke)
        float prev_speed = 0.0f, speed_rate = 0.0f;// speedValue and its smoothed rate of change (/s)
        float accel = 0.0f;   // 0 = off the throttle .. 1 = under power (gates exhaust glow/light)
        Clock::time_point ground_time{};
        rdVector3 ground_pos{};
        bool has_ground = false;
    };
    std::unordered_map<const swrRace*, PodFx> g_pods;

    // Nozzles per pod and side (0 = right engine, 1 = left), captured from the pod's own exhaust /
    // glow meshes as the renderer draws them. Kept across frames (those meshes are hidden at times).
    struct PodNozzles {
        std::vector<Nozzle> side[2];
        int kind[2] = {-1, -1};          // source kind currently in use (see the commit in tick)
        std::vector<Nozzle> staging[2][4];// [side][kind] reports gathered this frame
    };
    std::unordered_map<const swrRace*, PodNozzles> g_nozzles;

    // Vertex clusters (= separate nozzles) per mesh, in mesh-local units. Cached per mesh.
    struct Cluster {
        rdVector3 c;
        float r;
        std::vector<rdVector3> pts;// subsample of the cluster's vertices (mesh-local)
    };
    std::unordered_map<const swrModel_Mesh*, std::vector<Cluster>> g_mesh_clusters;

    int16_t be16(int16_t v) { return (int16_t) (((uint16_t) v >> 8) | ((uint16_t) v << 8)); }

    const std::vector<Cluster>& clusters_for(const swrModel_Mesh* m) {
        auto it = g_mesh_clusters.find(m);
        if (it != g_mesh_clusters.end())
            return it->second;
        std::vector<Cluster>& out = g_mesh_clusters[m];
        const int n = (m->vertices != nullptr) ? (m->num_vertices < 1024 ? m->num_vertices : 1024) : 0;
        if (n == 0)
            return out;
        std::vector<rdVector3> p((size_t) n);
        rdVector3 lo = {1e9f, 1e9f, 1e9f}, hi = {-1e9f, -1e9f, -1e9f};
        for (int k = 0; k < n; k++) {
            const Vtx_t& v = m->vertices[k].v;// N64 data: big-endian
            p[k] = {(float) be16(v.x), (float) be16(v.y), (float) be16(v.z)};
            lo = {std::min(lo.x, p[k].x), std::min(lo.y, p[k].y), std::min(lo.z, p[k].z)};
            hi = {std::max(hi.x, p[k].x), std::max(hi.y, p[k].y), std::max(hi.z, p[k].z)};
        }
        const float ext = std::max(hi.x - lo.x, std::max(hi.y - lo.y, hi.z - lo.z));
        const float thr = std::max(ext * 0.15f, 1.0f);
        // Single-linkage clustering: vertices closer than thr belong to the same nozzle.
        std::vector<int> parent((size_t) n);
        for (int k = 0; k < n; k++)
            parent[k] = k;
        auto find = [&](int x) {
            while (parent[x] != x)
                x = parent[x] = parent[parent[x]];
            return x;
        };
        for (int a = 0; a < n; a++)
            for (int b = a + 1; b < n; b++) {
                const rdVector3 d = {p[a].x - p[b].x, p[a].y - p[b].y, p[a].z - p[b].z};
                if (d.x * d.x + d.y * d.y + d.z * d.z < thr * thr)
                    parent[find(a)] = find(b);
            }
        std::unordered_map<int, std::pair<rdVector3, rdVector3>> boxes;
        for (int k = 0; k < n; k++) {
            auto [bit, fresh] = boxes.try_emplace(find(k), p[k], p[k]);
            auto& [blo, bhi] = bit->second;
            blo = {std::min(blo.x, p[k].x), std::min(blo.y, p[k].y), std::min(blo.z, p[k].z)};
            bhi = {std::max(bhi.x, p[k].x), std::max(bhi.y, p[k].y), std::max(bhi.z, p[k].z)};
        }
        std::unordered_map<int, size_t> index;
        for (auto& [root, box]: boxes) {
            const auto& [blo, bhi] = box;
            const float r = 0.5f * std::max(bhi.x - blo.x, std::max(bhi.y - blo.y, bhi.z - blo.z));
            index[root] = out.size();
            out.push_back({{0.5f * (blo.x + bhi.x), 0.5f * (blo.y + bhi.y), 0.5f * (blo.z + bhi.z)}, std::max(r, 0.5f), {}});
        }
        for (int k = 0; k < n; k++) {
            Cluster& c = out[index[find(k)]];
            if (c.pts.size() < 64)
                c.pts.push_back(p[k]);
        }
        if (out.size() > 12) {// a non-nozzle mesh shattered into pieces: treat it as one
            Cluster all{{0.5f * (lo.x + hi.x), 0.5f * (lo.y + hi.y), 0.5f * (lo.z + hi.z)}, 0.5f * ext, {}};
            for (int k = 0; k < n && all.pts.size() < 64; k++)
                all.pts.push_back(p[k]);
            out = {all};
        }
        return out;
    }

    // World <-> engine-local (engine matrices are orthogonal but may carry scale).
    rdVector3 to_local(const rdMatrix44& e, rdVector3 w) {
        const rdVector3 d = sub(w, v3(e.vD));
        auto comp = [&](const rdVector4& a) {
            const rdVector3 ax = v3(a);
            const float l2 = dot(ax, ax);
            return l2 > 1e-9f ? dot(d, ax) / l2 : 0.0f;
        };
        return {comp(e.vA), comp(e.vB), comp(e.vC)};
    }
    rdVector3 to_world(const rdMatrix44& e, rdVector3 l) {
        return add(v3(e.vD), add(mul(v3(e.vA), l.x), add(mul(v3(e.vB), l.y), mul(v3(e.vC), l.z))));
    }
    const rdMatrix44& engine_of(const swrRace* r, int side) { return side == 0 ? r->engineXfR : r->engineXfL; }

    // False once an engine has blown off: the game hides that engine's model node (partNodes[1]
    // = right, [2] = left; flags_1 bit 0x2 = visible), e.g. the engine lost in a crash while the
    // other one spins the pod out.
    bool engine_alive(const swrRace* r, int side) {
        if (pod_wreck_side_gone(r, side))// knocked off: its effects stay with the debris
            return false;
        const swrModel_Node* node = r->partNodes != nullptr ? r->partNodes[1 + side] : nullptr;
        return node == nullptr || (node->flags_1 & 0x2) != 0;
    }

    int pilot_of(const swrRace* r) {
        return (r->score_ptr && r->score_ptr->pilotId) ? *r->score_ptr->pilotId : -1;
    }
    // A pod's edited effect points (kind: 0 nozzle, 1 fire, 2 dust) for one side, or nullptr.
    const std::vector<std::array<float, 4>>* edited_points(const swrRace* r, int kind, int side) {
        return pod_edits_fx_points(pilot_of(r), kind, side);
    }

    // World positions + radii of a pod side's nozzles this frame (empty if none captured yet).
    // The pod editor's nozzles, when the pod's edits set them, replace the detected ones.
    void nozzles_world(const swrRace* r, int side, std::vector<std::pair<rdVector3, float>>& out) {
        out.clear();
        if (const auto* ed = edited_points(r, 0, side)) {
            const rdMatrix44& e = engine_of(r, side);
            const float scale = len(v3(e.vA));
            for (const auto& p: *ed)
                out.push_back({to_world(e, {p[0], p[1], p[2]}), p[3] * scale});
            return;
        }
        auto it = g_nozzles.find(r);
        if (it == g_nozzles.end())
            return;
        const rdMatrix44& e = engine_of(r, side);
        const float scale = len(v3(e.vA));
        for (const Nozzle& n: it->second.side[side])
            out.push_back({to_world(e, n.local), n.radius * scale});
    }

    // The actual engine bodies on one side. Most pods have one per side, at the side's engine
    // transform. Ben Quadinaros has two per side under one transform (which sits between them),
    // so the side's nozzles are grouped into engines -- groups further apart than ~a quarter pod
    // length -- and each engine's centre is its nozzle group moved forward by as much as the side
    // transform sits ahead of the nozzles.
    void engine_centres(const swrRace* r, int side, float L, std::vector<rdVector3>& out) {
        out.clear();
        const rdMatrix44& e = engine_of(r, side);
        const rdVector3 e_pos = v3(e.vD);
        static std::vector<std::pair<rdVector3, float>> noz;
        nozzles_world(r, side, noz);
        if (noz.size() < 2) {
            out.push_back(e_pos);
            return;
        }
        static std::vector<std::pair<rdVector3, int>> groups;// sum, count
        groups.clear();
        rdVector3 mean = {0, 0, 0};
        for (const auto& n: noz) {
            mean = add(mean, n.first);
            bool placed = false;
            for (auto& g: groups)
                if (len(sub(mul(g.first, 1.0f / (float) g.second), n.first)) < L * 0.25f) {
                    g.first = add(g.first, n.first);
                    g.second++;
                    placed = true;
                    break;
                }
            if (!placed)
                groups.push_back({n.first, 1});
        }
        if (groups.size() < 2) {
            out.push_back(e_pos);
            return;
        }
        mean = mul(mean, 1.0f / (float) noz.size());
        const rdVector3 fwd = norm(v3(e.vB));
        const rdVector3 ahead = mul(fwd, dot(sub(e_pos, mean), fwd));
        for (const auto& g: groups)
            out.push_back(add(mul(g.first, 1.0f / (float) g.second), ahead));
    }

    // HUD colour of a local player's engine segment: 1 = orange or worse, 0 = green/yellow,
    // -1 = no HUD for this pod (AI) or the sprite isn't showing.
    int hud_segment_orange(const swrRace* r, int seg) {
        if (r->score_ptr == nullptr)
            return -1;
        const bool two = NumLocalPlayers() == 2;
        int base;
        if (r->score_ptr == firstLocalPlayer)
            base = two ? 0x23 : 0x1b;// see swrObjJdge_HideEngineUI for the sprite layout
        else if (two && r->score_ptr == secondLocalPlayer)
            base = 0x1b;
        else
            return -1;
        const swrSprite& sp = swrSprite_array[base + seg];
        if (sp.a == 0 || (sp.r == 0 && sp.g == 0))
            return -1;// hidden / blinking off
        return (sp.r >= 90 && sp.g <= sp.r * 0.72f) ? 1 : 0;
    }

    // Exhaust sprites for this frame (drawn per viewport, rebuilt per tick).
    struct ExhaustSprite {
        rdVector3 pos, dir;
        float radius, intensity, flame_len, flicker;
        float ground_z = NAN;// ground height under the engine (for the light pool)
        float unit = 10.0f;  // pod length
    };
    std::vector<ExhaustSprite> g_exhaust;
    std::vector<rdVector3> g_markers;// debug: detected nozzle positions this frame

    // "Dump pod parts" diagnostics.
    bool g_debug_armed = false;
    std::string g_debug_status;
    std::vector<std::string> g_debug_lines;
    const swrRace* g_debug_racer = nullptr;

    constexpr int kEventTest = 0x54657374;// 'Test': one swrRace per racer
    constexpr float kTeleportDist = 200.0f;
    float g_time = 0.0f;

    float pod_length(const swrRace* r) {
        const rdVector3 mid = mul(add(v3(r->engineXfR.vD), v3(r->engineXfL.vD)), 0.5f);
        const float l = len(sub(v3(r->cockpitXf.vD), mid));
        return (l > 0.5f && l < 500.0f) ? l : 10.0f;
    }

    // ---- spawning --------------------------------------------------------------------------
    void spawn_spark(rdVector3 pos, rdVector3 pod_vel, rdVector3 dir, rdVector3 up, float L, float gz) {
        Particle& p = alloc();
        p.kind = kSpark;
        p.pos = pos;
        p.carrier = pod_vel;
        p.unit = L;
        const rdVector3 d = norm(add(add(dir, mul(rand_vec(), 0.8f)), mul(up, 0.4f)));
        p.vel = add(pod_vel, mul(d, L * (1.5f + 3.0f * frand())));
        p.life = 0.3f + 0.5f * frand();
        p.size = L * 0.012f;
        p.ground_z = gz;
    }

    void spawn_flame(rdVector3 pos, rdVector3 pod_vel, rdVector3 dir, rdVector3 up, float L) {
        Particle& p = alloc();
        p.kind = kFlame;
        p.pos = pos;
        p.carrier = pod_vel;
        p.unit = L;
        // Irregular licks: random strength, direction, size and life so no two look alike.
        p.vel = add(mul(pod_vel, 0.85f + 0.1f * frand()),
                    add(mul(dir, L * (0.2f + 0.6f * frand())), mul(up, L * (0.2f + 0.7f * frand()))));
        p.vel = add(p.vel, mul(rand_vec(), L * 0.45f));
        p.life = 0.12f + 0.45f * frand() * frand();// mostly short, the odd long tongue
        p.size = L * (0.02f + 0.05f * frand());
        p.shade = frand();// hue variation
    }

    // Exhaust fire: a short, fast spray of flame from a nozzle. Random size, speed, spread, life
    // and hue per particle so the jet flickers and breaks up instead of being one solid shape.
    void spawn_exfire(rdVector3 pos, rdVector3 pod_vel, rdVector3 dir, float L, float radius) {
        Particle& p = alloc();
        p.kind = kExFire;
        p.pos = add(pos, mul(rand_vec(), radius * 0.35f));
        p.carrier = pod_vel;
        p.unit = L;
        p.vel = add(pod_vel, add(mul(dir, L * (1.5f + 3.5f * frand())), mul(rand_vec(), L * (0.2f + 0.5f * frand()))));
        p.life = 0.06f + 0.18f * frand() * frand();
        p.size = radius * (0.45f + 0.9f * frand());
        p.shade = frand();
    }

    void spawn_smoke(rdVector3 pos, rdVector3 pod_vel, rdVector3 dir, float L, float shade) {
        Particle& p = alloc();
        p.kind = kSmoke;
        p.pos = pos;
        p.carrier = pod_vel;
        p.unit = L;
        p.vel = add(mul(pod_vel, 0.6f), add(mul(dir, L * 0.3f), mul(rand_vec(), L * 0.3f)));
        p.life = 1.8f + 2.0f * frand();// long-lived so the plume leaves a trail behind the pod
        p.size = L * (0.09f + 0.07f * frand());
        p.shade = shade;
    }

    // `back` = the engines' exhaust direction: the jets blow the dust out behind the pod even
    // when it is sitting still.
    void spawn_dust(rdVector3 pos, rdVector3 pod_vel, rdVector3 back, float L) {
        Particle& p = alloc();
        p.kind = kDust;
        p.pos = add(pos, {frand_sym() * L * 0.25f, frand_sym() * L * 0.25f, 0.0f});
        p.carrier = pod_vel;
        p.unit = L;
        // Blown backward by the engine jets, thrown up and outward, keeping only a little of the
        // pod's speed so it billows behind.
        const rdVector3 out = {frand_sym(), frand_sym(), 0.4f + 0.6f * frand()};
        rdVector3 jet = {back.x, back.y, 0.0f};// along the ground
        jet = len(jet) > 1e-3f ? norm(jet) : jet;
        p.vel = add(add(mul(pod_vel, 0.25f), mul(norm(out), L * (0.4f + 0.9f * frand()))),
                    mul(jet, L * (2.5f + 2.5f * frand())));
        p.life = 0.9f + 1.3f * frand();
        p.size = L * (0.06f + 0.05f * frand());
        p.shade = 0.85f + 0.3f * frand();// brightness variation
    }

    // Exhaust smoke trail: a jet blown backward out of the nozzle.
    // Trailing physics: the puff leaves the nozzle with the pod's own velocity plus a fast push
    // straight out the back (within a narrow cone, harder with throttle), so close to the engine
    // it streams backward as a jet. Air drag then bleeds both off, so further back it is left
    // hanging in the air the pod has passed through, swelling and rising slowly -- a cone that
    // widens behind each nozzle. `overheat` (0..1) darkens it.
    void spawn_trail(rdVector3 pos, rdVector3 pod_vel, rdVector3 dir, float L, float radius, float overheat,
                     float throttle) {
        Particle& p = alloc();
        p.kind = kTrail;
        p.pos = pos;
        p.carrier = pod_vel;
        p.unit = L;
        const rdVector3 jet_dir = norm(add(dir, mul(rand_vec(), 0.12f)));// ~7 deg cone
        const float jet = L * (5.0f + 9.0f * clampf(throttle, 0.0f, 1.6f)) * (0.8f + 0.4f * frand());
        p.vel = add(mul(pod_vel, 0.9f), mul(jet_dir, jet));
        p.life = 1.4f + 1.4f * frand();
        p.size = std::max(radius * 1.3f, L * 0.04f) * (0.8f + 0.4f * frand());
        p.shade = overheat;
    }

    void spawn_ember(rdVector3 pos, rdVector3 vel, float L) {
        Particle& p = alloc();
        p.kind = kEmber;
        p.pos = pos;
        p.carrier = vel;
        p.unit = L;
        p.vel = add(vel, mul(rand_vec(), L * 0.6f));
        p.life = 0.4f + 0.6f * frand();
        p.size = L * 0.008f;
    }

    // ---- per-pod emitters ------------------------------------------------------------------
    void tick_pod(swrRace* r, PodFx& fx, float dt) {
        const rdVector3 pos = v3(r->transform.vD);
        if (!fx.has_pos || len(sub(pos, fx.prev_pos)) > kTeleportDist) {
            fx = PodFx{};
            fx.has_pos = true;
            fx.prev_pos = pos;
            return;
        }
        const rdVector3 inst_vel = mul(sub(pos, fx.prev_pos), 1.0f / dt);
        fx.vel = add(fx.vel, mul(sub(inst_vel, fx.vel), 1.0f - std::exp(-dt / 0.05f)));
        fx.prev_pos = pos;

        const bool dead = (r->flags0 & swrObjTest_FLAG0_DEAD) != 0;
        const float L = pod_length(r);
        const float speed = clampf(r->speedValue / (s.top_speed > 1.0f ? s.top_speed : 1.0f), 0.0f, 1.5f);
        const bool boosting = (r->flags0 & swrObjTest_FLAG0_BOOSTING) != 0;
        const rdVector3 eng_mid = mul(add(v3(r->engineXfR.vD), v3(r->engineXfL.vD)), 0.5f);
        // Smoke only comes out while the pod is moving / pulling away: 0 when stopped, easing
        // up to 1 by ~55 speed.
        fx.moving += (clampf((r->speedValue - 5.0f) / 50.0f, 0.0f, 1.0f) - fx.moving) *
                     (1.0f - std::exp(-dt / 0.25f));
        const float moving = fx.moving;
        // The exhaust glow / flame / light show while the engines are under power: throttle
        // held (not flagged NOT_ACCEL, throttle demand above idle) or boosting. Fades fast.
        // After the finish line the autopilot drives the pod without the player-style throttle
        // flags, so also count a pod as under power while it holds or gains a good speed
        // (off the throttle, drag bleeds speed off noticeably).
        fx.speed_rate += ((r->speedValue - fx.prev_speed) / dt - fx.speed_rate) * (1.0f - std::exp(-dt / 0.3f));
        fx.prev_speed = r->speedValue;
        const bool cruising = speed > 0.3f && fx.speed_rate > -0.03f * s.top_speed;
        const bool powered = boosting || cruising ||
                             ((r->flags1 & swrObjTest_FLAG1_NOT_ACCEL) == 0 && r->throttle > 0.3f);
        fx.accel += ((powered ? 1.0f : 0.0f) - fx.accel) * (1.0f - std::exp(-dt / 0.12f));
        // An engine that has blown off (the game hides its model) emits nothing at all.
        const bool alive[2] = {engine_alive(r, 0), engine_alive(r, 1)};

        // Ground plane for spark bounces: the last dust-kick height, while it's recent.
        const bool ground_recent =
            fx.has_ground && std::chrono::duration<float>(Clock::now() - fx.ground_time).count() < 0.25f;
        const float gz = (s.ground_bounce && ground_recent) ? fx.ground_pos.z : NAN;

        // Nozzles of each engine side this frame (world space).
        std::vector<std::pair<rdVector3, float>> noz[2];
        nozzles_world(r, 0, noz[0]);
        nozzles_world(r, 1, noz[1]);

        // -- engine damage: sparks, fire, smoke per segment, only once the HUD shows it orange --
        if (s.damage) {
            const float fade_rate = 1.0f / (s.fade_secs > 0.05f ? s.fade_secs : 0.05f);
            const float thr = orange_threshold();
            const float radius = L * 0.09f * s.size;
            for (int i = 0; i < 6; i++) {
                const float h = r->engineHealth[i];
                // Local players: read the actual HUD colour (and learn the threshold from it).
                // Everyone else: use the learned threshold.
                const int hud = hud_segment_orange(r, i);
                if (hud == 1 && h < g_learn_hi) {
                    g_learn_hi = h;
                    g_learn_dirty = true;
                } else if (hud == 0 && h > g_learn_lo) {
                    g_learn_lo = h;
                    g_learn_dirty = true;
                }
                const bool orange = hud >= 0 ? hud == 1 : h > thr;
                // Starts at a visible 0.15 the moment it turns orange, up to 1 when blown.
                const float target =
                    (dead || !orange) ? 0.0f : clampf(0.15f + 0.85f * (h - thr) / (1.0f - thr), 0.15f, 1.0f);
                float& shown = fx.shown[i];
                if (target > shown)
                    shown += (target - shown) * (1.0f - std::exp(-dt / 0.1f));
                else
                    shown = (shown - dt * fade_rate > target) ? shown - dt * fade_rate : target;
                if (shown <= 0.001f) {
                    fx.acc[i][0] = fx.acc[i][1] = fx.acc[i][2] = 0.0f;
                    continue;
                }
                const bool left = (i < 3) != s.swap_sides;
                if (!alive[left ? 1 : 0]) {
                    fx.acc[i][0] = fx.acc[i][1] = fx.acc[i][2] = 0.0f;
                    continue;
                }
                const rdMatrix44& e = left ? r->engineXfL : r->engineXfR;
                const rdVector3 e_pos = v3(e.vD), e_right = norm(v3(e.vA)), e_fwd = norm(v3(e.vB)),
                                e_up = norm(v3(e.vC));
                // Each damage spot sits on one of this side's engines (two for Ben Quadinaros).
                static std::vector<rdVector3> centres;
                engine_centres(r, left ? 1 : 0, L, centres);
                rdVector3 outward = e_right;
                if (dot(sub(eng_mid, e_pos), outward) > 0.0f)
                    outward = mul(outward, -1.0f);
                const float seg = (i % 3 == 0) ? 1.0f : (i % 3 == 1 ? 0.0f : -1.0f);
                const rdVector3 seg_dir = norm(add(outward, mul(e_up, seg * 1.5f)));
                const float flame_t = clampf((shown - 0.35f) / 0.65f, 0.0f, 1.0f);

                fx.acc[i][0] += dt * s.sparks * 70.0f * std::pow(shown, 1.5f);
                fx.acc[i][1] += dt * s.flames * 55.0f * flame_t * (0.6f + 0.8f * frand());// uneven bursts
                fx.acc[i][2] += dt * s.smoke * moving * (8.0f + 30.0f * shown);
                // The pod editor's fire spots (this side's engine frame), when set, replace the spots
                // on the engine bodies.
                const auto* edited = edited_points(r, 1, left ? 1 : 0);
                auto spot = [&]() {
                    if (edited && !edited->empty()) {
                        const auto& p = (*edited)[(size_t) (frand() * edited->size()) % edited->size()];
                        return add(to_world(e, {p[0], p[1], p[2]}),
                                   add(mul(e_fwd, frand_sym() * radius * 0.5f), mul(e_up, frand_sym() * radius * 0.35f)));
                    }
                    const rdVector3 c = centres[(size_t) (frand() * centres.size()) % centres.size()];
                    return add(add(c, mul(seg_dir, radius)),
                               add(mul(e_fwd, L * (frand() * 0.4f - 0.25f)), mul(e_up, frand_sym() * radius * 0.35f)));
                };
                if (edited && edited->empty()) {// edits with no fire spot on this side: none here
                    fx.acc[i][0] = fx.acc[i][1] = fx.acc[i][2] = 0.0f;
                    continue;
                }
                for (; fx.acc[i][0] >= 1.0f; fx.acc[i][0] -= 1.0f)
                    spawn_spark(spot(), fx.vel, seg_dir, e_up, L, gz);
                for (; fx.acc[i][1] >= 1.0f; fx.acc[i][1] -= 1.0f)
                    spawn_flame(spot(), fx.vel, seg_dir, e_up, L);
                // Grey wisps at first, thick black once it's burning -- half from the damaged
                // spot, half pouring out of that engine's exhaust nozzles.
                const int side = left ? 1 : 0;
                for (; fx.acc[i][2] >= 1.0f; fx.acc[i][2] -= 1.0f) {
                    const float shade = clampf(0.25f + 0.75f * flame_t, 0.0f, 1.0f);
                    if (!noz[side].empty() && frand() < 0.5f) {
                        const auto& n = noz[side][(size_t) (frand() * noz[side].size()) % noz[side].size()];
                        spawn_smoke(add(n.first, mul(e_fwd, -L * 0.08f)), fx.vel, mul(e_fwd, -1.0f), L, shade);
                    } else {
                        spawn_smoke(spot(), fx.vel, seg_dir, L, shade);
                    }
                }
            }
        }

        // -- ground dust: billows wherever the game is kicking up its own dust trail --
        if (s.dust && ground_recent && !dead) {
            // The pod editor's dust spots (engine frames, dropped to the ground under that
            // engine), when set, replace the single point the game kicks its dust from.
            static std::vector<rdVector3> dust_pts;
            dust_pts.clear();
            const bool dust_edited = edited_points(r, 2, 0) != nullptr;
            for (int side = 0; side < 2 && dust_edited; side++)
                for (const auto& p: *edited_points(r, 2, side)) {
                    rdVector3 w = to_world(engine_of(r, side), {p[0], p[1], p[2]});
                    w.z = fx.ground_pos.z;
                    dust_pts.push_back(w);
                }
            if (!dust_edited)
                dust_pts.push_back(fx.ground_pos);
            fx.dust_acc += dt * s.dust_amount * (8.0f + 50.0f * clampf(speed, 0.0f, 1.0f));
            for (; fx.dust_acc >= 1.0f && !dust_pts.empty(); fx.dust_acc -= 1.0f)
                spawn_dust(dust_pts[(size_t) (frand() * dust_pts.size()) % dust_pts.size()], fx.vel,
                           mul(norm(add(v3(r->engineXfR.vB), v3(r->engineXfL.vB))), -1.0f), L);
        } else {
            fx.dust_acc = 0.0f;
        }

        // -- exhaust: Galactic Racer style core + halo + flame, and a few embers --
        if (s.exhaust && !dead) {
            const float target = clampf(0.25f + 0.75f * speed, 0.0f, 1.2f) + (boosting ? 0.6f : 0.0f);
            fx.throttle += (target - fx.throttle) * (1.0f - std::exp(-dt / 0.15f));
            const size_t first = g_exhaust.size();
            const bool local = (r->flags0 & swrObjTest_FLAG0_LOCAL) != 0;
            // Overheat: engineTemp drains from 100 toward 0 while boosting; below ~45 the trail
            // smoke starts going dark, fully black when the engines are about to blow.
            const float overheat = clampf((45.0f - r->engineTemp) / 45.0f, 0.0f, 1.0f);
            for (int side = 0; side < 2; side++) {
                if (!alive[side]) {
                    fx.trail_acc[side] = 0.0f;
                    continue;
                }
                const rdMatrix44& e = engine_of(r, side);
                const rdVector3 fwd = norm(v3(e.vB));
                const rdVector3 back = mul(fwd, -1.0f);
                // Every captured nozzle on this engine; before any are captured, fall back to a
                // point just behind the engine centre.
                std::vector<std::pair<rdVector3, float>> points = noz[side];
                if (points.empty())
                    points.push_back({sub(v3(e.vD), mul(fwd, L * 0.15f)), L * 0.05f});
                const float spread = 1.0f / std::sqrt((float) points.size());// many small nozzles share the output
                // Ground under this engine: the game lays each engine's shadow flat on the ground.
                const float ground = side == 0 ? r->shadowXf1.vD.z : r->shadowXf2.vD.z;
                // Glow, flame and light only while the engines are under power (fade with it).
                if (fx.accel > 0.02f) {
                    for (size_t k = 0; k < points.size(); k++) {
                        ExhaustSprite sp;
                        sp.pos = points[k].first;
                        sp.dir = back;
                        sp.radius = clampf(points[k].second, L * 0.012f, L * 0.09f) * s.size;
                        sp.intensity = fx.throttle * fx.accel;
                        sp.flame_len = L * (0.06f + 0.26f * fx.throttle) * spread * s.exhaust_flame;
                        sp.flicker = 0.85f + 0.15f * std::sin(g_time * 37.0f + (float) k * 2.1f + side) *
                                                 std::sin(g_time * 23.0f + (float) k + side * 1.7f);
                        sp.ground_z = ground;
                        sp.unit = L;
                        g_exhaust.push_back(sp);
                    }
                }
                // Smoke trails, one stream per nozzle, starting a little behind the glow -- only
                // while moving. Spawn points are spread along the path the nozzle travelled since
                // the last frame, so the trail is a continuous ribbon left hanging in the air
                // rather than clumps, however fast the pod goes.
                if (s.air_trails > 0.0f) {
                    fx.trail_acc[side] += dt * s.air_trails * moving * (local ? 1.0f : 0.4f) *
                                          (6.0f + 55.0f * clampf(speed, 0.0f, 1.0f)) * (float) points.size() * spread;
                    const rdVector3 step = mul(fx.vel, dt);// how far the pod moved this frame
                    for (; fx.trail_acc[side] >= 1.0f; fx.trail_acc[side] -= 1.0f) {
                        const auto& n = points[(size_t) (frand() * points.size()) % points.size()];
                        const rdVector3 start = add(n.first, mul(back, L * 0.08f));
                        spawn_trail(sub(start, mul(step, frand())), fx.vel, back, L, n.second, overheat, fx.throttle);
                    }
                }
            }
            if (s.show_nozzles)
                for (int side = 0; side < 2; side++)
                    for (const auto& n: noz[side])
                        g_markers.push_back(n.first);
            fx.ember_acc += dt * s.exhaust_embers * (boosting ? 25.0f : 1.0f * fx.throttle);
            const size_t count = g_exhaust.size() - first;
            for (; fx.ember_acc >= 1.0f && count > 0; fx.ember_acc -= 1.0f) {
                const ExhaustSprite& sp = g_exhaust[first + (size_t) (frand() * count) % count];
                spawn_ember(sp.pos, add(mul(fx.vel, 0.85f), mul(sp.dir, L * 2.0f)), L);
            }
        }
    }

    // ---- simulation ------------------------------------------------------------------------
    void simulate(Particle& p, float dt) {
        const float L = p.unit;
        float drag = 1.5f, gravity = 0.0f, lift = 0.0f, turb = 0.0f;
        switch (p.kind) {
            case kSpark: drag = 1.5f; gravity = 24.0f * L; break;
            case kEmber: drag = 2.5f; gravity = 5.0f * L; turb = 1.0f * L; break;
            case kFlame: drag = 2.0f; lift = 4.0f * L; turb = 1.5f * L; break;
            case kSmoke: drag = 2.5f; lift = 2.5f * L; turb = 2.0f * L; break;
            case kDust: drag = 3.5f; gravity = 0.8f * L; turb = 1.5f * L; break;
            case kTrail: drag = 2.0f; lift = 0.6f * L; turb = 1.2f * L; break;
            case kExFire: drag = 4.0f; lift = 1.0f * L; turb = 2.0f * L; break;
        }
        p.vel = mul(p.vel, std::exp(-drag * dt));// air drag (world-still air)
        p.vel.z += (lift - gravity) * dt;         // buoyancy / gravity, world z up
        if (turb > 0.0f && s.turbulence > 0.0f) {
            // Cheap swirling: a smooth, position- and time-varying push.
            const float k = 6.2831853f / (3.0f * L);
            const rdVector3 sw = {std::sin(p.pos.y * k + g_time * 1.1f), std::sin(p.pos.x * k + g_time * 1.3f),
                                  std::sin((p.pos.x + p.pos.y) * k * 0.7f + g_time * 0.9f)};
            p.vel = add(p.vel, mul(sw, turb * s.turbulence * dt));
        }
        p.pos = add(p.pos, mul(p.vel, dt));
        // Sparks skip off the ground instead of falling through it.
        if (p.kind == kSpark && !std::isnan(p.ground_z) && p.pos.z < p.ground_z && p.vel.z < 0.0f) {
            p.pos.z = p.ground_z;
            p.vel.z *= -0.35f;
            p.vel.x *= 0.7f;
            p.vel.y *= 0.7f;
        }
    }

    void tick(float dt, bool spawn) {
        g_time += dt;
        for (Particle& p: g_parts) {
            if (!p.active)
                continue;
            p.age += dt;
            if (p.age >= p.life) {
                p.active = false;
                continue;
            }
            simulate(p, dt);
        }
        g_exhaust.clear();
        g_markers.clear();
        // Commit the nozzles the renderer reported since the last tick. Sources, best first in Auto:
        // kind 2 = per-nozzle star-glow quads, 3 = per-nozzle exhaust discs (each pod model places
        // these on its real nozzles), 0/1 = the generic per-engine exhaust/glow, which sit on the
        // engine centre line (wrong on pods like Ark Roose's). A lower-ranked source is only used
        // until a better one has been seen; a side with no reports keeps what it had (some of these
        // meshes are hidden at times).
        static const int kOrders[4][4] = {{2, 3, 0, 1}, {3, 2, 0, 1}, {0, 1, 2, 3}, {1, 0, 2, 3}};
        const int* order = kOrders[std::clamp(s.nozzle_source, 0, 3)];
        auto rank_of = [&](int kind) {
            for (int k = 0; k < 4; k++)
                if (order[k] == kind)
                    return k;
            return 99;
        };
        for (auto& [racer, pn]: g_nozzles) {
            for (int side = 0; side < 2; side++) {
                for (int k = 0; k < 4; k++) {
                    const int kind = order[k];
                    if (pn.staging[side][kind].empty())
                        continue;
                    if (k <= rank_of(pn.kind[side])) {
                        pn.side[side] = pn.staging[side][kind];
                        pn.kind[side] = kind;
                    }
                    break;
                }
                for (auto& st: pn.staging[side])
                    st.clear();
            }
        }
        if (!spawn || !s.enabled)
            return;
        const int n = swrEvent_GetEventCount(kEventTest);
        for (int i = 0; i < n; i++) {
            swrRace* r = (swrRace*) swrEvent_GetItem(kEventTest, i);
            if (r == nullptr || r->partNodes == nullptr)// far-LOD pods have no engine parts
                continue;
            if (!s.ai_pods && (r->flags0 & swrObjTest_FLAG0_LOCAL) == 0)
                continue;
            tick_pod(r, g_pods[r], dt);
        }
    }

    // ---- drawing ---------------------------------------------------------------------------
    rdMatrix44 g_proj, g_view;

    bool project(rdVector3 w, float* sx, float* sy, float* wz, float* view_w) {
        rdVector4 in = {w.x, w.y, w.z, 1.0f}, vp, clip;
        rdMatrix_TransformPoint44(&vp, &in, &g_view);
        rdMatrix_TransformPoint44(&clip, &vp, &g_proj);
        if (clip.w <= 0.01f)
            return false;
        const float inv = 1.0f / clip.w;
        *sx = (clip.x * inv * 0.5f + 0.5f) * (float) swrDisplay_screenWidth;
        *sy = (0.5f - clip.y * inv * 0.5f) * (float) swrDisplay_screenHeight;
        *wz = clip.z * inv * 0.5f + 0.5f;
        *view_w = clip.w;
        return *wz >= 0.0f && *wz <= 1.0f;
    }

    GLuint make_texture(int N, float (*alpha_at)(float nx, float ny, int x, int y)) {
        std::vector<uint32_t> px((size_t) N * N);
        for (int y = 0; y < N; y++)
            for (int x = 0; x < N; x++) {
                const float nx = ((float) x + 0.5f) / N * 2.0f - 1.0f;
                const float ny = ((float) y + 0.5f) / N * 2.0f - 1.0f;
                const float a = clampf(alpha_at(nx, ny, x, y), 0.0f, 1.0f);
                px[(size_t) y * N + x] = ((uint32_t) (a * 255.0f) << 24) | 0x00ffffff;
            }
        GLuint tex = 0;
        glGenTextures(1, &tex);
        glBindTexture(GL_TEXTURE_2D, tex);
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, N, N, 0, GL_RGBA, GL_UNSIGNED_BYTE, px.data());
        glGenerateMipmap(GL_TEXTURE_2D);// small, distant sprites stay smooth instead of sparkling
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glBindTexture(GL_TEXTURE_2D, 0);
        return tex;
    }

    // Hash-based value noise for the puff texture.
    float hash2(int x, int y) {
        uint32_t h = (uint32_t) x * 374761393u + (uint32_t) y * 668265263u;
        h = (h ^ (h >> 13)) * 1274126177u;
        return (float) (h & 0xffff) / 65535.0f;
    }
    float vnoise(float x, float y) {
        const int xi = (int) std::floor(x), yi = (int) std::floor(y);
        const float fx = x - xi, fy = y - yi;
        const float sx = fx * fx * (3 - 2 * fx), sy = fy * fy * (3 - 2 * fy);
        const float a = hash2(xi, yi), b = hash2(xi + 1, yi), c = hash2(xi, yi + 1), d = hash2(xi + 1, yi + 1);
        return (a + (b - a) * sx) + ((c + (d - c) * sx) - (a + (b - a) * sx)) * sy;
    }

    GLuint soft_texture() {
        static GLuint tex = make_texture(128, [](float nx, float ny, int, int) {
            const float a = clampf((1.0f - std::sqrt(nx * nx + ny * ny)) * 1.4f, 0.0f, 1.0f);
            return a * a;
        });
        return tex;
    }

    // Lumpy, wispy puff for smoke and dust.
    GLuint puff_texture() {
        static GLuint tex = make_texture(128, [](float nx, float ny, int x, int y) {
            const float r = std::sqrt(nx * nx + ny * ny);
            float n = 0.0f, amp = 0.5f, f = 4.0f / 128.0f;// same lumps as before at the new size
            for (int o = 0; o < 4; o++, amp *= 0.5f, f *= 2.0f)
                n += amp * vnoise(x * f * 1.0f, y * f * 1.0f);
            const float fall = clampf(1.0f - r, 0.0f, 1.0f);
            // Denser body: a soft but mostly solid core with a lumpy, wispy edge.
            return clampf(std::pow(fall, 1.3f) * (0.75f + 0.9f * n), 0.0f, 1.0f);
        });
        return tex;
    }

    struct Batch {
        std::vector<D3DTLVERTEX> v;
        std::vector<WORD> i;
        void clear() {
            v.clear();
            i.clear();
        }
        // Quad with per-corner colours (head = corners 0,1; tail = 2,3).
        void quad(const float pts[4][2], const float uvs[4][2], D3DCOLOR head, D3DCOLOR tail, float wz) {
            if (v.size() + 4 > 65532)
                return;// WORD indices
            const WORD base = (WORD) v.size();
            for (int k = 0; k < 4; k++) {
                D3DTLVERTEX t{};
                t.sx = pts[k][0];
                t.sy = pts[k][1];
                t.sz = wz;
                t.rhw = 1.0f;
                t.color = k < 2 ? head : tail;
                t.tu = uvs[k][0];
                t.tv = uvs[k][1];
                v.push_back(t);
            }
            for (WORD k: {0, 1, 2, 0, 2, 3})
                i.push_back((WORD) (base + k));
        }
        void sprite(float x, float y, float half, D3DCOLOR c, float wz) {
            const float pts[4][2] = {{x - half, y - half}, {x + half, y - half}, {x + half, y + half}, {x - half, y + half}};
            const float uvs[4][2] = {{0, 0}, {1, 0}, {1, 1}, {0, 1}};
            quad(pts, uvs, c, c, wz);
        }
        // Screen-space streak from (hx,hy) to (tx,ty), `half` wide.
        // The round texture stretched into an ellipse: centre (cx, cy), half-length vector (ux, uy)
        // along its long axis, `half_w` across it.
        void ellipse(float cx, float cy, float ux, float uy, float half_w, D3DCOLOR c, float wz) {
            const float l = std::sqrt(ux * ux + uy * uy);
            if (l < 0.5f)
                return;
            const float nx = -uy / l * half_w, ny = ux / l * half_w;
            const float pts[4][2] = {{cx - ux - nx, cy - uy - ny}, {cx + ux - nx, cy + uy - ny},
                                     {cx + ux + nx, cy + uy + ny}, {cx - ux + nx, cy - uy + ny}};
            const float uvs[4][2] = {{0, 0}, {1, 0}, {1, 1}, {0, 1}};
            quad(pts, uvs, c, c, wz);
        }
        bool streak(float hx, float hy, float tx, float ty, float half, D3DCOLOR head, D3DCOLOR tail, float wz) {
            const float dx = hx - tx, dy = hy - ty;
            const float l = std::sqrt(dx * dx + dy * dy);
            if (l < 1.5f)
                return false;
            const float ox = -dy / l * half, oy = dx / l * half;
            const float pts[4][2] = {{hx + ox, hy + oy}, {hx - ox, hy - oy}, {tx - ox, ty - oy}, {tx + ox, ty + oy}};
            const float uvs[4][2] = {{0.5f, 0.0f}, {0.5f, 1.0f}, {0.5f, 1.0f}, {0.5f, 0.0f}};
            quad(pts, uvs, head, tail, wz);
            return true;
        }
        void flush(GLuint tex, bool additive) {
            if (v.empty())
                return;
            const GLboolean had_depth = glIsEnabled(GL_DEPTH_TEST);
            GLint old_func = GL_LESS;
            glGetIntegerv(GL_DEPTH_FUNC, &old_func);
            glEnable(GL_DEPTH_TEST);
            glDepthFunc(GL_LEQUAL);
            if (additive)
                glBlendFunc(GL_SRC_ALPHA, GL_ONE);
            std3D_DrawRenderList_delta((LPDIRECT3DTEXTURE2) (uintptr_t) tex,
                                       (Std3DRenderState) (STD3D_RS_BLEND_MODULATEALPHA | STD3D_RS_ZWRITE_DISABLED |
                                                           STD3D_RS_TEX_MAGFILTER_LINEAR | STD3D_RS_TEX_CLAMP_U |
                                                           STD3D_RS_TEX_CLAMP_V),
                                       v.data(), (int) v.size(), i.data(), (int) i.size());
            if (additive)
                glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
            glDepthFunc((GLenum) old_func);
            if (!had_depth)
                glDisable(GL_DEPTH_TEST);
            clear();
        }
    };
    Batch g_alpha, g_add, g_add_soft;

    D3DCOLOR argb(float a, float r, float g, float b) {
        auto c = [](float x) { return (uint32_t) (clampf(x, 0.0f, 1.0f) * 255.0f + 0.5f); };
        return (c(a) << 24) | (c(r) << 16) | (c(g) << 8) | c(b);
    }

namespace {
    // Energy binder meshes reported by the renderer this frame (long-axis ends, world space).
    struct BinderPiece {
        const swrRace* racer;
        rdVector3 a, b;
        float r, g, bl;
        bool card;// the game's glow card: placement only
    };
    std::vector<BinderPiece> g_binder_pieces;// cleared after the frame is drawn
    // One beam per binder: pieces whose ends touch are merged, and the beam spans their ends
    // along the merged direction (Ben Quadinaros's two binders stay two beams).
    struct BinderBeam {
        const swrRace* racer;
        rdVector3 a, b;
        float r, g, bl;
        float L;
        float share = 1.0f;// brightness share: pods with two binders (Ben Quadinaros) split it
    };
    std::vector<BinderBeam> g_binder_beams;
    bool g_binder_beams_built = false;

    const std::vector<BinderBeam>& binder_beams() {
        if (g_binder_beams_built)
            return g_binder_beams;
        g_binder_beams_built = true;
        g_binder_beams.clear();
        // A binder always spans the gap between a pod's left and right engines, so the beam runs
        // along that engine line (the binder meshes' own shapes don't say which way the beam goes).
        // A pod's pieces are grouped by height: same height = same binder (Ben Quadinaros's two
        // binders sit at different heights), and each group's beam runs between the engine pair
        // nearest its height.
        // Pods with the game's glow card: that card is laid exactly along the beam (in this very
        // frame), so each card is one beam; colour from the pod's other binder pieces.
        std::vector<bool> used(g_binder_pieces.size(), false);
        for (size_t i = 0; i < g_binder_pieces.size(); i++) {
            const BinderPiece& card = g_binder_pieces[i];
            if (!card.card)
                continue;
            float cr = 0, cg = 0, cb = 0;
            int cnt = 0;
            for (const BinderPiece& p: g_binder_pieces)
                if (!p.card && p.racer == card.racer)
                    cr += p.r, cg += p.g, cb += p.bl, cnt++;
            if (cnt == 0)
                cr = 0.6f, cg = 0.55f, cb = 1.0f, cnt = 1;
            const float L = pod_length(card.racer);
            if (len(sub(card.b, card.a)) > L * 0.05f)
                g_binder_beams.push_back({card.racer, card.a, card.b, cr / cnt, cg / cnt, cb / cnt, L});
            for (size_t j = 0; j < g_binder_pieces.size(); j++)
                if (g_binder_pieces[j].racer == card.racer)
                    used[j] = true;
        }
        for (size_t i = 0; i < g_binder_pieces.size(); i++) {
            if (used[i] || g_binder_pieces[i].card)
                continue;
            const swrRace* r = g_binder_pieces[i].racer;
            const float L = pod_length(r);
            const rdVector3 up = norm(v3(r->transform.vC));
            auto height = [&](const BinderPiece& p) { return dot(mul(add(p.a, p.b), 0.5f), up); };
            const float h0 = height(g_binder_pieces[i]);
            rdVector3 centre = {0, 0, 0};
            float cr = 0, cg = 0, cb = 0, hsum = 0;
            int cnt = 0;
            for (size_t j = i; j < g_binder_pieces.size(); j++) {
                const BinderPiece& p = g_binder_pieces[j];
                if (used[j] || p.racer != r || std::fabs(height(p) - h0) > L * 0.2f)
                    continue;
                used[j] = true;
                centre = add(centre, mul(add(p.a, p.b), 0.5f));
                cr += p.r, cg += p.g, cb += p.bl, hsum += height(p);
                cnt++;
            }
            centre = mul(centre, 1.0f / (float) cnt);
            const float h = hsum / (float) cnt;
            // Engine pair nearest this binder's height (Ben's second pair: engineXfR2 / L2).
            rdVector3 eR = v3(r->engineXfR.vD), eL = v3(r->engineXfL.vD);
            if (r->partNodes != nullptr && r->partNodes[3] && r->partNodes[4]) {
                const rdVector3 eR2 = v3(r->engineXfR2.vD), eL2 = v3(r->engineXfL2.vD);
                const float h1 = 0.5f * (dot(eR, up) + dot(eL, up)), h2 = 0.5f * (dot(eR2, up) + dot(eL2, up));
                if (std::fabs(h2 - h) < std::fabs(h1 - h))
                    eR = eR2, eL = eL2;
            }
            const rdVector3 dir = norm(sub(eL, eR));
            const float gap = dot(sub(eL, eR), dir);
            if (!(gap > L * 0.1f && gap < L * 4.0f))
                continue;
            // Through the pieces' centre along the engine line, stopping short of each engine's
            // centre (the beam meets the engines' inner faces).
            const rdVector3 mid = mul(add(eR, eL), 0.5f);
            const float off = dot(sub(centre, mid), dir);// centre's offset along the line
            const rdVector3 axis_centre = sub(centre, mul(dir, off));
            const float half = 0.5f * gap * 0.8f;
            BinderBeam beam{r, sub(axis_centre, mul(dir, half)), add(axis_centre, mul(dir, half)), cr / cnt, cg / cnt,
                            cb / cnt, L};
            g_binder_beams.push_back(beam);
        }
        for (BinderBeam& bm: g_binder_beams) {
            int count = 0;
            for (const BinderBeam& o: g_binder_beams)
                count += o.racer == bm.racer;
            bm.share = 1.0f / std::pow((float) std::max(count, 1), 0.75f);
        }
        return g_binder_beams;
    }

    // A gentle shimmer (the beam itself already crackles).
    float binder_flicker(const BinderBeam& bm, float speed) {
        const float ph = (float) ((uintptr_t) bm.racer % 97);
        return 0.93f + 0.05f * std::sin(g_time * speed + ph) + 0.02f * std::sin(g_time * speed * 2.3f + ph * 1.7f);
    }
}// namespace

    void draw() {
        const float focal = std::fabs(g_proj.vB.y) * 0.5f * (float) swrDisplay_screenHeight;
        for (const Particle& p: g_parts) {
            if (!p.active)
                continue;
            float hx, hy, wz, vw;
            if (!project(p.pos, &hx, &hy, &wz, &vw))
                continue;
            const float f = p.age / p.life;
            float half = p.size * s.size * focal / vw;
            switch (p.kind) {
                case kSpark: {
                    half = clampf(half, 0.8f, 6.0f);
                    const D3DCOLOR head = argb(1.0f - f * f, 1.0f, 0.95f - 0.45f * f, 0.7f - 0.6f * f);
                    const D3DCOLOR tail = argb(0.0f, 1.0f, 0.5f, 0.1f);
                    const rdVector3 tail_w = sub(p.pos, mul(sub(p.vel, p.carrier), 0.035f));
                    float tx, ty, twz, tvw;
                    if (project(tail_w, &tx, &ty, &twz, &tvw) && g_add.streak(hx, hy, tx, ty, half, head, tail, wz))
                        break;
                    g_add.sprite(hx, hy, half, head, wz);
                    break;
                }
                case kEmber: {
                    half = clampf(half, 0.8f, 4.0f);
                    g_add.sprite(hx, hy, half, argb((1.0f - f) * 0.9f, 1.0f, 0.55f - 0.3f * f, 0.15f), wz);
                    break;
                }
                case kFlame: {
                    half = clampf(half * (1.0f + 1.2f * f), 1.5f, 160.0f);
                    // Translucent red-orange tongues, deepening to dull red as they burn off.
                    const float a = (f < 0.15f ? f / 0.15f : 1.0f) * (1.0f - f) * 0.5f * s.flame_opacity;
                    const float hue = 0.3f + 0.25f * p.shade;// per-particle orange..red
                    g_add.sprite(hx, hy, half, argb(a, 1.0f, hue - 0.28f * f, 0.12f - 0.1f * f), wz);
                    break;
                }
                case kExFire: {
                    // Hot near the nozzle, reddening and thinning fast; each one a slightly
                    // different size and hue so the jet breaks up and flickers.
                    half = clampf(half * (1.0f + 0.8f * f), 1.0f, 120.0f);
                    const float a = std::pow(1.0f - f, 1.5f) * 0.5f * s.flame_opacity;
                    const float g = (0.35f + 0.3f * p.shade) * (1.0f - 0.7f * f);
                    g_add_soft.sprite(hx, hy, half, argb(a, 1.0f, g, 0.06f + 0.1f * (1.0f - f) * p.shade), wz);
                    break;
                }
                case kSmoke: {
                    half = clampf(half * (1.0f + 3.5f * f), 2.0f, 360.0f);// spreads as it rises
                    // Thick and opaque near the engine, thinning as it spreads; black smoke is
                    // denser than the grey.
                    // Grey wisps 20% lighter than they were; the black burning smoke unchanged.
                    const float grey_k = 0.8f + 0.2f * clampf((p.shade - 0.25f) / 0.75f, 0.0f, 1.0f);
                    const float a = (f < 0.06f ? f / 0.06f : 1.0f) * std::pow(1.0f - f, 1.1f) *
                                    (0.75f + 0.2f * p.shade) * grey_k * s.smoke_opacity;
                    const float g = 0.42f - 0.36f * p.shade;// dark grey -> black
                    g_alpha.sprite(hx, hy, half, argb(a, g, g * 0.97f, g * 0.95f), wz);
                    break;
                }
                case kTrail: {
                    // Exhaust smoke trail: grey puffs that swell and thin out behind the pod,
                    // turning dark and heavier as the engines overheat (p.shade).
                    half = clampf(half * (1.0f + 4.0f * f), 1.5f, 300.0f);
                    const float a = (f < 0.06f ? f / 0.06f : 1.0f) * std::pow(1.0f - f, 1.2f) * 0.65f *
                                    (1.0f + 0.4f * p.shade) * s.smoke_opacity;
                    const float g = 0.55f - 0.47f * p.shade;
                    g_alpha.sprite(hx, hy, half, argb(a, g, g, g * 1.04f), wz);
                    break;
                }
                case kDust: {
                    half = clampf(half * (1.0f + 4.0f * f), 2.0f, 400.0f);
                    const float a = (f < 0.12f ? f / 0.12f : 1.0f) * (1.0f - f) * 0.38f;
                    g_alpha.sprite(hx, hy, half,
                                   argb(a, s.dust_color[0] * p.shade, s.dust_color[1] * p.shade, s.dust_color[2] * p.shade), wz);
                    break;
                }
            }
        }

        // Energy binders: the glow comes from the middle of the beam -- a bloom at the centre, and a
        // halo + brighter core running out to each engine, fading to nothing at the ends.
        for (const BinderBeam& bm: binder_beams()) {
            const rdVector3 mid = mul(add(bm.a, bm.b), 0.5f);
            float ax, ay, awz, avw, bx, by, bwz, bvw, mx, my, mwz, mvw;
            if (!project(bm.a, &ax, &ay, &awz, &avw) || !project(bm.b, &bx, &by, &bwz, &bvw) ||
                !project(mid, &mx, &my, &mwz, &mvw))
                continue;
            const float fl = binder_flicker(bm, 6.0f) * s.binder_light * bm.share;
            const float halo = clampf(bm.L * 0.16f * focal / mvw, 2.0f, 260.0f);// thickness across the beam
            const float core = clampf(bm.L * 0.045f * focal / mvw, 1.0f, 80.0f);
            const float wz = std::min(mwz, std::min(awz, bwz));
            const D3DCOLOR c_halo = argb(clampf(0.26f * fl, 0.0f, 1.0f), bm.r, bm.g, bm.bl);
            const D3DCOLOR c_core = argb(clampf(0.5f * fl, 0.0f, 1.0f), 0.55f + 0.45f * bm.r, 0.55f + 0.45f * bm.g,
                                         0.55f + 0.45f * bm.bl);
            (void) c_halo;
            (void) c_core;
            // Oval glow along the beam: each layer is one ellipse stretched from end to end (the round
            // soft texture squashed), reaching a little past the beam's ends onto the engines.
            const float hx = (bx - ax) * 0.5f, hy = (by - ay) * 0.5f;// centre -> end, screen space
            g_add_soft.ellipse(mx, my, hx * 1.25f, hy * 1.25f, halo,
                               argb(clampf(0.3f * fl, 0.0f, 1.0f), bm.r, bm.g, bm.bl), wz);
            g_add_soft.ellipse(mx, my, hx * 1.05f, hy * 1.05f, core * 1.6f,
                               argb(clampf(0.45f * fl, 0.0f, 1.0f), 0.55f + 0.45f * bm.r, 0.55f + 0.45f * bm.g,
                                    0.55f + 0.45f * bm.bl), wz);
        }

        // Exhaust: wide orange halo, white-hot core, and a flame streaking back from the nozzle.
        for (const ExhaustSprite& e: g_exhaust) {
            float hx, hy, wz, vw;
            if (!project(e.pos, &hx, &hy, &wz, &vw))
                continue;
            const float r = e.radius * focal / vw;
            const float in = clampf(e.intensity, 0.0f, 1.8f) * e.flicker;
            // Fades in with the moving factor (folded into intensity) as the pod gets going.
            const float glow = s.exhaust_glow * clampf(e.intensity / 0.25f, 0.0f, 1.0f);
            g_add_soft.sprite(hx, hy, clampf(r * (2.6f + 0.8f * in), 2.0f, 500.0f),
                              argb(0.25f * in * glow, 1.0f, 0.22f, 0.05f), wz);
            g_add_soft.sprite(hx, hy, clampf(r * 1.2f, 1.5f, 250.0f), argb(0.55f * glow, 1.0f, 0.45f, 0.18f), wz);
            g_add_soft.sprite(hx, hy, clampf(r * 0.6f, 1.0f, 120.0f), argb(0.8f * glow, 1.0f, 0.85f, 0.65f), wz);

            // A faint beam cone thrown backward from the nozzle. (The light it casts on the ground
            // and walls is done properly by the lighting pass -- see pod_fx_gather_lights.)
            if (s.exhaust_light > 0.0f) {
                const float lit = clampf(in, 0.0f, 1.6f) * s.exhaust_light * glow / std::max(s.exhaust_glow, 1e-3f);
                const rdVector3 beam_end = add(e.pos, mul(e.dir, e.unit * 0.9f));
                float bx, by, bwz, bvw;
                if (project(beam_end, &bx, &by, &bwz, &bvw))
                    g_add_soft.streak(hx, hy, bx, by, clampf(r * 2.2f, 2.0f, 300.0f), argb(0.10f * lit, 1.0f, 0.35f, 0.1f),
                                      argb(0.0f, 1.0f, 0.2f, 0.05f), wz);
            }
            if (s.exhaust_flame > 0.0f) {
                const rdVector3 tip = add(e.pos, mul(e.dir, e.flame_len * e.flicker));
                float tx, ty, twz, tvw;
                if (project(tip, &tx, &ty, &twz, &tvw)) {
                    g_add_soft.streak(hx, hy, tx, ty, clampf(r * 0.9f, 1.0f, 200.0f),
                                      argb(0.4f * in * s.flame_opacity, 1.0f, 0.3f, 0.08f),
                                      argb(0.0f, 0.8f, 0.08f, 0.02f), wz);
                    g_add_soft.streak(hx, hy, tx, ty, clampf(r * 0.4f, 1.0f, 100.0f),
                                      argb(0.5f * in * s.flame_opacity, 1.0f, 0.6f, 0.3f),
                                      argb(0.0f, 1.0f, 0.25f, 0.06f), wz);
                }
            }
        }

        // Debug: bright cyan marker on every detected nozzle.
        for (const rdVector3& m: g_markers) {
            float hx, hy, wz, vw;
            if (project(m, &hx, &hy, &wz, &vw))
                g_add_soft.sprite(hx, hy, 6.0f, argb(1.0f, 0.2f, 1.0f, 1.0f), 0.0f);
        }

        g_alpha.flush(puff_texture(), false);
        g_add_soft.flush(soft_texture(), true);
        g_add.flush(soft_texture(), true);
    }

    // ---- settings UI -----------------------------------------------------------------------
    const char* kSec = "pod_fx";
    void load_settings() {
        auto b = [](const char* k, bool& v) { v = config::get_int(kSec, k, v) != 0; };
        auto f = [](const char* k, float& v, float lo, float hi) { v = clampf(config::get_float(kSec, k, v), lo, hi); };
        b("enabled", s.enabled);
        b("ai_pods", s.ai_pods);
        b("damage", s.damage);
        f("threshold", s.threshold, 0.0f, 0.95f);
        f("sparks", s.sparks, 0.0f, 4.0f);
        f("flames", s.flames, 0.0f, 4.0f);
        f("smoke", s.smoke, 0.0f, 4.0f);
        f("fade_secs", s.fade_secs, 0.1f, 10.0f);
        b("swap_sides", s.swap_sides);
        b("dust", s.dust);
        b("hide_stock_dust", s.hide_stock_dust);
        f("dust_amount", s.dust_amount, 0.0f, 4.0f);
        f("air_trails", s.air_trails, 0.0f, 4.0f);
        s.nozzle_source = std::clamp(config::get_int(kSec, "nozzle_src", s.nozzle_source), 0, 3);
        b("show_nozzles", s.show_nozzles);
        g_learn_lo = config::get_float(kSec, "learned_green_max", -1.0f);
        g_learn_hi = config::get_float(kSec, "learned_orange_min", 2.0f);
        f("dust_r", s.dust_color[0], 0.0f, 1.0f);
        f("dust_g", s.dust_color[1], 0.0f, 1.0f);
        f("dust_b", s.dust_color[2], 0.0f, 1.0f);
        b("exhaust", s.exhaust);
        f("exhaust_glow", s.exhaust_glow, 0.0f, 3.0f);
        f("exhaust_flame", s.exhaust_flame, 0.0f, 3.0f);
        f("embers", s.exhaust_embers, 0.0f, 4.0f);
        f("top_speed", s.top_speed, 50.0f, 2000.0f);
        f("turbulence", s.turbulence, 0.0f, 4.0f);
        b("ground_bounce", s.ground_bounce);
        f("size", s.size, 0.2f, 4.0f);
        f("smoke_opacity", s.smoke_opacity, 0.0f, 2.0f);
        f("flame_opacity", s.flame_opacity, 0.0f, 2.0f);
        f("exhaust_light", s.exhaust_light, 0.0f, 3.0f);
        f("binder_light", s.binder_light, 0.0f, 3.0f);
        b("hide_stock_binder_glow", s.hide_stock_binder_glow);
    }

    void save_settings() {
        auto f = [](const char* k, float v) { config::set_float(kSec, k, v); };
        auto b = [](const char* k, bool v) { config::set_bool(kSec, k, v); };
        b("enabled", s.enabled);
        b("ai_pods", s.ai_pods);
        b("damage", s.damage);
        f("threshold", s.threshold);
        f("sparks", s.sparks);
        f("flames", s.flames);
        f("smoke", s.smoke);
        f("fade_secs", s.fade_secs);
        b("swap_sides", s.swap_sides);
        b("dust", s.dust);
        b("hide_stock_dust", s.hide_stock_dust);
        f("dust_amount", s.dust_amount);
        f("air_trails", s.air_trails);
        config::set_int(kSec, "nozzle_src", s.nozzle_source);
        b("show_nozzles", s.show_nozzles);
        f("learned_green_max", g_learn_lo);
        f("learned_orange_min", g_learn_hi);
        f("dust_r", s.dust_color[0]);
        f("dust_g", s.dust_color[1]);
        f("dust_b", s.dust_color[2]);
        b("exhaust", s.exhaust);
        f("exhaust_glow", s.exhaust_glow);
        f("exhaust_flame", s.exhaust_flame);
        f("embers", s.exhaust_embers);
        f("top_speed", s.top_speed);
        f("turbulence", s.turbulence);
        b("ground_bounce", s.ground_bounce);
        f("size", s.size);
        f("smoke_opacity", s.smoke_opacity);
        f("flame_opacity", s.flame_opacity);
        f("exhaust_light", s.exhaust_light);
        f("binder_light", s.binder_light);
        b("hide_stock_binder_glow", s.hide_stock_binder_glow);
        config::save();
    }

    void panel() {
        bool changed = false;
        auto check = [&](const char* label, bool* v, const char* tip) {
            changed |= ImGui::Checkbox(label, v);
            if (tip && ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", tip);
        };
        auto slider = [&](const char* label, float* v, float lo, float hi, const char* fmt, const char* tip) {
            ImGui::SliderFloat(label, v, lo, hi, fmt);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", tip);
            changed |= ImGui::IsItemDeactivatedAfterEdit();
        };

        check("Pod FX", &s.enabled, "Master switch for all effects below. Visual only.");
        ImGui::BeginDisabled(!s.enabled);
        check("Apply to AI pods too", &s.ai_pods, nullptr);
        slider("Overall size", &s.size, 0.2f, 3.0f, "%.2fx", "Scales every effect.");
        slider("Smoke density", &s.smoke_opacity, 0.0f, 2.0f, "%.2fx", "How thick the engine smoke and smoke trails are.");
        slider("Flame opacity", &s.flame_opacity, 0.0f, 2.0f, "%.2fx", "Lower = more see-through flames.");

        ImGui::SeparatorText("Engine damage");
        check("Damage effects", &s.damage, nullptr);
        ImGui::BeginDisabled(!s.damage);
        ImGui::TextDisabled("Effects start when a HUD engine segment turns orange.");
        if (g_learn_lo >= 0.0f || g_learn_hi <= 1.0f)
            ImGui::TextDisabled("Orange learned from your HUD at damage %.2f (used for AI pods).",
                                orange_threshold());
        else
            ImGui::TextDisabled("Not learned yet: take some damage once to calibrate AI pods.");
        slider("Fallback orange level", &s.threshold, 0.0f, 0.9f, "%.2f",
               "Damage level (0 = new, 1 = blown) treated as orange for AI pods until the\n"
               "real HUD threshold has been learned from your own pod.");
        if (ImGui::Button("Forget learned threshold")) {
            g_learn_lo = -1.0f;
            g_learn_hi = 2.0f;
            changed = true;
        }
        slider("Sparks", &s.sparks, 0.0f, 4.0f, "%.2fx", "Spark amount.");
        slider("Fire", &s.flames, 0.0f, 4.0f, "%.2fx", "Fire trail amount (badly damaged segments).");
        slider("Smoke", &s.smoke, 0.0f, 4.0f, "%.2fx", "Smoke amount; turns black once the segment is burning.");
        slider("Fade after repair", &s.fade_secs, 0.1f, 8.0f, "%.1f s", "How long effects take to die down.");
        check("Swap left/right engines", &s.swap_sides,
              "Tick this if the effects come from the opposite engine to the\nHUD segment that's damaged.");
        ImGui::EndDisabled();

        ImGui::SeparatorText("Ground dust");
        check("Dust clouds", &s.dust, "Billowing dust wherever the game kicks up its dust trail.");
        ImGui::BeginDisabled(!s.dust);
        check("Replace stock dust", &s.hide_stock_dust, "Hide the game's own dust-kick models so only the particle dust shows.");
        slider("Dust amount", &s.dust_amount, 0.0f, 4.0f, "%.2fx", "Dust amount.");
        changed |= ImGui::ColorEdit3("Dust colour", s.dust_color, ImGuiColorEditFlags_NoInputs);
        ImGui::EndDisabled();

        ImGui::SeparatorText("Exhaust (Galactic Racer style)");
        check("Exhaust glow", &s.exhaust, "White-hot core, orange halo and a flame behind each engine.");
        ImGui::BeginDisabled(!s.exhaust);
        slider("Glow", &s.exhaust_glow, 0.0f, 3.0f, "%.2fx", "Core and halo brightness.");
        slider("Exhaust light", &s.exhaust_light, 0.0f, 3.0f, "%.2fx", "Light thrown backward from each nozzle: a faint beam plus a glow on the ground.");
        slider("Binder glow", &s.binder_light, 0.0f, 3.0f, "%.2fx",
               "Glow along the energy binder beam, and the light it throws in every direction on the pod and\n"
               "ground (the lighting needs Shadows > dynamic lights).");
        check("Hide stock binder glow", &s.hide_stock_binder_glow,
              "Hide the game's own flat glow card on the binder (texture #1411); the glow above replaces it.");
        slider("Flame length", &s.exhaust_flame, 0.0f, 3.0f, "%.2fx", "Flame streak length; grows with speed and boost.");
        ImGui::TextUnformatted("Nozzle positions from:");
        {
            bool src = false;
            src |= ImGui::RadioButton("Auto (per-nozzle glows)", &s.nozzle_source, 0);
            ImGui::SameLine();
            src |= ImGui::RadioButton("Per-nozzle discs", &s.nozzle_source, 1);
            src |= ImGui::RadioButton("Engine exhaust", &s.nozzle_source, 2);
            ImGui::SameLine();
            src |= ImGui::RadioButton("Engine glow", &s.nozzle_source, 3);
            if (src)
                g_nozzles.clear();// re-detect from the new source
            changed |= src;
        }
        check("Show nozzle markers", &s.show_nozzles, "Debug: cyan dot on every detected nozzle (drawn on top).");
        if (ImGui::Button("Dump pod parts to hook.log"))
            g_debug_armed = true;
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Diagnostics: logs every part of your pod (position on the pod and its\n"
                              "meshes) to hook.log in the game folder. Press it mid-race.");
        if (!g_debug_status.empty())
            ImGui::TextDisabled("%s", g_debug_status.c_str());
        slider("Embers", &s.exhaust_embers, 0.0f, 4.0f, "%.2fx", "Embers thrown from the exhaust (mostly while boosting).");
        slider("Smoke trails", &s.air_trails, 0.0f, 4.0f, "%.2fx", "Exhaust smoke trails streaming from every nozzle; thicken with speed.");
        slider("Full-effect speed", &s.top_speed, 100.0f, 1200.0f, "%.0f", "Speed where the exhaust reaches full strength.");
        ImGui::EndDisabled();

        ImGui::SeparatorText("Physics");
        slider("Turbulence", &s.turbulence, 0.0f, 4.0f, "%.2fx", "How much smoke, dust and fire swirl.");
        check("Sparks bounce off the ground", &s.ground_bounce, nullptr);
        ImGui::EndDisabled();

        if (ImGui::Button("Reset to defaults")) {
            s = kDefaults;
            changed = true;
        }
        if (changed)
            save_settings();
    }

    DebugPanel g_panel = {.category = "Mods", .name = "Pod FX", .draw = panel, .dev_only = false};

    Clock::time_point g_last_tick;
    bool g_has_tick = false;
}// namespace

void pod_fx_wreck_emit(const rdVector3& pos, const rdVector3& vel, const rdVector3& dir, float L, float ground_z,
                       int sparks, int embers, int flames, int smoke, float smoke_shade) {
    if (!s.enabled || !(L > 0.0f))
        return;
    const rdVector3 up = {0.0f, 0.0f, 1.0f};
    for (int i = 0; i < sparks; i++)
        spawn_spark(pos, vel, dir, up, L, s.ground_bounce ? ground_z : NAN);
    for (int i = 0; i < embers; i++)
        spawn_ember(add(pos, mul(rand_vec(), L * 0.04f)), add(vel, add(mul(dir, L * (0.5f + frand())), mul(rand_vec(), L * 0.8f))), L);
    for (int i = 0; i < flames; i++)
        spawn_flame(add(pos, mul(rand_vec(), L * 0.05f)), vel, dir, up, L);
    for (int i = 0; i < smoke; i++)
        spawn_smoke(add(pos, mul(rand_vec(), L * 0.05f)), vel, up, L, smoke_shade);
}

void pod_fx_report_nozzle_mesh(const swrRace* racer, int side, int kind, const swrModel_Mesh* mesh,
                               const rdMatrix44& model) {
    if (!s.enabled || !s.exhaust || racer == nullptr || mesh == nullptr || side < 0 || side > 1)
        return;
    PodNozzles& pn = g_nozzles[racer];
    if (kind < 0 || kind > 3)
        return;
    std::vector<Nozzle>& stage = pn.staging[side][kind];
    const rdMatrix44& e = engine_of(racer, side);
    const float e_scale = len(v3(e.vA));
    const float m_scale = len(v3(model.vA));
    if (e_scale < 1e-6f)
        return;
    // Per-nozzle parts: each mesh IS one nozzle, sitting right on it -- use its box centre.
    if (kind >= 2) {
        const rdVector3 c = {0.5f * (mesh->aabb[0] + mesh->aabb[3]), 0.5f * (mesh->aabb[1] + mesh->aabb[4]),
                             0.5f * (mesh->aabb[2] + mesh->aabb[5])};
        const float ext = std::max(mesh->aabb[3] - mesh->aabb[0],
                                   std::max(mesh->aabb[4] - mesh->aabb[1], mesh->aabb[5] - mesh->aabb[2]));
        const Nozzle n{to_local(e, to_world(model, c)), 0.5f * ext * m_scale / e_scale};
        for (const Nozzle& o: stage) {
            const rdVector3 d = sub(o.local, n.local);
            if (dot(d, d) < (n.radius * 0.5f) * (n.radius * 0.5f) + 1e-6f)
                return;// same nozzle seen again this frame
        }
        if (stage.size() < 16)
            stage.push_back(n);
        return;
    }
    const rdVector3 e_pos = v3(e.vD);
    for (const Cluster& c: clusters_for(mesh)) {
        // The exhaust meshes are flames that start at the nozzle and stretch far back, so their
        // centre floats behind the pod. The nozzle mouth is the end of the cluster nearest the
        // engine: average the quarter of its vertices closest to the engine centre.
        rdVector3 w = to_world(model, c.c);
        float radius = c.r * m_scale;
        if (!c.pts.empty()) {
            std::vector<std::pair<float, rdVector3>> byd;
            byd.reserve(c.pts.size());
            for (const rdVector3& lp: c.pts) {
                const rdVector3 pw = to_world(model, lp);
                const rdVector3 d = sub(pw, e_pos);
                byd.push_back({dot(d, d), pw});
            }
            std::sort(byd.begin(), byd.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
            const size_t take = std::max<size_t>(1, byd.size() / 4);
            rdVector3 sum{0, 0, 0};
            for (size_t k = 0; k < take; k++)
                sum = add(sum, byd[k].second);
            w = mul(sum, 1.0f / (float) take);
            float rmax = 0.0f;
            for (size_t k = 0; k < take; k++)
                rmax = std::max(rmax, len(sub(byd[k].second, w)));
            if (rmax > 1e-4f)
                radius = rmax;
        }
        const Nozzle n{to_local(e, w), radius / e_scale};
        // The same nozzle arrives once per viewport / per frame: keep one copy.
        bool dup = false;
        for (const Nozzle& o: stage) {
            const rdVector3 d = sub(o.local, n.local);
            if (dot(d, d) < (n.radius * 0.5f) * (n.radius * 0.5f) + 1e-6f) {
                dup = true;
                break;
            }
        }
        if (!dup && stage.size() < 16)
            stage.push_back(n);
    }
}

bool pod_fx_debug_armed() {
    return g_debug_armed;
}

namespace {
    // Pod-local coordinates (pod transform frame, in pod lengths) for the diagnostics.
    std::string pod_local_str(const swrRace* r, rdVector3 w) {
        const rdVector3 l = to_local(r->transform, w);
        const float L = pod_length(r) / std::max(len(v3(r->transform.vA)), 1e-6f);
        char buf[96];
        snprintf(buf, sizeof(buf), "(%+.3f %+.3f %+.3f)", l.x / L, l.y / L, l.z / L);
        return buf;
    }
}// namespace

void pod_fx_debug_part(const swrRace* racer, int part, const swrModel_Node* node, const rdMatrix44& model) {
    if (!g_debug_armed || racer == nullptr || node == nullptr)
        return;
    g_debug_racer = racer;
    char buf[256];
    snprintf(buf, sizeof(buf), "part 0x%02x node=%p type=0x%x children=%u flags1=0x%x origin=%s", part,
             (const void*) node, (unsigned) node->type, (unsigned) node->num_children, (unsigned) node->flags_1,
             pod_local_str(racer, v3(model.vD)).c_str());
    g_debug_lines.push_back(buf);
}

void pod_fx_debug_mesh(const swrRace* racer, int part, const swrModel_Mesh* mesh, const rdMatrix44& model) {
    if (!g_debug_armed || racer == nullptr || mesh == nullptr)
        return;
    const rdVector3 c = {0.5f * (mesh->aabb[0] + mesh->aabb[3]), 0.5f * (mesh->aabb[1] + mesh->aabb[4]),
                         0.5f * (mesh->aabb[2] + mesh->aabb[5])};
    char buf[512];
    snprintf(buf, sizeof(buf), "    mesh in part 0x%02x %p verts=%u mat_type=0x%x aabb_center=%s", part,
             (const void*) mesh, (unsigned) mesh->num_vertices,
             mesh->mesh_material ? (unsigned) mesh->mesh_material->type : 0u,
             pod_local_str(racer, to_world(model, c)).c_str());
    g_debug_lines.push_back(buf);
    for (const Cluster& cl: clusters_for(mesh)) {
        snprintf(buf, sizeof(buf), "        cluster center=%s r=%.1f pts=%zu",
                 pod_local_str(racer, to_world(model, cl.c)).c_str(), cl.r, cl.pts.size());
        g_debug_lines.push_back(buf);
    }
}

bool pod_fx_hide_stock_binder_glow() {
    return s.enabled && s.hide_stock_binder_glow;
}

void pod_fx_report_binder(const swrRace* racer, const rdVector3& a, const rdVector3& b, float r, float g, float bl,
                          bool card) {
    if (!s.enabled || s.binder_light <= 0.0f || racer == nullptr || g_binder_pieces.size() > 256)
        return;
    if ((racer->flags0 & swrObjTest_FLAG0_DEAD) != 0)
        return;
    // Before the binder lights up the game parks it far away: ignore pieces not near the pod.
    if (len(sub(mul(add(a, b), 0.5f), v3(racer->transform.vD))) > pod_length(racer) * 3.0f)
        return;
    // Normalise to full brightness; no usable colour -> a cool violet-blue.
    const float mx = std::max(r, std::max(g, bl));
    if (mx < 0.05f)
        r = 0.6f, g = 0.55f, bl = 1.0f;
    else
        r /= mx, g /= mx, bl /= mx;
    g_binder_pieces.push_back({racer, a, b, r, g, bl, card});
    g_binder_beams_built = false;
}

void pod_fx_gather_lights(std::vector<SceneLight>& out) {
    if (!s.enabled)
        return;
    // Energy binders: omni-directional point lights spread along each beam (a line of light),
    // flickering with the beam.
    for (const BinderBeam& bm: binder_beams()) {
        const float seg = len(sub(bm.b, bm.a));
        const int count = std::max(2, std::min(5, (int) (seg / (bm.L * 0.3f)) + 1));
        const float fl = binder_flicker(bm, 5.0f);
        for (int k = 0; k < count; k++) {
            const float t = (k + 0.5f) / (float) count;
            SceneLight l{};
            l.pos = add(bm.a, mul(sub(bm.b, bm.a), t));
            l.dir = {0, 0, 0};
            l.r = bm.r, l.g = bm.g, l.b = bm.bl;
            // Strongest in the middle of the beam, weaker toward the engines.
            const float centre = 1.0f - std::fabs(t - 0.5f) * 1.4f;
            l.intensity = 1.1f * s.binder_light * fl * centre * bm.share / std::sqrt((float) count);
            l.radius = bm.L * 0.9f;
            l.cos_inner = l.cos_outer = 0.0f;
            out.push_back(l);
        }
    }
    const int n = swrEvent_GetEventCount(kEventTest);
    std::vector<std::pair<rdVector3, float>> noz;
    for (int i = 0; i < n; i++) {
        const swrRace* r = (const swrRace*) swrEvent_GetItem(kEventTest, i);
        if (r == nullptr || r->partNodes == nullptr)
            continue;
        auto it = g_pods.find(r);
        if (it == g_pods.end())
            continue;
        const PodFx& fx = it->second;
        if ((r->flags0 & swrObjTest_FLAG0_DEAD) != 0)
            continue;
        const float L = pod_length(r);

        // Exhaust: a warm spotlight aimed backward from every nozzle while moving. The pod editor's
        // "exhaustlight" edit sets where it lands (aim, pod lengths) and scales its reach / cone / power.
        float xl[4] = {0.7f, 1.0f, 1.0f, 1.0f};
        pod_edits_exhaust_light(pilot_of(r), xl);
        const float ex = fx.throttle * fx.accel * s.exhaust_light * std::max(xl[3], 0.0f);
        if (s.exhaust && ex > 0.01f) {
            const bool boosting = (r->flags0 & swrObjTest_FLAG0_BOOSTING) != 0;
            for (int side = 0; side < 2; side++) {
                if (!engine_alive(r, side))
                    continue;
                const rdMatrix44& e = engine_of(r, side);
                const rdVector3 back = mul(norm(v3(e.vB)), -1.0f);
                nozzles_world(r, side, noz);
                if (noz.empty())
                    noz.push_back({sub(v3(e.vD), mul(norm(v3(e.vB)), L * 0.15f)), L * 0.05f});
                const float share = 1.0f / std::sqrt((float) noz.size());
                const float flick = 0.9f + 0.1f * std::sin(g_time * 31.0f + side * 2.0f);
                // Ground under this engine (the game lays each engine's shadow flat on it).
                const float ground = side == 0 ? r->shadowXf1.vD.z : r->shadowXf2.vD.z;
                for (const auto& nz: noz) {
                    SceneLight l{};
                    l.pos = add(nz.first, mul(back, -L * 0.12f));// starts inside the nozzle so the lit cone begins at the engine
                    l.dir = back;
                    // Tilt the cone down onto the floor just behind the nozzle, so the pool of light
                    // on the ground sits at the engine instead of far behind it.
                    const float h = l.pos.z - ground;
                    if (h > 0.0f && h < L * 2.0f) {
                        rdVector3 flat = {back.x, back.y, 0.0f};
                        flat = len(flat) > 1e-3f ? norm(flat) : back;
                        const rdVector3 target = {nz.first.x + flat.x * L * xl[0], nz.first.y + flat.y * L * xl[0], ground};
                        l.dir = norm(add(mul(back, 0.35f), mul(norm(sub(target, l.pos)), 0.65f)));
                    }
                    l.r = 1.0f, l.g = boosting ? 0.6f : 0.45f, l.b = boosting ? 0.3f : 0.15f;
                    // A cone thrown out the back of the nozzle: full inside ~20 deg, gone by ~38 deg,
                    // reaching further with throttle -- lights a streak behind the engine rather
                    // than a flat patch around it.
                    l.intensity = 1.4f * ex * share * flick;
                    l.radius = L * (1.8f + 1.0f * clampf(fx.throttle, 0.0f, 1.6f)) * std::max(xl[1], 0.05f);
                    // Full inside ~20 deg, gone by ~38 deg (x the edit's width).
                    const float w = clampf(xl[2], 0.1f, 3.0f);
                    l.cos_inner = std::cos(std::min(0.35f * w, 1.5f));
                    l.cos_outer = std::cos(std::min(0.66f * w, 1.55f));
                    out.push_back(l);
                }
            }
        }

        // Damage fire: a flickering point light on each burning engine.
        if (s.damage) {
            for (int side = 0; side < 2; side++) {
                const int base = ((side == 1) != s.swap_sides) ? 0 : 3;// shown[0..2] = left
                float burn = 0.0f;
                for (int k = base; k < base + 3; k++)
                    burn = std::max(burn, clampf((fx.shown[k] - 0.35f) / 0.65f, 0.0f, 1.0f));
                if (burn <= 0.01f || !engine_alive(r, side))
                    continue;
                // One light per engine body (Ben Quadinaros: two per side, sharing the burn).
                static std::vector<rdVector3> centres;
                engine_centres(r, side, L, centres);
                const float share = 1.0f / std::sqrt((float) centres.size());
                for (size_t c = 0; c < centres.size(); c++) {
                    SceneLight l{};
                    l.pos = centres[c];
                    l.dir = {0, 0, 0};
                    l.r = 1.0f, l.g = 0.35f, l.b = 0.08f;
                    l.intensity = burn * s.flames * share *
                                  (0.7f + 0.3f * std::sin(g_time * 19.0f + side + (float) c * 2.3f) *
                                              std::sin(g_time * 7.3f + side * 1.3f + (float) c));
                    l.radius = L * 0.9f;
                    l.cos_inner = l.cos_outer = 0.0f;
                    out.push_back(l);
                }
            }
        }
    }
}

void pod_fx_auto_points(const swrRace* racer, int side, std::vector<std::array<float, 4>>& nozzles,
                        std::vector<std::array<float, 4>>& fire, std::vector<std::array<float, 4>>& dust) {
    nozzles.clear();
    fire.clear();
    dust.clear();
    if (racer == nullptr)
        return;
    const rdMatrix44& e = engine_of(racer, side);
    // Engine matrices are rotation * scale + translation: local = (world - D) * (rows / scale^2).
    const rdVector3 d = v3(e.vD), a = v3(e.vA), b = v3(e.vB), c = v3(e.vC);
    auto local = [&](rdVector3 w) {
        const rdVector3 q = sub(w, d);
        return std::array<float, 4>{dot(q, a) / dot(a, a), dot(q, b) / dot(b, b), dot(q, c) / dot(c, c), 0.0f};
    };
    const float scale = len(a);
    auto it = g_nozzles.find(racer);
    if (it != g_nozzles.end())
        for (const Nozzle& n: it->second.side[side])
            nozzles.push_back({n.local.x, n.local.y, n.local.z, n.radius});
    if (nozzles.empty()) {// nothing captured yet: just behind the engine centre, like the fallback
        auto p = local(sub(d, mul(norm(b), pod_length(racer) * 0.15f)));
        p[3] = pod_length(racer) * 0.05f / (scale > 0 ? scale : 1.0f);
        nozzles.push_back(p);
    }
    std::vector<rdVector3> centres;
    engine_centres(racer, side, pod_length(racer), centres);
    for (const rdVector3& w: centres)
        fire.push_back(local(w));
    const rdMatrix44& sh = side == 0 ? racer->shadowXf1 : racer->shadowXf2;
    dust.push_back(local(v3(sh.vD)));
}

bool pod_fx_hide_stock_dust() {
    return s.enabled && s.dust && s.hide_stock_dust;
}

float pod_fx_engine_damage(const swrRace* racer, int side) {
    auto it = g_pods.find(racer);
    if (it == g_pods.end() || !s.enabled)
        return 0.0f;
    // shown[0..2] is the left engine, [3..5] the right (unless swapped).
    const bool left = side == 1;
    const int base = (left != s.swap_sides) ? 0 : 3;
    float m = 0.0f;
    for (int i = base; i < base + 3; i++)
        m = std::max(m, it->second.shown[i]);
    return m;
}

void pod_fx_on_ground_dust(const swrRace* player, const float* transform) {
    if (player == nullptr || transform == nullptr)
        return;
    const rdVector3 pos = {transform[12], transform[13], transform[14]};
    // Sanity check: the kick should be near the pod (guards against a misread transform).
    const rdVector3 pod = v3(player->transform.vD);
    if (!(len(sub(pos, pod)) < pod_length(player) * 4.0f))
        return;
    auto it = g_pods.find(player);
    if (it == g_pods.end())
        return;
    it->second.ground_pos = pos;
    it->second.ground_time = Clock::now();
    it->second.has_ground = true;
}

void pod_fx_tick_and_draw(const rdMatrix44* proj, const rdMatrix44* view, bool in_race) {
    // Binder pieces were reported during this frame's traversal (and used by the lighting pass);
    // drop them once this frame is drawn.
    struct ClearBinders {
        ~ClearBinders() {
            g_binder_pieces.clear();
            g_binder_beams.clear();
            g_binder_beams_built = false;
        }
    } clear_binders;
    // Diagnostics: the scene traversal just ran with the dump armed -- write what it saw.
    if (g_debug_armed && in_race) {
        if (!g_debug_lines.empty() && g_debug_racer != nullptr && hook_log != nullptr) {
            const swrRace* r = g_debug_racer;
            fprintf(hook_log, "==== Pod FX part dump (coords: pod frame, x=right y=forward z=up, in pod lengths) ====\n");
            fprintf(hook_log, "pod length %.2f  engineR %s  engineL %s  cockpit %s  exhaustXfR %s  exhaustXfL %s\n",
                    pod_length(r), pod_local_str(r, v3(r->engineXfR.vD)).c_str(),
                    pod_local_str(r, v3(r->engineXfL.vD)).c_str(), pod_local_str(r, v3(r->cockpitXf.vD)).c_str(),
                    pod_local_str(r, v3(r->engineExhaustXfR.vD)).c_str(),
                    pod_local_str(r, v3(r->engineExhaustXfL.vD)).c_str());
            for (const std::string& line: g_debug_lines)
                fprintf(hook_log, "%s\n", line.c_str());
            fprintf(hook_log, "==== end of part dump ====\n");
            fflush(hook_log);
            g_debug_status = "Dumped " + std::to_string(g_debug_lines.size()) + " lines to hook.log.";
        } else {
            g_debug_status = "Nothing captured - press it while racing with your pod visible.";
        }
        g_debug_lines.clear();
        g_debug_racer = nullptr;
        g_debug_armed = false;
    }
    static Clock::time_point last_race_view;
    static bool seen_race = false;
    const Clock::time_point now = Clock::now();
    if (in_race) {
        last_race_view = now;
        seen_race = true;
    }
    // Other (non-race) viewports can render in the same frame, so only treat it as "left the
    // race" once no race viewport has drawn for a while; then drop everything.
    const bool racing = seen_race && std::chrono::duration<float>(now - last_race_view).count() < 0.5f;
    if (!racing && seen_race) {
        for (Particle& p: g_parts)
            p.active = false;
        g_pods.clear();
        g_exhaust.clear();
        g_nozzles.clear();
        g_mesh_clusters.clear();// model memory is reused by the next load
        if (g_learn_dirty) {
            save_settings();
            g_learn_dirty = false;
        }
        seen_race = false;
    }

    // Simulate once per real frame (called once per viewport), frozen while paused.
    float dt = g_has_tick ? std::chrono::duration<float>(now - g_last_tick).count() : 0.0f;
    if (!g_has_tick || dt > 0.002f) {
        g_last_tick = now;
        g_has_tick = true;
        dt = clampf(dt, 0.0f, 0.05f);
        if (pauseState == 0 && dt > 0.0f)
            tick(dt, racing);
    }
    if (!in_race)
        return;
    g_proj = *proj;
    g_view = *view;
    draw();
}

void pod_fx_register_panel() {
    load_settings();
    debug_ui_register(&g_panel);
}
