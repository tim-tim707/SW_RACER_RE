#include "pod_wreck.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <imgui.h>

extern "C" {
#include <Swr/swrModel.h>// swrModel_NodeSetTransform_ADDR
#include <Swr/swrObj.h>  // swrObjSmok_Spawn_ADDR
#include <Swr/swrRace.h> // swrRace_RaycastModel_ADDR, swrRace_SpawnEngineFireball_ADDR
#include <Swr/swrSound.h>// swrSound_PlaySpatialRange_ADDR
#include <globals.h>     // swrRace_deltaTimeSecs, swrRace_collisionHitNode
#include <types_enums.h> // swrObjTest_FLAG0_*, swrObjTest_FLAG1_*
}

#include "../config.h"
#include "../debug_ui.h"
#include "pod_fx.h"// pod_fx_wreck_emit

namespace {
    typedef void(__cdecl* NodeSetTransform_t)(swrModel_Node* node, const rdMatrix44* m);
    typedef void(__cdecl* BuildStretchedQuad_t)(const rdMatrix44* cockpit, const rdMatrix44* engine, float mirror_x,
                                                float mirror_pair, int pilot, rdMatrix44* out);
    typedef float(__cdecl* RaycastModel_t)(swrModel_Node* model, float* ray, rdVector3* out_hit, rdVector3* out_normal);
    typedef void(__cdecl* SpawnEngineFireball_t)(swrRace* player, int engine_slot, rdVector3* pos, float scale);
    typedef swrObjSmok*(__cdecl* SmokSpawn_t)(int type, int flags, float lifetime, rdVector3* pos, float scale);
    typedef void(__cdecl* SmokSetVec_t)(swrObjSmok*, rdVector3*);
    typedef void(__cdecl* PlaySpatialRange_t)(int sound, int p2, float p3, float gain, rdVector3* pos, int p6,
                                              unsigned flags, float min_dist, float max_dist);

    // ---- settings --------------------------------------------------------------------------
    struct Settings {
        bool enabled = true;     // knocked-off engines tumble away as debris
        bool keep_racing = false;// an engine blown by damage is survivable (off: every blow-up is a death spin)
        bool ai_pods = true;     // ... for AI pods too
        int pull = 1;            // missing engine's segments held "badly damaged" (the game's pull, 0..3)
        float top_speed = 0.7f;  // top speed on one engine (x the pod's own)
        float gravity = 9.0f;    // pod lengths / s^2
        float bounce = 0.4f;     // bounciness (0 = dead stop .. 1 = no loss)
        float grip = 0.75f;      // speed kept along the surface at each hit
        float kick = 1.0f;       // how hard it is thrown off the pod
        float fling = 1.0f;      // extra push ahead, along the pod's motion
        float chase = 0.95f;     // the engine kept through the death spin: its speed when it lets go (x the pod's)
        float drag = 0.8f;       // ... and how fast it slows in the air (per second)
        float smoke = 1.0f;      // smoke amount (x)
        float debris = 1.0f;     // debris chips thrown off (x)
        bool crash_scatter = true;// the pod blowing up: whatever is left (engines, cockpit) flies apart
        float spin = 1.0f;       // tumbling
        float breakup = 1.0f;    // how fast it falls apart
        float life = 7.0f;       // seconds before its final burst
        float fx = 1.0f;         // sparks / fire / smoke amount
    } s;
    constexpr const char* kSec = "pod_wreck";

    void load_settings() {
        auto b = [](const char* k, bool& v) { v = config::get_int(kSec, k, v) != 0; };
        auto f = [](const char* k, float& v, float lo, float hi) {
            v = std::clamp(config::get_float(kSec, k, v), lo, hi);
        };
        b("enabled", s.enabled);
        b("keep_racing2", s.keep_racing);
        b("ai_pods", s.ai_pods);
        s.pull = std::clamp(config::get_int(kSec, "pull2", s.pull), 0, 3);
        f("top_speed", s.top_speed, 0.2f, 1.0f);
        f("gravity", s.gravity, 0.0f, 40.0f);
        f("bounce", s.bounce, 0.0f, 1.0f);
        f("grip", s.grip, 0.0f, 1.0f);
        f("kick", s.kick, 0.0f, 4.0f);
        f("fling", s.fling, 0.0f, 4.0f);
        f("chase2", s.chase, 0.3f, 3.0f);
        f("drag", s.drag, 0.0f, 4.0f);
        f("smoke", s.smoke, 0.0f, 4.0f);
        f("debris", s.debris, 0.0f, 4.0f);
        b("crash_scatter", s.crash_scatter);
        f("spin", s.spin, 0.0f, 4.0f);
        f("breakup", s.breakup, 0.0f, 4.0f);
        f("life", s.life, 1.0f, 30.0f);
        f("fx", s.fx, 0.0f, 4.0f);
    }
    void save_settings() {
        auto b = [](const char* k, bool v) { config::set_bool(kSec, k, v); };
        auto f = [](const char* k, float v) { config::set_float(kSec, k, v); };
        b("enabled", s.enabled);
        b("keep_racing2", s.keep_racing);
        b("ai_pods", s.ai_pods);
        config::set_int(kSec, "pull2", s.pull);
        f("top_speed", s.top_speed);
        f("gravity", s.gravity);
        f("bounce", s.bounce);
        f("grip", s.grip);
        f("kick", s.kick);
        f("fling", s.fling);
        f("chase2", s.chase);
        f("drag", s.drag);
        f("smoke", s.smoke);
        f("debris", s.debris);
        b("crash_scatter", s.crash_scatter);
        f("spin", s.spin);
        f("breakup", s.breakup);
        f("life", s.life);
        f("fx", s.fx);
    }

    // ---- small maths -------------------------------------------------------------------------
    rdVector3 v3(const rdVector4& v) { return {v.x, v.y, v.z}; }
    rdVector3 add(rdVector3 a, rdVector3 b) { return {a.x + b.x, a.y + b.y, a.z + b.z}; }
    rdVector3 sub(rdVector3 a, rdVector3 b) { return {a.x - b.x, a.y - b.y, a.z - b.z}; }
    rdVector3 mul(rdVector3 a, float k) { return {a.x * k, a.y * k, a.z * k}; }
    float dot(rdVector3 a, rdVector3 b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
    rdVector3 cross(rdVector3 a, rdVector3 b) {
        return {a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x};
    }
    float len(rdVector3 a) { return std::sqrt(dot(a, a)); }
    rdVector3 norm(rdVector3 a) {
        const float l = len(a);
        return l > 1e-8f ? mul(a, 1.0f / l) : rdVector3{0.0f, 0.0f, 0.0f};
    }

    uint32_t g_rng = 0x2545f491u;
    float frand() {
        g_rng ^= g_rng << 13;
        g_rng ^= g_rng >> 17;
        g_rng ^= g_rng << 5;
        return (float) (g_rng >> 8) * (1.0f / 16777216.0f);
    }
    float frand_sym() { return frand() * 2.0f - 1.0f; }
    rdVector3 rand_vec() { return {frand_sym(), frand_sym(), frand_sym()}; }

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
    // v turned about the unit axis a by angle (radians).
    rdVector3 rotate(rdVector3 v, rdVector3 a, float angle) {
        const float c = std::cos(angle), sn = std::sin(angle), d = dot(a, v);
        const rdVector3 cr = cross(a, v);
        return {v.x * c + cr.x * sn + a.x * d * (1.0f - c), v.y * c + cr.y * sn + a.y * d * (1.0f - c),
                v.z * c + cr.z * sn + a.z * d * (1.0f - c)};
    }

    // ---- state -----------------------------------------------------------------------------
    struct Attached {
        swrModel_Node* node;
        rdMatrix44 rel;// part = rel then engine
    };
    struct Body {
        int part = 1;// partNodes index of the engine (1..4)
        swrModel_Node* node = nullptr;
        rdVector3 axes[3];// the engine matrix's rows (orientation + scale)
        rdVector3 pos{}, vel{}, spin{};// spin: world angular velocity (rad/s)
        float age = 0.0f, breakup = 0.0f, radius = 1.0f, L = 10.0f, ground_z = NAN;
        float fire_acc = 0.0f, smoke_acc = 0.0f, debris_acc = 0.0f, rest = 0.0f, hit_cool = 0.0f;
        float drag = 0.15f;// air drag (per second)
        bool grounded = false, done = false;
        uint32_t seed = 1;
        std::vector<Attached> parts;
        rdMatrix44 matrix() const {
            rdMatrix44 m;
            m.vA = {axes[0].x, axes[0].y, axes[0].z, 0.0f};
            m.vB = {axes[1].x, axes[1].y, axes[1].z, 0.0f};
            m.vC = {axes[2].x, axes[2].y, axes[2].z, 0.0f};
            m.vD = {pos.x, pos.y, pos.z, 1.0f};
            return m;
        }
    };
    struct Wreck {
        int lost = 0;      // sides knocked off (bit 0 = right / partNodes[1], bit 1 = left)
        bool fatal = false;// the stock explosion ran (the pod is dying)
        bool scattered = false;// ... and it was blown apart (engines and cockpit flying)
        // Through the death spin: each engine still on the pod, held where it sat against the
        // cockpit when the other one blew (parts 1..4).
        bool held[5] = {};
        rdMatrix44 held_rel[5]{};
        bool saw_down = false;// the pod has been dead / exploding / respawning since
        float saved_top_speed = -1.0f;
        std::vector<Body> bodies;
        std::vector<std::pair<swrModel_Node*, uint32_t>> saved_flags;// nodes we hid / showed
        // Each engine's position and velocity, tracked frame to frame (parts 1..4).
        rdVector3 last_pos[6]{}, last_vel[6]{};// parts 1..5
        rdVector3 hist[6][8]{};// recent velocities per part (the speed from just before a crash)
        int hist_at = 0;
        bool has_last = false;
        rdVector3 pod_vel{};// the cockpit's velocity now (smoothed): the pod's own speed
    };
    std::unordered_map<swrRace*, Wreck> g_wrecks;
    struct Breakup {
        float amount;
        uint32_t seed;
    };
    std::unordered_map<const swrModel_Node*, Breakup> g_breakup;
    // Debris of a blown-apart pod, drawn on its own (the game hides the dead pod).
    std::unordered_set<const swrModel_Node*> g_apart;

    float pod_length(const swrRace* r) {
        const rdVector3 mid = mul(add(v3(r->engineXfR.vD), v3(r->engineXfL.vD)), 0.5f);
        const float l = len(sub(v3(r->cockpitXf.vD), mid));
        return (l > 0.5f && l < 500.0f) ? l : 10.0f;
    }
    const rdMatrix44& part_xf(const swrRace* r, int part) { return (&r->unk350_mat)[part]; }
    bool four_engines(const swrRace* r) { return r->partNodes && r->partNodes[3] && r->partNodes[4]; }
    // Explode's side argument (2 = the right engine at engineXfR, 1 = the left) -> side 0 / 1.
    int side_of_arg(int arg) { return (arg & 2) ? 0 : 1; }
    bool allowed(const swrRace* r) { return s.ai_pods || (r->flags0 & swrObjTest_FLAG0_LOCAL) != 0; }

    void remember_flags(Wreck& w, swrModel_Node* node) {
        for (const auto& [n, f]: w.saved_flags)
            if (n == node)
                return;
        w.saved_flags.push_back({node, node->flags_1});
    }
    void set_visible(Wreck& w, swrModel_Node* node, bool visible) {
        if (node == nullptr)
            return;
        remember_flags(w, node);
        node->flags_1 = visible ? (node->flags_1 | 0x2u) : (node->flags_1 & ~0x2u);
    }

    void collect_subtree(const swrModel_Node* node, std::unordered_set<const swrModel_Node*>& out, int depth) {
        if (node == nullptr || depth > 24 || !out.insert(node).second)
            return;
        if ((node->type & 0x4000) != 0 && node->type != NODE_MESH_GROUP)
            for (uint32_t i = 0; i < node->num_children; i++)
                collect_subtree(node->children.nodes[i], out, depth + 1);
    }

    // The nodes from `from` down to `target` (both included), if `target` is under it.
    bool find_path(swrModel_Node* from, const swrModel_Node* target, std::vector<swrModel_Node*>& path, int depth) {
        if (from == nullptr || depth > 24)
            return false;
        path.push_back(from);
        if (from == target)
            return true;
        if ((from->type & 0x4000) != 0 && from->type != NODE_MESH_GROUP)
            for (uint32_t i = 0; i < from->num_children; i++)
                if (find_path(from->children.nodes[i], target, path, depth + 1))
                    return true;
        path.pop_back();
        return false;
    }

    // Part slots that are not part of an engine's body, or that are hidden with it instead.
    bool skip_part(int p) {
        return p <= 13 ||                // root, engines, cockpit, binder, cables
               (p >= 0x3d && p <= 0x46) ||// shadows, scrape sparks, exhausts, afterburner glows
               p == 0x1c || p == 0x1d || p == 0x2a || p == 0x2b;// per-nozzle glows / discs
    }

    void play_explosion_sound(rdVector3 pos) {
        const int ids[3] = {0x34, 0x35, 0x36};
        const auto play = (PlaySpatialRange_t) swrSound_PlaySpatialRange_ADDR;
        play(ids[(int) (frand() * 3.0f) % 3], 7, frand() * 0.2f + 0.1f, 1.0f, &pos, 0, 0, 10.0f, 500.0f);
    }

    // The engine at partNodes[part] breaks off and starts tumbling.
    bool has_body(const Wreck& w, int part) {
        for (const Body& b: w.bodies)
            if (b.part == part)
                return true;
        return false;
    }

    // scatter: blown apart, every which way; momentum: just let go, carrying on as it was moving.
    void start_body(swrRace* r, Wreck& w, int part, int side, bool scatter, bool momentum = false) {
        if (r->partNodes == nullptr || r->partNodes[part] == nullptr)
            return;
        for (const Body& b: w.bodies)
            if (b.part == part)
                return;
        Body b;
        b.part = part;
        b.node = r->partNodes[part];
        const rdMatrix44& e = part_xf(r, part);
        b.axes[0] = v3(e.vA);
        b.axes[1] = v3(e.vB);
        b.axes[2] = v3(e.vC);
        b.pos = v3(e.vD);
        b.L = pod_length(r);
        b.radius = b.L * (part == 5 ? 0.08f : 0.1f);
        b.seed = (uint32_t) (uintptr_t) b.node * 2654435761u;
        // Thrown off with the pod's speed, outward and up, tumbling.
        const rdVector3 mid = mul(add(v3(r->engineXfR.vD), v3(r->engineXfL.vD)), 0.5f);
        rdVector3 out = norm(sub(b.pos, mid));
        if (len(out) < 0.5f)
            out = norm(side == 0 ? b.axes[0] : mul(b.axes[0], -1.0f));
        if (scatter)// blown apart: every which way
            out = norm(add(out, mul(rand_vec(), 1.2f)));
        const rdVector3 down = len(r->world_gravity) > 0.5f ? norm(r->world_gravity) : rdVector3{0.0f, 0.0f, -1.0f};
        const rdVector3 up = mul(down, -1.0f);
        const rdVector3 carried = w.has_last ? w.last_vel[part] : rdVector3{0.0f, 0.0f, 0.0f};
        // Ahead: along the pod's motion (or its nose when it is barely moving).
        rdVector3 ahead = norm(carried);
        if (len(carried) < b.L * 2.0f)
            ahead = norm(sub(v3(r->cockpitXf.vD), mid));
        const float throw_k = s.kick * (scatter ? 2.0f : 1.0f);
        b.vel = add(carried, add(add(mul(out, b.L * throw_k * (2.0f + 2.0f * frand())), mul(up, b.L * throw_k * (2.5f + 2.0f * frand()))),
                                 mul(rand_vec(), b.L * 0.6f * throw_k)));
        if (!scatter)
            b.vel = add(b.vel, mul(ahead, b.L * s.fling * (4.0f + 3.0f * frand())));
        b.spin = add(mul(rand_vec(), s.spin * (3.0f + 4.0f * frand())), mul(norm(b.axes[1]), s.spin * frand_sym() * 8.0f));
        if (momentum) {
            // Let go: on along the way it was moving (a touch of wobble), tumbling as it was spun --
            // but held to about the pod's own speed and slowing quickly, so it stays in view.
            b.vel = add(carried, mul(rand_vec(), b.L * 0.3f));
            const float sp = len(b.vel), cap = std::max(len(w.pod_vel), b.L * 0.5f) * s.chase;
            if (sp > cap)
                b.vel = mul(b.vel, cap / sp);
            b.drag = s.drag;
            b.spin = add(mul(rand_vec(), s.spin * (2.0f + 2.0f * frand())), mul(norm(b.axes[1]), s.spin * frand_sym() * 4.0f));
        }
        if (part == 5) {
            // The cockpit tumbles on ahead, end over end, where the camera is looking.
            b.vel = add(mul(carried, 0.9f), add(mul(ahead, b.L * s.fling * (3.0f + 2.0f * frand())), mul(up, b.L * 2.0f)));
            b.spin = add(mul(cross(ahead, up), s.spin * (4.0f + 3.0f * frand())), mul(rand_vec(), s.spin * 1.5f));
        }
        // Every other pod part riding on this engine (flaps, intakes...): the parts the game places
        // on their own whose position is nearest this engine. Parts under the engine's node already
        // move with it.
        std::unordered_set<const swrModel_Node*> under;
        collect_subtree(b.node, under, 0);
        rdMatrix44 inv;
        if (invert_affine(e, inv))
            for (int p = 0; p < 75; p++) {
                swrModel_Node* n = r->partNodes[p];
                if (n == nullptr || skip_part(p) || under.count(n))
                    continue;
                const rdVector3 o = v3(part_xf(r, p).vD);
                int nearest = -1;
                float best = 1e30f;
                for (int q = 1; q <= 5; q++) {
                    if (r->partNodes[q] == nullptr)
                        continue;
                    const float d = len(sub(o, v3(part_xf(r, q).vD)));
                    if (d < best)
                        best = d, nearest = q;
                }
                if (nearest == part && best < b.L * 0.6f)
                    b.parts.push_back({n, mat_then(part_xf(r, p), inv)});
            }
        // Breaking off: a burst of chips, sparks and smoke where it tore away.
        pod_fx_wreck_emit(b.pos, mul(b.vel, 0.4f), out, b.L, NAN, (int) (35 * s.fx), (int) (15 * s.fx), (int) (8 * s.fx),
                          (int) (22 * s.smoke), 0.7f, (int) (40 * s.debris));
        w.bodies.push_back(std::move(b));
    }

    void start_side(swrRace* r, Wreck& w, int side, bool scatter) {
        start_body(r, w, 1 + side, side, scatter);
        if (four_engines(r))
            start_body(r, w, 3 + side, side, scatter);
    }

    // One physics step for a tumbling engine.
    void step_body(swrRace* r, Body& b, float dt) {
        const rdVector3 down = len(r->world_gravity) > 0.5f ? norm(r->world_gravity) : rdVector3{0.0f, 0.0f, -1.0f};
        const float L = b.L;
        b.age += dt;
        b.vel = add(b.vel, mul(down, s.gravity * L * dt));
        b.vel = mul(b.vel, std::exp(-b.drag * dt));// air drag
        rdVector3 step = mul(b.vel, dt);
        const float step_len = len(step);
        bool hit = false;
        float impact = 0.0f;
        rdVector3 n{}, hit_point{};
        if (r->collisionModel != nullptr) {
            // Along the motion (plus the body's radius), or a short probe down when nearly still.
            const rdVector3 dir = step_len > 1e-4f ? mul(step, 1.0f / step_len) : down;
            float ray[7] = {b.pos.x, b.pos.y, b.pos.z, dir.x, dir.y, dir.z, step_len + b.radius};
            swrModel_Node* const saved_hit = swrRace_collisionHitNode;
            const float d = ((RaycastModel_t) swrRace_RaycastModel_ADDR)(r->collisionModel, ray, &hit_point, &n);
            swrRace_collisionHitNode = saved_hit;
            if (d >= 0.0f && len(n) > 0.5f) {
                n = norm(n);
                if (dot(n, dir) > 0.0f)
                    n = mul(n, -1.0f);// facing the body
                hit = true;
                b.pos = add(hit_point, mul(n, b.radius));
                const float vn = dot(b.vel, n);
                if (vn < 0.0f) {
                    impact = -vn;
                    const rdVector3 vt = sub(b.vel, mul(n, vn));
                    b.vel = add(mul(vt, s.grip), mul(n, -vn * s.bounce));
                    // Rolling along the surface, plus a random knock that grows with the hit.
                    const rdVector3 roll = mul(cross(n, vt), 1.0f / std::max(b.radius, 1e-3f));
                    b.spin = add(mul(b.spin, 0.5f), mul(roll, 0.5f * s.spin));
                    b.spin = add(b.spin, mul(rand_vec(), s.spin * std::min(impact / L, 6.0f)));
                }
                if (std::fabs(n.z) > 0.5f)
                    b.ground_z = hit_point.z;
            }
        }
        if (!hit)
            b.pos = add(b.pos, step);
        b.grounded = hit;
        // Turn it.
        const float w = len(b.spin);
        if (w > 1e-5f) {
            const rdVector3 a = mul(b.spin, 1.0f / w);
            for (rdVector3& axis: b.axes)
                axis = rotate(axis, a, w * dt);
        }
        b.spin = mul(b.spin, std::exp(-(hit ? 1.5f : 0.3f) * dt));
        // Coming to rest.
        if (hit && len(b.vel) < L * 0.4f) {
            b.rest += dt;
            b.vel = mul(b.vel, std::exp(-4.0f * dt));
            b.spin = mul(b.spin, std::exp(-4.0f * dt));
        }
        // Falling apart: slowly while burning, in chunks on each real hit.
        b.breakup += dt * 0.04f * s.breakup;
        const rdVector3 up = mul(down, -1.0f);
        // (At most one chunk per hit: a piece pressed into a wall touches it every frame.)
        b.hit_cool -= dt;
        if (impact > L * 1.2f && b.hit_cool <= 0.0f) {
            b.hit_cool = 0.15f;
            b.breakup += std::clamp(impact / (L * 40.0f), 0.03f, 0.12f) * s.breakup;
            const float hard = std::min(impact / L, 12.0f);
            const int sparks = (int) (hard * 6.0f * s.fx);
            pod_fx_wreck_emit(b.pos, mul(b.vel, 0.5f), n, L, b.ground_z, sparks, (int) (sparks * 0.3f), (int) (6 * s.fx),
                              (int) ((4.0f + hard) * s.smoke), 0.6f, (int) ((6.0f + 2.5f * hard) * s.debris));
        }
        // Burning: fire and smoke pour off it the whole way.
        b.fire_acc += dt * s.fx * (14.0f + 18.0f * (1.0f - std::min(b.breakup, 1.0f)));
        b.smoke_acc += dt * s.fx * s.smoke * 30.0f;
        b.debris_acc += dt * s.debris * 5.0f;// bits dropping off it as it burns
        const int flames = (int) b.fire_acc, smoke = (int) b.smoke_acc, chips = (int) b.debris_acc;
        b.fire_acc -= (float) flames;
        b.smoke_acc -= (float) smoke;
        b.debris_acc -= (float) chips;
        if (flames > 0 || smoke > 0 || chips > 0)
            pod_fx_wreck_emit(b.pos, mul(b.vel, 0.3f), up, L, b.ground_z, 0, flames > 1 ? 1 : 0, flames, smoke, 0.75f, chips);
        // The end: a last burst.
        if (b.age > s.life || (b.breakup >= 0.92f && b.age > 1.5f)) {
            b.done = true;
            rdVector3 p = b.pos;
            ((SmokSpawn_t) swrObjSmok_Spawn_ADDR)(swrObjSmok_TYPE_EXPLOSION, 0, 2.0f, &p, 1.0f);
            pod_fx_wreck_emit(b.pos, mul(b.vel, 0.2f), up, L, b.ground_z, (int) (80 * s.fx), (int) (30 * s.fx),
                              (int) (30 * s.fx), (int) (40 * s.smoke), 0.8f, (int) (70 * s.debris));
            play_explosion_sound(b.pos);
        }
    }

    void reset(swrRace* r, Wreck& w) {
        for (const Body& b: w.bodies) {
            g_breakup.erase(b.node);
            for (const Attached& a: b.parts)
                g_breakup.erase(a.node);
        }
        for (const auto& [node, flags]: w.saved_flags)
            node->flags_1 = (node->flags_1 & ~0x2u) | (flags & 0x2u);
        // The respawned pod has its engines back (whatever they were when they broke off).
        for (const Body& b: w.bodies) {
            b.node->flags_1 |= 0x2u;
            for (const Attached& a: b.parts)
                a.node->flags_1 |= 0x2u;
        }
        if (w.saved_top_speed > 0.0f)
            r->podStats.maxSpeed = w.saved_top_speed;
        // ... and repaired.
        for (int side = 0; side < 2; side++) {
            if (!(w.lost & (1 << side)))
                continue;
            const int first = side == 0 ? 3 : 0;
            for (int i = first; i < first + 3; i++) {
                r->engineHealth[i] = 0.0f;
                r->engineHealthMin[i] = 0.0f;
                r->engineStatus[i] = 0;
            }
        }
        w = Wreck{};
    }

    bool pod_down(const swrRace* r) {
        return (r->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) != 0 ||
               (r->flags1 & swrObjTest_FLAG1_EXPLODING) != 0;
    }

    // ---- panel -------------------------------------------------------------------------------
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
        check("Engines break off and tumble", &s.enabled,
              "A blown engine flies off the pod, bounces and rolls along the track, falls apart and bursts, "
              "instead of vanishing.");
        check("Keep racing on one engine", &s.keep_racing,
              "An engine blown by damage doesn't end the run: the pod keeps going on the other one. Losing the "
              "second engine, or crashing, is the normal death.");
        check("Pod blows apart", &s.crash_scatter,
              "When the pod blows up (a head-on crash, or the end of a death spin) its engines and cockpit fly "
              "off in all directions.");
        check("AI pods too", &s.ai_pods, "Apply to AI pods as well as players.");
        ImGui::SeparatorText("On one engine");
        changed |= ImGui::SliderInt("Pull to the missing side", &s.pull, 0, 3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("The game's own damaged-engine steering pull: how many of the missing engine's three "
                              "segments count as badly damaged. 3 is the game's strongest pull (hard to steer).");
        slider("Top speed", &s.top_speed, 0.2f, 1.0f, "%.2f x", "Top speed on one engine, times the pod's own.");
        ImGui::SeparatorText("Debris");
        slider("Throw", &s.kick, 0.0f, 4.0f, "%.2f", "How hard the engine is thrown off the pod.");
        slider("Fling ahead", &s.fling, 0.0f, 4.0f, "%.2f", "Extra push ahead, so it tumbles on in front of the pod.");
        slider("Last engine speed", &s.chase, 0.3f, 3.0f, "%.2f x",
               "The engine kept through the death spin: when it breaks off at the end, it leaves at no more\n"
               "than this times the pod's own speed, so it stays in view.");
        slider("Last engine drag", &s.drag, 0.0f, 4.0f, "%.2f", "How quickly that engine slows down in the air.");
        slider("Tumble", &s.spin, 0.0f, 4.0f, "%.2f", "How wildly it spins.");
        slider("Gravity", &s.gravity, 0.0f, 40.0f, "%.1f", "Pod lengths per second squared.");
        slider("Bounce", &s.bounce, 0.0f, 1.0f, "%.2f", "0 = no bounce .. 1 = no speed lost.");
        slider("Slide", &s.grip, 0.0f, 1.0f, "%.2f", "Speed kept along the ground at each hit.");
        slider("Break-up", &s.breakup, 0.0f, 4.0f, "%.2f", "How fast it falls to pieces.");
        slider("Burst after", &s.life, 1.0f, 30.0f, "%.1f s", "Seconds until whatever is left bursts.");
        slider("Sparks / fire", &s.fx, 0.0f, 4.0f, "%.2f", "Sparks, fire and smoke (drawn by Pod FX).");
        slider("Smoke", &s.smoke, 0.0f, 4.0f, "%.2f x", "How much smoke pours off the wreckage.");
        slider("Debris", &s.debris, 0.0f, 4.0f, "%.2f x", "Chips of metal scattered when parts break off and hit things.");
        if (changed)
            save_settings();
    }
    DebugPanel g_panel = {.category = "Mods", .name = "Pod Wrecks", .draw = panel, .dev_only = false};
}// namespace
static void place(swrRace* r, Wreck& w);

bool pod_wreck_on_explode(swrRace* r, int side_arg, bool crash) {
    // A crash is always the real thing; only an engine blown by damage can be survived.
    if (r == nullptr || crash || !s.keep_racing || !allowed(r))
        return false;
    // Only when the stock explosion would actually go off.
    const uint32_t f0 = r->flags0, f1 = r->flags1;
    if (!((f0 & 0x20) != 0 || (f1 & 0x4000000) != 0) || (f1 & swrObjTest_FLAG1_EXPLODING) != 0 || (f0 & 0x7000) != 0)
        return false;
    const int side = side_of_arg(side_arg);
    Wreck& w = g_wrecks[r];
    if (w.lost & (1 << side))
        return true;// already gone
    if (w.lost != 0)
        return false;// the other engine too: the real crash
    w.lost |= 1 << side;
    // The stock blast at that engine (fireball, two explosions, a bang), but no spin-out.
    const rdMatrix44& e = side == 0 ? r->engineXfR : r->engineXfL;
    rdVector3 pos = v3(e.vD), zero = {0.0f, 0.0f, 0.0f};
    ((SpawnEngineFireball_t) swrRace_SpawnEngineFireball_ADDR)(r, side_arg & 3, &zero, 0.3f);
    ((SmokSpawn_t) swrObjSmok_Spawn_ADDR)(swrObjSmok_TYPE_EXPLOSION, 0, 2.0f, &pos, 1.0f);
    ((SmokSpawn_t) swrObjSmok_Spawn_ADDR)(swrObjSmok_TYPE_EXPLOSION, 0, 2.2f, &pos, 3.0f);
    play_explosion_sound(pos);
    r->flags0 = (swrObjTest_FLAG0) (r->flags0 & ~swrObjTest_FLAG0_BOOSTING);
    if (s.enabled)
        start_side(r, w, side, false);
    return true;
}

void pod_wreck_after_explode(swrRace* r, int side_arg, bool crash) {
    if (r == nullptr || !s.enabled || !allowed(r) || (r->flags1 & swrObjTest_FLAG1_EXPLODING) == 0)
        return;
    const int side = side_of_arg(side_arg);
    Wreck& w = g_wrecks[r];
    (void) crash;
    w.fatal = true;
    w.lost |= 1 << side;
    start_side(r, w, side, false);
    // Only one engine rides out the spin: on a four-engine pod the other side's outer one goes too.
    if (four_engines(r))
        start_body(r, w, 3 + (1 - side), 1 - side, false);
    if (r->partNodes == nullptr)
        return;
    // The engine still on the pod rides out the spin on its cable.
    for (int p = 1; p <= 4; p++)
        if (!(w.lost & (1 << ((p - 1) % 2))) && r->partNodes[p] != nullptr && !has_body(w, p))
            w.held[p] = true;
}

void pod_wreck_before_death_explosion(swrRace* r) {
    // The pod blowing up for good, from where it is now (the game then moves the pod back to the track).
    if (r == nullptr || !s.enabled || !allowed(r) || r->partNodes == nullptr || (r->flags0 & swrObjTest_FLAG0_DEAD) != 0)
        return;
    Wreck& w = g_wrecks[r];
    if (w.fatal && !w.scattered) {
        // The end of a death spin: the cockpit goes up with the pod, and the engine that rode out the
        // spin lets go, tumbling on the way it was moving.
        w.scattered = true;
        for (int p = 1; p <= 4; p++)
            if (w.held[p])
                start_body(r, w, p, (p - 1) % 2, false, true);
        w.lost = 3;
        return;
    }
    // A head-on crash: everything flies off every which way.
    if (!s.crash_scatter)
        return;
    w.fatal = true;
    w.scattered = true;
    for (int side = 0; side < 2; side++)
        if (!(w.lost & (1 << side)))
            start_side(r, w, side, true);
    w.lost = 3;
    start_body(r, w, 5, 0, true);
}

void pod_wreck_frame(swrRace* r) {
    if (r == nullptr)
        return;
    auto it = g_wrecks.find(r);
    // Track the engines' motion (the speed a knocked-off engine leaves with).
    const float dt = (float) std::clamp(swrRace_deltaTimeSecs, 0.0, 0.1);
    Wreck* w = it != g_wrecks.end() ? &it->second : nullptr;
    if (w == nullptr) {
        if (!s.enabled || r->partNodes == nullptr)
            return;
        w = &g_wrecks[r];
    }
    if (r->partNodes != nullptr && dt > 0.0f) {
        const bool moving_parts = !w->scattered;
        w->hist_at = (w->hist_at + 1) % 8;
        for (int p = 1; p <= 5; p++) {
            const rdVector3 now = v3(part_xf(r, p).vD);
            if (w->has_last && moving_parts && (p == 5 || !(w->lost & (1 << ((p - 1) % 2))))) {
                rdVector3 v = mul(sub(now, w->last_pos[p]), 1.0f / dt);
                if (len(v) > 5000.0f)// a teleport (respawn / reset), not motion
                    v = {0.0f, 0.0f, 0.0f};
                w->hist[p][w->hist_at] = v;
                // The fastest of the last few frames: a crash stops the pod a frame before it blows.
                rdVector3 best = v;
                for (const rdVector3& h: w->hist[p])
                    if (len(h) > len(best))
                        best = h;
                w->last_vel[p] = best;
                if (p == 5)
                    w->pod_vel = add(mul(w->pod_vel, 0.7f), mul(v, 0.3f));
            }
            w->last_pos[p] = now;
        }
        w->has_last = true;
    }
    if (w->lost == 0 && w->bodies.empty())
        return;
    // Back in one piece once the pod has gone down (crash / respawn) and come back.
    if (pod_down(r))
        w->saw_down = true;
    else if (w->saw_down) {
        reset(r, *w);
        return;
    }
    // On one engine: the game's damaged-engine pull toward the missing side (its parts held just
    // under "blown", so the game doesn't blow it again) and a lower top speed.
    if (!w->fatal) {
        for (int side = 0; side < 2; side++) {
            if (!(w->lost & (1 << side)))
                continue;
            // engineHealth[0..2] = left engine, [3..5] = right. Held under "blown" (1.0) so the game
            // doesn't blow it again; "badly damaged" (> 0.8) pulls the steering toward it.
            const int first = side == 0 ? 3 : 0;
            for (int i = 0; i < 3; i++)
                r->engineHealth[first + i] = i < s.pull ? 0.9f : std::min(r->engineHealth[first + i], 0.75f);
        }
        if (w->saved_top_speed < 0.0f)
            w->saved_top_speed = r->podStats.maxSpeed;
        r->podStats.maxSpeed = w->saved_top_speed * s.top_speed;
    }
    for (Body& b: w->bodies)
        if (!b.done && dt > 0.0f && r->partNodes != nullptr)
            step_body(r, b, dt);
    place(r, *w);
}

void pod_wreck_after_f3(swrRace* r) {
    auto it = g_wrecks.find(r);
    if (it != g_wrecks.end() && (it->second.lost != 0 || !it->second.bodies.empty()))
        place(r, it->second);
}

// The pod's nodes for a wreck: what hung off a missing engine hidden, the debris where it is.
// Run after the game placed the parts (PoddAnimateVariousThings) and again after swrObjTest_F3,
// which copies the engine / cockpit matrices onto their nodes at its end.
static void place(swrRace* r, Wreck& wr) {
    Wreck* w = &wr;
    if (r->partNodes == nullptr)
        return;
    swrModel_Node** nodes = r->partNodes;
    // What hangs off a missing engine goes with it: its cable(s), the binder beam, its exhaust.
    for (int side = 0; side < 2; side++) {
        if (!(w->lost & (1 << side)))
            continue;
        set_visible(*w, nodes[10 + side], false);
        set_visible(*w, nodes[12 + side], false);
        for (int p = 6; p <= 9; p++)
            set_visible(*w, nodes[p], false);
        set_visible(*w, nodes[0x43 + side], false);
        set_visible(*w, nodes[0x45 + side], false);
        set_visible(*w, nodes[side == 0 ? 0x2a : 0x1c], false);
        set_visible(*w, nodes[side == 0 ? 0x2b : 0x1d], false);
    }
    // Every engine that came off takes its cable with it (cables 10..13 run to engines 1..4).
    for (const Body& b: w->bodies)
        if (b.part >= 1 && b.part <= 4)
            set_visible(*w, nodes[10 + b.part - 1], false);
    // Through the stock spin-out the game drops the cables; the engine still on the pod keeps its.
    const auto set = (NodeSetTransform_t) swrModel_NodeSetTransform_ADDR;
    const int pilot = (r->score_ptr && r->score_ptr->pilotId) ? *r->score_ptr->pilotId : -1;
    if (w->fatal && !w->scattered && pilot >= 0 && pilot < 23)
        for (int side = 0; side < 2; side++) {
            if (w->lost & (1 << side))
                continue;
            const bool four = four_engines(r);
            for (int k = 0; k < (four ? 2 : 1); k++) {
                const int p = 1 + side + 2 * k;
                swrModel_Node* cable = nodes[10 + side + 2 * k];
                swrModel_Node* engine = nodes[p];
                if (engine == nullptr || !w->held[p] || has_body(*w, p))
                    continue;
                // The engine stays on where the game's spin puts it (rolling, the cockpit swinging
                // round it), shown, and keeps its cable.
                const rdMatrix44& em = part_xf(r, p);
                set_visible(*w, engine, true);
                if (cable == nullptr)
                    continue;
                rdMatrix44 m;
                ((BuildStretchedQuad_t) swrRace_BuildStretchedQuad_ADDR)(&r->cockpitXf, &em, side == 0 ? 1.0f : -1.0f, 1.0f,
                                                                         pilot, &m);
                set(cable, &m);
                set_visible(*w, cable, true);
            }
        }
    // Blown apart: the dead pod's other parts stay hidden, and every node above a piece of debris
    // is kept shown (the game hides a dead pod).
    if (w->scattered) {
        // (Everything under a piece stays: its meshes hang on part nodes below it.)
        std::unordered_set<const swrModel_Node*> keep;
        for (const Body& b: w->bodies) {
            collect_subtree(b.node, keep, 0);
            for (const Attached& a: b.parts)
                collect_subtree(a.node, keep, 0);
        }
        for (int p = 1; p < 75; p++)
            if (nodes[p] != nullptr && !keep.count(nodes[p]))
                set_visible(*w, nodes[p], false);
        if (nodes[0] != nullptr)
            for (const Body& b: w->bodies) {
                if (b.done)
                    continue;
                std::vector<swrModel_Node*> path;
                if (find_path(nodes[0], b.node, path, 0))
                    for (swrModel_Node* n: path)
                        if (n != b.node)
                            set_visible(*w, n, true);
            }
    }
    // The debris.
    for (Body& b: w->bodies) {
        if (b.done) {
            set_visible(*w, b.node, false);
            for (const Attached& a: b.parts)
                set_visible(*w, a.node, false);
            g_breakup.erase(b.node);
            for (const Attached& a: b.parts)
                g_breakup.erase(a.node);
            continue;
        }
        const rdMatrix44 m = b.matrix();
        set(b.node, &m);
        set_visible(*w, b.node, true);
        g_breakup[b.node] = {std::min(b.breakup, 1.0f), b.seed};
        for (const Attached& a: b.parts) {
            const rdMatrix44 pm = mat_then(a.rel, m);
            set(a.node, &pm);
            set_visible(*w, a.node, true);
            g_breakup[a.node] = {std::min(b.breakup, 1.0f), b.seed ^ (uint32_t) (uintptr_t) a.node};
        }
    }
}

void pod_wreck_after_damage_fx(swrRace* r) {
    auto it = g_wrecks.find(r);
    if (it == g_wrecks.end())
        return;
    // The game's engine smoke (slot 0 = left, 1 = right) rides on the debris.
    for (const Body& b: it->second.bodies) {
        if (b.done || b.part > 2)
            continue;
        swrObjSmok* smoke = r->engineDamageSmoke[b.part == 1 ? 1 : 0];
        if (smoke != nullptr) {
            rdVector3 p = b.pos;
            ((SmokSetVec_t) swrObjSmok_SetPosition_ADDR)(smoke, &p);
        }
    }
}

void pod_wreck_apart_nodes(std::vector<swrModel_Node*>& out) {
    out.clear();
    g_apart.clear();
    for (const auto& [r, w]: g_wrecks) {
        if (!w.scattered)
            continue;
        for (const Body& b: w.bodies) {
            if (b.done)
                continue;
            out.push_back(b.node);
            for (const Attached& a: b.parts)
                out.push_back(a.node);
        }
    }
    g_apart.insert(out.begin(), out.end());
}

bool pod_wreck_drawn_apart(const swrModel_Node* node) {
    return !g_apart.empty() && g_apart.count(node) != 0;
}

float pod_wreck_breakup(const swrModel_Node* node, uint32_t* seed) {
    if (g_breakup.empty())
        return -1.0f;
    const auto it = g_breakup.find(node);
    if (it == g_breakup.end())
        return -1.0f;
    *seed = it->second.seed;
    return it->second.amount;
}

bool pod_wreck_side_gone(const swrRace* racer, int side) {
    if (g_wrecks.empty() || side < 0 || side > 1)
        return false;
    const auto it = g_wrecks.find(const_cast<swrRace*>(racer));
    return it != g_wrecks.end() && (it->second.lost & (1 << side)) != 0;
}

void pod_wreck_clear() {
    g_apart.clear();
    g_wrecks.clear();
    g_breakup.clear();
}

void pod_wreck_register_panel() {
    load_settings();
    debug_ui_register(&g_panel);
}
