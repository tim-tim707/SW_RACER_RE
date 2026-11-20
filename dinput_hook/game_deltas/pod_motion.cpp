#include "pod_motion.h"

#include <cmath>
#include <cstdint>
#include <unordered_map>

#include <imgui.h>

extern "C" {
#include <Swr/swrRace.h> // swrRace_PoddAnimateEngines_ADDR
#include <globals.h>     // swrRace_deltaTimeSecs
#include <types_enums.h> // swrObjTest_FLAG0_LOCAL
}

#include "../config.h"
#include "../debug_ui.h"
#include "../hook_helper.h"
#include "pod_fx.h"// pod_fx_engine_damage (damaged-engine wobble)
#include "pod_edits.h"// pod_edits_apply_gaps (the pod editor's engine / cockpit spacing)

// How it works
// ------------
// swrRace_PoddAnimateEngines places the engines and cockpit each tick by replaying the pod's own
// transform from a short history ring buffer (engines lag 16 ticks, cockpit 10) -- the parts trail
// along the same path but never swing, roll or bounce on their own. Right after it returns,
// swrObjTest_F3 bends the cables between those matrices and copies them onto the model nodes, so
// anything changed here is drawn (HD glTF pods included) and the cables stay attached.
//
// We measure the pod's real acceleration from its position each tick, split it into sideways
// (turning) and vertical (bumps/landings) parts in the pod's own frame, and drive a few damped
// springs with it:
//   - cockpit sway: thrown outward through a turn, overshoots and settles like a weight on cables;
//     it also leans and yaws toward the inside of the turn as it swings.
//   - cockpit bob: dips and rebounds on vertical jolts.
//   - engine bank: each engine rolls into the turn on its own spring; left and right are detuned so
//     they move slightly out of step instead of as one rigid piece.
// The matrices are rebuilt from scratch by the game every tick, so nothing accumulates.

namespace {
    struct Settings {
        bool enabled = true;
        bool ai_pods = true;          // also animate AI / remote pods, not just your own
        float turn_sensitivity = 500; // sideways accel (units/s^2) that counts as a "full" turn
        float bump_sensitivity = 1500;// vertical accel that counts as a "full" jolt
        float cockpit_sway = 0.12f;   // max sideways cockpit offset, as a fraction of pod length
        float cockpit_roll = 10.0f;   // max cockpit lean, degrees
        float cockpit_yaw = 4.0f;     // max cockpit yaw toward the inside of the turn, degrees
        float cockpit_bob = 0.05f;    // max vertical cockpit offset, fraction of pod length
        float swing_hz = 1.4f;        // cockpit swing frequency
        float swing_damping = 0.22f;  // damping ratio (lower = more overshoot / swinging)
        bool roll_with_bank = true;   // engines roll to match the tilt instead of just rising/dropping
        float cockpit_follow = 0.8f;  // how much of that tilt roll the cockpit takes (0..1)
        float engine_bank = 8.0f;     // max extra engine roll into turns, degrees
        float engine_hz = 2.2f;       // engine bank spring frequency
        float engine_damping = 0.30f; // engine bank damping ratio
        float engine_desync = 0.15f;  // left/right spring detune, so the engines drift out of step
        bool only_moving = true;      // stopped pods behave exactly like stock; effects fade in with speed
        float damage_wobble = 1.0f;   // extra jittery wobble on an engine whose HUD segments are orange+
    };
    Settings s;
    const Settings kDefaults;

    struct Spring {
        float x = 0, v = 0;
        // Semi-implicit Euler damped spring toward target.
        void step(float target, float hz, float zeta, float dt) {
            const float w = 6.2831853f * hz;
            v += dt * (w * w * (target - x) - 2.0f * zeta * w * v);
            x += dt * v;
        }
    };

    struct PodState {
        bool has_pos = false, has_vel = false;
        rdVector3 prev_pos{}, prev_vel{}, accel{};
        Spring sway, bob, engine[4];
        float moving = 0.0f;// 0 = stopped (stock behaviour) .. 1 = moving (full effect)
        float time = 0.0f;  // drives the damaged-engine wobble
        // 4-engine pods: each bottom engine's resting pose in the pod's frame (slow average),
        // used to hand its lag motion on to the top engine above it.
        rdMatrix44 bottom_rest[2]{};
        bool has_rest = false;
    };
    std::unordered_map<const swrRace*, PodState> g_pods;

    // ---- affine 4x4 helpers (row-vector convention: world = local * M, rows vA..vD) ----
    rdMatrix44 mat_mul(const rdMatrix44& a, const rdMatrix44& b) {
        const float* A = &a.vA.x;
        const float* B = &b.vA.x;
        rdMatrix44 o;
        float* O = &o.vA.x;
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                O[i * 4 + j] = A[i * 4 + 0] * B[0 * 4 + j] + A[i * 4 + 1] * B[1 * 4 + j] +
                               A[i * 4 + 2] * B[2 * 4 + j] + A[i * 4 + 3] * B[3 * 4 + j];
        return o;
    }
    bool mat_inv_affine(const rdMatrix44& m, rdMatrix44& out) {
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

    // Ben Quadinaros (4 engines): the game replays the pod's motion with a lag onto the bottom
    // pair only (engineXfR/L), which is what makes engines bob and pitch; the top pair
    // (engineXfR2/L2) is held rigid to the pod. Give each top engine the same lag motion as the
    // bottom engine on its side: how far that bottom engine is from its resting pose on the pod
    // right now, applied on top of the top engine's own pose.
    void follow_bottom_engines(swrRace* p, PodState& st) {
        rdMatrix44 inv_pod;
        if (!mat_inv_affine(p->transform, inv_pod))
            return;
        for (int side = 0; side < 2; side++) {
            const rdMatrix44& bottom = side == 0 ? p->engineXfR : p->engineXfL;
            rdMatrix44& top = side == 0 ? p->engineXfR2 : p->engineXfL2;
            const rdMatrix44 local = mat_mul(bottom, inv_pod);
            rdMatrix44& rest = st.bottom_rest[side];
            if (!st.has_rest) {
                rest = local;
            } else {
                float* R = &rest.vA.x;
                const float* L = &local.vA.x;
                for (int k = 0; k < 16; k++)
                    R[k] += (L[k] - R[k]) * 0.01f;// ~2 s average at 50 Hz
            }
            rdMatrix44 inv_rest_world;
            if (!mat_inv_affine(mat_mul(rest, p->transform), inv_rest_world))
                continue;
            const rdMatrix44 dev = mat_mul(inv_rest_world, bottom);// rest pose -> current pose
            top = mat_mul(top, dev);
        }
        st.has_rest = true;
    }

    constexpr float kTeleportDist = 200.0f;// position jump in one tick = respawn/reset, not motion
    constexpr float kMaxAccel = 8000.0f;   // ignore collision spikes beyond this
    constexpr float kAccelFilterSecs = 0.06f;
    constexpr float kDegToRad = 0.017453293f;

    rdVector3 v3(const rdVector4& v) { return {v.x, v.y, v.z}; }
    rdVector3 sub(rdVector3 a, rdVector3 b) { return {a.x - b.x, a.y - b.y, a.z - b.z}; }
    rdVector3 scale(rdVector3 a, float k) { return {a.x * k, a.y * k, a.z * k}; }
    float dot(rdVector3 a, rdVector3 b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
    float len(rdVector3 a) { return std::sqrt(dot(a, a)); }
    rdVector3 norm(rdVector3 a) {
        const float l = len(a);
        return l > 1e-6f ? scale(a, 1.0f / l) : rdVector3{0, 0, 0};
    }
    float clampf(float x, float lo, float hi) { return x < lo ? lo : (x > hi ? hi : x); }

    rdVector4& axis(rdMatrix44& m, int i) { return i == 0 ? m.vA : (i == 1 ? m.vB : m.vC); }

    // Rotates matrix axis `from` toward axis `to` by `angle` radians, in the plane they span,
    // keeping each axis's length (the part matrices can carry scale). Handedness-agnostic.
    void rotate_plane(rdMatrix44& m, int from, int to, float angle) {
        if (angle == 0.0f)
            return;
        rdVector4& A = axis(m, from);
        rdVector4& B = axis(m, to);
        const float la = len(v3(A)), lb = len(v3(B));
        if (la < 1e-6f || lb < 1e-6f)
            return;
        const rdVector3 a = scale(v3(A), 1.0f / la), b = scale(v3(B), 1.0f / lb);
        const float c = std::cos(angle), sn = std::sin(angle);
        A.x = la * (a.x * c + b.x * sn);
        A.y = la * (a.y * c + b.y * sn);
        A.z = la * (a.z * c + b.z * sn);
        B.x = lb * (b.x * c - a.x * sn);
        B.y = lb * (b.y * c - a.y * sn);
        B.z = lb * (b.z * c - a.z * sn);
    }

    void translate(rdMatrix44& m, rdVector3 d) {
        m.vD.x += d.x;
        m.vD.y += d.y;
        m.vD.z += d.z;
    }

    // Axis indices in rdMatrix44: vA = right, vB = forward, vC = up.
    constexpr int kRight = 0, kForward = 1, kUp = 2;

    // Angle (radians) of the line between an engine pair, measured from the pod's right axis
    // toward its up axis -- i.e. how far the stock tilt has rolled the pair. 0 when level.
    // Sign-agnostic about which engine sits on the +right side.
    float engine_line_bank(const rdMatrix44& a, const rdMatrix44& b, rdVector3 right, rdVector3 up) {
        const rdVector3 d = sub(v3(a.vD), v3(b.vD));
        const float r = dot(d, right);
        if (std::fabs(r) < 1e-4f)
            return 0.0f;
        const float sgn = r > 0.0f ? 1.0f : -1.0f;
        return std::atan2(sgn * dot(d, up), std::fabs(r));
    }

    // Rolls a part about its own forward axis so its right axis sits `angle` radians above the
    // pod's right axis (toward pod up), replacing whatever roll it had relative to the pod.
    float part_roll(const rdMatrix44& m, rdVector3 right, rdVector3 up) {
        const rdVector3 a = norm(v3(m.vA));
        return std::atan2(dot(a, up), dot(a, right));
    }

    void set_roll(rdMatrix44& m, rdVector3 right, rdVector3 up, float angle) {
        rotate_plane(m, kRight, kUp, angle - part_roll(m, right, up));
    }

    void animate(swrRace* p) {
        PodState& st = g_pods[p];
        const float dt = (float) clampf((float) swrRace_deltaTimeSecs, 0.0f, 0.05f);

        const rdVector3 pos = v3(p->transform.vD);
        if (!st.has_pos || len(sub(pos, st.prev_pos)) > kTeleportDist) {
            st = PodState{};// fresh pod or respawn: start at rest
            st.has_pos = true;
            st.prev_pos = pos;
            return;
        }

        if (dt > 1e-5f) {
            st.time += dt;
            // Moving factor: 0 when stopped, easing to 1 once the pod is under way (~40 speed),
            // so a stationary pod looks exactly like stock and the new motion fades in with speed.
            const float target_moving =
                s.only_moving ? clampf((p->speedValue - 3.0f) / 40.0f, 0.0f, 1.0f) : 1.0f;
            st.moving += (target_moving - st.moving) * (1.0f - std::exp(-dt / 0.3f));
            const rdVector3 vel = scale(sub(pos, st.prev_pos), 1.0f / dt);
            if (st.has_vel) {
                rdVector3 acc = scale(sub(vel, st.prev_vel), 1.0f / dt);
                const float mag = len(acc);
                if (mag > kMaxAccel)
                    acc = scale(acc, kMaxAccel / mag);
                const float k = 1.0f - std::exp(-dt / kAccelFilterSecs);
                st.accel = {st.accel.x + (acc.x - st.accel.x) * k,
                            st.accel.y + (acc.y - st.accel.y) * k,
                            st.accel.z + (acc.z - st.accel.z) * k};
            }
            st.prev_vel = vel;
            st.has_vel = true;
            st.prev_pos = pos;

            const rdVector3 right = norm(v3(p->transform.vA));
            const rdVector3 up = norm(v3(p->transform.vC));
            // +lat: the turn's centre is toward +right.
            const float lat = clampf(dot(st.accel, right) / s.turn_sensitivity, -1.5f, 1.5f);
            const float vert = clampf(dot(st.accel, up) / s.bump_sensitivity, -1.5f, 1.5f);

            st.sway.step(-lat, s.swing_hz, s.swing_damping, dt);// thrown to the outside
            st.bob.step(-vert, s.swing_hz * 1.4f, s.swing_damping + 0.1f, dt);
            for (int i = 0; i < 4; i++) {
                // engineXfR, engineXfL, engineXfR2, engineXfL2: detune right vs left.
                const float detune = (i % 2 == 0) ? (1.0f + s.engine_desync) : (1.0f - s.engine_desync);
                st.engine[i].step(lat, s.engine_hz * detune, s.engine_damping, dt);
            }
        }

        // Pod length (cockpit to the midpoint between the engines) scales the offsets, so big and
        // small pods sway in proportion.
        const rdVector3 eng_mid = scale(
            {p->engineXfR.vD.x + p->engineXfL.vD.x, p->engineXfR.vD.y + p->engineXfL.vD.y,
             p->engineXfR.vD.z + p->engineXfL.vD.z},
            0.5f);
        float pod_len = len(sub(v3(p->cockpitXf.vD), eng_mid));
        if (!(pod_len > 0.5f && pod_len < 500.0f))
            pod_len = 10.0f;

        const rdVector3 right = norm(v3(p->transform.vA));
        const rdVector3 up = norm(v3(p->transform.vC));
        const float m = st.moving;// every effect below is scaled by it
        if (m <= 0.001f)
            return;// stopped: leave the stock pose untouched

        // Rigid bank. When the pod tilts, the stock game moves the engines up/down around the
        // pod's centre line but leaves each engine nearly upright. Measure the bank from the line
        // joining each engine pair and roll the engines (and, partly, the cockpit) to match it,
        // so the pod rolls as one piece like in the films.
        if (s.roll_with_bank) {
            // Blend from the stock roll toward the matched roll by the moving factor.
            auto blend_roll = [&](rdMatrix44& mx, float target) {
                const float cur = part_roll(mx, right, up);
                set_roll(mx, right, up, cur + (target - cur) * m);
            };
            const float bank = engine_line_bank(p->engineXfR, p->engineXfL, right, up);
            blend_roll(p->engineXfR, bank);
            blend_roll(p->engineXfL, bank);
            if (p->partNodes[3] && p->partNodes[4]) {// 4-engine pods: second pair
                const float bank2 = engine_line_bank(p->engineXfR2, p->engineXfL2, right, up);
                blend_roll(p->engineXfR2, bank2);
                blend_roll(p->engineXfL2, bank2);
            }
            blend_roll(p->cockpitXf, bank * s.cockpit_follow);
        }

        // Cockpit: swing outward + bob, while leaning/yawing toward the inside of the turn
        // (sway.x < 0 when the turn centre is to the right).
        translate(p->cockpitXf, scale(right, m * st.sway.x * s.cockpit_sway * pod_len));
        translate(p->cockpitXf, scale(up, m * st.bob.x * s.cockpit_bob * pod_len));
        rotate_plane(p->cockpitXf, kUp, kRight, -m * st.sway.x * s.cockpit_roll * kDegToRad);
        rotate_plane(p->cockpitXf, kForward, kRight, -m * st.sway.x * s.cockpit_yaw * kDegToRad);

        // Engines: bank into the turn, each on its own spring.
        rdMatrix44* engines[4] = {&p->engineXfR, &p->engineXfL, &p->engineXfR2, &p->engineXfL2};
        for (int i = 0; i < 4; i++)
            rotate_plane(*engines[i], kUp, kRight, m * st.engine[i].x * s.engine_bank * kDegToRad);

        // Damaged-engine wobble: an engine whose HUD segments are orange or worse shakes on its
        // strained tether -- small, quick, irregular roll/yaw and bob, growing with the damage.
        // (Engine index 0/2 = right side, 1/3 = left side.)
        if (s.damage_wobble > 0.0f) {
            const float t = st.time;
            for (int side = 0; side < 2; side++) {
                const float d = pod_fx_engine_damage(p, side) * s.damage_wobble * m;
                if (d <= 0.001f)
                    continue;
                const float ph = (float) side * 2.3f + (float) (((uintptr_t) p >> 4) & 63) * 0.37f;
                // Two fast incommensurate sines plus a slower swell give an uneven shudder.
                auto jit = [&](float hz, float o) {
                    return 0.55f * std::sin(6.2831853f * hz * t + ph + o) +
                           0.30f * std::sin(6.2831853f * hz * 1.73f * t + ph * 1.9f + o) +
                           0.15f * std::sin(6.2831853f * 0.6f * t + ph + o * 0.5f);
                };
                const float roll = d * 1.8f * kDegToRad * jit(5.2f, 0.0f);
                const float yaw = d * 1.2f * kDegToRad * jit(4.1f, 1.1f);
                const float bob = d * 0.006f * pod_len * jit(6.3f, 2.2f);
                for (int i = side; i < 4; i += 2) {
                    if (i >= 2 && !(p->partNodes[3] && p->partNodes[4]))
                        break;
                    rotate_plane(*engines[i], kUp, kRight, roll);
                    rotate_plane(*engines[i], kForward, kRight, yaw);
                    translate(*engines[i], scale(up, bob));
                }
            }
        }
    }

    void load_settings() {
        auto f = [](const char* key, float& v) { v = config::get_float("pod_motion", key, v); };
        s.enabled = config::get_int("pod_motion", "enabled", s.enabled) != 0;
        s.ai_pods = config::get_int("pod_motion", "ai_pods", s.ai_pods) != 0;
        f("turn_sensitivity", s.turn_sensitivity);
        f("bump_sensitivity", s.bump_sensitivity);
        f("cockpit_sway", s.cockpit_sway);
        f("cockpit_roll", s.cockpit_roll);
        f("cockpit_yaw", s.cockpit_yaw);
        f("cockpit_bob", s.cockpit_bob);
        f("swing_hz", s.swing_hz);
        f("swing_damping", s.swing_damping);
        s.roll_with_bank = config::get_int("pod_motion", "roll_with_bank", s.roll_with_bank) != 0;
        f("cockpit_follow", s.cockpit_follow);
        s.cockpit_follow = clampf(s.cockpit_follow, 0.0f, 1.0f);
        f("engine_bank", s.engine_bank);
        f("engine_hz", s.engine_hz);
        f("engine_damping", s.engine_damping);
        f("engine_desync", s.engine_desync);
        s.only_moving = config::get_int("pod_motion", "only_moving", s.only_moving) != 0;
        f("damage_wobble", s.damage_wobble);
        s.damage_wobble = clampf(s.damage_wobble, 0.0f, 4.0f);
        // Guard the spring and divisor inputs against a hand-edited ini.
        s.turn_sensitivity = clampf(s.turn_sensitivity, 50.0f, 5000.0f);
        s.bump_sensitivity = clampf(s.bump_sensitivity, 50.0f, 10000.0f);
        s.swing_hz = clampf(s.swing_hz, 0.2f, 6.0f);
        s.engine_hz = clampf(s.engine_hz, 0.2f, 6.0f);
        s.swing_damping = clampf(s.swing_damping, 0.02f, 2.0f);
        s.engine_damping = clampf(s.engine_damping, 0.02f, 2.0f);
        s.engine_desync = clampf(s.engine_desync, 0.0f, 0.6f);
    }

    void save_settings() {
        config::set_bool("pod_motion", "enabled", s.enabled);
        config::set_bool("pod_motion", "ai_pods", s.ai_pods);
        config::set_float("pod_motion", "turn_sensitivity", s.turn_sensitivity);
        config::set_float("pod_motion", "bump_sensitivity", s.bump_sensitivity);
        config::set_float("pod_motion", "cockpit_sway", s.cockpit_sway);
        config::set_float("pod_motion", "cockpit_roll", s.cockpit_roll);
        config::set_float("pod_motion", "cockpit_yaw", s.cockpit_yaw);
        config::set_float("pod_motion", "cockpit_bob", s.cockpit_bob);
        config::set_float("pod_motion", "swing_hz", s.swing_hz);
        config::set_float("pod_motion", "swing_damping", s.swing_damping);
        config::set_bool("pod_motion", "roll_with_bank", s.roll_with_bank);
        config::set_float("pod_motion", "cockpit_follow", s.cockpit_follow);
        config::set_float("pod_motion", "engine_bank", s.engine_bank);
        config::set_float("pod_motion", "engine_hz", s.engine_hz);
        config::set_float("pod_motion", "engine_damping", s.engine_damping);
        config::set_float("pod_motion", "engine_desync", s.engine_desync);
        config::set_bool("pod_motion", "only_moving", s.only_moving);
        config::set_float("pod_motion", "damage_wobble", s.damage_wobble);
        config::save();
    }

    void panel() {
        bool changed = false;
        changed |= ImGui::Checkbox("Movie pod motion", &s.enabled);
        ImGui::TextDisabled("Visual only: handling and collision are unchanged.");
        ImGui::BeginDisabled(!s.enabled);
        changed |= ImGui::Checkbox("Apply to AI pods too", &s.ai_pods);
        changed |= ImGui::Checkbox("Only while moving", &s.only_moving);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("A stopped pod looks exactly like stock; the motion fades in as it gets going.");

        auto slider = [&](const char* label, float* v, float lo, float hi, const char* fmt,
                          const char* tip) {
            ImGui::SliderFloat(label, v, lo, hi, fmt);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", tip);
            changed |= ImGui::IsItemDeactivatedAfterEdit();
        };

        ImGui::SeparatorText("Cockpit on its cables");
        slider("Sway", &s.cockpit_sway, 0.0f, 0.5f, "%.2f",
               "How far the cockpit swings out in turns (fraction of pod length).");
        slider("Lean", &s.cockpit_roll, 0.0f, 35.0f, "%.1f deg", "Cockpit roll while swinging.");
        slider("Yaw", &s.cockpit_yaw, 0.0f, 20.0f, "%.1f deg",
               "Cockpit nose turning toward the inside of the turn.");
        slider("Bob", &s.cockpit_bob, 0.0f, 0.25f, "%.2f",
               "Vertical bounce on bumps and landings (fraction of pod length).");
        slider("Swing speed", &s.swing_hz, 0.3f, 4.0f, "%.2f Hz", "Swing frequency.");
        slider("Swing damping", &s.swing_damping, 0.03f, 1.0f, "%.2f",
               "Lower = swings back and forth longer before settling.");

        ImGui::SeparatorText("Engines");
        changed |= ImGui::Checkbox("Roll with tilt", &s.roll_with_bank);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("When the pod tilts, roll the engines to match instead of\n"
                              "just raising one and lowering the other.");
        ImGui::BeginDisabled(!s.roll_with_bank);
        slider("Cockpit follows tilt", &s.cockpit_follow, 0.0f, 1.0f, "%.2f",
               "How much of the tilt roll the cockpit takes (1 = same as the engines).");
        ImGui::EndDisabled();
        slider("Extra bank", &s.engine_bank, 0.0f, 45.0f, "%.1f deg",
               "Springy extra engine roll into turns, on top of the tilt.");
        slider("Bank speed", &s.engine_hz, 0.3f, 5.0f, "%.2f Hz", "Engine bank spring frequency.");
        slider("Bank damping", &s.engine_damping, 0.03f, 1.0f, "%.2f",
               "Lower = engines wobble longer after a turn.");
        slider("Out of sync", &s.engine_desync, 0.0f, 0.5f, "%.2f",
               "How differently the left and right engines respond.");
        slider("Damaged engine wobble", &s.damage_wobble, 0.0f, 3.0f, "%.2fx",
               "Subtle shudder on an engine whose HUD segments are orange or worse\n"
               "(needs Mods > Pod FX enabled to read the damage).");

        ImGui::SeparatorText("Response");
        slider("Turn sensitivity", &s.turn_sensitivity, 100.0f, 2000.0f, "%.0f",
               "Sideways acceleration for full effect. Lower = reacts to gentler turns.");
        slider("Bump sensitivity", &s.bump_sensitivity, 200.0f, 5000.0f, "%.0f",
               "Vertical acceleration for full bob. Lower = bouncier.");
        ImGui::EndDisabled();

        if (ImGui::Button("Reset to defaults")) {
            s = kDefaults;
            changed = true;
        }
        if (changed)
            save_settings();
    }

    DebugPanel g_panel = {.category = "Mods", .name = "Pod Motion", .draw = panel, .dev_only = false};
}// namespace

typedef void(__cdecl* swrRace_PoddAnimateEngines_t)(swrRace* player);

void __cdecl swrRace_PoddAnimateEngines_delta(swrRace* player) {
    hook_call_original((swrRace_PoddAnimateEngines_t) swrRace_PoddAnimateEngines_ADDR, player);
    // The pod editor's engine / cockpit spacing, before any motion (not while crashing).
    if (player != nullptr && (player->flags1 & (swrObjTest_FLAG1_EXPLODING_LEFT | swrObjTest_FLAG1_EXPLODING_RIGHT)) == 0 &&
        (player->flags0 & swrObjTest_FLAG0_DEAD) == 0)
        pod_edits_apply_gaps(player);
    // partNodes == NULL is the far-LOD single-mesh pod: no separate parts to move.
    if (!s.enabled || player == nullptr || player->partNodes == nullptr)
        return;
    if (!s.ai_pods && (player->flags0 & swrObjTest_FLAG0_LOCAL) == 0)
        return;
    // Neva Kee's pod has no energy binder (its engines are fused to the cockpit -- pilot 14, the
    // same check the game uses for its "fused engines" special), so it keeps the stock motion.
    if (player->score_ptr != nullptr && player->score_ptr->pilotId != nullptr && *player->score_ptr->pilotId == 14) {
        g_pods.erase(player);
        return;
    }
    // Crash sequence (an engine blew and the pod is spinning out, or it's dead/exploding): hand
    // back to the stock animation completely, so the surviving engine and cockpit spin out of
    // control as the game intends (our roll alignment would otherwise cancel the spin). The pod's
    // motion state is dropped so it starts fresh after the respawn.
    if ((player->flags1 & (swrObjTest_FLAG1_EXPLODING_LEFT | swrObjTest_FLAG1_EXPLODING_RIGHT)) != 0 ||
        (player->flags0 & swrObjTest_FLAG0_DEAD) != 0) {
        g_pods.erase(player);
        return;
    }
    if (player->partNodes[3] && player->partNodes[4])
        follow_bottom_engines(player, g_pods[player]);
    animate(player);
}

void pod_motion_register_panel() {
    load_settings();
    debug_ui_register(&g_panel);
}
