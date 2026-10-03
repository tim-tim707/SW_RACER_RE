#include "swrMain_smoothing.h"
#include "swrMain_delta.h"   // swr_fixedTimestepHz
#include "swrObjJdge_delta.h"// swrText_FormatTimeEntryText

#include <cmath>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

extern "C" {
#include <Swr/swrEvent.h>   // swrEvent_GetEventCount, swrEvent_GetItem
#include <Swr/swrModel.h>   // swrModel_AnimationUpdateTime_ADDR, swrModel_Update*Animation_ADDR
#include <Swr/swrViewport.h>// swrViewport_SetMat3_ADDR
#include <globals.h>
}

bool swr_fixedTimestepSmoothing = true;
float swr_fixedTimestepPrediction = 0.0f;
int swr_fixedTimestep_smoothedNodes = 0;

namespace {
    constexpr int kEventTest = 0x54657374;// 'Test': one swrRace per racer
    constexpr int kMaxNodeDepth = 64;
    constexpr uintptr_t kMinValidAddress = 0x10000;// below the first mappable page
    constexpr int kNumViewports = 4;               // swrViewport_array[4]

    // A pose that moves further than this in one tick is a teleport (respawn, reset, scene swap):
    // show it as-is instead of blending across the jump.
    constexpr float kSnapDistancePerTick = 200.0f;
    // Same for rotation: an axis turning past ~60 degrees in one tick.
    constexpr float kSnapMinAxisDot = 0.5f;
    // When a tick lands somewhere other than where the last frame showed it, that miss is faded out
    // as exp(-k * ticks elapsed since that frame) instead of snapped.
    constexpr float kErrorDecayPerTick = 2.0f;
    constexpr uint32_t kNodeFlagVisible = 0x2;// swrModel_Node.flags_1
    // Respawn test: a step more than this many times the previous one, plus a floor (units per tick)
    // so a node starting to move from rest still blends.
    constexpr float kRespawnJumpRatio = 3.0f;
    constexpr float kRespawnJumpFloor = 8.0f;

    typedef void(__cdecl *swrViewport_SetMat3_t)(swrViewport *, const rdMatrix44 *);

    // The three basis axes (carrying scale) and the position of a node, racer or camera matrix.
    // Copy-assignment skips self-assignment: the analyzer models the implicit one as a memcpy and
    // otherwise flags the this == &other path as an overlapping copy.
    struct Xform {
        rdVector3 axes[3];
        rdVector3 pos;
        Xform &operator=(const Xform &other) {
            if (this != &other)
                memcpy(this, &other, sizeof(*this));
            return *this;
        }
    };

    float length3(const rdVector3 &v) {
        return sqrtf(v.x * v.x + v.y * v.y + v.z * v.z);
    }

    float dot3(const rdVector3 &a, const rdVector3 &b) {
        return a.x * b.x + a.y * b.y + a.z * b.z;
    }

    rdVector3 sub3(const rdVector3 &a, const rdVector3 &b) {
        return {a.x - b.x, a.y - b.y, a.z - b.z};
    }

    rdVector3 madd3(const rdVector3 &a, const rdVector3 &b, float s) {
        return {a.x + b.x * s, a.y + b.y * s, a.z + b.z * s};
    }

    rdVector3 scale3(const rdVector3 &v, float s) {
        return {v.x * s, v.y * s, v.z * s};
    }

    rdVector3 xyz(const rdVector4 &v) {
        return {v.x, v.y, v.z};
    }

    void set_xyz(rdVector4 &v, const rdVector3 &x) {
        v.x = x.x;
        v.y = x.y;
        v.z = x.z;
    }

    Xform to_xform(const rdMatrix34 &m) {
        return {{m.rvec, m.lvec, m.uvec}, m.scale};
    }

    Xform to_xform(const rdMatrix44 &m) {
        return {{xyz(m.vA), xyz(m.vB), xyz(m.vC)}, xyz(m.vD)};
    }

    void write_xform(rdMatrix34 &m, const Xform &x) {
        m.rvec = x.axes[0];
        m.lvec = x.axes[1];
        m.uvec = x.axes[2];
        m.scale = x.pos;
    }

    // Keeps the w column.
    void write_xform(rdMatrix44 &m, const Xform &x) {
        set_xyz(m.vA, x.axes[0]);
        set_xyz(m.vB, x.axes[1]);
        set_xyz(m.vC, x.axes[2]);
        set_xyz(m.vD, x.pos);
    }

    bool same(const Xform &a, const Xform &b) {
        return memcmp(&a, &b, sizeof(Xform)) == 0;
    }

    // An axis that is zero in both poses is a degenerate (flattened) node, not a teleport; one that
    // appears or vanishes between them is a show / hide.
    bool is_snap(const Xform &p, const Xform &c, float maxDistance) {
        if (length3(sub3(c.pos, p.pos)) > maxDistance)
            return true;
        for (int i = 0; i < 3; i++) {
            const float lp = length3(p.axes[i]);
            const float lc = length3(c.axes[i]);
            if (lp < 1e-6f && lc < 1e-6f)
                continue;
            if (lp < 1e-6f || lc < 1e-6f)
                return true;
            if (dot3(p.axes[i], c.axes[i]) / (lp * lc) < kSnapMinAxisDot)
                return true;
        }
        return false;
    }

    // Rotation + per-axis scale: unit axes mutually perpendicular. Skewed or flattened matrices (e.g.
    // the binder's scale nodes) aren't, and re-orthogonalizing them would bend the shape.
    bool is_rigid(const Xform &x) {
        rdVector3 u[3];
        for (int i = 0; i < 3; i++) {
            const float len = length3(x.axes[i]);
            if (len < 1e-6f)
                return false;
            u[i] = scale3(x.axes[i], 1.0f / len);
        }
        return fabsf(dot3(u[0], u[1])) < 1e-3f && fabsf(dot3(u[0], u[2])) < 1e-3f &&
               fabsf(dot3(u[1], u[2])) < 1e-3f;
    }

    // p -> c at alpha: extrapolate runs past c, interpolate stops between them. Rigid axes are blended
    // as directions, re-orthogonalized (Gram-Schmidt keeps handedness, so mirrored nodes stay
    // mirrored), then rescaled by the blended axis lengths -- a raw matrix lerp would shear and shrink.
    bool blend(const Xform &p, const Xform &c, float alpha, bool extrapolate, float maxDistance,
               Xform &out) {
        if (is_snap(p, c, maxDistance))
            return false;
        auto lerp = [&](float a, float b) {
            return extrapolate ? b + (b - a) * alpha : a + (b - a) * alpha;
        };
        auto lerp3 = [&](const rdVector3 &a, const rdVector3 &b) {
            return extrapolate ? madd3(b, sub3(b, a), alpha) : madd3(a, sub3(b, a), alpha);
        };
        out.pos = lerp3(p.pos, c.pos);
        if (!is_rigid(p) || !is_rigid(c)) {
            for (int i = 0; i < 3; i++)
                out.axes[i] = lerp3(p.axes[i], c.axes[i]);
            return true;
        }
        float lengths[3];
        for (int i = 0; i < 3; i++) {
            const float lp = length3(p.axes[i]);
            const float lc = length3(c.axes[i]);
            lengths[i] = lerp(lp, lc);
            out.axes[i] = lerp3(scale3(p.axes[i], 1.0f / lp), scale3(c.axes[i], 1.0f / lc));
        }
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < i; j++)
                out.axes[i] = madd3(out.axes[i], out.axes[j], -dot3(out.axes[i], out.axes[j]));
            const float len = length3(out.axes[i]);
            if (len < 1e-6f || lengths[i] <= 0.0f)
                return false;
            out.axes[i] = scale3(out.axes[i], 1.0f / len);
        }
        // Rescale only once all three are orthonormal: the projections above assume unit axes.
        for (int i = 0; i < 3; i++)
            out.axes[i] = scale3(out.axes[i], lengths[i]);
        return true;
    }

    // Applies the rigid offset that takes `from` to `to` (rotation about the origin, then
    // translation) to `pose`, keeping its own axis lengths.
    void retarget(const Xform &from, const Xform &to, Xform &pose) {
        rdVector3 f[3], t[3];
        for (int k = 0; k < 3; k++) {
            const float lf = length3(from.axes[k]), lt = length3(to.axes[k]);
            if (lf < 1e-6f || lt < 1e-6f)
                return;
            f[k] = scale3(from.axes[k], 1.0f / lf);
            t[k] = scale3(to.axes[k], 1.0f / lt);
        }
        for (int i = 0; i < 3; i++) {
            rdVector3 out = {0.0f, 0.0f, 0.0f};
            for (int k = 0; k < 3; k++)
                out = madd3(out, t[k], dot3(pose.axes[i], f[k]));
            pose.axes[i] = out;
        }
        pose.pos = madd3(pose.pos, sub3(to.pos, from.pos), 1.0f);
    }

    struct History {
        Xform prev2;// the capture before prev, for the velocity at curr when extrapolating
        Xform prev;
        Xform curr;
        float spanPrev;// ticks prev2 -> prev
        float span;    // ticks prev -> curr
        int samples;   // consecutive captures held, up to 3
        bool visible;  // node flags_1 visible bit at curr (always true for non-nodes)
        unsigned int seenCapture;
        // What the last frame showed and when (alpha of its capture), to measure the miss when the
        // next tick lands.
        Xform shown;
        float shownAlpha;
        unsigned int shownCapture;
        bool hasShown;
        // The miss being faded out: the offset taking errFrom (this capture's prediction at the
        // moment of the last shown frame, errAt -- a negative alpha) to errTo (what that frame showed).
        bool errPending;
        bool hasErr;
        float errAt;
        Xform errFrom;
        Xform errTo;
    };

    unsigned int s_capture = 0;
    int s_ticksLastCapture = 1;// prev -> curr spans this many ticks
    std::unordered_map<swrModel_Node *, History> s_nodes;
    // Each racer's transform (some camera modes copy it) and the engine / cockpit transforms the HD pod
    // and binder are drawn from, keyed by the matrix itself.
    std::unordered_map<rdMatrix44 *, History> s_matrices;
    // Camera world pose per viewport (swrViewport.unk_mat3). cMan computes it inside the ticks and
    // swrViewport_UpdateCameras only copies it out, so the view steps at the sim rate too.
    std::unordered_map<swrViewport *, History> s_cameras;

    struct NodeRestore {
        swrModel_NodeTransformed *node;
        rdMatrix34 pose;
    };
    struct MatrixRestore {
        rdMatrix44 *matrix;
        rdMatrix44 pose;
    };
    struct CameraRestore {
        swrViewport *viewport;
        rdMatrix44 cameraPose;
        rdMatrix44 modelMatrix;
    };
    std::vector<NodeRestore> s_nodeRestores;
    std::vector<MatrixRestore> s_matrixRestores;
    std::vector<CameraRestore> s_cameraRestores;

    // 2D HUD state swrObjJdge_F3 writes inside the tick and phase 2 only reads: the sprite registry
    // (countdown digits, engine panel, dial frame, minimap markers), the speed dial fill
    // (speedDialPosition1/2, read only by rdProcEntry_Add2DPolygon) and the pod positions the
    // above-pod labels are drawn at. Snapshotted per capture and blended for the render.
    constexpr int kNumSprites = 251;    // swrSprite_array[251]
    constexpr int kNumMapPositions = 20;// player_sprite_positions_on_map[20]
    // A sprite moving further than this in one tick was repurposed or teleported: show it as-is.
    constexpr int kSpriteSnapPixels = 64;
    // Rotations only blend across small steps (the unit isn't pinned down; spins and wraps snap).
    constexpr float kSpriteMaxRotationStep = 45.0f;
    constexpr float kDialMaxStep = 0.5f;// of the 0..1 fill
    struct HudState {
        swrSprite sprites[kNumSprites];
        float dial[2];
        rdVector3 mapPositions[kNumMapPositions];
        HudState &operator=(const HudState &other) {// see Xform
            if (this != &other)
                memcpy(this, &other, sizeof(*this));
            return *this;
        }
    };
    HudState s_hudPrev, s_hudCurr;
    int s_hudSamples = 0;
    bool s_spriteBlended[kNumSprites];
    bool s_dialBlended = false;
    bool s_mapBlended[kNumMapPositions];

    // Per-material colour / alpha the tick writes (fades: smoke, fire, dust, debris). Captured and
    // blended inside the render walk, restored after phase 2. texture_offset is deliberately left
    // alone: particles use it as a flipbook frame select, and blending frames slides the image.
    template<typename T, int N>
    struct ValueHistory {
        T prev[N];
        T curr[N];
        unsigned int seenCapture;
        int samples;
        unsigned int blendedFrame;// s_frame it last got a display value (shared materials)
    };
    unsigned int s_frame = 0;
    std::unordered_map<swrModel_Material *, ValueHistory<uint8_t, 4>> s_colors;
    struct ColorRestore {
        swrModel_Material *material;
        uint8_t color[4];
    };
    std::vector<ColorRestore> s_colorRestores;

    // Keyframed transform animations (types 8 axis-angle / 9 translation / 10 scale: debris, doors,
    // hazards) are re-evaluated at the frame's display time instead of blending their nodes: the
    // keyframes are the exact curve. Animation structs + driven nodes are saved first and restored
    // after phase 2, so the sim never sees it. Flipbook / UV scroll types are frame selects: left as is.
    constexpr uint32_t kAnimTypeMask = 0xf;
    constexpr uint32_t kAnimTypeAxisAngle = 0x8;
    constexpr uint32_t kAnimTypeTranslation = 0x9;
    constexpr uint32_t kAnimTypeScale = 0xa;
    typedef void(__cdecl *anim_fn_t)(swrModel_Animation *);
    struct AnimSave {
        swrModel_Animation *anim;
        swrModel_Animation state;
    };
    struct AnimNodeSave {
        swrModel_NodeTransformed *node;
        rdMatrix34 transform;
        uint16_t flags_3;
    };
    std::vector<AnimSave> s_animSaves;
    std::vector<AnimNodeSave> s_animNodeSaves;
    std::unordered_set<swrModel_Node *> s_animNodes;// excluded from node blending this frame

    // Race-time text entries noted during the tick (swrText_CreateTimeEntry's delta).
    struct TimeEntry {
        int index;// into swrTextEntries1Text
        float seconds;
        int fracScale;
        int fracDigits;
        std::string prefix;
    };
    std::vector<TimeEntry> s_timeTick, s_timePrev, s_timeCurr;
    bool s_inTick = false;
    struct TextRestore {
        int index;
        char text[128];
    };
    std::vector<TextRestore> s_textRestores;
    constexpr int kNumTextEntries = 128;// swrTextEntries1Text[128][128]
    // A clock advanced within this fraction of a tick's real time per tick is running.
    constexpr float kRunningClockTolerance = 0.25f;

    // Per-frame state: set up in phase 1 (smoothing_capture / smoothing_apply), consumed by the
    // render hook, cleared by smoothing_restore after phase 2.
    bool s_frameReady = false;
    float s_framePrediction = 0.0f;
    float s_frameAlpha = 0.0f;// raw fraction of a tick since the last one
    bool s_pendingNodeCapture = false;
    std::vector<swrModel_Node *> s_rootsThisFrame;

    template<typename Key>
    void record(std::unordered_map<Key, History> &map, Key key, const Xform &pose,
                bool visible = true) {
        History &h = map[key];
        if (h.seenCapture == s_capture && h.seenCapture != 0)
            return;// reached twice this capture (shared subtree): it already holds the display pose
        // A node shown again after being hidden (a pooled particle respawning) starts fresh rather
        // than blending in from wherever it was parked.
        const bool continuous = h.seenCapture + 1 == s_capture && (h.visible || !visible);
        h.visible = visible;
        if (continuous) {
            h.prev2 = h.prev;
            h.prev = h.curr;
            h.spanPrev = h.span;
            h.samples = h.samples < 3 ? h.samples + 1 : 3;
        } else {
            h.prev2 = pose;
            h.prev = pose;
            h.spanPrev = 1.0f;
            h.samples = 1;
        }
        h.span = (float) s_ticksLastCapture;
        h.curr = pose;
        h.seenCapture = s_capture;
        h.errPending = continuous && h.hasShown && h.shownCapture + 1 == s_capture;
        h.hasErr = false;
        if (h.errPending) {
            h.errTo = h.shown;
            h.errAt = h.shownAlpha - (float) s_ticksLastCapture;
        }
    }

    // Linear extrapolation from the velocity AT curr: the slope at t = 0 of the parabola through
    // prev2 (t = -(n1 + n2)), prev (t = -n2) and curr (t = 0), in units per tick. (curr - prev) alone is
    // the velocity half a tick ago, so it lags every acceleration and turn and resets each tick.
    float velocity_at_curr(float pp, float p, float c, float n1, float n2) {
        return c * (2.0f * n2 + n1) / (n2 * (n1 + n2)) - p * (n1 + n2) / (n1 * n2) +
               pp * n2 / (n1 * (n1 + n2));
    }

    bool extrapolate_from_velocity(const History &h, float ticks, Xform &out) {
        if (!is_rigid(h.prev2) || !is_rigid(h.prev) || !is_rigid(h.curr))
            return false;
        const float n1 = h.spanPrev, n2 = h.span;
        auto ext = [&](float pp, float p, float c) {
            return c + velocity_at_curr(pp, p, c, n1, n2) * ticks;
        };
        auto ext3 = [&](const rdVector3 &pp, const rdVector3 &p, const rdVector3 &c) {
            return rdVector3{ext(pp.x, p.x, c.x), ext(pp.y, p.y, c.y), ext(pp.z, p.z, c.z)};
        };
        float lengths[3];
        for (int i = 0; i < 3; i++) {
            const float l2 = length3(h.prev2.axes[i]), l1 = length3(h.prev.axes[i]),
                        l0 = length3(h.curr.axes[i]);
            if (l2 < 1e-6f || l1 < 1e-6f || l0 < 1e-6f)
                return false;
            lengths[i] = ext(l2, l1, l0);
            out.axes[i] =
                ext3(scale3(h.prev2.axes[i], 1.0f / l2), scale3(h.prev.axes[i], 1.0f / l1),
                     scale3(h.curr.axes[i], 1.0f / l0));
        }
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < i; j++)
                out.axes[i] = madd3(out.axes[i], out.axes[j], -dot3(out.axes[i], out.axes[j]));
            const float len = length3(out.axes[i]);
            if (len < 1e-6f || lengths[i] <= 0.0f)
                return false;
            out.axes[i] = scale3(out.axes[i], 1.0f / len);
        }
        for (int i = 0; i < 3; i++)
            out.axes[i] = scale3(out.axes[i], lengths[i]);
        out.pos = ext3(h.prev2.pos, h.prev.pos, h.curr.pos);
        return true;
    }

    // Pooled particles get reused (a dust puff respawns, a smoke particle's phase wraps back to its
    // spawn point) without being hidden first: the node becomes a different particle. That shows up
    // as a step far bigger than the one before it; blending into it would draw a streak.
    bool is_respawn_jump(const History &h) {
        if (h.samples < 3)
            return false;
        const float step = length3(sub3(h.curr.pos, h.prev.pos)) / h.span;
        const float before = length3(sub3(h.prev.pos, h.prev2.pos)) / h.spanPrev;
        return step > kRespawnJumpRatio * before + kRespawnJumpFloor;
    }

    // The pose `rawAlpha` ticks after the last one, shown (1 - prediction) ticks behind it: behind
    // curr it interpolates prev -> curr (which may span several ticks), past curr it extrapolates.
    Xform predict(const History &h, float rawAlpha, bool &snapped) {
        snapped = false;
        if (same(h.prev, h.curr))
            return h.curr;
        if (is_respawn_jump(h)) {
            snapped = true;
            return h.curr;
        }
        const float ticksPastCurr = rawAlpha - (1.0f - s_framePrediction);
        const bool ahead = ticksPastCurr > 0.0f;
        Xform out;
        if (ahead && h.samples >= 3 &&
            !is_snap(h.prev2, h.prev, kSnapDistancePerTick * h.spanPrev) &&
            !is_snap(h.prev, h.curr, kSnapDistancePerTick * h.span) &&
            extrapolate_from_velocity(h, ticksPastCurr, out))
            return out;
        const float along = ahead ? ticksPastCurr / h.span : 1.0f + ticksPastCurr / h.span;
        const float maxDistance = kSnapDistancePerTick * h.span;
        if (blend(h.prev, h.curr, along, ahead, maxDistance, out))
            return out;
        // Orientation jumped (an axis flipped or appeared) but the node didn't teleport: show this
        // tick's orientation at the smoothed position. A frame whose free axes spin around a pinned
        // one (the binder) would otherwise sit at the tick pose and detach from the parts around it.
        if (length3(sub3(h.curr.pos, h.prev.pos)) <= maxDistance) {
            out = h.curr;
            out.pos = ahead ? madd3(h.curr.pos, sub3(h.curr.pos, h.prev.pos), along)
                            : madd3(h.prev.pos, sub3(h.curr.pos, h.prev.pos), along);
            return out;
        }
        snapped = true;
        return h.curr;
    }

    // This frame's display pose for `h`, with the last tick's miss faded out on top.
    Xform display_pose(History &h) {
        bool snapped;
        const Xform pred = predict(h, s_frameAlpha, snapped);
        // Interpolation is already continuous across a tick; only the predicted part misses.
        if (snapped || s_framePrediction <= 0.0f) {
            h.errPending = false;
            h.hasErr = false;
        }
        if (h.errPending) {
            bool snappedThen;
            h.errFrom = predict(h, h.errAt, snappedThen);
            h.hasErr = !snappedThen && !is_snap(h.errFrom, h.errTo, kSnapDistancePerTick);
            h.errPending = false;
        }
        Xform display = pred;
        if (h.hasErr) {
            Xform withErr = pred;
            retarget(h.errFrom, h.errTo, withErr);
            Xform faded;
            const float remaining = expf(-kErrorDecayPerTick * (s_frameAlpha - h.errAt));
            if (blend(pred, withErr, remaining, false, kSnapDistancePerTick, faded))
                display = faded;
        }
        h.shown = display;
        h.shownAlpha = s_frameAlpha;
        h.shownCapture = s_capture;
        h.hasShown = true;
        return display;
    }

    // A pose that no longer matches the last capture was rewritten at render cadence: leave it alone
    // rather than blending stale history over it.
    template<typename Key, typename Matrix>
    bool smoothed_pose(std::unordered_map<Key, History> &map, Key key, const Matrix &live,
                       Xform &out) {
        auto it = map.find(key);
        if (it == map.end() || it->second.seenCapture != s_capture)
            return false;
        History &h = it->second;
        if (!same(to_xform(live), h.curr)) {
            h.hasShown = false;
            return false;
        }
        out = display_pose(h);
        return !same(out, h.curr);
    }

    // NODE_TRANSFORMED_COMPUTED is rebuilt at render time from the camera, so only 0xD064/0xD065
    // carry a tick-written matrix. Mesh groups list meshes, not child nodes.
    bool is_known_node_type(uint32_t type) {
        switch (type) {
            case NODE_MESH_GROUP:
            case NODE_BASIC:
            case NODE_SELECTOR:
            case NODE_LOD_SELECTOR:
            case NODE_TRANSFORMED:
            case NODE_TRANSFORMED_WITH_PIVOT:
            case NODE_TRANSFORMED_COMPUTED:
                return true;
            default:
                return false;
        }
    }

    // One value at the frame's display time, same mapping as predict(): behind curr it interpolates
    // prev -> curr, past it it extrapolates.
    float hud_blend(float p, float c) {
        const float span = (float) s_ticksLastCapture;
        const float ticksPastCurr = s_frameAlpha - (1.0f - s_framePrediction);
        if (ticksPastCurr > 0.0f)
            return c + (c - p) * (ticksPastCurr / span);
        return p + (c - p) * (1.0f + ticksPastCurr / span);
    }

    uint8_t hud_blend_byte(uint8_t p, uint8_t c) {
        const float v = hud_blend((float) p, (float) c);
        return (uint8_t) (v < 0.0f ? 0.0f : v > 255.0f ? 255.0f : v + 0.5f);
    }

    short hud_blend_short(short p, short c) {
        return (short) lroundf(hud_blend((float) p, (float) c));
    }

    template<typename T, int N>
    void record_values(ValueHistory<T, N> &h, const T *live) {
        if (h.seenCapture == s_capture && h.seenCapture != 0)
            return;// shared material, already handled this capture
        const bool continuous = h.seenCapture + 1 == s_capture;
        memcpy(h.prev, continuous ? h.curr : live, sizeof(h.prev));
        memcpy(h.curr, live, sizeof(h.curr));
        h.seenCapture = s_capture;
        h.samples = continuous ? 2 : 1;
    }

    void smooth_mesh_materials(swrModel_Node *meshGroup, bool capture) {
        for (uint32_t i = 0; i < meshGroup->num_children; i++) {
            swrModel_Mesh *mesh = meshGroup->children.meshes[i];
            if ((uintptr_t) mesh < kMinValidAddress)
                continue;
            swrModel_MeshMaterial *mm = mesh->mesh_material;
            if ((uintptr_t) mm < kMinValidAddress)
                continue;
            swrModel_Material *mat = mm->material;
            if ((uintptr_t) mat < kMinValidAddress)
                continue;
            ValueHistory<uint8_t, 4> &h = s_colors[mat];
            if (capture)
                record_values(h, mat->primitive_color);
            if (h.blendedFrame == s_frame || h.seenCapture != s_capture || h.samples < 2 ||
                memcmp(mat->primitive_color, h.curr, 4) != 0 || memcmp(h.prev, h.curr, 4) == 0)
                continue;
            h.blendedFrame = s_frame;
            ColorRestore r{mat, {}};
            memcpy(r.color, h.curr, 4);
            s_colorRestores.push_back(r);
            for (int k = 0; k < 4; k++)
                mat->primitive_color[k] = hud_blend_byte(h.prev[k], h.curr[k]);
        }
    }

    void walk_tree(swrModel_Node *node, int depth, bool capture) {
        if ((uintptr_t) node < kMinValidAddress || depth > kMaxNodeDepth ||
            !is_known_node_type(node->type))
            return;
        if ((node->type == NODE_TRANSFORMED || node->type == NODE_TRANSFORMED_WITH_PIVOT) &&
            s_animNodes.count(node) == 0) {
            swrModel_NodeTransformed *tn = (swrModel_NodeTransformed *) node;
            if (capture)
                record(s_nodes, node, to_xform(tn->transform),
                       (node->flags_1 & kNodeFlagVisible) != 0);
            Xform display;
            if (smoothed_pose(s_nodes, node, tn->transform, display)) {
                s_nodeRestores.push_back({tn, tn->transform});
                write_xform(tn->transform, display);
                swr_fixedTimestep_smoothedNodes++;
            }
        }
        if (node->type == NODE_MESH_GROUP) {
            smooth_mesh_materials(node, capture);
            return;
        }
        if ((node->type & NODE_HAS_CHILDREN) == 0)
            return;
        for (uint32_t i = 0; i < node->num_children; i++)
            walk_tree(node->children.nodes[i], depth + 1, capture);
    }

    template<typename Key, typename Entry>
    void drop_older_than_last(std::unordered_map<Key, Entry> &map) {
        for (auto it = map.begin(); it != map.end();) {
            if (it->second.seenCapture + 1 < s_capture)
                it = map.erase(it);
            else
                ++it;
        }
    }

    bool is_transform_anim(const swrModel_Animation *anim) {
        const uint32_t type = anim->flags & kAnimTypeMask;
        return (anim->flags & ANIMATION_ENABLED) != 0 && (anim->flags & ANIMATION_DISABLED) == 0 &&
               (type == kAnimTypeAxisAngle || type == kAnimTypeTranslation ||
                type == kAnimTypeScale) &&
               (uintptr_t) anim->node_ptr >= kMinValidAddress;
    }

    // Re-run each transform animation from its tick state by the display offset (negative while
    // interpolating behind the last tick).
    void apply_animations(double dtSeconds) {
        for (int i = 0; i < swrScene_animations_count; i++) {
            swrModel_Animation *anim = swrScene_animations[i];
            if ((uintptr_t) anim < kMinValidAddress || !is_transform_anim(anim))
                continue;
            swrModel_NodeTransformed *node = anim->node_ptr;
            if (s_animNodes.insert(&node->node).second)
                s_animNodeSaves.push_back({node, node->transform, node->node.flags_3});
        }
        if (dtSeconds == 0.0)
            return;
        const double savedDt = swrRace_deltaTimeSecs;
        swrRace_deltaTimeSecs = dtSeconds;
        for (int i = 0; i < swrScene_animations_count; i++) {
            swrModel_Animation *anim = swrScene_animations[i];
            if ((uintptr_t) anim < kMinValidAddress || !is_transform_anim(anim))
                continue;
            s_animSaves.push_back({anim, *anim});
            ((anim_fn_t) swrModel_AnimationUpdateTime_ADDR)(anim);
            switch (anim->flags & kAnimTypeMask) {
                case kAnimTypeAxisAngle:
                    ((anim_fn_t) swrModel_UpdateAxisAngleAnimation_ADDR)(anim);
                    break;
                case kAnimTypeTranslation:
                    ((anim_fn_t) swrModel_UpdateTranslationAnimation_ADDR)(anim);
                    break;
                case kAnimTypeScale:
                    ((anim_fn_t) swrModel_UpdateScaleAnimation_ADDR)(anim);
                    break;
            }
        }
        swrRace_deltaTimeSecs = savedDt;
    }

    // Each entry of the latest tick is paired with the previous capture's entry of the same prefix
    // and order; only a clock that moved by the real time between them is shifted.
    void apply_time_text(float displaySeconds, float tickSeconds) {
        const float elapsed = tickSeconds * (float) s_ticksLastCapture;
        for (size_t i = 0; i < s_timeCurr.size(); i++) {
            const TimeEntry &c = s_timeCurr[i];
            const TimeEntry *p = i < s_timePrev.size() && s_timePrev[i].prefix == c.prefix
                                     ? &s_timePrev[i]
                                     : nullptr;
            if (p == nullptr || c.index < 0 || c.index >= kNumTextEntries ||
                fabsf((c.seconds - p->seconds) - elapsed) > kRunningClockTolerance * elapsed)
                continue;
            char expected[128], shown[128];
            swrText_FormatTimeEntryText(expected, sizeof(expected), c.prefix.c_str(), c.seconds,
                                        c.fracScale, c.fracDigits);
            char *live = swrTextEntries1Text[c.index];
            if (strncmp(live, expected, sizeof(expected)) != 0)
                continue;// not our entry any more
            swrText_FormatTimeEntryText(shown, sizeof(shown), c.prefix.c_str(),
                                        c.seconds + displaySeconds, c.fracScale, c.fracDigits);
            TextRestore r;
            r.index = c.index;
            memcpy(r.text, live, sizeof(r.text));
            s_textRestores.push_back(r);
            strncpy(live, shown, sizeof(r.text) - 1);
            live[sizeof(r.text) - 1] = 0;
        }
    }

    void capture_hud() {
        if (s_hudSamples > 0)
            s_hudPrev = s_hudCurr;
        memcpy(s_hudCurr.sprites, swrSprite_array, sizeof(s_hudCurr.sprites));
        s_hudCurr.dial[0] = speedDialPosition1;
        s_hudCurr.dial[1] = speedDialPosition2;
        memcpy(s_hudCurr.mapPositions, player_sprite_positions_on_map,
               sizeof(s_hudCurr.mapPositions));
        if (s_hudSamples < 2)
            s_hudSamples++;
    }

    // Only state still exactly as the last tick left it is blended, and only between two snapshots
    // of the same element (same texture + flags for a sprite).
    void apply_hud() {
        if (s_hudSamples < 2)
            return;
        for (int i = 0; i < kNumSprites; i++) {
            const swrSprite &p = s_hudPrev.sprites[i];
            const swrSprite &c = s_hudCurr.sprites[i];
            swrSprite &live = swrSprite_array[i];
            if (memcmp(&live, &c, sizeof(c)) != 0 || memcmp(&p, &c, sizeof(c)) == 0 ||
                p.texture != c.texture || p.flags != c.flags ||
                abs(c.x - p.x) > kSpriteSnapPixels || abs(c.y - p.y) > kSpriteSnapPixels)
                continue;
            live.x = hud_blend_short(p.x, c.x);
            live.y = hud_blend_short(p.y, c.y);
            live.width = hud_blend(p.width, c.width);
            live.height = hud_blend(p.height, c.height);
            if (fabsf(c.rotation_angle - p.rotation_angle) < kSpriteMaxRotationStep)
                live.rotation_angle = hud_blend(p.rotation_angle, c.rotation_angle);
            live.r = hud_blend_byte(p.r, c.r);
            live.g = hud_blend_byte(p.g, c.g);
            live.b = hud_blend_byte(p.b, c.b);
            live.a = hud_blend_byte(p.a, c.a);
            s_spriteBlended[i] = true;
        }
        // The fill is forced to 1 while boosting and the heat bar is only written then, so a big step
        // is a mode switch, not motion.
        if (speedDialPosition1 == s_hudCurr.dial[0] && speedDialPosition2 == s_hudCurr.dial[1]) {
            for (int i = 0; i < 2; i++) {
                const float p = s_hudPrev.dial[i], c = s_hudCurr.dial[i];
                const float v = fabsf(c - p) > kDialMaxStep ? c : hud_blend(p, c);
                (i == 0 ? speedDialPosition1 : speedDialPosition2) = v < 0.0f ? 0.0f : v;
            }
            s_dialBlended = true;
        }
        for (int i = 0; i < kNumMapPositions; i++) {
            const rdVector3 &p = s_hudPrev.mapPositions[i];
            const rdVector3 &c = s_hudCurr.mapPositions[i];
            rdVector3 &live = player_sprite_positions_on_map[i];
            if (memcmp(&live, &c, sizeof(c)) != 0 ||
                length3(sub3(c, p)) > kSnapDistancePerTick * (float) s_ticksLastCapture)
                continue;
            live = {hud_blend(p.x, c.x), hud_blend(p.y, c.y), hud_blend(p.z, c.z)};
            s_mapBlended[i] = true;
        }
    }

    void restore_poses() {
        for (auto it = s_animNodeSaves.rbegin(); it != s_animNodeSaves.rend(); ++it) {
            it->node->transform = it->transform;
            it->node->node.flags_3 = it->flags_3;
        }
        for (const AnimSave &a: s_animSaves)
            *a.anim = a.state;
        for (const TextRestore &r: s_textRestores)
            memcpy(swrTextEntries1Text[r.index], r.text, sizeof(r.text));
        for (const NodeRestore &r: s_nodeRestores)
            r.node->transform = r.pose;
        for (const MatrixRestore &r: s_matrixRestores)
            *r.matrix = r.pose;
        for (const CameraRestore &r: s_cameraRestores) {
            r.viewport->unk_mat3 = r.cameraPose;
            r.viewport->model_matrix = r.modelMatrix;
        }
        for (const ColorRestore &r: s_colorRestores)
            memcpy(r.material->primitive_color, r.color, 4);
        for (int i = 0; i < kNumSprites; i++) {
            if (s_spriteBlended[i])
                swrSprite_array[i] = s_hudCurr.sprites[i];
            s_spriteBlended[i] = false;
        }
        if (s_dialBlended) {
            speedDialPosition1 = s_hudCurr.dial[0];
            speedDialPosition2 = s_hudCurr.dial[1];
            s_dialBlended = false;
        }
        for (int i = 0; i < kNumMapPositions; i++) {
            if (s_mapBlended[i])
                player_sprite_positions_on_map[i] = s_hudCurr.mapPositions[i];
            s_mapBlended[i] = false;
        }
        s_animNodeSaves.clear();
        s_animSaves.clear();
        s_animNodes.clear();
        s_textRestores.clear();
        s_nodeRestores.clear();
        s_matrixRestores.clear();
        s_cameraRestores.clear();
        s_colorRestores.clear();
    }
}// namespace

void smoothing_tick_begin() {
    s_timeTick.clear();
    s_inTick = true;
}

void smoothing_note_time_entry(int index, float seconds, int fracScale, int fracDigits,
                               const char *screenText) {
    if (s_inTick)
        s_timeTick.push_back({index, seconds, fracScale, fracDigits, screenText ? screenText : ""});
}

void smoothing_capture(int ticks) {
    s_inTick = false;
    s_timePrev = std::move(s_timeCurr);
    s_timeCurr = std::move(s_timeTick);
    s_timeTick.clear();
    s_capture++;
    s_ticksLastCapture = ticks > 0 ? ticks : 1;
    s_pendingNodeCapture = true;
    const int racers = swrEvent_GetEventCount(kEventTest);
    for (int i = 0; i < racers; i++) {
        swrRace *racer = (swrRace *) swrEvent_GetItem(kEventTest, i);
        if (racer == nullptr)
            continue;
        rdMatrix44 *const parts[] = {&racer->transform,  &racer->engineXfR,  &racer->engineXfL,
                                     &racer->engineXfR2, &racer->engineXfL2, &racer->cockpitXf};
        for (rdMatrix44 *m: parts)
            record(s_matrices, m, to_xform(*m));
    }
    capture_hud();
    // Node / material keys are only compared, never dereferenced, outside a live walk, so stale ones
    // are safe to keep until here.
    drop_older_than_last(s_nodes);
    drop_older_than_last(s_matrices);
    drop_older_than_last(s_colors);
}

void smoothing_apply(float alpha) {
    restore_poses();
    swr_fixedTimestep_smoothedNodes = 0;
    s_frame++;
    s_frameReady = swr_fixedTimestepSmoothing;
    if (!s_frameReady)
        return;
    s_framePrediction = swr_fixedTimestepPrediction < 0.0f   ? 0.0f
                        : swr_fixedTimestepPrediction > 1.0f ? 1.0f
                                                             : swr_fixedTimestepPrediction;
    s_frameAlpha = alpha;

    for (auto &[m, h]: s_matrices) {
        Xform display;
        if (!smoothed_pose(s_matrices, m, *m, display))
            continue;
        s_matrixRestores.push_back({m, *m});
        write_xform(*m, display);
        swr_fixedTimestep_smoothedNodes++;
    }
    apply_hud();
    const float hz = swr_fixedTimestepHz > 1.0f ? swr_fixedTimestepHz : 1.0f;
    const float displaySeconds = (alpha - (1.0f - s_framePrediction)) / hz;
    apply_animations(displaySeconds);
    apply_time_text(displaySeconds, 1.0f / hz);
}

void smoothing_apply_cameras() {
    for (int i = 0; i < kNumViewports; i++) {
        swrViewport *vp = &swrViewport_array[i];
        if (s_pendingNodeCapture)
            record(s_cameras, vp, to_xform(vp->unk_mat3));
        if (!s_frameReady)
            continue;
        auto it = s_cameras.find(vp);
        if (it == s_cameras.end() || it->second.seenCapture != s_capture)
            continue;
        History &h = it->second;
        const Xform target = display_pose(h);
        if (same(target, h.curr))
            continue;
        // The camera is rebuilt every frame and can differ from the tick pose by per-frame work, so
        // move this frame's camera by the tick -> display offset rather than replacing it.
        Xform shown = to_xform(vp->unk_mat3);
        retarget(h.curr, target, shown);
        rdMatrix44 display = vp->unk_mat3;
        write_xform(display, shown);
        s_cameraRestores.push_back({vp, vp->unk_mat3, vp->model_matrix});
        // Through the game's setter so model_matrix (= unk_mat1 * unk_mat3) stays consistent.
        ((swrViewport_SetMat3_t) swrViewport_SetMat3_ADDR)(vp, &display);
        swr_fixedTimestep_smoothedNodes++;
    }
}

void smoothing_render_root(swrModel_Node *root) {
    if (!s_frameReady || root == nullptr)
        return;
    for (swrModel_Node *seen: s_rootsThisFrame)
        if (seen == root)
            return;
    s_rootsThisFrame.push_back(root);
    walk_tree(root, 0, s_pendingNodeCapture);
}

void smoothing_restore() {
    restore_poses();
    s_rootsThisFrame.clear();
    s_pendingNodeCapture = false;
    s_frameReady = false;
}

void smoothing_reset() {
    smoothing_restore();
    s_nodes.clear();
    s_matrices.clear();
    s_cameras.clear();
    s_colors.clear();
    s_hudSamples = 0;
    s_inTick = false;
    s_timeTick.clear();
    s_timePrev.clear();
    s_timeCurr.clear();
    swr_fixedTimestep_smoothedNodes = 0;
}
