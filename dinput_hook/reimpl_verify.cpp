#include "reimpl_verify.h"

#include <windows.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
#include <General/stdMath.h>
#include <General/utils.h>
#include <General/stdFnames.h>
#include <General/stdHashTable.h>
#include <Main/swrControl.h>
#include <Primitives/rdMath.h>
#include <Primitives/rdMatrix.h>
#include <Primitives/rdVector.h>
#include <Swr/swrEvent.h>
#include <Swr/swrModel.h>
#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
#include <Swr/swrSound.h>
#include <globals.h>
#include <hook_mode.h>
}

#define REIMPL_VERIFY_LOG_FILE "reimpl_verify.log"

#define VERIFY_ITERATIONS 20000

namespace {

    FILE *verify_log = nullptr;

    int cases_run = 0;
    int cases_passed = 0;
    int cases_skipped = 0;

    // Deterministic, so a reported failing input can be reproduced.
    uint32_t rng_state = 0x13579bdfu;

    uint32_t next_u32() {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 17;
        rng_state ^= rng_state << 5;
        return rng_state;
    }

    float next_float(float lo, float hi) {
        const float unit = (float) (next_u32() >> 8) / (float) (1u << 24);
        return lo + (hi - lo) * unit;
    }

    // Values that break range-reduction and clamping: domain edges, the branch constants in
    // stdMath's polynomial approximations, and the sign boundaries.
    const float interesting[] = {
        0.0f,      -0.0f,      1.0f,       -1.0f,       0.5f,   -0.5f,   0.999999f, -0.999999f,
        1.000001f, -1.000001f, 0.7071068f, -0.7071068f, 0.001f, -0.001f, 0.0001f,   -0.0001f,
        90.0f,     -90.0f,     180.0f,     -180.0f,     270.0f, 360.0f,  -360.0f,   720.0f,
        -720.0f,   1e-20f,     -1e-20f,    1e20f,       -1e20f,
    };
    const int interesting_count = (int) (sizeof(interesting) / sizeof(interesting[0]));

    // Interesting values first, then random samples. An interesting value outside [lo, hi] is
    // SKIPPED, not forced through -- out-of-domain failures say nothing about the inputs the game
    // can actually generate. Widen the caller's range to pin down out-of-domain behaviour.
    float sample(int i, float lo, float hi) {
        if (i < interesting_count) {
            const float v = interesting[i];
            if (v >= lo && v <= hi)
                return v;
        }
        return next_float(lo, hi);
    }

    struct Stats {
        const char *name;
        int total;
        int exact;
        int tolerated;
        int mismatch;
        int worst_ulp;
        char first_fail[256];
    };

    void stats_init(Stats &s, const char *name) {
        s.name = name;
        s.total = 0;
        s.exact = 0;
        s.tolerated = 0;
        s.mismatch = 0;
        s.worst_ulp = 0;
        s.first_fail[0] = '\0';
    }

    // Same-sign IEEE-754 bit patterns are monotonic, so subtracting them counts ULPs.
    int ulp_diff(float a, float b) {
        if (a == b)
            return 0;
        if (std::isnan(a) && std::isnan(b))
            return 0;
        if (std::isnan(a) != std::isnan(b))
            return INT32_MAX;

        int32_t ia, ib;
        std::memcpy(&ia, &a, sizeof(ia));
        std::memcpy(&ib, &b, sizeof(ib));
        if ((ia < 0) != (ib < 0))
            return INT32_MAX;

        const int64_t d = (int64_t) ia - (int64_t) ib;
        const int64_t abs_d = d < 0 ? -d : d;
        return abs_d > INT32_MAX ? INT32_MAX : (int) abs_d;
    }

    // `tolerance` is a ULP budget. Every case currently passes at 0 (bit-identical to retail);
    // widening one to turn a case green hides a defect -- every divergence investigated so far was
    // a real bug, not unavoidable rounding.
    void record(Stats &s, float ours, float retail, int tolerance, const char *input_desc) {
        s.total++;
        const int ulp = ulp_diff(ours, retail);

        if (ulp == 0) {
            s.exact++;
            return;
        }
        if (ulp > s.worst_ulp)
            s.worst_ulp = ulp;
        if (ulp <= tolerance) {
            s.tolerated++;
            return;
        }
        s.mismatch++;
        if (s.first_fail[0] == '\0') {
            std::snprintf(s.first_fail, sizeof(s.first_fail),
                          "%s -> ours=%.9g (0x%08x) retail=%.9g (0x%08x) ulp=%d", input_desc, ours,
                          *(const uint32_t *) &ours, retail, *(const uint32_t *) &retail, ulp);
        }
    }

    void record_int(Stats &s, int ours, int retail, const char *input_desc) {
        s.total++;
        if (ours == retail) {
            s.exact++;
            return;
        }
        s.mismatch++;
        if (s.first_fail[0] == '\0') {
            std::snprintf(s.first_fail, sizeof(s.first_fail), "%s -> ours=%d retail=%d", input_desc,
                          ours, retail);
        }
    }

    void report(const Stats &s) {
        const bool passed = s.mismatch == 0;
        cases_run++;
        if (passed)
            cases_passed++;

        std::fprintf(verify_log, "  %-36s %-6s %6d cases", s.name, passed ? "PASS" : "FAIL",
                     s.total);
        if (s.tolerated > 0)
            std::fprintf(verify_log, ", %d within tolerance", s.tolerated);
        if (s.worst_ulp > 0)
            std::fprintf(verify_log, ", worst %d ulp", s.worst_ulp);
        if (!passed)
            std::fprintf(verify_log, ", %d MISMATCH\n    first: %s", s.mismatch, s.first_fail);
        std::fprintf(verify_log, "\n");
        std::fflush(verify_log);
    }

    // Detours rewrites a target's prologue with a jump, so if the delta layer forward-hooked this
    // function, hook_retail_ptr() reaches the replacement rather than retail code.
    // LIMITATION: only the entry of the function under test is inspected, not its callees. A clean
    // prologue can still call inward to something the delta replaced (rdMatrix_PreRotate34 reaches
    // rdMatrix_PreMultiply34 that way), so such a case compares a hybrid. Catching that needs the
    // call graph.
    bool retail_entry_redirected(const uint8_t *entry) {
        if (entry[0] == 0xe9 || entry[0] == 0xeb)// jmp rel32 / rel8
            return true;
        if (entry[0] == 0xff && entry[1] == 0x25)// jmp dword ptr [mem]
            return true;
        return false;
    }

    // Both bodies must be reachable and be the ones we mean: our symbol detoured to retail (any
    // mode but `both`) compares retail against itself, and retail detoured to a delta compares the
    // delta. Both would pass while proving nothing.
    bool testable(const char *name, uint32_t retail_addr) {
        if (hook_mode_for(name) != HOOK_MODE_BOTH) {
            cases_skipped++;
            std::fprintf(verify_log, "  %-36s SKIP   not in `both` mode (add `both %s` to %s)\n",
                         name, name, HOOK_MODE_CONFIG_FILE);
            std::fflush(verify_log);
            return false;
        }
        if (retail_entry_redirected(hook_retail_ptr(retail_addr))) {
            cases_skipped++;
            std::fprintf(verify_log,
                         "  %-36s SKIP   retail entry is hooked by the delta layer, so there is no "
                         "original body left to compare against\n",
                         name);
            std::fflush(verify_log);
            return false;
        }
        return true;
    }

    using F_f = float (*)(float);
    using F_ff = float (*)(float, float);
    using I_f = int (*)(float);
    using F_fi = float (*)(float, int);
    using V_fpp = void (*)(float, float *, float *);
    using V_pffff = void (*)(float *, float, float, float, float);
    using V_pffii = void (*)(int *, float, float, int, int);

    // rdVector3 shapes: `out` is always the first parameter and the inputs are const, so these
    // drive the same way as the scalar cases.
    using F_v = float (*)(const rdVector3 *);
    using F_vv = float (*)(const rdVector3 *, const rdVector3 *);
    using F_vacc = float (*)(rdVector3 *);
    using V_vvv = void (*)(rdVector3 *, const rdVector3 *, const rdVector3 *);
    using V_vfv = void (*)(rdVector3 *, float, const rdVector3 *);
    using V_vvfv = void (*)(rdVector3 *, const rdVector3 *, float, const rdVector3 *);

    rdVector3 random_vec3(int i, float lo, float hi) {
        rdVector3 v;
        v.x = sample(i, lo, hi);
        v.y = sample(i + 3, lo, hi);
        v.z = sample(i + 11, lo, hi);
        return v;
    }

    // rdVector3/4 and rdMatrix34/44 are all runs of floats, so one element-by-element compare
    // covers every structured output; the index is reported so a failure names the component.
    void record_floats(Stats &s, const float *ours, const float *retail, int count, int tolerance,
                       const char *input_desc) {
        for (int k = 0; k < count; k++) {
            char desc[240];
            std::snprintf(desc, sizeof(desc), "%s[%d]", input_desc, k);
            record(s, ours[k], retail[k], tolerance, desc);
        }
    }

    void record_vec3(Stats &s, const rdVector3 &ours, const rdVector3 &retail, int tolerance,
                     const char *input_desc) {
        record_floats(s, &ours.x, &retail.x, 3, tolerance, input_desc);
    }

    void describe_vec3(char *out, size_t n, const rdVector3 &a) {
        std::snprintf(out, n, "(%.9g, %.9g, %.9g)", a.x, a.y, a.z);
    }

    void run_f_v(const char *name, uint32_t retail_addr, F_v ours, float lo, float hi,
                 int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const F_v retail = (F_v) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 a = random_vec3(i, lo, hi);
            char desc[96];
            describe_vec3(desc, sizeof(desc), a);
            record(s, ours(&a), retail(&a), tolerance, desc);
        }
        report(s);
    }

    void run_f_vv(const char *name, uint32_t retail_addr, F_vv ours, float lo, float hi,
                  int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const F_vv retail = (F_vv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 a = random_vec3(i, lo, hi);
            const rdVector3 b = random_vec3(i + 23, lo, hi);
            char desc[200];
            char sa[96], sb[96];
            describe_vec3(sa, sizeof(sa), a);
            describe_vec3(sb, sizeof(sb), b);
            std::snprintf(desc, sizeof(desc), "%s, %s", sa, sb);
            record(s, ours(&a, &b), retail(&a, &b), tolerance, desc);
        }
        report(s);
    }

    // In-place: the return value AND the mutated vector both matter.
    void run_f_vacc(const char *name, uint32_t retail_addr, F_vacc ours, float lo, float hi,
                    int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const F_vacc retail = (F_vacc) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 seed = random_vec3(i, lo, hi);
            rdVector3 our_v = seed;
            rdVector3 ret_v = seed;
            const float our_r = ours(&our_v);
            const float ret_r = retail(&ret_v);

            char desc[112];
            describe_vec3(desc, sizeof(desc), seed);
            std::strncat(desc, "[ret]", sizeof(desc) - std::strlen(desc) - 1);
            record(s, our_r, ret_r, tolerance, desc);

            describe_vec3(desc, sizeof(desc), seed);
            record_vec3(s, our_v, ret_v, tolerance, desc);
        }
        report(s);
    }

    void run_v_vvv(const char *name, uint32_t retail_addr, V_vvv ours, float lo, float hi,
                   int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_vvv retail = (V_vvv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 a = random_vec3(i, lo, hi);
            const rdVector3 b = random_vec3(i + 23, lo, hi);
            rdVector3 our_out = {-12345.0f, -12345.0f, -12345.0f};
            rdVector3 ret_out = our_out;
            ours(&our_out, &a, &b);
            retail(&ret_out, &a, &b);

            char desc[200], sa[96], sb[96];
            describe_vec3(sa, sizeof(sa), a);
            describe_vec3(sb, sizeof(sb), b);
            std::snprintf(desc, sizeof(desc), "%s, %s", sa, sb);
            record_vec3(s, our_out, ret_out, tolerance, desc);
        }
        report(s);
    }

    void run_v_vfv(const char *name, uint32_t retail_addr, V_vfv ours, float lo, float hi,
                   int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_vfv retail = (V_vfv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float scale = sample(i, -100.0f, 100.0f);
            const rdVector3 a = random_vec3(i + 23, lo, hi);
            rdVector3 our_out = {-12345.0f, -12345.0f, -12345.0f};
            rdVector3 ret_out = our_out;
            ours(&our_out, scale, &a);
            retail(&ret_out, scale, &a);

            char desc[160], sa[96];
            describe_vec3(sa, sizeof(sa), a);
            std::snprintf(desc, sizeof(desc), "%.9g * %s", scale, sa);
            record_vec3(s, our_out, ret_out, tolerance, desc);
        }
        report(s);
    }

    using V_v4vvv = void (*)(rdVector4 *, rdVector3 *, rdVector3 *, rdVector3 *);
    using V_vvvv = void (*)(rdVector3 *, rdVector3 *, rdVector3 *, rdVector3 *);
    using F_vvv = float (*)(rdVector3 *, rdVector3 *, rdVector3 *);
    using I_vvv = int (*)(rdVector3 *, rdVector3 *, rdVector3 *);
    using V_vf_acc = void (*)(rdVector3 *, float);
    using V_slerp = void (*)(const rdVector4 *, const rdVector4 *, float, rdVector4 *);
    using V_v4v4 = void (*)(rdVector4 *, const rdVector4 *);

    rdVector4 random_vec4(int i, float lo, float hi) {
        rdVector4 v;
        v.x = sample(i, lo, hi);
        v.y = sample(i + 3, lo, hi);
        v.z = sample(i + 11, lo, hi);
        v.w = sample(i + 17, lo, hi);
        return v;
    }

    void describe3(char *out, size_t n, const rdVector3 &a, const rdVector3 &b,
                   const rdVector3 &c) {
        char sa[96], sb[96], sc[96];
        describe_vec3(sa, sizeof(sa), a);
        describe_vec3(sb, sizeof(sb), b);
        describe_vec3(sc, sizeof(sc), c);
        std::snprintf(out, n, "%s, %s, %s", sa, sb, sc);
    }

    void run_v4vvv(const char *name, uint32_t retail_addr, V_v4vvv ours, float lo, float hi,
                   int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_v4vvv retail = (V_v4vvv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdVector3 a = random_vec3(i, lo, hi);
            rdVector3 b = random_vec3(i + 23, lo, hi);
            rdVector3 c = random_vec3(i + 41, lo, hi);
            rdVector4 our_out = {-12345.0f, -12345.0f, -12345.0f, -12345.0f};
            rdVector4 ret_out = our_out;
            ours(&our_out, &a, &b, &c);
            retail(&ret_out, &a, &b, &c);

            char desc[304];
            describe3(desc, sizeof(desc), a, b, c);
            record_floats(s, &our_out.x, &ret_out.x, 4, tolerance, desc);
        }
        report(s);
    }

    void run_vvvv(const char *name, uint32_t retail_addr, V_vvvv ours, float lo, float hi,
                  int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_vvvv retail = (V_vvvv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdVector3 a = random_vec3(i, lo, hi);
            rdVector3 b = random_vec3(i + 23, lo, hi);
            rdVector3 c = random_vec3(i + 41, lo, hi);
            rdVector3 our_out = {-12345.0f, -12345.0f, -12345.0f};
            rdVector3 ret_out = our_out;
            ours(&our_out, &a, &b, &c);
            retail(&ret_out, &a, &b, &c);

            char desc[304];
            describe3(desc, sizeof(desc), a, b, c);
            record_vec3(s, our_out, ret_out, tolerance, desc);
        }
        report(s);
    }

    void run_f_vvv(const char *name, uint32_t retail_addr, F_vvv ours, float lo, float hi,
                   int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const F_vvv retail = (F_vvv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdVector3 a = random_vec3(i, lo, hi);
            rdVector3 b = random_vec3(i + 23, lo, hi);
            rdVector3 c = random_vec3(i + 41, lo, hi);
            char desc[304];
            describe3(desc, sizeof(desc), a, b, c);
            record(s, ours(&a, &b, &c), retail(&a, &b, &c), tolerance, desc);
        }
        report(s);
    }

    void run_i_vvv(const char *name, uint32_t retail_addr, I_vvv ours, float lo, float hi) {
        if (!testable(name, retail_addr))
            return;

        const I_vvv retail = (I_vvv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdVector3 a = random_vec3(i, lo, hi);
            rdVector3 b = random_vec3(i + 23, lo, hi);
            // Every third case is collinear, or that branch is essentially never exercised.
            rdVector3 c = (i % 3 == 0)
                              ? rdVector3{a.x + (b.x - a.x) * 2.0f, a.y + (b.y - a.y) * 2.0f,
                                          a.z + (b.z - a.z) * 2.0f}
                              : random_vec3(i + 41, lo, hi);
            char desc[304];
            describe3(desc, sizeof(desc), a, b, c);
            record_int(s, ours(&a, &b, &c), retail(&a, &b, &c), desc);
        }
        report(s);
    }

    void run_v_vf_acc(const char *name, uint32_t retail_addr, V_vf_acc ours, float lo, float hi,
                      int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_vf_acc retail = (V_vf_acc) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 seed = random_vec3(i, lo, hi);
            const float limit = sample(i + 7, -10.0f, 10.0f);
            rdVector3 our_v = seed;
            rdVector3 ret_v = seed;
            ours(&our_v, limit);
            retail(&ret_v, limit);

            char desc[160], sa[96];
            describe_vec3(sa, sizeof(sa), seed);
            std::snprintf(desc, sizeof(desc), "%s, %.9g", sa, limit);
            record_vec3(s, our_v, ret_v, tolerance, desc);
        }
        report(s);
    }

    // Slerp's out-param comes last, unlike the rest.
    void run_slerp(const char *name, uint32_t retail_addr, V_slerp ours, int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_slerp retail = (V_slerp) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            // Unit quaternions: the only input the callers produce, and the only one for which
            // the shortest-arc logic is meaningful.
            rdVector4 a = random_vec4(i, -1.0f, 1.0f);
            rdVector4 b = random_vec4(i + 29, -1.0f, 1.0f);
            const float la = std::sqrt(a.x * a.x + a.y * a.y + a.z * a.z + a.w * a.w);
            const float lb = std::sqrt(b.x * b.x + b.y * b.y + b.z * b.z + b.w * b.w);
            if (la > 1e-6f) {
                a.x /= la;
                a.y /= la;
                a.z /= la;
                a.w /= la;
            }
            if (lb > 1e-6f) {
                b.x /= lb;
                b.y /= lb;
                b.z /= lb;
                b.w /= lb;
            }
            const float t = sample(i + 13, 0.0f, 1.0f);

            rdVector4 our_out = {-12345.0f, -12345.0f, -12345.0f, -12345.0f};
            rdVector4 ret_out = our_out;
            ours(&a, &b, t, &our_out);
            retail(&a, &b, t, &ret_out);

            char desc[256];
            std::snprintf(desc, sizeof(desc),
                          "(%.9g,%.9g,%.9g,%.9g) -> (%.9g,%.9g,%.9g,%.9g) @ t=%.9g", a.x, a.y, a.z,
                          a.w, b.x, b.y, b.z, b.w, t);
            record_floats(s, &our_out.x, &ret_out.x, 4, tolerance, desc);
        }
        report(s);
    }

    void run_v4v4(const char *name, uint32_t retail_addr, V_v4v4 ours, float lo, float hi,
                  int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_v4v4 retail = (V_v4v4) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector4 a = random_vec4(i, lo, hi);
            rdVector4 our_out = {-12345.0f, -12345.0f, -12345.0f, -12345.0f};
            rdVector4 ret_out = our_out;
            ours(&our_out, &a);
            retail(&ret_out, &a);

            char desc[160];
            std::snprintf(desc, sizeof(desc), "(%.9g, %.9g, %.9g, %.9g)", a.x, a.y, a.z, a.w);
            record_floats(s, &our_out.x, &ret_out.x, 4, tolerance, desc);
        }
        report(s);
    }

    using U_si = unsigned int (*)(char *, int);
    using I_i = int (*)(int);

    void run_u_si(const char *name, uint32_t retail_addr, U_si ours) {
        if (!testable(name, retail_addr))
            return;

        const U_si retail = (U_si) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            char buf[24];
            const int len = (int) (next_u32() % (sizeof(buf) - 1));
            for (int k = 0; k < len; k++)
                buf[k] = (char) (0x20 + (next_u32() % 0x5f));// printable ASCII
            buf[len] = '\0';
            // hashSize divides, so it must never be zero.
            const int hash_size = (int) (next_u32() % 1024u) + 1;

            char desc[96];
            std::snprintf(desc, sizeof(desc), "\"%s\", %d", buf, hash_size);
            record_int(s, (int) ours(buf, hash_size), (int) retail(buf, hash_size), desc);
        }
        report(s);
    }

    void run_i_i(const char *name, uint32_t retail_addr, I_i ours, int lo, int hi) {
        if (!testable(name, retail_addr))
            return;

        const I_i retail = (I_i) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const int x = lo + (int) (next_u32() % (unsigned) (hi - lo + 1));
            char desc[48];
            std::snprintf(desc, sizeof(desc), "f(%d)", x);
            record_int(s, ours(x), retail(x), desc);
        }
        report(s);
    }

    using V_m44 = void (*)(rdMatrix44 *);
    using V_m44fff = void (*)(rdMatrix44 *, float, float, float);
    using V_m44ffff = void (*)(rdMatrix44 *, float, float, float, float);
    using V_m44m44 = void (*)(rdMatrix44 *, rdMatrix44 *);
    using V_m44m34 = void (*)(rdMatrix44 *, const rdMatrix34 *);
    using V_m34v = void (*)(rdMatrix34 *, rdVector3 *);
    using V_m44iv = void (*)(rdMatrix44 *, int, rdVector3 *);

    rdMatrix44 random_mat44(int i, float lo, float hi) {
        rdMatrix44 m;
        float *f = &m.vA.x;
        for (int k = 0; k < 16; k++)
            f[k] = sample(i + k * 7, lo, hi);
        return m;
    }

    rdMatrix34 random_mat34(int i, float lo, float hi) {
        rdMatrix34 m;
        float *f = &m.rvec.x;
        for (int k = 0; k < 12; k++)
            f[k] = sample(i + k * 7, lo, hi);
        return m;
    }

    void run_v_m44(const char *name, uint32_t retail_addr, V_m44 ours, int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_m44 retail = (V_m44) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdMatrix44 our_m = random_mat44(i, -100.0f, 100.0f);
            rdMatrix44 ret_m = our_m;
            ours(&our_m);
            retail(&ret_m);
            char desc[32];
            std::snprintf(desc, sizeof(desc), "case %d", i);
            record_floats(s, &our_m.vA.x, &ret_m.vA.x, 16, tolerance, desc);
        }
        report(s);
    }

    void run_v_m44fff(const char *name, uint32_t retail_addr, V_m44fff ours, float lo, float hi,
                      int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_m44fff retail = (V_m44fff) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float a = sample(i, lo, hi);
            const float b = sample(i + 5, lo, hi);
            const float c = sample(i + 9, lo, hi);
            rdMatrix44 our_m = random_mat44(i, -100.0f, 100.0f);
            rdMatrix44 ret_m = our_m;
            ours(&our_m, a, b, c);
            retail(&ret_m, a, b, c);
            char desc[112];
            std::snprintf(desc, sizeof(desc), "(%.9g, %.9g, %.9g)", a, b, c);
            record_floats(s, &our_m.vA.x, &ret_m.vA.x, 16, tolerance, desc);
        }
        report(s);
    }

    void run_v_m44ffff(const char *name, uint32_t retail_addr, V_m44ffff ours, float lo, float hi,
                       int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_m44ffff retail = (V_m44ffff) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float angle = sample(i, -720.0f, 720.0f);
            const float x = sample(i + 5, lo, hi);
            const float y = sample(i + 9, lo, hi);
            const float z = sample(i + 13, lo, hi);
            rdMatrix44 our_m = random_mat44(i, -100.0f, 100.0f);
            rdMatrix44 ret_m = our_m;
            ours(&our_m, angle, x, y, z);
            retail(&ret_m, angle, x, y, z);
            char desc[144];
            std::snprintf(desc, sizeof(desc), "angle=%.9g axis=(%.9g, %.9g, %.9g)", angle, x, y, z);
            record_floats(s, &our_m.vA.x, &ret_m.vA.x, 16, tolerance, desc);
        }
        report(s);
    }

    void run_v_m44m44(const char *name, uint32_t retail_addr, V_m44m44 ours, int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_m44m44 retail = (V_m44m44) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdMatrix44 in = random_mat44(i, -100.0f, 100.0f);
            rdMatrix44 our_out = random_mat44(i + 3, -1.0f, 1.0f);
            rdMatrix44 ret_out = our_out;
            ours(&our_out, &in);
            retail(&ret_out, &in);
            char desc[32];
            std::snprintf(desc, sizeof(desc), "case %d", i);
            record_floats(s, &our_out.vA.x, &ret_out.vA.x, 16, tolerance, desc);
        }
        report(s);
    }

    void run_v_m44m34(const char *name, uint32_t retail_addr, V_m44m34 ours, int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_m44m34 retail = (V_m44m34) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdMatrix34 in = random_mat34(i, -100.0f, 100.0f);
            rdMatrix44 our_out = random_mat44(i + 3, -1.0f, 1.0f);
            rdMatrix44 ret_out = our_out;
            ours(&our_out, &in);
            retail(&ret_out, &in);
            char desc[32];
            std::snprintf(desc, sizeof(desc), "case %d", i);
            record_floats(s, &our_out.vA.x, &ret_out.vA.x, 16, tolerance, desc);
        }
        report(s);
    }

    void run_v_m34v(const char *name, uint32_t retail_addr, V_m34v ours, float lo, float hi,
                    int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_m34v retail = (V_m34v) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdVector3 v = random_vec3(i, lo, hi);
            rdMatrix34 our_m = random_mat34(i + 3, -100.0f, 100.0f);
            rdMatrix34 ret_m = our_m;
            ours(&our_m, &v);
            retail(&ret_m, &v);
            char desc[112];
            describe_vec3(desc, sizeof(desc), v);
            record_floats(s, &our_m.rvec.x, &ret_m.rvec.x, 12, tolerance, desc);
        }
        report(s);
    }

    // Gram-Schmidt into a real rotation: a random rdMatrix34 is not orthonormal, and the
    // angle-extraction path returns NaN for one that is not.
    void orthonormalize34(rdMatrix34 &m) {
        rdVector_Normalize3Acc(&m.rvec);
        const float d = rdVector_Dot3(&m.lvec, &m.rvec);
        m.lvec.x -= m.rvec.x * d;
        m.lvec.y -= m.rvec.y * d;
        m.lvec.z -= m.rvec.z * d;
        if (rdVector_Len3(&m.lvec) < 1e-4f)
            m.lvec = rdVector3{m.rvec.y, -m.rvec.x, m.rvec.z};
        rdVector_Normalize3Acc(&m.lvec);
        rdVector_Cross3(&m.uvec, &m.rvec, &m.lvec);
        rdVector_Normalize3Acc(&m.uvec);
    }

    // rdMatrix_ExtractAngles34 shares the (rdMatrix34*, rdVector3*) shape with the builders but
    // runs the other way, so the VECTOR is the result -- comparing the matrix would always pass.
    void run_v_m34_outv(const char *name, uint32_t retail_addr, V_m34v ours, float lo, float hi,
                        int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_m34v retail = (V_m34v) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdMatrix34 in = random_mat34(i, lo, hi);
            orthonormalize34(in);
            rdVector3 our_out = {-12345.0f, -12345.0f, -12345.0f};
            rdVector3 ret_out = our_out;
            rdMatrix34 our_in = in;
            rdMatrix34 ret_in = in;
            ours(&our_in, &our_out);
            retail(&ret_in, &ret_out);

            char desc[48];
            std::snprintf(desc, sizeof(desc), "case %d", i);
            record_vec3(s, our_out, ret_out, tolerance, desc);
        }
        report(s);
    }

    // Only columns 0..3 are in range for a 4x4.
    void run_v_m44iv(const char *name, uint32_t retail_addr, V_m44iv ours, bool writes_matrix,
                     int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_m44iv retail = (V_m44iv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const int n = (int) (next_u32() % 4u);
            rdVector3 v = random_vec3(i, -100.0f, 100.0f);
            rdMatrix44 our_m = random_mat44(i + 3, -100.0f, 100.0f);
            rdMatrix44 ret_m = our_m;
            rdVector3 our_v = v;
            rdVector3 ret_v = v;
            ours(&our_m, n, &our_v);
            retail(&ret_m, n, &ret_v);

            char desc[128], sv[96];
            describe_vec3(sv, sizeof(sv), v);
            std::snprintf(desc, sizeof(desc), "col %d, %s", n, sv);
            if (writes_matrix)
                record_floats(s, &our_m.vA.x, &ret_m.vA.x, 16, tolerance, desc);
            else
                record_vec3(s, our_v, ret_v, tolerance, desc);
        }
        report(s);
    }

    void run_v_vvfv(const char *name, uint32_t retail_addr, V_vvfv ours, float lo, float hi,
                    int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_vvfv retail = (V_vvfv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 a = random_vec3(i, lo, hi);
            const float scale = sample(i + 5, -100.0f, 100.0f);
            const rdVector3 b = random_vec3(i + 23, lo, hi);
            rdVector3 our_out = {-12345.0f, -12345.0f, -12345.0f};
            rdVector3 ret_out = our_out;
            ours(&our_out, &a, scale, &b);
            retail(&ret_out, &a, scale, &b);

            char desc[224], sa[96], sb[96];
            describe_vec3(sa, sizeof(sa), a);
            describe_vec3(sb, sizeof(sb), b);
            std::snprintf(desc, sizeof(desc), "%s + %.9g * %s", sa, scale, sb);
            record_vec3(s, our_out, ret_out, tolerance, desc);
        }
        report(s);
    }

    void run_f_f(const char *name, uint32_t retail_addr, F_f ours, float lo, float hi,
                 int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const F_f retail = (F_f) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float x = sample(i, lo, hi);
            char desc[64];
            std::snprintf(desc, sizeof(desc), "f(%.9g)", x);
            record(s, ours(x), retail(x), tolerance, desc);
        }
        report(s);
    }

    void run_f_ff(const char *name, uint32_t retail_addr, F_ff ours, float lo, float hi,
                  int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const F_ff retail = (F_ff) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float a = sample(i, lo, hi);
            const float b = sample(i + 7, lo, hi);
            char desc[96];
            std::snprintf(desc, sizeof(desc), "f(%.9g, %.9g)", a, b);
            record(s, ours(a, b), retail(a, b), tolerance, desc);
        }
        report(s);
    }

    void run_i_f(const char *name, uint32_t retail_addr, I_f ours, float lo, float hi) {
        if (!testable(name, retail_addr))
            return;

        const I_f retail = (I_f) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float x = sample(i, lo, hi);
            char desc[64];
            std::snprintf(desc, sizeof(desc), "f(%.9g)", x);
            record_int(s, ours(x), retail(x), desc);
        }
        report(s);
    }

    void run_f_fi(const char *name, uint32_t retail_addr, F_fi ours, float lo, float hi,
                  int max_exp, int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const F_fi retail = (F_fi) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float x = sample(i, lo, hi);
            const int e = (int) (next_u32() % (uint32_t) (max_exp + 1));
            char desc[80];
            std::snprintf(desc, sizeof(desc), "f(%.9g, %d)", x, e);
            record(s, ours(x, e), retail(x, e), tolerance, desc);
        }
        report(s);
    }

    void run_v_fpp(const char *name, uint32_t retail_addr, V_fpp ours, float lo, float hi,
                   int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_fpp retail = (V_fpp) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float x = sample(i, lo, hi);
            // Poison the out-params so a function that fails to write one is caught.
            float our_a = -12345.0f, our_b = -12345.0f;
            float ret_a = -12345.0f, ret_b = -12345.0f;
            ours(x, &our_a, &our_b);
            retail(x, &ret_a, &ret_b);

            char desc[80];
            std::snprintf(desc, sizeof(desc), "f(%.9g)[out0]", x);
            record(s, our_a, ret_a, tolerance, desc);
            std::snprintf(desc, sizeof(desc), "f(%.9g)[out1]", x);
            record(s, our_b, ret_b, tolerance, desc);
        }
        report(s);
    }

    void run_v_pffff(const char *name, uint32_t retail_addr, V_pffff ours, float lo, float hi,
                     int tolerance) {
        if (!testable(name, retail_addr))
            return;

        const V_pffff retail = (V_pffff) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float seed = sample(i, lo, hi);
            const float value = next_float(lo, hi);
            const float multiplier = next_float(-4.0f, 4.0f);
            float min = next_float(lo, hi);
            float max = next_float(lo, hi);
            if (max < min) {
                const float t = min;
                min = max;
                max = t;
            }

            float our_io = seed;
            float ret_io = seed;
            ours(&our_io, value, multiplier, min, max);
            retail(&ret_io, value, multiplier, min, max);

            char desc[176];
            std::snprintf(desc, sizeof(desc), "f(inout=%.9g, %.9g, %.9g, [%.9g, %.9g])", seed,
                          value, multiplier, min, max);
            record(s, our_io, ret_io, tolerance, desc);
        }
        report(s);
    }

    void run_v_pffii(const char *name, uint32_t retail_addr, V_pffii ours) {
        if (!testable(name, retail_addr))
            return;

        const V_pffii retail = (V_pffii) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);

        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const int seed = (int) (next_u32() % 4000u) - 2000;
            // The product accumulates at x87 register precision and only the final sum is
            // truncated, so a scaled add landing either side of an integer is where they diverge.
            const float value = next_float(-2000.0f, 2000.0f);
            const float multiplier = next_float(-4.0f, 4.0f);
            int min = (int) (next_u32() % 2000u) - 1000;
            int max = (int) (next_u32() % 2000u) - 1000;
            if (max < min) {
                const int t = min;
                min = max;
                max = t;
            }

            int our_io = seed;
            int ret_io = seed;
            ours(&our_io, value, multiplier, min, max);
            retail(&ret_io, value, multiplier, min, max);

            char desc[160];
            std::snprintf(desc, sizeof(desc), "f(inout=%d, %.9g, %.9g, [%d, %d])", seed, value,
                          multiplier, min, max);
            record_int(s, our_io, ret_io, desc);
        }
        report(s);
    }

    // The table-driven trig helpers interpolate a quarter wave baked into .data; an empty table
    // would make both sides agree on zero and pass without testing anything.
    bool trig_tables_populated() {
        for (int i = 0; i < 4096; i++) {
            if (stdMath_SinTable[i] != 0.0f)
                return true;
        }
        return false;
    }

    // Game logic reads globals (the frame delta) and racer state, so each case owns the globals
    // it touches and restores them afterwards.

    // Frame deltas the game produces: fixed 60/30 Hz steps, then the spread of a variable rate.
    double sample_delta(int i) {
        static const double fixed[] = {1.0 / 60.0, 1.0 / 30.0, 1.0 / 120.0, 0.0, 0.1};
        if (i < (int) (sizeof(fixed) / sizeof(fixed[0])))
            return fixed[i];
        return next_float(0.001f, 0.1f);
    }

    struct DeltaGuard {
        double saved;
        DeltaGuard() : saved(swrRace_deltaTimeSecs) {}
        ~DeltaGuard() {
            swrRace_deltaTimeSecs = saved;
        }
    };

    // Racer-state cases compare the whole swrRace, so a stray write anywhere in the struct is
    // caught, not only the fields the function is documented to touch.
    void record_racer(Stats &s, const swrRace &ours, const swrRace &retail,
                      const char *input_desc) {
        const uint8_t *a = (const uint8_t *) &ours;
        const uint8_t *b = (const uint8_t *) &retail;
        s.total++;
        for (size_t off = 0; off + 4 <= sizeof(swrRace); off += 4) {
            if (std::memcmp(a + off, b + off, 4) == 0)
                continue;
            s.mismatch++;
            if (s.first_fail[0] == '\0') {
                float fa, fb;
                std::memcpy(&fa, a + off, 4);
                std::memcpy(&fb, b + off, 4);
                std::snprintf(s.first_fail, sizeof(s.first_fail),
                              "%s -> swrRace+0x%04x ours=%.9g (0x%08x) retail=%.9g (0x%08x)",
                              input_desc, (unsigned) off, fa, *(const uint32_t *) (a + off), fb,
                              *(const uint32_t *) (b + off));
            }
            return;
        }
        s.exact++;
    }

    swrRace *racer_pair[2];

    bool alloc_racers() {
        racer_pair[0] = (swrRace *) std::calloc(1, sizeof(swrRace));
        racer_pair[1] = (swrRace *) std::calloc(1, sizeof(swrRace));
        return racer_pair[0] != nullptr && racer_pair[1] != nullptr;
    }

    void free_racers() {
        std::free(racer_pair[0]);
        std::free(racer_pair[1]);
    }

    // A random proper rotation: Gram-Schmidt on random vectors, then a cross product so the
    // basis is right-handed like the pod transforms the game builds.
    void random_rotation(rdMatrix44 &m, int i) {
        rdVector3 a, b, c;
        do {
            a = random_vec3(i, -1.0f, 1.0f);
        } while (a.x * a.x + a.y * a.y + a.z * a.z < 0.01f);
        float l = std::sqrt(a.x * a.x + a.y * a.y + a.z * a.z);
        a.x /= l, a.y /= l, a.z /= l;
        do {
            b = random_vec3(i + 7, -1.0f, 1.0f);
            const float d = a.x * b.x + a.y * b.y + a.z * b.z;
            b.x -= d * a.x, b.y -= d * a.y, b.z -= d * a.z;
        } while (b.x * b.x + b.y * b.y + b.z * b.z < 0.01f);
        l = std::sqrt(b.x * b.x + b.y * b.y + b.z * b.z);
        b.x /= l, b.y /= l, b.z /= l;
        c.x = a.y * b.z - a.z * b.y;
        c.y = a.z * b.x - a.x * b.z;
        c.z = a.x * b.y - a.y * b.x;
        std::memset(&m, 0, sizeof(m));
        m.vA.x = a.x, m.vA.y = a.y, m.vA.z = a.z;
        m.vB.x = b.x, m.vB.y = b.y, m.vB.z = b.z;
        m.vC.x = c.x, m.vC.y = c.y, m.vC.z = c.z;
        m.vD.x = next_float(-5000.0f, 5000.0f);
        m.vD.y = next_float(-5000.0f, 5000.0f);
        m.vD.z = next_float(-500.0f, 500.0f);
        m.vD.w = 1.0f;
    }

    using F_step = float (*)(float, float, float, float, float, float);

    void run_step_toward_clamped() {
        const char *name = "swrMath_StepTowardClamped";
        if (!testable(name, swrMath_StepTowardClamped_ADDR))
            return;
        const F_step retail = (F_step) hook_retail_ptr(swrMath_StepTowardClamped_ADDR);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float value = sample(i, -100.0f, 100.0f);
            const float current = next_float(-100.0f, 100.0f);
            float lo = next_float(-100.0f, 100.0f);
            float hi = next_float(-100.0f, 100.0f);
            if (hi < lo) {
                const float t = lo;
                lo = hi;
                hi = t;
            }
            const float up = next_float(0.0f, 10.0f);
            const float down = next_float(0.0f, 10.0f);
            char desc[160];
            std::snprintf(desc, sizeof(desc), "f(%.9g, %.9g, [%.9g, %.9g], %.9g, %.9g)", value,
                          current, lo, hi, up, down);
            record(s, swrMath_StepTowardClamped(value, current, lo, hi, up, down),
                   retail(value, current, lo, hi, up, down), 0, desc);
        }
        report(s);
    }

    using V_tilt = void (*)(float *, float, void *, float, float);

    void run_set_angle_from_turn_rate() {
        const char *name = "swrRace_SetAngleFromTurnRate";
        if (!testable(name, swrRace_SetAngleFromTurnRate_ADDR))
            return;
        const V_tilt retail = (V_tilt) hook_retail_ptr(swrRace_SetAngleFromTurnRate_ADDR);
        DeltaGuard guard;
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            swrRace_deltaTimeSecs = sample_delta(i);
            const float seed = next_float(-90.0f, 90.0f);
            const float rate = sample(i, -200.0f, 200.0f);
            const float max_rate = next_float(1.0f, 200.0f);
            const float max_angle = next_float(0.0f, 120.0f);
            float our_tilt = seed, ret_tilt = seed;
            swrRace_SetAngleFromTurnRate(&our_tilt, rate, nullptr, max_rate, max_angle);
            retail(&ret_tilt, rate, nullptr, max_rate, max_angle);
            char desc[160];
            std::snprintf(desc, sizeof(desc), "f(inout=%.9g, %.9g, %.9g, %.9g) dt=%.9g", seed, rate,
                          max_rate, max_angle, swrRace_deltaTimeSecs);
            record(s, our_tilt, ret_tilt, 0, desc);
        }
        report(s);
    }

    using V_turn = void (*)(float *, float *, float, float, float, float);

    void run_update_turn() {
        const char *name = "swrRace_UpdateTurn";
        if (!testable(name, swrRace_UpdateTurn_ADDR))
            return;
        const V_turn retail = (V_turn) hook_retail_ptr(swrRace_UpdateTurn_ADDR);
        DeltaGuard guard;
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            swrRace_deltaTimeSecs = sample_delta(i);
            const float rate = next_float(-200.0f, 200.0f);
            const float heading = next_float(-180.0f, 180.0f);
            const float target = sample(i, -200.0f, 200.0f);
            const float accel = next_float(0.0f, 1000.0f);
            const float steer = (i % 3 == 0) ? 0.0f : next_float(-100.0f, 100.0f);
            const float extra = next_float(-50.0f, 50.0f);
            float our_rate = rate, our_heading = heading;
            float ret_rate = rate, ret_heading = heading;
            swrRace_UpdateTurn(&our_rate, &our_heading, target, accel, steer, extra);
            retail(&ret_rate, &ret_heading, target, accel, steer, extra);
            char desc[200];
            std::snprintf(desc, sizeof(desc), "f(%.9g, %.9g, %.9g, %.9g, %.9g, %.9g) dt=%.9g", rate,
                          heading, target, accel, steer, extra, swrRace_deltaTimeSecs);
            record(s, our_rate, ret_rate, 0, desc);
            record(s, our_heading, ret_heading, 0, desc);
        }
        report(s);
    }

    using V_tilt_angles = void (*)(rdVector3 *, rdVector3 *, rdVector3 *, rdVector3 *);

    void run_compute_tilt_angles() {
        const char *name = "swrRace_ComputeTiltAngles";
        if (!testable(name, swrRace_ComputeTiltAngles_ADDR))
            return;
        const V_tilt_angles retail =
            (V_tilt_angles) hook_retail_ptr(swrRace_ComputeTiltAngles_ADDR);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdMatrix44 basis;
            random_rotation(basis, i);
            rdVector3 fwd = {basis.vB.x, basis.vB.y, basis.vB.z};
            rdVector3 right = {basis.vA.x, basis.vA.y, basis.vA.z};
            // The reference is the track normal: near the pod's up axis most of the time.
            rdVector3 ref = random_vec3(i + 31, -0.4f, 0.4f);
            ref.x += basis.vC.x, ref.y += basis.vC.y, ref.z += basis.vC.z;
            rdVector_Normalize3Acc(&ref);
            rdVector3 our_out = {-12345.0f, -12345.0f, -12345.0f};
            rdVector3 ret_out = our_out;
            swrRace_ComputeTiltAngles(&fwd, &right, &ref, &our_out);
            retail(&fwd, &right, &ref, &ret_out);
            char desc[200], sa[96], sb[96];
            describe_vec3(sa, sizeof(sa), fwd);
            describe_vec3(sb, sizeof(sb), ref);
            std::snprintf(desc, sizeof(desc), "fwd=%s ref=%s", sa, sb);
            record_vec3(s, our_out, ret_out, 0, desc);
        }
        report(s);
    }

    void random_handling(PodHandlingData &d) {
        d.antiSkid = next_float(0.0f, 1.0f);
        d.turnResponse = next_float(50.0f, 1000.0f);
        d.maxTurnRate = next_float(50.0f, 200.0f);
        d.acceleration = next_float(0.5f, 5.0f);
        d.maxSpeed = next_float(400.0f, 700.0f);
        d.airBrakeInv = next_float(1.0f, 100.0f);
        d.deceleration_interval = next_float(0.0f, 1000.0f);
        d.boost_thrust = next_float(0.0f, 1000.0f);
        d.heatRate = next_float(0.0f, 50.0f);
        d.coolRate = next_float(0.0f, 50.0f);
        d.hoverHeight = next_float(0.0f, 10.0f);
        d.repairRate = next_float(0.0f, 1.0f);
        d.bumpMass = next_float(0.0f, 200.0f);
        d.damageImmunity = next_float(0.0f, 2.0f);
        d.intersectRadius = next_float(0.0f, 10.0f);
    }

    using V_upgrades = void (*)(PodHandlingData *, PodHandlingData *, char *, char *);

    // Covers swrRace_CalculateUpgradedStat for every category and level, at every part health.
    void run_apply_upgrades_to_stats() {
        const char *name = "swrRace_ApplyUpgradesToStats";
        if (!testable(name, swrRace_ApplyUpgradesToStats_ADDR))
            return;
        const V_upgrades retail = (V_upgrades) hook_retail_ptr(swrRace_ApplyUpgradesToStats_ADDR);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            PodHandlingData base;
            random_handling(base);
            char levels[7], healths[7];
            for (int k = 0; k < 7; k++) {
                levels[k] = (char) (next_u32() % 7u);
                healths[k] = (char) ((i % 4 == 0) ? 255 : next_u32() % 256u);
            }
            PodHandlingData our_out, ret_out;
            std::memset(&our_out, 0xcd, sizeof(our_out));
            std::memset(&ret_out, 0xcd, sizeof(ret_out));
            swrRace_ApplyUpgradesToStats(&our_out, &base, levels, healths);
            retail(&ret_out, &base, levels, healths);
            char desc[96];
            std::snprintf(desc, sizeof(desc), "levels=%d%d%d%d%d%d%d health0=%u", levels[0],
                          levels[1], levels[2], levels[3], levels[4], levels[5], levels[6],
                          (unsigned) (uint8_t) healths[0]);
            record_floats(s, &our_out.antiSkid, &ret_out.antiSkid, 15, 0, desc);
        }
        report(s);
    }

    using V_stat_bars = void (*)(PodHandlingData *, PodHandlingData *);

    void run_compute_stat_bars() {
        const char *name = "swrRace_ComputeStatBars";
        if (!testable(name, swrRace_ComputeStatBars_ADDR))
            return;
        const V_stat_bars retail = (V_stat_bars) hook_retail_ptr(swrRace_ComputeStatBars_ADDR);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            PodHandlingData stats;
            random_handling(stats);
            PodHandlingData our_out, ret_out;
            std::memset(&our_out, 0xcd, sizeof(our_out));
            std::memset(&ret_out, 0xcd, sizeof(ret_out));
            swrRace_ComputeStatBars(&our_out, &stats);
            retail(&ret_out, &stats);
            char desc[96];
            std::snprintf(desc, sizeof(desc), "accel=%.9g airBrake=%.9g", stats.acceleration,
                          stats.airBrakeInv);
            record_floats(s, &our_out.antiSkid, &ret_out.antiSkid, 15, 0, desc);
        }
        report(s);
    }

    using U_crc = unsigned int (*)(void *, int);

    void run_crc32() {
        const char *name = "swrRace_Crc32";
        if (!testable(name, swrRace_Crc32_ADDR))
            return;
        const U_crc retail = (U_crc) hook_retail_ptr(swrRace_Crc32_ADDR);
        Stats s;
        stats_init(s, name);
        uint8_t buf[512];
        for (int i = 0; i < VERIFY_ITERATIONS / 10; i++) {
            const int len = (int) (next_u32() % sizeof(buf));
            for (int k = 0; k < len; k++)
                buf[k] = (uint8_t) next_u32();
            char desc[48];
            std::snprintf(desc, sizeof(desc), "len=%d", len);
            record_int(s, (int) swrRace_Crc32(buf, len), (int) retail(buf, len), desc);
        }
        report(s);
    }

    using F_racer = float (*)(swrRace *);

    void run_engine_damage_penalty() {
        const char *name = "swrRace_GetEngineDamagePenalty";
        if (!testable(name, swrRace_GetEngineDamagePenalty_ADDR))
            return;
        const F_racer retail = (F_racer) hook_retail_ptr(swrRace_GetEngineDamagePenalty_ADDR);
        Stats s;
        stats_init(s, name);
        swrRace *r = racer_pair[0];
        std::memset(r, 0, sizeof(swrRace));
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            for (int k = 0; k < 6; k++)
                r->engineHealth[k] = (next_u32() % 4u == 0) ? 0.8f : next_float(0.0f, 1.0f);
            char desc[64];
            std::snprintf(desc, sizeof(desc), "health[0]=%.9g", r->engineHealth[0]);
            record(s, swrRace_GetEngineDamagePenalty(r), retail(r), 0, desc);
        }
        report(s);
    }

    using F_exhaust = float (*)(swrRace *, int, float, float, float, float, float, float);

    void run_smooth_engine_exhaust_size() {
        const char *name = "swrRace_SmoothEngineExhaustSize";
        if (!testable(name, swrRace_SmoothEngineExhaustSize_ADDR))
            return;
        const F_exhaust retail = (F_exhaust) hook_retail_ptr(swrRace_SmoothEngineExhaustSize_ADDR);
        DeltaGuard guard;
        Stats s;
        stats_init(s, name);
        swrRace *ours = racer_pair[0];
        swrRace *ret = racer_pair[1];
        static const uint32_t flag0[] = {0, swrObjTest_FLAG0_BOOSTING, swrObjTest_FLAG0_BRAKING,
                                         swrObjTest_FLAG0_BOOSTING | swrObjTest_FLAG0_BRAKING};
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            swrRace_deltaTimeSecs = sample_delta(i);
            std::memset(ours, 0, sizeof(swrRace));
            const int part = (int) (next_u32() % 75u);
            ours->partOffset[part].y = next_float(-10.0f, 10.0f);
            ours->flags0 = (swrObjTest_FLAG0) flag0[i % 4];
            ours->flags1 = (swrObjTest_FLAG1) ((i / 4) % 2 ? swrObjTest_FLAG1_FINISHED : 0);
            std::memcpy(ret, ours, sizeof(swrRace));
            float lo = next_float(-10.0f, 10.0f), hi = next_float(-10.0f, 10.0f);
            if (hi < lo) {
                const float t = lo;
                lo = hi;
                hi = t;
            }
            const float target = next_float(-10.0f, 10.0f);
            const float brake = next_float(-10.0f, 10.0f);
            const float down = next_float(0.0f, 20.0f);
            const float up = next_float(0.0f, 20.0f);
            const float our_r =
                swrRace_SmoothEngineExhaustSize(ours, part, target, brake, down, up, lo, hi);
            const float ret_r = retail(ret, part, target, brake, down, up, lo, hi);
            char desc[160];
            std::snprintf(desc, sizeof(desc), "part=%d target=%.9g flags0=0x%x dt=%.9g", part,
                          target, (unsigned) ours->flags0, swrRace_deltaTimeSecs);
            record(s, our_r, ret_r, 0, desc);
            record_racer(s, *ours, *ret, desc);
        }
        report(s);
    }

    using V_extrapolate = void (*)(swrRace *, rdMatrix44 *, rdMatrix44 *, float);

    void run_extrapolate_transform() {
        const char *name = "swrRace_ExtrapolateTransform";
        if (!testable(name, swrRace_ExtrapolateTransform_ADDR))
            return;
        const V_extrapolate retail =
            (V_extrapolate) hook_retail_ptr(swrRace_ExtrapolateTransform_ADDR);
        Stats s;
        stats_init(s, name);
        swrRace *r = racer_pair[0];
        std::memset(r, 0, sizeof(swrRace));
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdMatrix44 in;
            random_rotation(in, i);
            r->speedValue = next_float(0.0f, 1000.0f);
            const float dt = next_float(0.0f, 0.1f);
            rdMatrix44 our_out, ret_out;
            std::memset(&our_out, 0xcd, sizeof(our_out));
            std::memset(&ret_out, 0xcd, sizeof(ret_out));
            swrRace_ExtrapolateTransform(r, &our_out, &in, dt);
            retail(r, &ret_out, &in, dt);
            char desc[96];
            std::snprintf(desc, sizeof(desc), "speed=%.9g dt=%.9g", r->speedValue, dt);
            record_floats(s, &our_out.vA.x, &ret_out.vA.x, 16, 0, desc);
        }
        report(s);
    }

    using V_turn2 = void (*)(swrRace *, rdVector3 *, rdVector3 *);

    // The per-frame pod orientation update: both the full 3-axis path (local racer, near LOD,
    // forced ground) and the yaw-only path for distant AI, plus the every-8-frames renormalize.
    void run_update_turn2() {
        const char *name = "swrRace_UpdateTurn2";
        if (!testable(name, swrRace_UpdateTurn2_ADDR))
            return;
        const V_turn2 retail = (V_turn2) hook_retail_ptr(swrRace_UpdateTurn2_ADDR);
        Stats s;
        stats_init(s, name);
        swrRace *ours = racer_pair[0];
        swrRace *ret = racer_pair[1];
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            std::memset(ours, 0, sizeof(swrRace));
            random_rotation(ours->transform, i);
            switch (i % 4) {
                case 0:
                    ours->flags0 = swrObjTest_FLAG0_LOCAL;
                    break;
                case 1:
                    ours->flags1 = swrObjTest_FLAG1_FORCE_GROUND;
                    break;
                default:
                    ours->lodDistance = (int) (next_u32() % 2000u);
                    break;
            }
            ours->orthoRenormCounter = (int) (next_u32() % 9u);
            std::memcpy(ret, ours, sizeof(swrRace));
            rdVector3 pos = random_vec3(i, -5000.0f, 5000.0f);
            rdVector3 turn = random_vec3(i + 5, -10.0f, 10.0f);
            swrRace_UpdateTurn2(ours, &pos, &turn);
            retail(ret, &pos, &turn);
            char desc[160], st[96];
            describe_vec3(st, sizeof(st), turn);
            std::snprintf(desc, sizeof(desc), "turn=%s lod=%d flags0=0x%x renorm=%d", st,
                          ret->lodDistance, (unsigned) ret->flags0, ours->orthoRenormCounter);
            record_racer(s, *ours, *ret, desc);
        }
        report(s);
    }


    // rdVector2 shapes. Retail leaves an input pointer in EAX rather than returning `v1`, and
    // no caller reads it, so only the written vector is compared.
    using V2_vvv = rdVector2 *(*) (rdVector2 *, const rdVector2 *, const rdVector2 *);
    using V2_vfv = rdVector2 *(*) (rdVector2 *, float, const rdVector2 *);
    using V_v2v2fv2 = void (*)(rdVector2 *, rdVector2 *, float, rdVector2 *);
    using F_v2 = float (*)(const rdVector2 *);
    using F_v2acc = float (*)(rdVector2 *);

    rdVector2 random_vec2(int i, float lo, float hi) {
        rdVector2 v;
        v.x = sample(i, lo, hi);
        v.y = sample(i + 5, lo, hi);
        return v;
    }

    void run_v2_vvv(const char *name, uint32_t retail_addr, V2_vvv ours, float lo, float hi) {
        if (!testable(name, retail_addr))
            return;
        const V2_vvv retail = (V2_vvv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector2 a = random_vec2(i, lo, hi);
            const rdVector2 b = random_vec2(i + 17, lo, hi);
            rdVector2 our_out = {-12345.0f, -12345.0f};
            rdVector2 ret_out = our_out;
            ours(&our_out, &a, &b);
            retail(&ret_out, &a, &b);
            char desc[96];
            std::snprintf(desc, sizeof(desc), "(%.9g, %.9g), (%.9g, %.9g)", a.x, a.y, b.x, b.y);
            record_floats(s, &our_out.x, &ret_out.x, 2, 0, desc);
        }
        report(s);
    }

    void run_v2_vfv(const char *name, uint32_t retail_addr, V2_vfv ours, float lo, float hi) {
        if (!testable(name, retail_addr))
            return;
        const V2_vfv retail = (V2_vfv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector2 a = random_vec2(i, lo, hi);
            const float k = sample(i + 9, lo, hi);
            rdVector2 our_out = {-12345.0f, -12345.0f};
            rdVector2 ret_out = our_out;
            ours(&our_out, k, &a);
            retail(&ret_out, k, &a);
            char desc[96];
            std::snprintf(desc, sizeof(desc), "k=%.9g (%.9g, %.9g)", k, a.x, a.y);
            record_floats(s, &our_out.x, &ret_out.x, 2, 0, desc);
        }
        report(s);
    }

    void run_v_v2v2fv2(const char *name, uint32_t retail_addr, V_v2v2fv2 ours, float lo, float hi) {
        if (!testable(name, retail_addr))
            return;
        const V_v2v2fv2 retail = (V_v2v2fv2) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdVector2 a = random_vec2(i, lo, hi);
            rdVector2 b = random_vec2(i + 17, lo, hi);
            const float k = sample(i + 9, lo, hi);
            rdVector2 our_out = {-12345.0f, -12345.0f};
            rdVector2 ret_out = our_out;
            ours(&our_out, &a, k, &b);
            retail(&ret_out, &a, k, &b);
            char desc[120];
            std::snprintf(desc, sizeof(desc), "(%.9g, %.9g) + %.9g * (%.9g, %.9g)", a.x, a.y, k,
                          b.x, b.y);
            record_floats(s, &our_out.x, &ret_out.x, 2, 0, desc);
        }
        report(s);
    }

    void run_f_v2(const char *name, uint32_t retail_addr, F_v2 ours, float lo, float hi) {
        if (!testable(name, retail_addr))
            return;
        const F_v2 retail = (F_v2) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector2 a = random_vec2(i, lo, hi);
            char desc[64];
            std::snprintf(desc, sizeof(desc), "(%.9g, %.9g)", a.x, a.y);
            record(s, ours(&a), retail(&a), 0, desc);
        }
        report(s);
    }

    void run_f_v2acc(const char *name, uint32_t retail_addr, F_v2acc ours, float lo, float hi) {
        if (!testable(name, retail_addr))
            return;
        const F_v2acc retail = (F_v2acc) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector2 seed = random_vec2(i, lo, hi);
            rdVector2 our_v = seed, ret_v = seed;
            char desc[64];
            std::snprintf(desc, sizeof(desc), "(%.9g, %.9g)", seed.x, seed.y);
            record(s, ours(&our_v), retail(&ret_v), 0, desc);
            record_floats(s, &our_v.x, &ret_v.x, 2, 0, desc);
        }
        report(s);
    }

    // Remaining rdVector3/4 shapes.
    using V_copy3 = void (*)(rdVector3 *, const rdVector3 *);
    using V3_set3 = rdVector3 *(*) (rdVector3 *, float, float, float);
    using V4_set4 = rdVector4 *(*) (rdVector4 *, float, float, float, float);
    using B_vv = bool (*)(rdVector3 *, rdVector3 *);
    using V_scale_both = void (*)(rdVector3 *, float, const rdVector3 *, float, const rdVector3 *);
    using V_persp = void (*)(rdVector4 *, rdVector3 *, rdVector3 *);

    void run_copy3(const char *name, uint32_t retail_addr, V_copy3 ours) {
        if (!testable(name, retail_addr))
            return;
        const V_copy3 retail = (V_copy3) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 a = random_vec3(i, -1000.0f, 1000.0f);
            rdVector3 our_out = {-12345.0f, -12345.0f, -12345.0f};
            rdVector3 ret_out = our_out;
            ours(&our_out, &a);
            retail(&ret_out, &a);
            char desc[96];
            describe_vec3(desc, sizeof(desc), a);
            record_vec3(s, our_out, ret_out, 0, desc);
        }
        report(s);
    }

    void run_set3(const char *name, uint32_t retail_addr, V3_set3 ours) {
        if (!testable(name, retail_addr))
            return;
        const V3_set3 retail = (V3_set3) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 a = random_vec3(i, -1000.0f, 1000.0f);
            rdVector3 our_out = {-12345.0f, -12345.0f, -12345.0f};
            rdVector3 ret_out = our_out;
            const bool same_ret = (ours(&our_out, a.x, a.y, a.z) == &our_out) ==
                                  (retail(&ret_out, a.x, a.y, a.z) == &ret_out);
            char desc[96];
            describe_vec3(desc, sizeof(desc), a);
            record_vec3(s, our_out, ret_out, 0, desc);
            record_int(s, same_ret, 1, desc);
        }
        report(s);
    }

    void run_set4(const char *name, uint32_t retail_addr, V4_set4 ours) {
        if (!testable(name, retail_addr))
            return;
        const V4_set4 retail = (V4_set4) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 a = random_vec3(i, -1000.0f, 1000.0f);
            const float w = sample(i + 13, -1000.0f, 1000.0f);
            rdVector4 our_out = {-12345.0f, -12345.0f, -12345.0f, -12345.0f};
            rdVector4 ret_out = our_out;
            const bool same_ret = (ours(&our_out, a.x, a.y, a.z, w) == &our_out) ==
                                  (retail(&ret_out, a.x, a.y, a.z, w) == &ret_out);
            char desc[96];
            describe_vec3(desc, sizeof(desc), a);
            record_floats(s, &our_out.x, &ret_out.x, 4, 0, desc);
            record_int(s, same_ret, 1, desc);
        }
        report(s);
    }

    // Half the cases compare a vector against an exact copy, or one that differs in a single
    // component, so both outcomes are exercised.
    void run_are_same3(const char *name, uint32_t retail_addr, B_vv ours) {
        if (!testable(name, retail_addr))
            return;
        const B_vv retail = (B_vv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdVector3 a = random_vec3(i, -10.0f, 10.0f);
            rdVector3 b = random_vec3(i + 23, -10.0f, 10.0f);
            if (i % 2 == 0) {
                b = a;
                if (i % 8 == 2)
                    b.x = -b.x;
                else if (i % 8 == 4)
                    b.y = next_float(-10.0f, 10.0f);
                else if (i % 8 == 6)
                    b.z = -0.0f, a.z = 0.0f;
            }
            char desc[200], sa[96], sb[96];
            describe_vec3(sa, sizeof(sa), a);
            describe_vec3(sb, sizeof(sb), b);
            std::snprintf(desc, sizeof(desc), "%s, %s", sa, sb);
            record_int(s, ours(&a, &b) ? 1 : 0, retail(&a, &b) ? 1 : 0, desc);
        }
        report(s);
    }

    void run_scale3add3_both(const char *name, uint32_t retail_addr, V_scale_both ours) {
        if (!testable(name, retail_addr))
            return;
        const V_scale_both retail = (V_scale_both) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 a = random_vec3(i, -1000.0f, 1000.0f);
            const rdVector3 b = random_vec3(i + 23, -1000.0f, 1000.0f);
            const float k1 = sample(i + 3, -10.0f, 10.0f);
            const float k2 = sample(i + 31, -10.0f, 10.0f);
            rdVector3 our_out = {-12345.0f, -12345.0f, -12345.0f};
            rdVector3 ret_out = our_out;
            ours(&our_out, k1, &a, k2, &b);
            retail(&ret_out, k1, &a, k2, &b);
            char desc[64];
            std::snprintf(desc, sizeof(desc), "k1=%.9g k2=%.9g case %d", k1, k2, i);
            record_vec3(s, our_out, ret_out, 0, desc);
        }
        report(s);
    }

    void run_point3_to_perspective3(const char *name, uint32_t retail_addr, V_persp ours) {
        if (!testable(name, retail_addr))
            return;
        const V_persp retail = (V_persp) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 a = random_vec3(i, -1000.0f, 1000.0f);
            const rdVector3 b = random_vec3(i + 23, -1000.0f, 1000.0f);
            rdVector3 our_a = a, our_b = b, ret_a = a, ret_b = b;
            rdVector4 our_out = {-12345.0f, -12345.0f, -12345.0f, -12345.0f};
            rdVector4 ret_out = our_out;
            ours(&our_out, &our_a, &our_b);
            retail(&ret_out, &ret_a, &ret_b);
            char desc[200], sa[96], sb[96];
            describe_vec3(sa, sizeof(sa), a);
            describe_vec3(sb, sizeof(sb), b);
            std::snprintf(desc, sizeof(desc), "%s, %s", sa, sb);
            record_floats(s, &our_out.x, &ret_out.x, 4, 0, desc);
            record_vec3(s, our_a, ret_a, 0, desc);
            record_vec3(s, our_b, ret_b, 0, desc);
        }
        report(s);
    }

    // Remaining rdMatrix shapes.
    using V_m33fff = void (*)(rdMatrix33 *, float, float, float);
    using V_m34vv = void (*)(rdMatrix34 *, rdVector3 *, rdVector3 *);
    using V_m34m34 = void (*)(rdMatrix34 *, rdMatrix34 *);
    using V_copy44 = void (*)(rdMatrix44 *, const rdMatrix44 *);
    using V_to_trs = void (*)(const rdMatrix44 *, rdVector3 *, rdMatrix44 *, rdVector3 *);
    using V_m44tr = void (*)(rdMatrix44 *, swrTranslationRotation *);

    void run_build_rotation33(const char *name, uint32_t retail_addr, V_m33fff ours) {
        if (!testable(name, retail_addr))
            return;
        const V_m33fff retail = (V_m33fff) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdVector3 a = random_vec3(i, -720.0f, 720.0f);
            rdMatrix33 our_m, ret_m;
            std::memset(&our_m, 0xcd, sizeof(our_m));
            std::memset(&ret_m, 0xcd, sizeof(ret_m));
            ours(&our_m, a.x, a.y, a.z);
            retail(&ret_m, a.x, a.y, a.z);
            char desc[96];
            describe_vec3(desc, sizeof(desc), a);
            record_floats(s, &our_m.rvec.x, &ret_m.rvec.x, 9, 0, desc);
        }
        report(s);
    }

    void run_build_rotation34(const char *name, uint32_t retail_addr, V_m34vv ours) {
        if (!testable(name, retail_addr))
            return;
        const V_m34vv retail = (V_m34vv) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdVector3 angles = random_vec3(i, -720.0f, 720.0f);
            rdVector3 trans = random_vec3(i + 23, -1000.0f, 1000.0f);
            rdMatrix34 our_m, ret_m;
            std::memset(&our_m, 0xcd, sizeof(our_m));
            std::memset(&ret_m, 0xcd, sizeof(ret_m));
            ours(&our_m, &angles, &trans);
            retail(&ret_m, &angles, &trans);
            char desc[96];
            describe_vec3(desc, sizeof(desc), angles);
            record_floats(s, &our_m.rvec.x, &ret_m.rvec.x, 12, 0, desc);
        }
        report(s);
    }

    void run_build_translate34(const char *name, uint32_t retail_addr, V_m34v ours) {
        if (!testable(name, retail_addr))
            return;
        const V_m34v retail = (V_m34v) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdVector3 t = random_vec3(i, -1000.0f, 1000.0f);
            rdMatrix34 our_m, ret_m;
            std::memset(&our_m, 0xcd, sizeof(our_m));
            std::memset(&ret_m, 0xcd, sizeof(ret_m));
            ours(&our_m, &t);
            retail(&ret_m, &t);
            char desc[96];
            describe_vec3(desc, sizeof(desc), t);
            record_floats(s, &our_m.rvec.x, &ret_m.rvec.x, 12, 0, desc);
        }
        report(s);
    }

    // `orthonormal` feeds a real rotation: the Norm variant assumes unit axes, and a general
    // matrix exercises the scale-correcting path of the other.
    void run_invert34(const char *name, uint32_t retail_addr, V_m34m34 ours, bool orthonormal) {
        if (!testable(name, retail_addr))
            return;
        const V_m34m34 retail = (V_m34m34) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdMatrix34 in = random_mat34(i, -10.0f, 10.0f);
            if (orthonormal || i % 2 == 0) {
                const rdVector3 t = in.scale;
                orthonormalize34(in);
                in.scale = t;
                if (!orthonormal) {
                    const float k = next_float(0.1f, 10.0f);
                    in.rvec.x *= k, in.rvec.y *= k, in.rvec.z *= k;
                    in.lvec.x *= k, in.lvec.y *= k, in.lvec.z *= k;
                    in.uvec.x *= k, in.uvec.y *= k, in.uvec.z *= k;
                }
            }
            rdMatrix34 our_in = in, ret_in = in;
            rdMatrix34 our_m, ret_m;
            std::memset(&our_m, 0xcd, sizeof(our_m));
            std::memset(&ret_m, 0xcd, sizeof(ret_m));
            ours(&our_m, &our_in);
            retail(&ret_m, &ret_in);
            char desc[32];
            std::snprintf(desc, sizeof(desc), "case %d", i);
            record_floats(s, &our_m.rvec.x, &ret_m.rvec.x, 12, 0, desc);
        }
        report(s);
    }

    void run_copy44(const char *name, uint32_t retail_addr, V_copy44 ours) {
        if (!testable(name, retail_addr))
            return;
        const V_copy44 retail = (V_copy44) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS / 10; i++) {
            const rdMatrix44 in = random_mat44(i, -1000.0f, 1000.0f);
            rdMatrix44 our_m, ret_m;
            std::memset(&our_m, 0xcd, sizeof(our_m));
            std::memset(&ret_m, 0xcd, sizeof(ret_m));
            ours(&our_m, &in);
            retail(&ret_m, &in);
            char desc[32];
            std::snprintf(desc, sizeof(desc), "case %d", i);
            record_floats(s, &our_m.vA.x, &ret_m.vA.x, 16, 0, desc);
        }
        report(s);
    }

    // A scaled rotation plus translation, the shape the game decomposes.
    rdMatrix44 random_trs44(int i) {
        rdMatrix44 m;
        random_rotation(m, i);
        const float sx = next_float(0.05f, 20.0f), sy = next_float(0.05f, 20.0f),
                    sz = next_float(0.05f, 20.0f);
        m.vA.x *= sx, m.vA.y *= sx, m.vA.z *= sx;
        m.vB.x *= sy, m.vB.y *= sy, m.vB.z *= sy;
        m.vC.x *= sz, m.vC.y *= sz, m.vC.z *= sz;
        m.vD.x = next_float(-5000.0f, 5000.0f);
        m.vD.y = next_float(-5000.0f, 5000.0f);
        m.vD.z = next_float(-5000.0f, 5000.0f);
        m.vD.w = 1.0f;
        return m;
    }

    void run_to_trans_rot_scale(const char *name, uint32_t retail_addr, V_to_trs ours) {
        if (!testable(name, retail_addr))
            return;
        const V_to_trs retail = (V_to_trs) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const rdMatrix44 in = random_trs44(i);
            rdVector3 our_t, ret_t, our_s, ret_s;
            rdMatrix44 our_r, ret_r;
            std::memset(&our_t, 0xcd, sizeof(our_t));
            std::memset(&ret_t, 0xcd, sizeof(ret_t));
            std::memset(&our_s, 0xcd, sizeof(our_s));
            std::memset(&ret_s, 0xcd, sizeof(ret_s));
            std::memset(&our_r, 0xcd, sizeof(our_r));
            std::memset(&ret_r, 0xcd, sizeof(ret_r));
            ours(&in, &our_t, &our_r, &our_s);
            retail(&in, &ret_t, &ret_r, &ret_s);
            char desc[32];
            std::snprintf(desc, sizeof(desc), "case %d", i);
            record_vec3(s, our_t, ret_t, 0, desc);
            record_floats(s, &our_r.vA.x, &ret_r.vA.x, 16, 0, desc);
            record_vec3(s, our_s, ret_s, 0, desc);
        }
        report(s);
    }

    // Reads the matrix, writes the translation/rotation pair; the matrix is compared too in
    // case the body normalises it in place.
    void run_extract_transform(const char *name, uint32_t retail_addr, V_m44tr ours) {
        if (!testable(name, retail_addr))
            return;
        const V_m44tr retail = (V_m44tr) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdMatrix44 our_m = random_trs44(i);
            rdMatrix44 ret_m = our_m;
            swrTranslationRotation our_tr, ret_tr;
            std::memset(&our_tr, 0xcd, sizeof(our_tr));
            std::memset(&ret_tr, 0xcd, sizeof(ret_tr));
            ours(&our_m, &our_tr);
            retail(&ret_m, &ret_tr);
            char desc[32];
            std::snprintf(desc, sizeof(desc), "case %d", i);
            record_floats(s, &our_tr.translation.x, &ret_tr.translation.x, 6, 0, desc);
            record_floats(s, &our_m.vA.x, &ret_m.vA.x, 16, 0, desc);
        }
        report(s);
    }

    void run_set_transform44(const char *name, uint32_t retail_addr, V_m44tr ours) {
        if (!testable(name, retail_addr))
            return;
        const V_m44tr retail = (V_m44tr) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            swrTranslationRotation tr;
            tr.translation = random_vec3(i, -5000.0f, 5000.0f);
            tr.yaw_roll_pitch = random_vec3(i + 23, -720.0f, 720.0f);
            swrTranslationRotation our_tr = tr, ret_tr = tr;
            rdMatrix44 our_m, ret_m;
            std::memset(&our_m, 0xcd, sizeof(our_m));
            std::memset(&ret_m, 0xcd, sizeof(ret_m));
            ours(&our_m, &our_tr);
            retail(&ret_m, &ret_tr);
            char desc[96];
            describe_vec3(desc, sizeof(desc), tr.yaw_roll_pitch);
            record_floats(s, &our_m.vA.x, &ret_m.vA.x, 16, 0, desc);
        }
        report(s);
    }

    // stdFnames: string in, pointer-into-buffer or mutated buffer out. Both sides get their own
    // copy of the same input, and a returned pointer is compared as an offset into that copy.
    const char *const fname_parts[] = {"data",  "", "\\",   "\\\\",  "track", ".",   "..",
                                       "a.b",   "file.txt", "x",  "dir\\", "\\sub", "ext.",
                                       ".bin",  "mod.bmp.bak", "C:", "C:\\", "wav",  "a\\\\b"};
    const int fname_part_count = (int) (sizeof(fname_parts) / sizeof(fname_parts[0]));

    void random_path(char *out, size_t n) {
        std::memset(out, 0, n);
        size_t len = 0;
        const int pieces = (int) (next_u32() % 5u);
        for (int k = 0; k < pieces; k++) {
            const char *p = fname_parts[next_u32() % (uint32_t) fname_part_count];
            const size_t plen = std::strlen(p);
            if (len + plen + 1 < n) {
                std::memcpy(out + len, p, plen);
                len += plen;
            }
        }
    }

    int offset_or_null(const char *p, const char *base) {
        return p == nullptr ? -1 : (int) (p - base);
    }

    using S_s = char *(*) (char *);
    using I_ss = int (*)(char *, char *);
    using S_ssi = char *(*) (char *, char *, int);
    using V_sisS = void (*)(char *, int, char *, char *);

    // `mutates`: the function may write into its argument, so the whole buffer is compared.
    void run_s_s(const char *name, uint32_t retail_addr, S_s ours, bool mutates) {
        if (!testable(name, retail_addr))
            return;
        const S_s retail = (S_s) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS / 10; i++) {
            char in[64], our_b[64], ret_b[64];
            random_path(in, sizeof(in));
            std::memcpy(our_b, in, sizeof(in));
            std::memcpy(ret_b, in, sizeof(in));
            char desc[96];
            std::snprintf(desc, sizeof(desc), "\"%s\"", in);
            record_int(s, offset_or_null(ours(our_b), our_b), offset_or_null(retail(ret_b), ret_b),
                       desc);
            if (mutates)
                record_int(s, std::memcmp(our_b, ret_b, sizeof(our_b)), 0, desc);
        }
        report(s);
    }

    void run_change_ext(const char *name, uint32_t retail_addr, I_ss ours) {
        if (!testable(name, retail_addr))
            return;
        const I_ss retail = (I_ss) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS / 10; i++) {
            char in[128], our_b[128], ret_b[128], ext[16];
            std::memset(in, 0, sizeof(in));
            random_path(in, 64);
            static const char *const exts[] = {"txt", "", "bmp", "a.b", "wav"};
            std::snprintf(ext, sizeof(ext), "%s", exts[next_u32() % 5u]);
            std::memcpy(our_b, in, sizeof(in));
            std::memcpy(ret_b, in, sizeof(in));
            char desc[112];
            std::snprintf(desc, sizeof(desc), "\"%s\" ext=\"%s\"", in, ext);
            record_int(s, ours(our_b, ext), retail(ret_b, ext), desc);
            record_int(s, std::memcmp(our_b, ret_b, sizeof(our_b)), 0, desc);
        }
        report(s);
    }

    // Small buffer sizes reach the truncation paths.
    void run_concat(const char *name, uint32_t retail_addr, S_ssi ours) {
        if (!testable(name, retail_addr))
            return;
        const S_ssi retail = (S_ssi) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS / 10; i++) {
            char left[128], right[64], our_b[128], ret_b[128];
            std::memset(left, 0, sizeof(left));
            random_path(left, 64);
            random_path(right, sizeof(right));
            const int len = (int) std::strlen(left);
            const int buf = len + 1 + (int) (next_u32() % 40u);
            std::memcpy(our_b, left, sizeof(left));
            std::memcpy(ret_b, left, sizeof(left));
            char desc[160];
            std::snprintf(desc, sizeof(desc), "\"%s\" + \"%s\" len=%d", left, right, buf);
            record_int(s, offset_or_null(ours(our_b, right, buf), our_b),
                       offset_or_null(retail(ret_b, right, buf), ret_b), desc);
            record_int(s, std::memcmp(our_b, ret_b, sizeof(our_b)), 0, desc);
        }
        report(s);
    }

    void run_make_path(const char *name, uint32_t retail_addr, V_sisS ours) {
        if (!testable(name, retail_addr))
            return;
        const V_sisS retail = (V_sisS) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS / 10; i++) {
            char a[64], b[64], our_b[128], ret_b[128];
            random_path(a, sizeof(a));
            random_path(b, sizeof(b));
            const int buf = 1 + (int) (next_u32() % 100u);
            std::memset(our_b, 0x5a, sizeof(our_b));
            std::memset(ret_b, 0x5a, sizeof(ret_b));
            ours(our_b, buf, a, b);
            retail(ret_b, buf, a, b);
            char desc[160];
            std::snprintf(desc, sizeof(desc), "\"%s\" , \"%s\" len=%d", a, b, buf);
            record_int(s, std::memcmp(our_b, ret_b, sizeof(our_b)), 0, desc);
        }
        report(s);
    }

    // swrRace leaves on a zeroed racer.
    using U_racer = unsigned int (*)(swrRace *);
    using V_take_damage = void (*)(int, int, float);
    using V_boost_bar = void (*)(swrRace *, uint8_t *, uint8_t *, float *);
    using F_closest = float (*)(rdVector2 *, float *, rdVector2 *, float *, rdVector2 *,
                                rdVector2 *, rdVector2 *, rdVector2 *);

    void run_damaged_engine_sides() {
        const char *name = "swrRace_GetDamagedEngineSides";
        if (!testable(name, swrRace_GetDamagedEngineSides_ADDR))
            return;
        const U_racer retail = (U_racer) hook_retail_ptr(swrRace_GetDamagedEngineSides_ADDR);
        Stats s;
        stats_init(s, name);
        swrRace *r = racer_pair[0];
        std::memset(r, 0, sizeof(swrRace));
        for (int i = 0; i < VERIFY_ITERATIONS / 10; i++) {
            for (int k = 0; k < 6; k++)
                r->engineStatus[k] = (next_u32() % 3u == 0) ? (next_u32() & 0x3fu) : 0;
            char desc[64];
            std::snprintf(desc, sizeof(desc), "status=%x,%x,%x,%x,%x,%x", r->engineStatus[0],
                          r->engineStatus[1], r->engineStatus[2], r->engineStatus[3],
                          r->engineStatus[4], r->engineStatus[5]);
            record_int(s, (int) swrRace_GetDamagedEngineSides(r), (int) retail(r), desc);
        }
        report(s);
    }

    void run_take_damage() {
        const char *name = "swrRace_TakeDamage";
        if (!testable(name, swrRace_TakeDamage_ADDR))
            return;
        const V_take_damage retail = (V_take_damage) hook_retail_ptr(swrRace_TakeDamage_ADDR);
        const unsigned int saved_invincible = swrRace_IsInvincible;
        Stats s;
        stats_init(s, name);
        swrRace *ours = racer_pair[0];
        swrRace *ret = racer_pair[1];
        static const uint32_t flag0[] = {0, swrObjTest_FLAG0_BOOSTING,
                                         swrObjTest_FLAG0_RESPAWN_INVINC, swrObjTest_FLAG0_DEAD};
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            swrRace_IsInvincible = (i % 16 == 15) ? 1u : 0u;
            std::memset(ours, 0, sizeof(swrRace));
            ours->flags0 = (swrObjTest_FLAG0) flag0[i % 4];
            ours->flags1 = (swrObjTest_FLAG1) ((i / 4) % 5 == 4 ? swrObjTest_FLAG1_FINISHED : 0);
            ours->podStats.damageImmunity = next_float(0.0f, 2.0f);
            for (int k = 0; k < 6; k++) {
                ours->engineHealth[k] = next_float(0.0f, 1.0f);
                ours->engineHealthMin[k] = next_float(0.0f, 1.0f);
                ours->engineStatus[k] = next_u32() & 0x1fu;
            }
            ours->totalDamage = next_float(0.0f, 100.0f);
            std::memcpy(ret, ours, sizeof(swrRace));
            const int engine = (int) (next_u32() % 6u);
            const float amount = next_float(0.0f, 1.5f);
            swrRace_TakeDamage((int) ours, engine, amount);
            retail((int) ret, engine, amount);
            char desc[96];
            std::snprintf(desc, sizeof(desc), "engine=%d amount=%.9g flags0=0x%x inv=%u", engine,
                          amount, (unsigned) ret->flags0, swrRace_IsInvincible);
            record_racer(s, *ours, *ret, desc);
        }
        swrRace_IsInvincible = saved_invincible;
        report(s);
    }

    void run_boost_bar_color() {
        const char *name = "swrRace_GetBoostBarColor";
        if (!testable(name, swrRace_GetBoostBarColor_ADDR))
            return;
        const V_boost_bar retail = (V_boost_bar) hook_retail_ptr(swrRace_GetBoostBarColor_ADDR);
        Stats s;
        stats_init(s, name);
        swrRace *r = racer_pair[0];
        std::memset(r, 0, sizeof(swrRace));
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            r->boostIndicatorStatus = (uint32_t) (i % 4);
            r->speedValue = next_float(0.0f, 1200.0f);
            r->podStats.maxSpeed = next_float(100.0f, 1000.0f);
            r->boostChargeTimer = next_float(0.0f, 2.0f);
            uint8_t our_rgb[3], ret_rgb[3], our_rgba[4], ret_rgba[4];
            float our_fill = -12345.0f, ret_fill = -12345.0f;
            swrRace_GetBoostBarColor(r, our_rgb, our_rgba, &our_fill);
            retail(r, ret_rgb, ret_rgba, &ret_fill);
            char desc[96];
            std::snprintf(desc, sizeof(desc), "status=%u speed=%.9g max=%.9g",
                          r->boostIndicatorStatus, r->speedValue, r->podStats.maxSpeed);
            record(s, our_fill, ret_fill, 0, desc);
            record_int(s, std::memcmp(our_rgb, ret_rgb, 3), 0, desc);
            record_int(s, std::memcmp(our_rgba, ret_rgba, 4), 0, desc);
        }
        report(s);
    }

    void run_closest_approach_2d() {
        const char *name = "swrRace_ClosestApproach2D";
        if (!testable(name, swrRace_ClosestApproach2D_ADDR))
            return;
        const F_closest retail = (F_closest) hook_retail_ptr(swrRace_ClosestApproach2D_ADDR);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            rdVector2 a0 = random_vec2(i, -1000.0f, 1000.0f);
            rdVector2 b0 = random_vec2(i + 19, -1000.0f, 1000.0f);
            // Pods move a few units per tick; every 8th case moves in parallel, which hits the
            // near-zero relative-velocity early-out.
            rdVector2 da = random_vec2(i + 7, -20.0f, 20.0f);
            rdVector2 db = (i % 8 == 0) ? da : random_vec2(i + 29, -20.0f, 20.0f);
            float a1[2] = {a0.x + da.x, a0.y + da.y};
            float b1[2] = {b0.x + db.x, b0.y + db.y};
            rdVector2 o[4], r[4];
            for (int k = 0; k < 4; k++)
                o[k] = r[k] = rdVector2{-12345.0f, -12345.0f};
            const float ot = swrRace_ClosestApproach2D(&a0, a1, &b0, b1, &o[0], &o[1], &o[2], &o[3]);
            const float rt = retail(&a0, a1, &b0, b1, &r[0], &r[1], &r[2], &r[3]);
            char desc[96];
            std::snprintf(desc, sizeof(desc), "a0=(%.9g, %.9g) da=(%.9g, %.9g)", a0.x, a0.y, da.x,
                          da.y);
            record(s, ot, rt, 0, desc);
            record_floats(s, &o[0].x, &r[0].x, 8, 0, desc);
        }
        report(s);
    }


    // Side-effecting callees (RNG, sound, rumble, Explode) are jmp-patched at BOTH entries to
    // recording stubs for a case, so both sides share scripted RNG and SFX-flag state and log
    // every call. Original bytes, including any Detours jump, are restored afterwards.
    struct EntryPatch {
        uint8_t *at;
        uint8_t saved[5];
    };

    void write_code(uint8_t *at, const uint8_t *bytes) {
        DWORD old;
        VirtualProtect(at, 5, PAGE_EXECUTE_READWRITE, &old);
        std::memcpy(at, bytes, 5);
        VirtualProtect(at, 5, old, &old);
        FlushInstructionCache(GetCurrentProcess(), at, 5);
    }

    void patch_jmp(EntryPatch &p, void *at, void *to) {
        p.at = (uint8_t *) at;
        std::memcpy(p.saved, p.at, 5);
        uint8_t jmp[5] = {0xe9};
        const int32_t rel = (int32_t) ((uintptr_t) to - ((uintptr_t) at + 5));
        std::memcpy(jmp + 1, &rel, 4);
        write_code(p.at, jmp);
    }

    void unpatch(EntryPatch &p) {
        write_code(p.at, p.saved);
    }

    struct CallLog {
        uint32_t words[64];
        int count;
        uint32_t rng_state;
        int rng_calls;
        uint32_t sfx_flags;
        const swrRace *racer;
    };

    CallLog *active_log = nullptr;

    void log_word(uint32_t w) {
        if (active_log->count < 64)
            active_log->words[active_log->count] = w;
        active_log->count++;
    }

    uint32_t float_bits(float f) {
        uint32_t u;
        std::memcpy(&u, &f, 4);
        return u;
    }

    // Pointers into the racer are logged as offsets, so the two copies compare equal.
    uint32_t racer_offset(const void *p) {
        return (uint32_t) ((const uint8_t *) p - (const uint8_t *) active_log->racer);
    }

    int stub_rand(void) {
        active_log->rng_calls++;
        active_log->rng_state = active_log->rng_state * 1103515245u + 12345u;
        return (int) (active_log->rng_state >> 1);
    }
    int stub_play_force(int id, int a, int b, int c) {
        log_word(0xf0000000u | (uint32_t) id);
        log_word((uint32_t) a), log_word((uint32_t) b), log_word((uint32_t) c);
        return 0;
    }
    int stub_stop_force(int id) {
        log_word(0xf1000000u | (uint32_t) id);
        return 0;
    }
    unsigned int stub_test_sfx(int index, unsigned int mask) {
        log_word(0xe0000000u | ((uint32_t) index & 0xffff));
        return active_log->sfx_flags & mask;
    }
    void stub_set_sfx(int index, unsigned int mask) {
        log_word(0xe1000000u | ((uint32_t) index & 0xffff));
        active_log->sfx_flags |= mask;
    }
    void stub_clear_sfx(int index, unsigned int mask) {
        log_word(0xe2000000u | ((uint32_t) index & 0xffff));
        active_log->sfx_flags &= ~mask;
    }
    int stub_play_random_sfx(int category, int variant, int s1, int s2, int s3, int s4, int s5,
                                    rdVector3 *pos) {
        log_word(0xd0000000u | (uint32_t) category);
        log_word((uint32_t) variant), log_word((uint32_t) s1), log_word((uint32_t) s2);
        log_word((uint32_t) s3), log_word((uint32_t) s4), log_word((uint32_t) s5);
        log_word(racer_offset(pos));
        return 0;
    }
    void stub_play_spatial(int id, short p2, float p3, float gain, rdVector3 *pos, int p6,
                                  unsigned int flags, float min_dist, float max_dist) {
        log_word(0xd1000000u | (uint32_t) id);
        log_word((uint32_t) p2), log_word(float_bits(p3)), log_word(float_bits(gain));
        log_word(racer_offset(pos)), log_word((uint32_t) p6), log_word(flags);
        log_word(float_bits(min_dist)), log_word(float_bits(max_dist));
    }
    void stub_explode(swrRace *player, char side) {
        log_word(0xc0000000u | (uint8_t) side);
        log_word(racer_offset(player));
    }

    struct SideEffectPatches {
        EntryPatch p[18];
        int n = 0;

        void both(void *ours, uint32_t retail_addr, void *stub) {
            patch_jmp(p[n++], hook_retail_ptr(retail_addr), stub);
            patch_jmp(p[n++], ours, stub);
        }

        SideEffectPatches() {
            both((void *) swrUtils_Rand, swrUtils_Rand_ADDR, (void *) stub_rand);
            both((void *) swrControl_PlayForceEffect, swrControl_PlayForceEffect_ADDR,
                 (void *) stub_play_force);
            both((void *) swrControl_StopForceEffect, swrControl_StopForceEffect_ADDR,
                 (void *) stub_stop_force);
            both((void *) swrSound_TestSfxFlag, swrSound_TestSfxFlag_ADDR, (void *) stub_test_sfx);
            both((void *) swrSound_SetSfxFlag, swrSound_SetSfxFlag_ADDR, (void *) stub_set_sfx);
            both((void *) swrSound_ClearSfxFlag, swrSound_ClearSfxFlag_ADDR,
                 (void *) stub_clear_sfx);
            both((void *) swrSound_PlayRandomSfx, swrSound_PlayRandomSfx_ADDR,
                 (void *) stub_play_random_sfx);
            both((void *) swrSound_PlaySpatialRange, swrSound_PlaySpatialRange_ADDR,
                 (void *) stub_play_spatial);
            both((void *) swrRace_Explode, swrRace_Explode_ADDR, (void *) stub_explode);
        }

        ~SideEffectPatches() {
            while (n > 0)
                unpatch(p[--n]);
        }
    };

    void record_calls(Stats &s, const CallLog &ours, const CallLog &retail, const char *desc) {
        char d[200];
        std::snprintf(d, sizeof(d), "%s [calls]", desc);
        int same = ours.count == retail.count && ours.rng_calls == retail.rng_calls &&
                   ours.sfx_flags == retail.sfx_flags;
        const int n = ours.count < 64 ? ours.count : 64;
        for (int k = 0; same && k < n; k++)
            same = ours.words[k] == retail.words[k];
        if (!same) {
            std::snprintf(d, sizeof(d), "%s [calls ours=%d rng=%d sfx=%x, retail=%d rng=%d sfx=%x]",
                          desc, ours.count, ours.rng_calls, ours.sfx_flags, retail.count,
                          retail.rng_calls, retail.sfx_flags);
        }
        record_int(s, same, 1, d);
    }

    void begin_log(CallLog &log, const swrRace *racer, uint32_t seed, uint32_t sfx_flags) {
        std::memset(&log, 0, sizeof(log));
        log.rng_state = seed;
        log.sfx_flags = sfx_flags;
        log.racer = racer;
        active_log = &log;
    }

    struct InputGuard {
        float thrust, throttle, pitch, boost;
        InputGuard()
            : thrust(swrRace_ThrustInput), throttle(swrRace_ThrottleInput),
              pitch(swrRace_PitchInput), boost(swrRace_BoostInput) {}
        ~InputGuard() {
            swrRace_ThrustInput = thrust;
            swrRace_ThrottleInput = throttle;
            swrRace_PitchInput = pitch;
            swrRace_BoostInput = boost;
        }
    };

    using V_racer = void (*)(swrRace *);
    using I_int = int (*)(int);

    // Damage values cluster around the thresholds the body branches on: 0.5 (repair target),
    // half the peak (repair start) and 1.0 (destroyed).
    float sample_damage() {
        switch (next_u32() % 6u) {
            case 0:
                return 0.0f;
            case 1:
                return 1.0f;
            case 2:
                return 0.5f;
            case 3:
                return next_float(0.95f, 1.05f);
            default:
                return next_float(0.0f, 1.0f);
        }
    }

    void run_repair() {
        const char *name = "swrRace_Repair";
        if (!testable(name, swrRace_Repair_ADDR))
            return;
        const V_racer retail = (V_racer) hook_retail_ptr(swrRace_Repair_ADDR);
        DeltaGuard guard;
        Stats s;
        stats_init(s, name);
        swrRace *ours = racer_pair[0];
        swrRace *ret = racer_pair[1];
        swrScore score;
        int pilot = 5;
        std::memset(&score, 0, sizeof(score));
        score.sfxChannel = 3;
        score.pilotId = &pilot;
        SideEffectPatches patches;
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            swrRace_deltaTimeSecs = sample_delta(i);
            std::memset(ours, 0, sizeof(swrRace));
            ours->score_ptr = &score;
            uint32_t f0 = 0;
            if (next_u32() % 3u == 0)
                f0 |= swrObjTest_FLAG0_REPAIRING;
            if (next_u32() % 2u == 0)
                f0 |= swrObjTest_FLAG0_LOCAL;
            if (next_u32() % 4u == 0)
                f0 |= swrObjTest_FLAG0_WAS_BOOSTING;
            ours->flags0 = (swrObjTest_FLAG0) f0;
            ours->flags1 = (swrObjTest_FLAG1) (next_u32() % 4u == 0 ? swrObjTest_FLAG1_ON_LAVA : 0);
            ours->repairTimer = next_float(-0.2f, 0.2f);
            ours->damageWarningTimer = next_float(-1.0f, 10.0f);
            ours->podStats.repairRate = next_float(0.0f, 1.0f);
            for (int k = 0; k < 6; k++) {
                ours->engineHealth[k] = sample_damage();
                ours->engineHealthMin[k] = sample_damage();
                ours->engineStatus[k] = next_u32() & 0x1fu;
            }
            std::memcpy(ret, ours, sizeof(swrRace));
            const uint32_t seed = next_u32();
            const uint32_t sfx = (next_u32() % 2u) ? swrSound_SFXFLAG_REPAIRING : 0u;

            CallLog our_log, ret_log;
            begin_log(our_log, ours, seed, sfx);
            swrRace_Repair(ours);
            begin_log(ret_log, ret, seed, sfx);
            retail(ret);
            active_log = nullptr;

            char desc[128];
            std::snprintf(desc, sizeof(desc), "case %d flags0=0x%x dt=%.9g timer=%.9g", i, f0,
                          swrRace_deltaTimeSecs, ret->repairTimer);
            record_racer(s, *ours, *ret, desc);
            record_calls(s, our_log, ret_log, desc);
        }
        report(s);
    }

    void run_boost_charge() {
        const char *name = "swrRace_BoostCharge";
        if (!testable(name, swrRace_BoostCharge_ADDR))
            return;
        const I_int retail = (I_int) hook_retail_ptr(swrRace_BoostCharge_ADDR);
        DeltaGuard guard;
        InputGuard inputs;
        Stats s;
        stats_init(s, name);
        swrRace *ours = racer_pair[0];
        swrRace *ret = racer_pair[1];
        static const float pitches[] = {0.0f, 0.7f, 0.70000005f, 0.69999999f, 1.0f, -1.0f};
        static const float throttles[] = {0.0f, 0.6f, 0.60000002f, 1.0f};
        SideEffectPatches patches;
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            swrRace_deltaTimeSecs = sample_delta(i);
            std::memset(ours, 0, sizeof(swrRace));
            uint32_t f0 = next_u32() % 5u ? swrObjTest_FLAG0_CAN_CHARGE_BOOST : 0;
            if (next_u32() % 6u == 0)
                f0 |= swrObjTest_FLAG0_BOOSTING;
            if (next_u32() % 2u == 0)
                f0 |= swrObjTest_FLAG0_BOOST_OVERDRIVE;
            ours->flags0 = (swrObjTest_FLAG0) f0;
            ours->boostIndicatorStatus = next_u32() % 4u;
            const uint32_t status0 = ours->boostIndicatorStatus;
            // Near 1.0 so a single tick's add straddles the ready threshold.
            ours->boostChargeTimer = next_u32() % 2u ? next_float(0.9f, 1.0f) : next_float(0.0f, 1.0f);
            std::memcpy(ret, ours, sizeof(swrRace));
            swrRace_ThrustInput = next_u32() % 2u ? 0.0f : 1.0f;
            swrRace_ThrottleInput = throttles[next_u32() % 4u];
            swrRace_PitchInput = next_u32() % 3u ? pitches[next_u32() % 6u] : next_float(-1.0f, 1.0f);
            swrRace_BoostInput = next_u32() % 2u ? 0.0f : next_float(0.0f, 2.0f);
            const uint32_t seed = next_u32();

            CallLog our_log, ret_log;
            begin_log(our_log, ours, seed, 0);
            const int our_r = swrRace_BoostCharge((int) ours);
            begin_log(ret_log, ret, seed, 0);
            const int ret_r = retail((int) ret);
            active_log = nullptr;

            char desc[160];
            std::snprintf(desc, sizeof(desc),
                          "status=%u flags0=0x%x thrust=%.9g throttle=%.9g pitch=%.9g boost=%.9g",
                          status0, f0, swrRace_ThrustInput, swrRace_ThrottleInput,
                          swrRace_PitchInput, swrRace_BoostInput);
            record_int(s, our_r, ret_r, desc);
            record_racer(s, *ours, *ret, desc);
            record_calls(s, our_log, ret_log, desc);
        }
        report(s);
    }


    void stub_dispatch_sub_events(void *obj, int *sub_events) {
        log_word(0xb0000000u);
        log_word(racer_offset(obj));
        log_word((uint32_t) sub_events[0]), log_word((uint32_t) sub_events[1]);
        log_word((uint32_t) sub_events[2]);
    }

    void stub_spawn_engine_fireball(swrRace *player, int slot, rdVector3 *pos, float scale) {
        log_word(0xb1000000u | (uint32_t) slot);
        log_word(racer_offset(player));
        log_word(float_bits(pos->x)), log_word(float_bits(pos->y)), log_word(float_bits(pos->z));
        log_word(float_bits(scale));
    }

    struct PhysicsPatches {
        SideEffectPatches base;
        EntryPatch p[4];

        PhysicsPatches() {
            patch_jmp(p[0], hook_retail_ptr(swrEvent_DispatchSubEvents_ADDR),
                      (void *) stub_dispatch_sub_events);
            patch_jmp(p[1], (void *) swrEvent_DispatchSubEvents, (void *) stub_dispatch_sub_events);
            patch_jmp(p[2], hook_retail_ptr(swrRace_SpawnEngineFireball_ADDR),
                      (void *) stub_spawn_engine_fireball);
            patch_jmp(p[3], (void *) swrRace_SpawnEngineFireball,
                      (void *) stub_spawn_engine_fireball);
        }

        ~PhysicsPatches() {
            for (int k = 3; k >= 0; k--)
                unpatch(p[k]);
        }
    };

    void record_ld(Stats &s, long double ours, long double retail, const char *input_desc) {
        s.total++;
        if (std::memcmp(&ours, &retail, 10) == 0) {
            s.exact++;
            return;
        }
        s.mismatch++;
        if (s.first_fail[0] == '\0') {
            std::snprintf(s.first_fail, sizeof(s.first_fail), "%s -> ours=%.21Lg retail=%.21Lg",
                          input_desc, ours, retail);
        }
    }

    // Per-case outputs that live outside the racer (out-params, return value).
    struct RacerOut {
        float ret;
        float extra[3];
        long double ret_ld;
    };

    // Shared driver for racer-state functions: `fill` randomises a zeroed racer (and any
    // per-case arguments it captures), `invoke` calls one side and writes its outputs.
    template <typename Fn, typename Fill, typename Invoke>
    void run_racer(const char *name, uint32_t retail_addr, Fn ours_fn, Fill fill, Invoke invoke) {
        if (!testable(name, retail_addr))
            return;
        const Fn retail_fn = (Fn) hook_retail_ptr(retail_addr);
        DeltaGuard guard;
        Stats s;
        stats_init(s, name);
        swrRace *ours = racer_pair[0];
        swrRace *ret = racer_pair[1];
        swrScore score;
        int pilot = 5;
        std::memset(&score, 0, sizeof(score));
        score.pilotId = &pilot;
        PhysicsPatches patches;
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            swrRace_deltaTimeSecs = sample_delta(i);
            score.flag = (next_u32() % 4u == 0) ? 8 : 0;
            std::memset(ours, 0, sizeof(swrRace));
            ours->score_ptr = &score;
            char desc[160];
            std::snprintf(desc, sizeof(desc), "case %d dt=%.9g", i, swrRace_deltaTimeSecs);
            fill(*ours, i, desc);
            std::memcpy(ret, ours, sizeof(swrRace));
            const uint32_t seed = next_u32();

            RacerOut our_out = {-12345.0f, {-12345.0f, -12345.0f, -12345.0f}, 0.0L};
            RacerOut ret_out = our_out;
            CallLog our_log, ret_log;
            begin_log(our_log, ours, seed, 0);
            invoke(ours_fn, ours, our_out);
            begin_log(ret_log, ret, seed, 0);
            invoke(retail_fn, ret, ret_out);
            active_log = nullptr;

            record(s, our_out.ret, ret_out.ret, 0, desc);
            record_floats(s, our_out.extra, ret_out.extra, 3, 0, desc);
            record_ld(s, our_out.ret_ld, ret_out.ret_ld, desc);
            record_racer(s, *ours, *ret, desc);
            record_calls(s, our_log, ret_log, desc);
        }
        report(s);
    }

    uint32_t random_bits(uint32_t mask) {
        return next_u32() & mask;
    }

    void random_podstats(swrRace &r) {
        r.podStats.acceleration = next_float(0.1f, 3.0f);
        r.podStats.maxSpeed = next_float(300.0f, 650.0f);
        r.podStats.airBrakeInv = next_float(1.0f, 100.0f);
        r.podStats.deceleration_interval = next_float(1.0f, 100.0f);
        r.podStats.boost_thrust = next_float(0.0f, 300.0f);
        r.podStats.heatRate = next_float(0.0f, 50.0f);
        r.podStats.coolRate = next_float(0.0f, 50.0f);
        r.podStats.hoverHeight = next_float(1.0f, 10.0f);
        r.podStats.intersectRadius = next_float(1.0f, 10.0f);
    }

    // An ST0 return that callers consume unrounded: all 80 bits must match, not just the
    // float a caller would eventually store.
    using LD_ff = long double (*)(float, float);


    void run_ld_ff(const char *name, uint32_t retail_addr, LD_ff ours, float lo, float hi) {
        if (!testable(name, retail_addr))
            return;
        const LD_ff retail = (LD_ff) hook_retail_ptr(retail_addr);
        Stats s;
        stats_init(s, name);
        for (int i = 0; i < VERIFY_ITERATIONS; i++) {
            const float a = sample(i, lo, hi);
            const float b = sample(i + 7, lo, hi);
            char desc[64];
            std::snprintf(desc, sizeof(desc), "(%.9g, %.9g)", a, b);
            record_ld(s, ours(a, b), retail(a, b), desc);
        }
        report(s);
    }

    using F_racer_speed = float (*)(swrRace *);
    using LD_racer = long double (*)(swrRace *);
    using V_racer_only = void (*)(swrRace *);
    using V_glide = void (*)(swrRace *, rdVector3 *, rdVector3 *, int);
    using V_reset_input = void (*)(swrRace *, int);
    using V_gravity = void (*)(swrRace *, float *, float);
    using V_wall = void (*)(swrRace *, rdVector3 *, rdVector3 *);

    void run_physics_suite() {
        run_racer(
            "swrRace_UpdateSpeed", swrRace_UpdateSpeed_ADDR, (F_racer_speed) swrRace_UpdateSpeed,
            [](swrRace &r, int i, char *) {
                random_podstats(r);
                static const float throttles[] = {0.1f, -0.1f, 0.99f, -0.6f, 1.0f, -1.0f, 0.0f};
                r.throttle = (i % 3 == 0) ? throttles[next_u32() % 7u] : next_float(-1.0f, 1.0f);
                r.accelThrust = next_float(-3.0f, 12.0f);
                r.speedMultiplier = next_float(0.5f, 1.5f);
                r.groundToPodMeasure = next_u32() % 2u ? 15.0f : next_float(0.0f, 30.0f);
                r.surfaceSpeedFactor = next_u32() % 2u ? 1.0f : next_float(0.3f, 1.2f);
                r.surfaceSpeedBonus = next_u32() % 3u ? 0.0f : next_float(-50.0f, 50.0f);
                r.pitch = next_u32() % 2u ? -1.0f : next_float(-1.0f, 1.0f);
                r.flags0 = (swrObjTest_FLAG0) random_bits(swrObjTest_FLAG0_BOOSTING | swrObjTest_FLAG0_BRAKING |
                                                          swrObjTest_FLAG0_ZOFF | swrObjTest_FLAG0_AI);
                r.flags1 = (swrObjTest_FLAG1) random_bits(swrObjTest_FLAG1_BOOST_START | swrObjTest_FLAG1_GROUNDED |
                                                          swrObjTest_FLAG1_FINISHED);
            },
            [](F_racer_speed fn, swrRace *r, RacerOut &o) { o.ret = fn(r); });

        run_racer(
            "swrRace_ApplyBoost", swrRace_ApplyBoost_ADDR, (LD_racer) swrRace_ApplyBoost,
            [](swrRace &r, int, char *) {
                random_podstats(r);
                r.boostValue = next_u32() % 4u ? next_float(0.0f, 3.0f) : next_float(0.0f, 0.002f);
                r.flags0 = (swrObjTest_FLAG0) random_bits(swrObjTest_FLAG0_BOOSTING | swrObjTest_FLAG0_BRAKING);
            },
            [](LD_racer fn, swrRace *r, RacerOut &o) { o.ret_ld = fn(r); });

        run_racer(
            "swrRace_ApplyEngineDamage", swrRace_ApplyEngineDamage_ADDR,
            (V_racer_only) swrRace_ApplyEngineDamage,
            [](swrRace &r, int, char *) {
                r.podStats.damageImmunity = next_float(0.0f, 2.0f);
                for (int k = 0; k < 6; k++) {
                    r.engineStatus[k] = next_u32() % 3u == 0 ? random_bits(0x1f) : 0;
                    r.engineHealth[k] = next_float(0.0f, 1.0f);
                    r.engineHealthMin[k] = next_float(0.0f, 1.0f);
                }
                r.flags0 = (swrObjTest_FLAG0) random_bits(swrObjTest_FLAG0_BOOSTING);
            },
            [](V_racer_only fn, swrRace *r, RacerOut &o) {
                active_log->sfx_flags = (active_log->rng_state & 1) ? swrSound_SFXFLAG_ENGINE_FIRE : 0;
                fn(r);
                o.ret = 0.0f;
            });

        run_racer(
            "swrRace_UpdateHeat", swrRace_UpdateHeat_ADDR, (V_racer_only) swrRace_UpdateHeat,
            [](swrRace &r, int, char *) {
                random_podstats(r);
                r.engineTemp = next_u32() % 3u ? next_float(-1.0f, 2.0f) : next_float(0.0f, 101.0f);
                r.tiltManualMult = next_float(-1.0f, 1.0f);
                for (int k = 0; k < 6; k++)
                    r.engineStatus[k] = random_bits(0x8);
                r.flags0 = (swrObjTest_FLAG0) random_bits(swrObjTest_FLAG0_BOOSTING);
                r.flags1 = (swrObjTest_FLAG1) random_bits(swrObjTest_FLAG1_ON_LAVA);
            },
            [](V_racer_only fn, swrRace *r, RacerOut &o) {
                fn(r);
                o.ret = 0.0f;
            });

        static float gravity_b;
        run_racer(
            "swrRace_ApplyGravity", swrRace_ApplyGravity_ADDR, (V_gravity) swrRace_ApplyGravity,
            [](swrRace &r, int i, char *desc) {
                random_podstats(r);
                static const float heights[] = {12.0f, 30.0f, 99999.0f, 100000.0f, 0.0f};
                gravity_b = (i % 3 == 0) ? heights[next_u32() % 5u] : next_float(-5.0f, 60.0f);
                r.world_gravity = rdVector3{0.0f, 0.0f, -1.0f};
                r.up = random_vec3(i, -1.0f, 1.0f);
                r.transform.vA.z = next_float(-1.0f, 1.0f);
                r.collisionWidth = next_float(0.0f, 20.0f);
                r.fallTimer = next_float(0.0f, 4.0f);
                r.fallVelocity = next_float(-3.0f, 3.0f);
                r.gravityScale = next_float(0.0f, 2.0f);
                r.speedValue = next_float(-100.0f, 600.0f);
                r.pitch = next_float(-1.0f, 1.0f);
                r.flags0 = (swrObjTest_FLAG0) random_bits(swrObjTest_FLAG0_HIT_BOTTOM);
                r.flags1 = (swrObjTest_FLAG1) random_bits(swrObjTest_FLAG1_MAGNET | swrObjTest_FLAG1_AIRBORNE);
                std::snprintf(desc + std::strlen(desc), 40, " b=%.9g", gravity_b);
            },
            [](V_gravity fn, swrRace *r, RacerOut &o) {
                o.extra[0] = 1.0f, o.extra[1] = -2.0f, o.extra[2] = 3.0f;
                fn(r, o.extra, gravity_b);
                o.ret = 0.0f;
            });

        static rdVector3 wall_normal, wall_dir;
        run_racer(
            "swrRace_ApplyWallCollision", swrRace_ApplyWallCollision_ADDR,
            (V_wall) swrRace_ApplyWallCollision,
            [](swrRace &r, int i, char *) {
                random_rotation(r.transform, i);
                r.world_gravity = rdVector3{0.0f, 0.0f, -1.0f};
                wall_normal = random_vec3(i, -1.0f, 1.0f);
                wall_dir = random_vec3(i + 5, -1.0f, 1.0f);
                if (i % 4 == 0)
                    wall_dir = rdVector3{r.transform.vB.x, r.transform.vB.y, r.transform.vB.z};
                r.speedValue = next_float(0.0f, 600.0f);
                r.accelThrust = next_float(0.0f, 10.0f);
                r.velocityCollision = random_vec3(i + 9, -50.0f, 50.0f);
                r.flags0 = (swrObjTest_FLAG0) random_bits(swrObjTest_FLAG0_THROTTLE_SETTLED | swrObjTest_FLAG0_RESPAWN |
                                                          swrObjTest_FLAG0_DEAD);
                r.flags1 = (swrObjTest_FLAG1) random_bits(swrObjTest_FLAG1_MAGNET);
            },
            [](V_wall fn, swrRace *r, RacerOut &o) {
                rdVector3 n = wall_normal, d = wall_dir;
                fn(r, &n, &d);
                o.extra[0] = n.x, o.extra[1] = n.y, o.extra[2] = n.z;
                o.ret = 0.0f;
            });

        static rdVector3 spline_pos;
        static int use_clearance;
        run_racer(
            "swrRace_UpdateAIGlidePitch", swrRace_UpdateAIGlidePitch_ADDR,
            (V_glide) swrRace_UpdateAIGlidePitch,
            [](swrRace &r, int i, char *) {
                r.transform.vD.z = next_float(-100.0f, 100.0f);
                spline_pos = random_vec3(i, -100.0f, 100.0f);
                if (i % 5 == 0)
                    spline_pos.z = r.transform.vD.z;
                use_clearance = (int) (next_u32() % 2u);
                static const float clearances[] = {400.0f, 400.00003f, 399.99997f, 0.0f};
                r.groundToPodMeasure = next_u32() % 2u ? clearances[next_u32() % 4u] : next_float(0.0f, 800.0f);
                r.flags1 = (swrObjTest_FLAG1) random_bits(swrObjTest_FLAG1_AIRBORNE);
            },
            [](V_glide fn, swrRace *r, RacerOut &o) {
                rdVector3 look = {0.0f, 0.0f, 0.0f}, sp = spline_pos;
                fn(r, &look, &sp, use_clearance);
                o.ret = 0.0f;
            });

        static swrModel_Node *fake_nodes[6];
        run_racer(
            "swrRace_ApplyPartSinkOffset", swrRace_ApplyPartSinkOffset_ADDR,
            (V_racer_only) swrRace_ApplyPartSinkOffset,
            [](swrRace &r, int, char *) {
                r.unk11_1 = next_float(-5.0f, 5.0f);
                for (int k = 0; k < 6; k++)
                    fake_nodes[k] = next_u32() % 3u ? (swrModel_Node *) &fake_nodes : nullptr;
                r.partNodes = next_u32() % 6u ? fake_nodes : nullptr;
                r.engineXfR.vD.z = next_float(-50.0f, 50.0f);
                r.engineXfL.vD.z = next_float(-50.0f, 50.0f);
                r.engineXfR2.vD.z = next_float(-50.0f, 50.0f);
                r.engineXfL2.vD.z = next_float(-50.0f, 50.0f);
                r.cockpitXf.vD.z = next_float(-50.0f, 50.0f);
            },
            [](V_racer_only fn, swrRace *r, RacerOut &o) {
                fn(r);
                o.ret = 0.0f;
            });

        static int reset_index;
        const int saved_inputs[4] = {inRaceLocalPlayerInputBitset3[0], inRaceLocalPlayerInputBitset3[1],
                                     inRaceLocalPlayerInputBitset3[2], inRaceLocalPlayerInputBitset3[3]};
        run_racer(
            "swrRace_CheckResetInput", swrRace_CheckResetInput_ADDR,
            (V_reset_input) swrRace_CheckResetInput,
            [](swrRace &r, int, char *) {
                reset_index = (int) (next_u32() % 4u);
                for (int k = 0; k < 4; k++)
                    inRaceLocalPlayerInputBitset3[k] = (int) next_u32();
                r.flags0 = (swrObjTest_FLAG0) random_bits(swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_LOCAL);
            },
            [](V_reset_input fn, swrRace *r, RacerOut &o) {
                fn(r, reset_index);
                o.ret = 0.0f;
            });
        for (int k = 0; k < 4; k++)
            inRaceLocalPlayerInputBitset3[k] = saved_inputs[k];

        run_racer(
            "swrRace_ResetGravityDown", swrRace_ResetGravityDown_ADDR,
            (V_racer_only) swrRace_ResetGravityDown,
            [](swrRace &r, int i, char *) {
                r.gravityScale = next_float(0.0f, 5.0f);
                r.world_gravity = random_vec3(i, -1.0f, 1.0f);
            },
            [](V_racer_only fn, swrRace *r, RacerOut &o) {
                fn(r);
                o.ret = 0.0f;
            });
    }

}// namespace

extern "C" void reimpl_verify_run(FILE *hook_log) {
    verify_log = std::fopen(REIMPL_VERIFY_LOG_FILE, "w");
    if (verify_log == nullptr) {
        std::fprintf(hook_log, "[reimpl_verify] could not open %s\n", REIMPL_VERIFY_LOG_FILE);
        std::fflush(hook_log);
        return;
    }

    std::fprintf(verify_log,
                 "Differential verification of reimplemented functions against retail.\n"
                 "%d cases per function, deterministic inputs (seed 0x%08x).\n"
                 "A case passes only when every single result is bit-identical to retail.\n\n",
                 VERIFY_ITERATIONS, 0x13579bdfu);

    std::fprintf(verify_log, "stdMath\n");

    run_f_f("stdMath_Sqrt", stdMath_Sqrt_ADDR, stdMath_Sqrt, 0.0f, 1.0e6f, 0);
    run_f_f("stdMath_Sqrt_2", stdMath_Sqrt_2_ADDR, stdMath_Sqrt_2, 0.0f, 1.0e6f, 0);
    run_f_f("stdMath_fround", stdMath_fround_ADDR, stdMath_fround, -1.0e6f, 1.0e6f, 0);
    run_i_f("stdMath_FRoundInt", stdMath_FRoundInt_ADDR, stdMath_FRoundInt, -1.0e6f, 1.0e6f);

    // Pure arithmetic, no library calls: these must be bit-identical.
    run_f_f("stdMath_NormalizeAngle", stdMath_NormalizeAngle_ADDR, stdMath_NormalizeAngle, -2000.0f,
            2000.0f, 0);
    run_f_f("stdMath_NormalizeAngleAcute", stdMath_NormalizeAngleAcute_ADDR,
            stdMath_NormalizeAngleAcute, -2000.0f, 2000.0f, 0);
    run_ld_ff("stdMath_Decelerator", stdMath_Decelerator_ADDR, stdMath_Decelerator, -100.0f, 100.0f);
    run_f_fi("stdMath_FlexPower", stdMath_FlexPower_ADDR, stdMath_FlexPower, -10.0f, 10.0f, 8, 0);
    run_v_pffff("stdMath_MultiplyAddClamped", stdMath_MultiplyAddClamped_ADDR,
                stdMath_MultiplyAddClamped, -1000.0f, 1000.0f, 0);
    run_v_pffii("stdMath_AddScaledValueAndClamp_i32", stdMath_AddScaledValueAndClamp_i32_ADDR,
                stdMath_AddScaledValueAndClamp_i32);

    // Polynomial approximations; every coefficient came out of the decompile.
    run_f_f("stdMath_ArcSin", stdMath_ArcSin_ADDR, stdMath_ArcSin, -1.2f, 1.2f, 0);
    run_f_f("stdMath_ArcCos", stdMath_ArcCos_ADDR, stdMath_ArcCos, -1.2f, 1.2f, 0);
    run_f_f("stdMath_ArcSin3", stdMath_ArcSin3_ADDR, stdMath_ArcSin3, -1.0f, 1.0f, 0);
    run_f_ff("stdMath_ArcTan2", stdMath_ArcTan2_ADDR, stdMath_ArcTan2, -1000.0f, 1000.0f, 0);

    run_v_fpp("stdMath_SinCos", stdMath_SinCos_ADDR, stdMath_SinCos, -1000.0f, 1000.0f, 0);
    run_f_f("stdMath_Tan", stdMath_Tan_ADDR, stdMath_Tan, -1000.0f, 1000.0f, 0);

    if (trig_tables_populated()) {
        run_v_fpp("stdMath_SinCosFast", stdMath_SinCosFast_ADDR, stdMath_SinCosFast, -2000.0f,
                  2000.0f, 0);
        run_f_f("stdMath_FastTan", stdMath_FastTan_ADDR, stdMath_FastTan, -2000.0f, 2000.0f, 0);
    } else {
        cases_skipped += 2;
        std::fprintf(verify_log, "  %-36s SKIP   stdMath_SinTable is empty this early in startup\n",
                     "stdMath_SinCosFast/FastTan");
    }

    // rdVector3 is the pod flight model's arithmetic, so a divergence here moves the physics.
    // Plain float expressions, so bit-identical -- except where they route through stdMath_Sqrt.
    std::fprintf(verify_log, "\nrdVector\n");
    run_v_vvv("rdVector_Add3", rdVector_Add3_ADDR, (V_vvv) rdVector_Add3, -1000.0f, 1000.0f, 0);
    run_v_vvv("rdVector_Sub3", rdVector_Sub3_ADDR, (V_vvv) rdVector_Sub3, -1000.0f, 1000.0f, 0);
    run_v_vvv("rdVector_Cross3", rdVector_Cross3_ADDR, rdVector_Cross3, -1000.0f, 1000.0f, 0);
    run_v_vfv("rdVector_Scale3", rdVector_Scale3_ADDR, (V_vfv) rdVector_Scale3, -1000.0f, 1000.0f,
              0);
    run_v_vvfv("rdVector_Scale3Add3", rdVector_Scale3Add3_ADDR, rdVector_Scale3Add3, -1000.0f,
               1000.0f, 0);
    run_f_vv("rdVector_Dot3", rdVector_Dot3_ADDR, rdVector_Dot3, -1000.0f, 1000.0f, 0);
    // Retail narrows dx and dy to 32-bit mid-computation but not dz; the reimpl reproduces that
    // (see rdVector_DistSquared3).
    run_f_vv("rdVector_DistSquared3", rdVector_DistSquared3_ADDR, rdVector_DistSquared3, -1000.0f,
             1000.0f, 0);
    run_f_v("rdVector_Len3", rdVector_Len3_ADDR, rdVector_Len3, -1000.0f, 1000.0f, 0);
    run_f_vv("rdVector_Dist3", rdVector_Dist3_ADDR, rdVector_Dist3, -1000.0f, 1000.0f, 0);
    run_f_vacc("rdVector_Normalize3Acc", rdVector_Normalize3Acc_ADDR, rdVector_Normalize3Acc,
               -1000.0f, 1000.0f, 0);
    run_f_vacc("rdVector_Normalize3Acc_2", rdVector_Normalize3Acc_2_ADDR, rdVector_Normalize3Acc_2,
               -1000.0f, 1000.0f, 0);

    std::fprintf(verify_log, "\nrdMath\n");
    run_v4vvv("rdMath_CalcSurfaceNormal2", rdMath_CalcSurfaceNormal2_ADDR,
              rdMath_CalcSurfaceNormal2, -100.0f, 100.0f, 0);
    run_vvvv("rdMath_CalcSurfaceNormal", rdMath_CalcSurfaceNormal_ADDR, rdMath_CalcSurfaceNormal,
             -100.0f, 100.0f, 0);
    run_f_vvv("rdMath_DistancePointToPlane", rdMath_DistancePointToPlane_ADDR,
              rdMath_DistancePointToPlane, -100.0f, 100.0f, 0);
    run_i_vvv("rdMath_PointsCollinear", rdMath_PointsCollinear_ADDR, rdMath_PointsCollinear,
              -100.0f, 100.0f);
    run_v_vf_acc("rdMath_ClampVector", rdMath_ClampVector_ADDR, rdMath_ClampVector, -10.0f, 10.0f,
                 0);
    run_slerp("rdMath_SlerpQuaternions", rdMath_SlerpQuaternions_ADDR, rdMath_SlerpQuaternions, 0);
    run_v4v4("rdMath_QuaternionToAxisAngle", rdMath_QuaternionToAxisAngle_ADDR,
             rdMath_QuaternionToAxisAngle, -1.0f, 1.0f, 0);
    run_v4v4("rdMath_AxisAngleToQuaternion", rdMath_AxisAngleToQuaternion_ADDR,
             rdMath_AxisAngleToQuaternion, -1.0f, 1.0f, 0);

    // Pure integer arithmetic -> exact. isPrime trial-divides up to its argument, so keep the
    // range small enough that 20000 cases stay quick.
    std::fprintf(verify_log, "\nstdHashtbl\n");
    run_u_si("stdHashTable_CalculateHash", stdHashTable_CalculateHash_ADDR, stdHashTable_CalculateHash);
    run_i_i("stdHashTable_isPrime", stdHashTable_isPrime_ADDR, stdHashTable_isPrime, -50, 400);
    run_i_i("stdHashTable_nextPrime", stdHashTable_nextPrime_ADDR, stdHashTable_nextPrime, -50, 400);

    std::fprintf(verify_log, "\nrdMatrix\n");
    run_v_m44("rdMatrix_SetIdentity44", rdMatrix_SetIdentity44_ADDR, rdMatrix_SetIdentity44, 0);
    run_v_m44fff("rdMatrix_SetDiagonal44", rdMatrix_SetDiagonal44_ADDR, rdMatrix_SetDiagonal44,
                 -100.0f, 100.0f, 0);
    run_v_m44fff("rdMatrix_SetTranslation44", rdMatrix_SetTranslation44_ADDR,
                 rdMatrix_SetTranslation44, -100.0f, 100.0f, 0);
    run_v_m44fff("rdMatrix_BuildRotation44", rdMatrix_BuildRotation44_ADDR,
                 rdMatrix_BuildRotation44, -720.0f, 720.0f, 0);
    run_v_m44fff("rdMatrix_SetRotation44", rdMatrix_SetRotation44_ADDR, rdMatrix_SetRotation44,
                 -720.0f, 720.0f, 0);
    run_v_m44ffff("rdMatrix_BuildFromVectorAngle44", rdMatrix_BuildFromVectorAngle44_ADDR,
                  rdMatrix_BuildFromVectorAngle44, -1.0f, 1.0f, 0);
    run_v_m44m44("rdMatrix_BuildViewMatrix", rdMatrix_BuildViewMatrix_ADDR,
                 rdMatrix_BuildViewMatrix, 0);
    run_v_m44m34("rdMatrix_Copy44_34", rdMatrix_Copy44_34_ADDR, rdMatrix_Copy44_34, 0);
    run_v_m34v("rdMatrix_BuildRotate34", rdMatrix_BuildRotate34_ADDR, rdMatrix_BuildRotate34,
               -720.0f, 720.0f, 0);
    run_v_m34v("rdMatrix_PreRotate34", rdMatrix_PreRotate34_ADDR, rdMatrix_PreRotate34, -720.0f,
               720.0f, 0);
    run_v_m34v("rdMatrix_PostTranslate34", rdMatrix_PostTranslate34_ADDR, rdMatrix_PostTranslate34,
               -100.0f, 100.0f, 0);
    run_v_m34_outv("rdMatrix_ExtractAngles34", rdMatrix_ExtractAngles34_ADDR,
                   rdMatrix_ExtractAngles34, -1.0f, 1.0f, 0);
    run_v_m44iv("rdMatrix_SetColumn", rdMatrix_SetColumn_ADDR, rdMatrix_SetColumn, true, 0);
    run_v_m44iv("rdMatrix_GetColumn", rdMatrix_GetColumn_ADDR, rdMatrix_GetColumn, false, 0);

    std::fprintf(verify_log, "\nrdVector (round 3)\n");
    run_v2_vvv("rdVector_Add2", rdVector_Add2_ADDR, rdVector_Add2, -1000.0f, 1000.0f);
    run_v2_vfv("rdVector_Scale2", rdVector_Scale2_ADDR, rdVector_Scale2, -1000.0f, 1000.0f);
    run_v_v2v2fv2("rdVector_Scale2Add2", rdVector_Scale2Add2_ADDR, rdVector_Scale2Add2, -1000.0f,
                  1000.0f);
    run_f_v2("rdVector_Len2", rdVector_Len2_ADDR, rdVector_Len2, -1000.0f, 1000.0f);
    run_f_v2acc("rdVector_Normalize2Acc", rdVector_Normalize2Acc_ADDR, rdVector_Normalize2Acc,
                -1000.0f, 1000.0f);
    run_copy3("rdVector_Copy3", rdVector_Copy3_ADDR, rdVector_Copy3);
    run_set3("rdVector_Set3", rdVector_Set3_ADDR, rdVector_Set3);
    run_set4("rdVector_Set4", rdVector_Set4_ADDR, rdVector_Set4);
    run_are_same3("rdVector_AreSame3", rdVector_AreSame3_ADDR, rdVector_AreSame3);
    run_scale3add3_both("rdVector_Scale3Add3_both", rdVector_Scale3Add3_both_ADDR,
                        rdVector_Scale3Add3_both);
    run_point3_to_perspective3("rdVector_Point3ToPerspective3", rdVector_Point3ToPerspective3_ADDR,
                               rdVector_Point3ToPerspective3);

    std::fprintf(verify_log, "\nrdMatrix (round 3)\n");
    run_build_rotation33("rdMatrix_BuildRotation33", rdMatrix_BuildRotation33_ADDR,
                         rdMatrix_BuildRotation33);
    if (trig_tables_populated())
        run_build_rotation34("rdMatrix_BuildRotation34", rdMatrix_BuildRotation34_ADDR,
                             rdMatrix_BuildRotation34);
    run_build_translate34("rdMatrix_BuildTranslate34", rdMatrix_BuildTranslate34_ADDR,
                          rdMatrix_BuildTranslate34);
    run_copy44("rdMatrix_Copy44", rdMatrix_Copy44_ADDR, rdMatrix_Copy44);
    run_invert34("rdMatrix_InvertOrtho34", rdMatrix_InvertOrtho34_ADDR, rdMatrix_InvertOrtho34,
                 false);
    run_invert34("rdMatrix_InvertOrthoNorm34", rdMatrix_InvertOrthoNorm34_ADDR,
                 rdMatrix_InvertOrthoNorm34, true);
    run_to_trans_rot_scale("rdMatrix_ToTransRotScale", rdMatrix_ToTransRotScale_ADDR,
                           rdMatrix_ToTransRotScale);
    run_extract_transform("rdMatrix_ExtractTransform", rdMatrix_ExtractTransform_ADDR,
                          rdMatrix_ExtractTransform);
    run_set_transform44("rdMatrix_SetTransform44", rdMatrix_SetTransform44_ADDR,
                        rdMatrix_SetTransform44);

    std::fprintf(verify_log, "\nstdFnames\n");
    run_s_s("stdFnames_FindMedName", stdFnames_FindMedName_ADDR, stdFnames_FindMedName, false);
    run_s_s("stdFnames_FindExt", stdFnames_FindExt_ADDR, stdFnames_FindExt, false);
    run_s_s("stdFnames_Basename", stdFnames_Basename_ADDR, stdFnames_Basename, false);
    run_s_s("stdFnames_StripExtAndDot", stdFnames_StripExtAndDot_ADDR, stdFnames_StripExtAndDot,
            true);
    run_change_ext("stdFnames_ChangeExt", stdFnames_ChangeExt_ADDR, stdFnames_ChangeExt);
    run_concat("stdFnames_Concat", stdFnames_Concat_ADDR, stdFnames_Concat);
    run_make_path("stdFnames_MakePath", stdFnames_MakePath_ADDR, stdFnames_MakePath);

    std::fprintf(verify_log, "\nswrRace\n");
    run_step_toward_clamped();
    run_set_angle_from_turn_rate();
    run_update_turn();
    run_compute_tilt_angles();
    run_apply_upgrades_to_stats();
    run_compute_stat_bars();
    run_crc32();
    run_closest_approach_2d();
    if (alloc_racers()) {
        run_engine_damage_penalty();
        run_smooth_engine_exhaust_size();
        run_extrapolate_transform();
        run_update_turn2();
        run_damaged_engine_sides();
        run_take_damage();
        run_boost_bar_color();
        run_repair();
        run_boost_charge();
        run_physics_suite();
    }
    free_racers();

    std::fprintf(verify_log, "\n%d cases run, %d passed, %d failed, %d skipped\n", cases_run,
                 cases_passed, cases_run - cases_passed, cases_skipped);
    std::fclose(verify_log);
    verify_log = nullptr;

    std::fprintf(hook_log, "[reimpl_verify] %d cases run, %d passed, %d failed, %d skipped -> %s\n",
                 cases_run, cases_passed, cases_run - cases_passed, cases_skipped,
                 REIMPL_VERIFY_LOG_FILE);
    std::fflush(hook_log);
}

extern "C" void reimpl_verify_tick(FILE *hook_log) {
    static bool already_run = false;

    if (already_run)
        return;
    already_run = true;

    if (hook_verify_requested())
        reimpl_verify_run(hook_log);
}
