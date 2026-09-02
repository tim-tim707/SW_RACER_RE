#include "reimpl_verify.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" {
#include <General/stdMath.h>
#include <General/stdHashTable.h>
#include <Primitives/rdMath.h>
#include <Primitives/rdMatrix.h>
#include <Primitives/rdVector.h>
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

    // Retail used the MSVC CRT and this build uses MinGW's, hence the 1 ULP budget.
    run_f_f("stdMath_Sqrt", stdMath_Sqrt_ADDR, stdMath_Sqrt, 0.0f, 1.0e6f, 0);
    run_f_f("stdMath_Sqrt_2", stdMath_Sqrt_2_ADDR, stdMath_Sqrt_2, 0.0f, 1.0e6f, 0);
    run_f_f("stdMath_fround", stdMath_fround_ADDR, stdMath_fround, -1.0e6f, 1.0e6f, 0);
    run_i_f("stdMath_FRoundInt", stdMath_FRoundInt_ADDR, stdMath_FRoundInt, -1.0e6f, 1.0e6f);

    // Pure arithmetic, no library calls: these must be bit-identical.
    run_f_f("stdMath_NormalizeAngle", stdMath_NormalizeAngle_ADDR, stdMath_NormalizeAngle, -2000.0f,
            2000.0f, 0);
    run_f_f("stdMath_NormalizeAngleAcute", stdMath_NormalizeAngleAcute_ADDR,
            stdMath_NormalizeAngleAcute, -2000.0f, 2000.0f, 0);
    run_f_ff("stdMath_Decelerator", stdMath_Decelerator_ADDR, stdMath_Decelerator, -100.0f, 100.0f,
             0);
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

    // sin/cos through the CRT: same rounding budget as sqrt.
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
    // 1 ULP deliberately: retail narrows dx and dy to 32-bit mid-computation but not dz (see
    // rdVector_DistSquared3). An x87-intermediate artifact, not a defect in the expression.
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
    run_u_si("stdHashtbl_CalculateHash", stdHashtbl_CalculateHash_ADDR, stdHashtbl_CalculateHash);
    run_i_i("stdHashtbl_isPrime", stdHashtbl_isPrime_ADDR, stdHashtbl_isPrime, -50, 400);
    run_i_i("stdHashtbl_nextPrime", stdHashtbl_nextPrime_ADDR, stdHashtbl_nextPrime, -50, 400);

    // The rotation builders route through stdMath_SinCos, hence the 1 ULP budget on those; the
    // rest is plain assignment and arithmetic.
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
