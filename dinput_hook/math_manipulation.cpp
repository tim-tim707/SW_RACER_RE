#include "math_manipulation.h"

#include <cmath>

namespace math_manipulation {

    rdVector3 v3(const rdVector4& v) { return {v.x, v.y, v.z}; }
    rdVector3 add(rdVector3 a, rdVector3 b) { return {a.x + b.x, a.y + b.y, a.z + b.z}; }
    rdVector3 sub(rdVector3 a, rdVector3 b) { return {a.x - b.x, a.y - b.y, a.z - b.z}; }
    rdVector3 mul(rdVector3 a, float k) { return {a.x * k, a.y * k, a.z * k}; }
    float dot(rdVector3 a, rdVector3 b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
    rdVector3 cross(rdVector3 a, rdVector3 b) { return {a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x}; }
    float len(rdVector3 a) { return std::sqrt(dot(a, a)); }
    rdVector3 norm(rdVector3 a) {
        const float l = len(a);
        return l > 1e-6f ? mul(a, 1.0f / l) : rdVector3{0.0f, 0.0f, 0.0f};
    }
    float clampf(float x, float lo, float hi) { return x < lo ? lo : (x > hi ? hi : x); }

    rdVector3 rotate(rdVector3 v, rdVector3 a, float angle) {
        const float c = std::cos(angle), sn = std::sin(angle), d = dot(a, v);
        const rdVector3 cr = cross(a, v);
        return {v.x * c + cr.x * sn + a.x * d * (1.0f - c), v.y * c + cr.y * sn + a.y * d * (1.0f - c),
                v.z * c + cr.z * sn + a.z * d * (1.0f - c)};
    }

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

    rdVector3 xf_point(const rdMatrix44& m, rdVector3 p) {
        return {p.x * m.vA.x + p.y * m.vB.x + p.z * m.vC.x + m.vD.x, p.x * m.vA.y + p.y * m.vB.y + p.z * m.vC.y + m.vD.y,
                p.x * m.vA.z + p.y * m.vB.z + p.z * m.vC.z + m.vD.z};
    }

    rdVector3 to_local(const rdMatrix44& m, rdVector3 w) {
        const rdVector3 d = sub(w, v3(m.vD));
        const auto comp = [&](const rdVector4& axis) {
            const rdVector3 ax = v3(axis);
            const float l2 = dot(ax, ax);
            return l2 > 1e-9f ? dot(d, ax) / l2 : 0.0f;
        };
        return {comp(m.vA), comp(m.vB), comp(m.vC)};
    }

}// namespace math_manipulation
