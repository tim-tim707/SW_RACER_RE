#pragma once

// Small vector / matrix helpers for the mod's own code (pod effects, wrecks, motion, the pod editor's
// in-game side, the renderer's cables). Matrices are the game's rdMatrix44 with row vectors: a point
// p is placed by p' = p * M (rows vA, vB, vC are the axes, vD the translation).

#include <types.h>// rdVector3, rdVector4, rdMatrix44

namespace math_manipulation {

    rdVector3 v3(const rdVector4& v);// the first three components
    rdVector3 add(rdVector3 a, rdVector3 b);
    rdVector3 sub(rdVector3 a, rdVector3 b);
    rdVector3 mul(rdVector3 a, float k);
    float dot(rdVector3 a, rdVector3 b);
    rdVector3 cross(rdVector3 a, rdVector3 b);
    float len(rdVector3 a);
    rdVector3 norm(rdVector3 a);// unit length; the zero vector for a (near) zero one
    float clampf(float x, float lo, float hi);
    // v turned about the unit axis a by angle (radians).
    rdVector3 rotate(rdVector3 v, rdVector3 a, float angle);

    // a then b: the matrix that places a point by a, then by b (row vectors: a * b).
    rdMatrix44 mat_then(const rdMatrix44& a, const rdMatrix44& b);
    // Inverse of an affine matrix (rotation / scale / shear + translation); false if singular.
    bool invert_affine(const rdMatrix44& m, rdMatrix44& out);
    // A point placed by m.
    rdVector3 xf_point(const rdMatrix44& m, rdVector3 p);
    // A world point in m's own frame, for m with orthogonal (possibly scaled) axes.
    rdVector3 to_local(const rdMatrix44& m, rdVector3 w);

}// namespace math_manipulation
