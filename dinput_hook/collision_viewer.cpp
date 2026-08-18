#include "collision_viewer.h"
#include "node_utils.h"
#include "imgui_utils.h"
#include "shaders_utils.h"

extern "C" {
#include <Swr/swrEvent.h>
}

#include <glad/glad.h>

#include <cmath>
#include <vector>

// One overlay vertex in world space. rgb in [0,1]; the per-pass alpha is applied in the shader.
struct CollisionVert {
    float x, y, z;
    float r, g, b;
};

// Map a swrModel_Behavior::vehicle_reaction bitset to an overlay color. Mirrors annodue's palette:
// the lowest set reaction bit that has a color wins; everything else falls back to white. Values
// are RGB (boost zones orange, lava blue, fall light-blue, no-respawn magenta, ...).
static void reaction_color(uint32_t reaction, float &r, float &g, float &b) {
    uint8_t cr, cg, cb;
    if (reaction & swrVehicleReaction_ZOn) {
        cr = 255, cg = 180, cb = 50;// boost zone (on)
    } else if (reaction & swrVehicleReaction_ZOff) {
        cr = 100, cg = 255, cb = 100;// boost zone (off)
    } else if (reaction & swrVehicleReaction_Fast) {
        cr = 0, cg = 255, cb = 255;
    } else if (reaction & swrVehicleReaction_Slow) {
        cr = 255, cg = 100, cb = 170;
    } else if (reaction & swrVehicleReaction_Swst) {
        cr = 255, cg = 0, cb = 0;// start line
    } else if (reaction & swrVehicleReaction_Slip) {
        cr = 255, cg = 255, cb = 127;
    } else if (reaction & swrVehicleReaction_Lava) {
        cr = 50, cg = 50, cb = 255;
    } else if (reaction & swrVehicleReaction_Fall) {
        cr = 0, cg = 127, cb = 255;
    } else if (reaction & swrVehicleReaction_NRSp) {
        cr = 255, cg = 0, cb = 255;// no-respawn
    } else if (reaction & swrVehicleReaction_Side) {
        cr = 0, cg = 255, cb = 0;
    } else {
        cr = 255, cg = 255, cb = 255;
    }
    r = cr / 255.0f, g = cg / 255.0f, b = cb / 255.0f;
}

// Transform a quantized (int16) collision vertex by the accumulated model matrix into world space.
// model_mat is column-major (vA..vD are columns), matching apply_node_transform / the visual draw.
static rdVector3 transform_collision_vertex(const rdMatrix44 &model_mat,
                                            const swrModel_CollisionVertex &v) {
    const float x = (float) v.x, y = (float) v.y, z = (float) v.z;
    return {
        model_mat.vA.x * x + model_mat.vB.x * y + model_mat.vC.x * z + model_mat.vD.x,
        model_mat.vA.y * x + model_mat.vB.y * y + model_mat.vC.y * z + model_mat.vD.y,
        model_mat.vA.z * x + model_mat.vB.z * y + model_mat.vC.z * z + model_mat.vD.z,
    };
}

// Decode one mesh's collision primitives into world-space triangles (3 verts each, appended to
// out). Reads collision_vertices in flat order and expands primitive_type 3 (triangle list), 4
// (quad list) and 5 (triangle strips, each strip length from primitive_sizes[i], with the standard
// odd-index winding flip) - the same decode the game's collision loader produces. Meshes without
// collision data are skipped.
static void decode_collision_mesh(const swrModel_Mesh *mesh, const rdMatrix44 &model_mat,
                                  std::vector<CollisionVert> &out) {
    if (!mesh || !mesh->collision_vertices || mesh->num_collision_vertices == 0)
        return;

    float r, g, b;
    reaction_color(mesh->behavior ? mesh->behavior->vehicle_reaction : 0, r, g, b);

    std::vector<rdVector3> verts(mesh->num_collision_vertices);
    for (int i = 0; i < mesh->num_collision_vertices; i++)
        verts[i] = transform_collision_vertex(model_mat, mesh->collision_vertices[i]);

    const auto emit = [&](int i0, int i1, int i2) {
        if (i0 >= (int) verts.size() || i1 >= (int) verts.size() || i2 >= (int) verts.size())
            return;
        for (int idx: {i0, i1, i2}) {
            const rdVector3 &p = verts[idx];
            out.push_back({p.x, p.y, p.z, r, g, b});
        }
    };

    switch (mesh->primitive_type) {
        case 3:// triangle list
            for (int i = 0; i < mesh->num_primitives; i++)
                emit(3 * i + 0, 3 * i + 1, 3 * i + 2);
            break;
        case 4:// quad list -> two triangles
            for (int i = 0; i < mesh->num_primitives; i++) {
                emit(4 * i + 0, 4 * i + 1, 4 * i + 2);
                emit(4 * i + 0, 4 * i + 2, 4 * i + 3);
            }
            break;
        case 5: {// triangle strips
            int offset = 0;
            for (int i = 0; i < mesh->num_primitives; i++) {
                const int s = (int) mesh->primitive_sizes[i];
                for (int j = 0; j < s - 2; j++) {
                    if (j % 2 == 0)
                        emit(offset + j + 0, offset + j + 1, offset + j + 2);
                    else
                        emit(offset + j + 1, offset + j + 0, offset + j + 2);
                }
                offset += s;
            }
            break;
        }
        default:
            break;
    }
}

// Walk the track scene graph exactly as swrModel_CollideNodeRecursiveRay does: a NODE_MESH_GROUP is
// a collision leaf; container nodes (type & 0x4000) accumulate their transform (type & 0x8000) and
// recurse into children that pass the flags_2 exact-match gate. model_mat is taken by value so each
// branch keeps its own accumulated transform.
static void walk_collision_node(const swrViewport &vp, const swrModel_Node *node,
                                rdMatrix44 model_mat, uint32_t col_exact_mask,
                                std::vector<CollisionVert> &out) {
    if (!node)
        return;

    if (node->type == NODE_MESH_GROUP) {
        for (uint32_t i = 0; i < node->num_children; i++)
            decode_collision_mesh(node->children.meshes[i], model_mat, out);
        return;
    }

    if (!(node->type & 0x4000))
        return;

    if (node->type & 0x8000)
        apply_node_transform(model_mat, node, (rdVector3 *) &vp.model_matrix.vD);

    for (uint32_t i = 0; i < node->num_children; i++) {
        const swrModel_Node *child = node->children.nodes[i];
        if (child && (child->flags_2 & col_exact_mask) == col_exact_mask)
            walk_collision_node(vp, child, model_mat, col_exact_mask, out);
    }
}

// --- Trigger / marker shapes (port of annodue PR #8) ----------------------------------------------
// Each shape is a unit triangle strip in local space; it is placed by a basis (A,B,C) + origin (D)
// and expanded into world-space triangles. Triggers are box-less plane/capsule volumes; racer
// markers are small cubes.

static constexpr float COLLISION_PI = 3.14159265f;

// 4-vertex plane (a quad in the local XZ plane), used for planar trigger types.
static const std::vector<rdVector3> &plane_strip() {
    static const std::vector<rdVector3> s = {{-1, 0, -1}, {1, 0, -1}, {-1, 0, 1}, {1, 0, 1}};
    return s;
}

// 42-vertex capsule outline (two half-rings joined), used for volumetric trigger types.
static const std::vector<rdVector3> &capsule_strip() {
    static const std::vector<rdVector3> s = [] {
        std::vector<rdVector3> v;
        for (int i = 0; i < 10; i++) {
            const float t = i / 9.0f * COLLISION_PI;
            v.push_back({1 + std::sin(t), std::cos(t), 1});
            v.push_back({1 + std::sin(t), std::cos(t), -1});
        }
        for (int i = 0; i < 10; i++) {
            const float t = (i / 9.0f + 1) * COLLISION_PI;
            v.push_back({-1 + std::sin(t), std::cos(t), 1});
            v.push_back({-1 + std::sin(t), std::cos(t), -1});
        }
        v.push_back(v[0]);
        v.push_back(v[1]);
        return v;
    }();
    return s;
}

// 14-vertex unit cube as a triangle strip (annodue's packed bit-pattern construction).
static const std::vector<rdVector3> &box_strip() {
    static const std::vector<rdVector3> s = [] {
        std::vector<rdVector3> v(14);
        for (int k = 0; k < 14; k++)
            v[k] = {2 * float((0x05e8 >> k) & 1) - 1, 2 * float((0x238e >> k) & 1) - 1,
                    2 * float((0x0f43 >> k) & 1) - 1};
        return v;
    }();
    return s;
}

// Unit-radius UV sphere as a triangle list (origin-centered). Used for the pod track-collision skin.
static const std::vector<rdVector3> &unit_sphere_tris() {
    static const std::vector<rdVector3> s = [] {
        const int stacks = 8, slices = 12;
        const auto pt = [](float th, float ph) -> rdVector3 {
            return {std::sin(ph) * std::cos(th), std::cos(ph), std::sin(ph) * std::sin(th)};
        };
        std::vector<rdVector3> v;
        for (int i = 0; i < stacks; i++) {
            const float ph0 = COLLISION_PI * i / stacks, ph1 = COLLISION_PI * (i + 1) / stacks;
            for (int j = 0; j < slices; j++) {
                const float th0 = 2 * COLLISION_PI * j / slices;
                const float th1 = 2 * COLLISION_PI * (j + 1) / slices;
                const rdVector3 a = pt(th0, ph0), b = pt(th1, ph0), c = pt(th0, ph1),
                                d = pt(th1, ph1);
                v.push_back(a), v.push_back(b), v.push_back(c);
                v.push_back(b), v.push_back(d), v.push_back(c);
            }
        }
        return v;
    }();
    return s;
}

// Unit-radius disc in the world XY plane (the pod-vs-pod test is 2D in X/Y), as a triangle fan.
static const std::vector<rdVector3> &unit_disc_tris() {
    static const std::vector<rdVector3> s = [] {
        const int seg = 24;
        std::vector<rdVector3> v;
        for (int i = 0; i < seg; i++) {
            const float t0 = 2 * COLLISION_PI * i / seg, t1 = 2 * COLLISION_PI * (i + 1) / seg;
            v.push_back({0, 0, 0});
            v.push_back({std::cos(t0), std::sin(t0), 0});
            v.push_back({std::cos(t1), std::sin(t1), 0});
        }
        return v;
    }();
    return s;
}

// Append a triangle list scaled per-axis and translated to center, in the given color.
static void append_tris(std::vector<CollisionVert> &out, const std::vector<rdVector3> &tris,
                        float sx, float sy, float sz, const rdVector3 &center, float cr, float cg,
                        float cb) {
    for (const rdVector3 &p: tris)
        out.push_back({p.x * sx + center.x, p.y * sy + center.y, p.z * sz + center.z, cr, cg, cb});
}

// Draw each racer's collision hitbox. The pod's body collides with the track via a sphere centered
// on the pod whose radius comes from the pod's own collision-width field (swrRace.unk4 @0xa8),
// shrunk by lean angle and clamped to a 1.5 minimum - exactly swrRace_DetectWallScrape /
// swrRace_UpdateWallContact (tilt factor 0.75 @0x004adcb8, min 1.5 @0x004add20). This - not the much
// smaller surface-follow skin from swrRace_CollideTrack - is what stops the pod against a wall, so it
// is the radius read live per pod. Pod-vs-pod is a separate flat 2D (x/y) test: a 5.0 disc
// (sqrt(100.0)/2 @0x004add5c, swrRace_ResolvePodCollision).
static void append_pod_hitboxes(std::vector<CollisionVert> &out) {
    const float tilt_factor = 0.75f;
    const float min_radius = 1.5f;
    const float pod_pod_radius = 5.0f;
    const int count = swrEvent_GetEventCount('Test');
    for (int i = 0; i < count; i++) {
        const swrRace *racer = (const swrRace *) swrEvent_GetItem('Test', i);
        if (!racer)
            continue;
        const rdVector3 c{racer->transform.vD.x, racer->transform.vD.y, racer->transform.vD.z};

        const float base = *(const float *) racer->unk4;
        const float tilt =
            racer->tiltManualMult < 0 ? -racer->tiltManualMult : racer->tiltManualMult;
        float wall_radius = base * (1.0f - tilt_factor * tilt);
        if (wall_radius < min_radius)
            wall_radius = min_radius;
        if (wall_radius > 50.0f)// guard against an unexpected field value filling the screen
            wall_radius = min_radius;

        append_tris(out, unit_sphere_tris(), wall_radius, wall_radius, wall_radius, c, 0.2f, 1.0f,
                    0.2f);// green: pod body collision radius (what stops it at walls)
        append_tris(out, unit_disc_tris(), pod_pod_radius, pod_pod_radius, pod_pod_radius, c, 0.0f,
                    1.0f, 1.0f);// cyan: pod-vs-pod horizontal radius
    }
}

// Place a local triangle strip with basis (a,b,c) + origin (d), expand it to world-space triangles,
// and append them in the given color. Culling is disabled for the overlay, so winding is irrelevant.
static void append_strip(std::vector<CollisionVert> &out, const std::vector<rdVector3> &strip,
                         const rdVector3 &a, const rdVector3 &b, const rdVector3 &c,
                         const rdVector3 &d, float cr, float cg, float cb) {
    const auto to_world = [&](const rdVector3 &p) -> rdVector3 {
        return {a.x * p.x + b.x * p.y + c.x * p.z + d.x, a.y * p.x + b.y * p.y + c.y * p.z + d.y,
                a.z * p.x + b.z * p.y + c.z * p.z + d.z};
    };
    for (int i = 0; i + 2 < (int) strip.size(); i++) {
        for (int k = 0; k < 3; k++) {
            const rdVector3 w = to_world(strip[i + k]);
            out.push_back({w.x, w.y, w.z, cr, cg, cb});
        }
    }
}

// Walk the whole scene graph and emit a shape for every (enabled) trigger attached to a mesh's
// behavior. Planar trigger types (102/104) draw as a plane; everything else as a capsule. Matches
// annodue: triggers are gathered scene-wide (not flags_2 gated) and skipped when flags & 0x1.
static void walk_triggers(const swrModel_Node *node, std::vector<CollisionVert> &out) {
    if (!node)
        return;

    if (node->type & 0x4000) {
        for (uint32_t i = 0; i < node->num_children; i++)
            walk_triggers(node->children.nodes[i], out);
    }
    if (node->type == NODE_MESH_GROUP) {
        for (uint32_t i = 0; i < node->num_children; i++) {
            const swrModel_Mesh *mesh = node->children.meshes[i];
            if (!mesh || !mesh->behavior)
                continue;
            for (const swrModel_TriggerDescription *t = mesh->behavior->triggers; t; t = t->next) {
                if (t->flags & 0x1)
                    continue;
                const rdVector3 &p = t->center;
                const rdVector3 &dir = t->direction;
                const float s_xy = t->size_xy * 0.5f;
                const float s_z = t->size_z * 0.5f;
                const rdVector3 a{-dir.y * s_xy, dir.x * s_xy, 0};
                const rdVector3 b{dir.x * s_xy, dir.y * s_xy, 0};
                const rdVector3 c{0, 0, s_z};
                const std::vector<rdVector3> &shape =
                    (t->type == 102 || t->type == 104) ? plane_strip() : capsule_strip();
                append_strip(out, shape, a, b, c, p, 0.0f, 0.0f, 1.0f);// blue
            }
        }
    }
}

// Small yellow cube at every racer ('Test' entity) position - shows where triggers fire.
static void append_racer_markers(std::vector<CollisionVert> &out) {
    const int count = swrEvent_GetEventCount('Test');
    for (int i = 0; i < count; i++) {
        const swrRace *racer = (const swrRace *) swrEvent_GetItem('Test', i);
        if (!racer)
            continue;
        const rdVector3 p{racer->transform.vD.x, racer->transform.vD.y, racer->transform.vD.z};
        append_strip(out, box_strip(), {0.15f, 0, 0}, {0, 0.15f, 0}, {0, 0, 0.15f}, p, 1.0f, 1.0f,
                     0.0f);
    }
}

// Minimal flat-color shader for the overlay. The context is a core profile, so the draw uses a
// VAO/VBO + shader rather than fixed-function immediate mode. gl_Position matches the visual scene
// shader (projMatrix * viewMatrix * worldPos), so the overlay shares its transform and depth.
static const char *collision_vert_src = R"(#version 450 core
layout(location = 0) in vec3 position;
layout(location = 1) in vec3 color;
uniform mat4 projMatrix;
uniform mat4 viewMatrix;
out vec3 passColor;
void main() {
    gl_Position = projMatrix * viewMatrix * vec4(position, 1.0);
    passColor = color;
}
)";

static const char *collision_frag_src = R"(#version 450 core
in vec3 passColor;
uniform float alpha;
out vec4 fragColor;
void main() {
    fragColor = vec4(passColor, alpha);
}
)";

void render_collision_overlay(const swrViewport &vp, const swrModel_Node *root_node,
                              const rdMatrix44 &proj_mat, const rdMatrix44 &view_mat) {
    if (!root_node || root_node->num_children <= 3)
        return;

    std::vector<CollisionVert> collision_verts;
    if (imgui_state.show_collision) {
        // The track collision lives under the track model (root child 3). The per-planet-track
        // flags_2 mask mirrors LoadTrackModels: bit 0x2 plus a track-select bit keyed off
        // planet_track_number (0x10/0x20/0x40 for tracks 0/1/2, track 3 reuses 0x10). This is the
        // exact-match mask the game sets for swrModel_CollideNodeRecursiveRay.
        const swrObjJdge *jdge = (const swrObjJdge *) swrEvent_GetItem('Jdge', 0);
        if (jdge) {
            const int track = jdge->planet_track_number;
            const uint32_t track_bit = (track == 1) ? 0x20 : (track == 2) ? 0x40 : 0x10;
            const uint32_t col_exact_mask = track_bit | 0x2;

            rdMatrix44 model_mat;
            rdMatrix_SetIdentity44(&model_mat);
            walk_collision_node(vp, root_node->children.nodes[3], model_mat, col_exact_mask,
                                collision_verts);
        }
    }

    std::vector<CollisionVert> trigger_verts;
    if (imgui_state.show_triggers) {
        walk_triggers(root_node, trigger_verts);
        append_racer_markers(trigger_verts);
    }

    std::vector<CollisionVert> hitbox_verts;
    if (imgui_state.show_hitbox)
        append_pod_hitboxes(hitbox_verts);

    if (collision_verts.empty() && trigger_verts.empty() && hitbox_verts.empty())
        return;

    // Capture every GL state bit this overlay touches up front, and restore it before returning.
    // ImGui's GL backend saves/restores the polygon mode around its own draw, so a leaked GL_LINE
    // here would be re-applied after ImGui and turn the game's 2D UI / HUD into wireframe; likewise
    // a leaked blend/depth bit corrupts the 2D sprite draw. Leave the renderer's state exactly as
    // found so the overlay is invisible to the rest of the frame.
    GLint prev_program, prev_vao, prev_array_buffer, prev_poly_mode[2];
    glGetIntegerv(GL_CURRENT_PROGRAM, &prev_program);
    glGetIntegerv(GL_VERTEX_ARRAY_BINDING, &prev_vao);
    glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &prev_array_buffer);
    glGetIntegerv(GL_POLYGON_MODE, prev_poly_mode);
    const GLboolean prev_depth_test = glIsEnabled(GL_DEPTH_TEST);
    const GLboolean prev_cull = glIsEnabled(GL_CULL_FACE);
    const GLboolean prev_blend = glIsEnabled(GL_BLEND);
    const GLboolean prev_poly_offset = glIsEnabled(GL_POLYGON_OFFSET_FILL);
    GLboolean prev_depth_mask;
    glGetBooleanv(GL_DEPTH_WRITEMASK, &prev_depth_mask);

    static GLuint program = 0;
    static GLint proj_loc = -1, view_loc = -1, alpha_loc = -1;
    static GLuint vao = 0, vbo = 0;
    if (program == 0) {
        std::optional<GLuint> p = compileProgram(1, &collision_vert_src, 1, &collision_frag_src);
        if (!p.has_value())
            return;
        program = p.value();
        proj_loc = glGetUniformLocation(program, "projMatrix");
        view_loc = glGetUniformLocation(program, "viewMatrix");
        alpha_loc = glGetUniformLocation(program, "alpha");
        glGenVertexArrays(1, &vao);
        glGenBuffers(1, &vbo);
        glBindVertexArray(vao);
        glBindBuffer(GL_ARRAY_BUFFER, vbo);
        glEnableVertexAttribArray(0);
        glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, sizeof(CollisionVert),
                              (void *) offsetof(CollisionVert, x));
        glEnableVertexAttribArray(1);
        glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, sizeof(CollisionVert),
                              (void *) offsetof(CollisionVert, r));
    }

    glUseProgram(program);
    glBindVertexArray(vao);
    glBindBuffer(GL_ARRAY_BUFFER, vbo);
    glUniformMatrix4fv(proj_loc, 1, GL_FALSE, &proj_mat.vA.x);
    glUniformMatrix4fv(view_loc, 1, GL_FALSE, &view_mat.vA.x);

    // Overlay reads the scene depth (so geometry in front occludes it) but must not write depth.
    // Drawn double-sided since collision/trigger faces have no consistent winding.
    glEnable(GL_DEPTH_TEST);
    glDepthMask(GL_FALSE);
    glDisable(GL_CULL_FACE);

    const float fill_alpha = imgui_state.collision_opacity;

    // Upload one vertex set and draw it as a translucent fill (skipped in wireframe-only mode or at
    // zero opacity; polygon offset pushes it back so the wireframe pass sits cleanly on top) plus a
    // full-opacity wireframe pass.
    const auto draw_verts = [&](const std::vector<CollisionVert> &verts) {
        if (verts.empty())
            return;
        glBufferData(GL_ARRAY_BUFFER, verts.size() * sizeof(CollisionVert), verts.data(),
                     GL_DYNAMIC_DRAW);

        if (!imgui_state.collision_wireframe && fill_alpha > 0.0f) {
            glEnable(GL_BLEND);
            glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
            glPolygonMode(GL_FRONT_AND_BACK, GL_FILL);
            glEnable(GL_POLYGON_OFFSET_FILL);
            glPolygonOffset(1.0f, 1.0f);
            glUniform1f(alpha_loc, fill_alpha);
            glDrawArrays(GL_TRIANGLES, 0, (GLsizei) verts.size());
            glDisable(GL_POLYGON_OFFSET_FILL);
        }

        glDisable(GL_BLEND);
        glPolygonMode(GL_FRONT_AND_BACK, GL_LINE);
        glLineWidth(1.0f);
        glUniform1f(alpha_loc, 1.0f);
        glDrawArrays(GL_TRIANGLES, 0, (GLsizei) verts.size());
    };

    draw_verts(collision_verts);
    draw_verts(trigger_verts);
    draw_verts(hitbox_verts);

    // Restore exactly what we captured.
    glPolygonMode(GL_FRONT_AND_BACK, (GLenum) prev_poly_mode[0]);
    glDepthMask(prev_depth_mask);
    (prev_depth_test ? glEnable : glDisable)(GL_DEPTH_TEST);
    (prev_cull ? glEnable : glDisable)(GL_CULL_FACE);
    (prev_blend ? glEnable : glDisable)(GL_BLEND);
    (prev_poly_offset ? glEnable : glDisable)(GL_POLYGON_OFFSET_FILL);
    glBindVertexArray(prev_vao);
    glBindBuffer(GL_ARRAY_BUFFER, prev_array_buffer);
    glUseProgram(prev_program);
}
