#include <glad/glad.h>

#include "shadows.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <list>
#include <unordered_map>

#include <imgui.h>

#include "config.h"
#include "debug_ui.h"
#include "game_deltas/pod_fx.h"// pod_fx_gather_lights

extern "C" {
extern FILE* hook_log;
}

int g_shadow_caster_depth = 0;

namespace {
    // ---- settings --------------------------------------------------------------------------
    struct Settings {
        bool enabled = true;
        bool hide_blob = true;
        float darkness = 0.5f;   // 0 = no shadow, 1 = black
        float softness = 1.5f;   // PCF kernel radius in shadow-map texels
        float extent = 160.0f;   // half-size of the shadowed area around the camera (world units)
        int map_size = 2048;     // shadow map resolution
        float sun_azimuth = 40.0f;  // degrees, direction the light comes FROM, around world z
        float sun_elevation = 60.0f;// degrees above the horizon
        float bias = 0.0006f;    // depth bias against self-shadow acne
        float sun_shading = 0.25f; // darken surfaces facing away from the sun (0 = off)
        bool lights = true;        // dynamic exhaust / fire lights on the surroundings
        float light_intensity = 1.0f;
        float light_glow = 0.15f;  // direct glow added on top (helps on dark surfaces)
        float exhaust_tint = 0.6f; // fixed dim on the pod exhaust (the "in shadow" look), 1 = none
    };
    Settings s;
    const Settings kDefaults;

    // ---- caster geometry -------------------------------------------------------------------
    // One drawn instance of a mesh. The SAME mesh is often drawn several times with different
    // matrices (both engines of a pod share their meshes), so the cache holds every instance of a
    // mesh, matched by matrix -- keying by mesh alone made the second engine overwrite the first.
    struct CasterGeo {
        rdMatrix44 matrix{};
        std::vector<ShadowCasterVertex> pos;
        ShadowCasterTexture tex{};
        unsigned last_used = 0;
    };
    std::unordered_map<const swrModel_Mesh*, std::list<CasterGeo>> g_cache;// list: stable addresses
    std::vector<const CasterGeo*> g_frame;
    // Pod cables (role 3): cast onto the ground and other pods, but not onto pod bodies / engines
    // -- the thin tubes only made stray dark streaks across the engines and exhaust.
    std::vector<const CasterGeo*> g_frame_cables;
    std::vector<const CasterGeo*> g_mask_frame[2];// [0] exhaust/glow, [1] energy binders
    unsigned g_frame_no = 0;

    // ---- column-major 4x4 helpers (GL layout, same memory layout as rdMatrix44) -----------
    struct M4 {
        float m[16];
    };
    M4 mul(const M4& a, const M4& b) {
        M4 r{};
        for (int c = 0; c < 4; c++)
            for (int rr = 0; rr < 4; rr++) {
                float v = 0.0f;
                for (int k = 0; k < 4; k++)
                    v += a.m[k * 4 + rr] * b.m[c * 4 + k];
                r.m[c * 4 + rr] = v;
            }
        return r;
    }
    bool invert(const float m[16], float out[16]) {
        float inv[16];
        inv[0] = m[5] * m[10] * m[15] - m[5] * m[11] * m[14] - m[9] * m[6] * m[15] + m[9] * m[7] * m[14] + m[13] * m[6] * m[11] - m[13] * m[7] * m[10];
        inv[4] = -m[4] * m[10] * m[15] + m[4] * m[11] * m[14] + m[8] * m[6] * m[15] - m[8] * m[7] * m[14] - m[12] * m[6] * m[11] + m[12] * m[7] * m[10];
        inv[8] = m[4] * m[9] * m[15] - m[4] * m[11] * m[13] - m[8] * m[5] * m[15] + m[8] * m[7] * m[13] + m[12] * m[5] * m[11] - m[12] * m[7] * m[9];
        inv[12] = -m[4] * m[9] * m[14] + m[4] * m[10] * m[13] + m[8] * m[5] * m[14] - m[8] * m[6] * m[13] - m[12] * m[5] * m[10] + m[12] * m[6] * m[9];
        inv[1] = -m[1] * m[10] * m[15] + m[1] * m[11] * m[14] + m[9] * m[2] * m[15] - m[9] * m[3] * m[14] - m[13] * m[2] * m[11] + m[13] * m[3] * m[10];
        inv[5] = m[0] * m[10] * m[15] - m[0] * m[11] * m[14] - m[8] * m[2] * m[15] + m[8] * m[3] * m[14] + m[12] * m[2] * m[11] - m[12] * m[3] * m[10];
        inv[9] = -m[0] * m[9] * m[15] + m[0] * m[11] * m[13] + m[8] * m[1] * m[15] - m[8] * m[3] * m[13] - m[12] * m[1] * m[11] + m[12] * m[3] * m[9];
        inv[13] = m[0] * m[9] * m[14] - m[0] * m[10] * m[13] - m[8] * m[1] * m[14] + m[8] * m[2] * m[13] + m[12] * m[1] * m[10] - m[12] * m[2] * m[9];
        inv[2] = m[1] * m[6] * m[15] - m[1] * m[7] * m[14] - m[5] * m[2] * m[15] + m[5] * m[3] * m[14] + m[13] * m[2] * m[7] - m[13] * m[3] * m[6];
        inv[6] = -m[0] * m[6] * m[15] + m[0] * m[7] * m[14] + m[4] * m[2] * m[15] - m[4] * m[3] * m[14] - m[12] * m[2] * m[7] + m[12] * m[3] * m[6];
        inv[10] = m[0] * m[5] * m[15] - m[0] * m[7] * m[13] - m[4] * m[1] * m[15] + m[4] * m[3] * m[13] + m[12] * m[1] * m[7] - m[12] * m[3] * m[5];
        inv[14] = -m[0] * m[5] * m[14] + m[0] * m[6] * m[13] + m[4] * m[1] * m[14] - m[4] * m[2] * m[13] - m[12] * m[1] * m[6] + m[12] * m[2] * m[5];
        inv[3] = -m[1] * m[6] * m[11] + m[1] * m[7] * m[10] + m[5] * m[2] * m[11] - m[5] * m[3] * m[10] - m[9] * m[2] * m[7] + m[9] * m[3] * m[6];
        inv[7] = m[0] * m[6] * m[11] - m[0] * m[7] * m[10] - m[4] * m[2] * m[11] + m[4] * m[3] * m[10] + m[8] * m[2] * m[7] - m[8] * m[3] * m[6];
        inv[11] = -m[0] * m[5] * m[11] + m[0] * m[7] * m[9] + m[4] * m[1] * m[11] - m[4] * m[3] * m[9] - m[8] * m[1] * m[7] + m[8] * m[3] * m[5];
        inv[15] = m[0] * m[5] * m[10] - m[0] * m[6] * m[9] - m[4] * m[1] * m[10] + m[4] * m[2] * m[9] + m[8] * m[1] * m[6] - m[8] * m[2] * m[5];
        float det = m[0] * inv[0] + m[1] * inv[4] + m[2] * inv[8] + m[3] * inv[12];
        if (std::fabs(det) < 1e-12f)
            return false;
        det = 1.0f / det;
        for (int i = 0; i < 16; i++)
            out[i] = inv[i] * det;
        return true;
    }
    struct V3 {
        float x, y, z;
    };
    V3 v_sub(V3 a, V3 b) { return {a.x - b.x, a.y - b.y, a.z - b.z}; }
    V3 v_cross(V3 a, V3 b) { return {a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x}; }
    float v_dot(V3 a, V3 b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
    V3 v_norm(V3 a) {
        const float l = std::sqrt(v_dot(a, a));
        return l > 1e-9f ? V3{a.x / l, a.y / l, a.z / l} : V3{0, 0, 1};
    }
    // Right-handed look-at (GL convention), column-major.
    M4 look_at(V3 eye, V3 center, V3 up) {
        const V3 f = v_norm(v_sub(center, eye));
        const V3 sx = v_norm(v_cross(f, up));
        const V3 u = v_cross(sx, f);
        M4 r{};
        r.m[0] = sx.x; r.m[4] = sx.y; r.m[8] = sx.z;  r.m[12] = -v_dot(sx, eye);
        r.m[1] = u.x;  r.m[5] = u.y;  r.m[9] = u.z;   r.m[13] = -v_dot(u, eye);
        r.m[2] = -f.x; r.m[6] = -f.y; r.m[10] = -f.z; r.m[14] = v_dot(f, eye);
        r.m[15] = 1.0f;
        return r;
    }
    M4 ortho(float l, float r, float b, float t, float n, float f) {
        M4 o{};
        o.m[0] = 2.0f / (r - l);
        o.m[5] = 2.0f / (t - b);
        o.m[10] = -2.0f / (f - n);
        o.m[12] = -(r + l) / (r - l);
        o.m[13] = -(t + b) / (t - b);
        o.m[14] = -(f + n) / (f - n);
        o.m[15] = 1.0f;
        return o;
    }

    // ---- GL objects ------------------------------------------------------------------------
    GLuint g_depth_prog = 0, g_apply_prog = 0, g_light_prog = 0;
    GLuint g_vao = 0, g_vbo = 0, g_empty_vao = 0;

    // Caster geometry as uploaded: world position + final texture coordinate, in runs that share
    // a texture.
    struct GpuVert {
        float x, y, z, u, v;
    };
    struct TexRun {
        GLuint tex;
        GLint first;
        GLsizei count;
    };
    void build_batches(const std::vector<const CasterGeo*>& geos, std::vector<GpuVert>& out,
                       std::vector<TexRun>& runs) {
        out.clear();
        runs.clear();
        for (const CasterGeo* g: geos) {
            const ShadowCasterTexture& t = g->tex;
            const GLint first = (GLint) out.size();
            for (const ShadowCasterVertex& v: g->pos)
                out.push_back({v.pos.x, v.pos.y, v.pos.z, v.tu / (t.scale_u * 4096.0f) + t.offset_u,
                               v.tv / (t.scale_v * 4096.0f) + t.offset_v});
            const GLsizei n = (GLsizei) (out.size() - first);
            if (!runs.empty() && runs.back().tex == t.handle && runs.back().first + runs.back().count == first)
                runs.back().count += n;
            else
                runs.push_back({t.handle, first, n});
        }
    }
    void draw_runs(const std::vector<TexRun>& runs) {
        glActiveTexture(GL_TEXTURE0);
        for (const TexRun& r: runs) {
            glBindTexture(GL_TEXTURE_2D, r.tex);
            glDrawArrays(GL_TRIANGLES, r.first, r.count);
        }
    }
    GLuint g_shadow_fbo = 0, g_shadow_tex = 0;
    GLuint g_body_fbo = 0, g_body_tex = 0;// same map without the cables (used on pod surfaces)
    int g_shadow_size = 0;
    GLuint g_scene_depth_fbo = 0, g_scene_depth_tex = 0;
    GLuint g_mask_prog = 0, g_mask_fbo = 0, g_mask_tex = 0;// pod exhaust / binder screen mask
    int g_scene_w = 0, g_scene_h = 0;
    bool g_gl_failed = false;

    GLuint compile(GLenum type, const char* src) {
        const GLuint sh = glCreateShader(type);
        glShaderSource(sh, 1, &src, nullptr);
        glCompileShader(sh);
        GLint ok = 0;
        glGetShaderiv(sh, GL_COMPILE_STATUS, &ok);
        if (!ok) {
            char log[1024];
            glGetShaderInfoLog(sh, sizeof(log), nullptr, log);
            if (hook_log)
                fprintf(hook_log, "[shadows] shader compile failed: %s\n", log);
            glDeleteShader(sh);
            return 0;
        }
        return sh;
    }
    GLuint link(const char* vs, const char* fs) {
        const GLuint v = compile(GL_VERTEX_SHADER, vs), f = compile(GL_FRAGMENT_SHADER, fs);
        if (!v || !f)
            return 0;
        const GLuint p = glCreateProgram();
        glAttachShader(p, v);
        glAttachShader(p, f);
        glLinkProgram(p);
        glDeleteShader(v);
        glDeleteShader(f);
        GLint ok = 0;
        glGetProgramiv(p, GL_LINK_STATUS, &ok);
        if (!ok) {
            char log[1024];
            glGetProgramInfoLog(p, sizeof(log), nullptr, log);
            if (hook_log)
                fprintf(hook_log, "[shadows] program link failed: %s\n", log);
            glDeleteProgram(p);
            return 0;
        }
        return p;
    }

    // Casters are alpha-tested against their texture so cut-out texels (spinning fan blades,
    // grilles) don't cast solid squares.
    const char* kDepthVS = R"(#version 330 core
layout(location = 0) in vec3 position;
layout(location = 1) in vec2 texcoord;
uniform mat4 lightVP;
out vec2 vUV;
void main() { vUV = texcoord; gl_Position = lightVP * vec4(position, 1.0); }
)";
    const char* kDepthFS = R"(#version 330 core
in vec2 vUV;
uniform sampler2D tex;
void main() { if (texture(tex, vUV).a < 0.5) discard; }
)";
    // Full-screen triangle; the inverse of the scene's projection*view is computed once per vertex.
    const char* kApplyVS = R"(#version 330 core
uniform mat4 proj;
uniform mat4 view;
out vec2 uv;
flat out mat4 invVP;
void main() {
    vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));
    uv = p;
    gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
    invVP = inverse(proj * view);
}
)";
    // Rebuild the pixel's world position from scene depth, look it up in the sun's depth map with
    // a 5x5 PCF kernel, and output a darkening factor (multiplied onto the scene by the blend).
    const char* kApplyFS = R"(#version 330 core
in vec2 uv;
flat in mat4 invVP;
uniform sampler2D sceneDepth;
uniform sampler2D shadowMap;
uniform sampler2D shadowMapBody;// same, without the pod cables (for pod surfaces)
uniform mat4 lightVP;
uniform float darkness;
uniform float softness;
uniform float texel;
uniform float bias;
uniform vec3 camPos;
uniform vec3 toSun;
uniform float sunShading;
uniform int hasCasters;
uniform sampler2D podMask;   // r = pod exhaust/glow, g = energy binder
uniform float exhaustTint;
out vec4 color;
void main() {
    float d = texture(sceneDepth, uv).r;
    if (d >= 0.999999) discard;                       // sky / nothing drawn
    vec4 w = invVP * vec4(uv * 2.0 - 1.0, d * 2.0 - 1.0, 1.0);
    w /= w.w;
    // Directional sun shading: surfaces turned away from the sun get darker (surface normal
    // rebuilt from the depth buffer).
    vec3 n = normalize(cross(dFdx(w.xyz), dFdy(w.xyz)));
    if (dot(n, camPos - w.xyz) < 0.0) n = -n;
    float shade = 1.0 - sunShading * (1.0 - clamp(dot(n, toSun), 0.0, 1.0));
    float sh = 0.0;
    vec4 m = texture(podMask, uv);
    bool body = m.b > 0.5;
    vec4 l = lightVP * w;
    vec3 p = l.xyz / l.w * 0.5 + 0.5;
    if (hasCasters != 0 && p.x > 0.0 && p.x < 1.0 && p.y > 0.0 && p.y < 1.0 && p.z < 1.0) {
        float r = softness * texel * 0.5;
        for (int i = -2; i <= 2; i++)
            for (int j = -2; j <= 2; j++) {
                vec2 q = p.xy + vec2(float(i), float(j)) * r;
                float sd = body ? texture(shadowMapBody, q).r : texture(shadowMap, q).r;
                sh += (p.z - bias > sd) ? 1.0 : 0.0;
            }
        sh /= 25.0;
        vec2 e = min(p.xy, 1.0 - p.xy);               // fade out at the edge of the shadowed area
        sh *= clamp(min(e.x, e.y) * 12.0, 0.0, 1.0);
    }
    float f = (1.0 - darkness * sh) * shade;
    // Pod exhaust: a fixed dim (the "in shadow" look) instead of whatever real shadow / sun
    // shading falls there; energy binders: left untouched.
    f = mix(f, exhaustTint, m.r);
    f = mix(f, 1.0, m.g);
    if (f >= 0.999) discard;
    color = vec4(vec3(f), 1.0);
}
)";

    // Dynamic lights (exhaust spotlights, damage-fire point lights) applied to whatever surface
    // is at each pixel -- ground, walls, pods. mode 0 multiplies light onto the surface colour
    // (lit = colour * (1 + light)); mode 1 adds a small direct glow so dark surfaces still pick
    // some of it up.
    const char* kLightFS = R"(#version 330 core
in vec2 uv;
flat in mat4 invVP;
uniform sampler2D sceneDepth;
uniform vec3 camPos;
uniform int numLights;
uniform vec4 lightPos[32];  // xyz, radius
uniform vec4 lightDir[32];  // xyz (0 = point light), cos of outer cone
uniform vec4 lightCol[32];  // rgb * intensity, cos of inner cone
uniform int mode;
uniform float glow;
uniform sampler2D podMask;
out vec4 color;
void main() {
    float d = texture(sceneDepth, uv).r;
    if (d >= 0.999999) discard;
    vec4 w4 = invVP * vec4(uv * 2.0 - 1.0, d * 2.0 - 1.0, 1.0);
    vec3 w = w4.xyz / w4.w;
    vec3 n = normalize(cross(dFdx(w), dFdy(w)));
    if (dot(n, camPos - w) < 0.0) n = -n;
    vec3 sum = vec3(0.0);
    for (int i = 0; i < numLights; i++) {
        vec3 L = lightPos[i].xyz - w;
        float dist = length(L);
        float rad = lightPos[i].w;
        if (dist >= rad) continue;
        vec3 l = L / max(dist, 1e-4);
        float att = 1.0 - dist / rad;
        att *= att;
        float spot = 1.0;
        if (dot(lightDir[i].xyz, lightDir[i].xyz) > 0.0)
            spot = smoothstep(lightDir[i].w, lightCol[i].w, dot(-l, lightDir[i].xyz));
        float ndl = max(dot(n, l), 0.0) * 0.8 + 0.2;
        sum += lightCol[i].rgb * att * spot * ndl;
    }
    vec2 m = texture(podMask, uv).rg;
    sum *= 1.0 - max(m.r, m.g);// exhaust / binders keep their own look
    if (max(sum.r, max(sum.g, sum.b)) < 0.002) discard;
    color = vec4(mode == 0 ? sum : sum * glow, 1.0);
}
)";

    // Screen mask of the pod exhaust / binder meshes recorded this frame (depth-tested against the
    // scene so hidden parts don't count).
    // The binder is a soft additive glow on a larger quad: its mask is weighted by how visible the
    // texel is, so the see-through part of the quad doesn't leave an unshadowed box around the beam.
    const char* kMaskVS = R"(#version 330 core
layout(location = 0) in vec3 position;
layout(location = 1) in vec2 texcoord;
uniform mat4 proj;
uniform mat4 view;
out vec2 vUV;
void main() { vUV = texcoord; gl_Position = proj * view * vec4(position, 1.0); }
)";
    const char* kMaskFS = R"(#version 330 core
in vec2 vUV;
uniform sampler2D tex;
uniform vec4 maskColor;
uniform int weighted;
out vec4 color;
void main() {
    float w = 1.0;
    if (weighted == 2) {
        if (texture(tex, vUV).a < 0.5) discard;
    } else if (weighted != 0) {
        vec4 t = texture(tex, vUV);
        w = clamp(max(t.r, max(t.g, t.b)) * t.a * 3.0, 0.0, 1.0);
        if (w < 0.004) discard;
    }
    color = maskColor * w;
}
)";

    bool ensure_gl() {
        if (g_gl_failed)
            return false;
        if (g_depth_prog == 0) {
            g_depth_prog = link(kDepthVS, kDepthFS);
            g_apply_prog = link(kApplyVS, kApplyFS);
            g_light_prog = link(kApplyVS, kLightFS);
            g_mask_prog = link(kMaskVS, kMaskFS);
            if (!g_depth_prog || !g_apply_prog || !g_light_prog || !g_mask_prog) {
                g_gl_failed = true;
                return false;
            }
            glGenVertexArrays(1, &g_vao);
            glGenBuffers(1, &g_vbo);
            glBindVertexArray(g_vao);
            glBindBuffer(GL_ARRAY_BUFFER, g_vbo);
            glEnableVertexAttribArray(0);
            glEnableVertexAttribArray(1);
            glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, sizeof(GpuVert), nullptr);
            glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, sizeof(GpuVert), (void*) (3 * sizeof(float)));
            glGenVertexArrays(1, &g_empty_vao);
        }
        if (g_shadow_size != s.map_size) {
            if (g_shadow_fbo) {
                glDeleteFramebuffers(1, &g_shadow_fbo);
                glDeleteTextures(1, &g_shadow_tex);
                glDeleteFramebuffers(1, &g_body_fbo);
                glDeleteTextures(1, &g_body_tex);
            }
            g_shadow_size = s.map_size;
            for (int k = 0; k < 2; k++) {
                GLuint& tex = k == 0 ? g_shadow_tex : g_body_tex;
                GLuint& fbo = k == 0 ? g_shadow_fbo : g_body_fbo;
                glGenTextures(1, &tex);
                glBindTexture(GL_TEXTURE_2D, tex);
                glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT24, g_shadow_size, g_shadow_size, 0,
                             GL_DEPTH_COMPONENT, GL_FLOAT, nullptr);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
                glGenFramebuffers(1, &fbo);
                glBindFramebuffer(GL_FRAMEBUFFER, fbo);
                glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_TEXTURE_2D, tex, 0);
                glDrawBuffer(GL_NONE);
                glReadBuffer(GL_NONE);
            }
        }
        return true;
    }

    bool ensure_scene_depth(int w, int h) {
        if (g_scene_depth_fbo && g_scene_w == w && g_scene_h == h)
            return true;
        if (g_scene_depth_fbo) {
            glDeleteFramebuffers(1, &g_scene_depth_fbo);
            glDeleteTextures(1, &g_scene_depth_tex);
        }
        g_scene_w = w;
        g_scene_h = h;
        // Same format as the scene's depth (DEPTH_COMPONENT32) so the multisample resolve blit is legal.
        glGenTextures(1, &g_scene_depth_tex);
        glBindTexture(GL_TEXTURE_2D, g_scene_depth_tex);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT32, w, h, 0, GL_DEPTH_COMPONENT, GL_FLOAT, nullptr);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glGenFramebuffers(1, &g_scene_depth_fbo);
        glBindFramebuffer(GL_FRAMEBUFFER, g_scene_depth_fbo);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_TEXTURE_2D, g_scene_depth_tex, 0);
        glDrawBuffer(GL_NONE);
        glReadBuffer(GL_NONE);
        const bool depth_ok = glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
        // Pod exhaust / binder mask, same size, sharing that depth for the depth test.
        if (g_mask_fbo) {
            glDeleteFramebuffers(1, &g_mask_fbo);
            glDeleteTextures(1, &g_mask_tex);
        }
        glGenTextures(1, &g_mask_tex);
        glBindTexture(GL_TEXTURE_2D, g_mask_tex);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glGenFramebuffers(1, &g_mask_fbo);
        glBindFramebuffer(GL_FRAMEBUFFER, g_mask_fbo);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, g_mask_tex, 0);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_TEXTURE_2D, g_scene_depth_tex, 0);
        {
            const GLenum db = GL_COLOR_ATTACHMENT0;
            glDrawBuffers(1, &db);
        }
        return depth_ok && glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
    }

    // Every piece of GL state this module touches, saved and restored, so the renderer's own
    // state caching never sees a change.
    struct SavedState {
        GLint draw_fbo, read_fbo, viewport[4], program, vao, array_buffer, active_tex, tex0, tex1, tex2, tex3;
        GLint blend_src_rgb, blend_dst_rgb, blend_src_a, blend_dst_a;
        GLboolean blend, depth_test, depth_mask, cull, poly_offset, scissor, color_mask[4];
        GLint depth_func;
        GLfloat po_factor, po_units, clear_color[4];
        void save() {
            glGetIntegerv(GL_DRAW_FRAMEBUFFER_BINDING, &draw_fbo);
            glGetIntegerv(GL_READ_FRAMEBUFFER_BINDING, &read_fbo);
            glGetIntegerv(GL_VIEWPORT, viewport);
            glGetIntegerv(GL_CURRENT_PROGRAM, &program);
            glGetIntegerv(GL_VERTEX_ARRAY_BINDING, &vao);
            glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &array_buffer);
            glGetIntegerv(GL_ACTIVE_TEXTURE, &active_tex);
            glActiveTexture(GL_TEXTURE0);
            glGetIntegerv(GL_TEXTURE_BINDING_2D, &tex0);
            glActiveTexture(GL_TEXTURE1);
            glGetIntegerv(GL_TEXTURE_BINDING_2D, &tex1);
            glActiveTexture(GL_TEXTURE2);
            glGetIntegerv(GL_TEXTURE_BINDING_2D, &tex2);
            glActiveTexture(GL_TEXTURE3);
            glGetIntegerv(GL_TEXTURE_BINDING_2D, &tex3);
            glGetIntegerv(GL_BLEND_SRC_RGB, &blend_src_rgb);
            glGetIntegerv(GL_BLEND_DST_RGB, &blend_dst_rgb);
            glGetIntegerv(GL_BLEND_SRC_ALPHA, &blend_src_a);
            glGetIntegerv(GL_BLEND_DST_ALPHA, &blend_dst_a);
            blend = glIsEnabled(GL_BLEND);
            depth_test = glIsEnabled(GL_DEPTH_TEST);
            glGetBooleanv(GL_DEPTH_WRITEMASK, &depth_mask);
            glGetIntegerv(GL_DEPTH_FUNC, &depth_func);
            cull = glIsEnabled(GL_CULL_FACE);
            poly_offset = glIsEnabled(GL_POLYGON_OFFSET_FILL);
            glGetFloatv(GL_POLYGON_OFFSET_FACTOR, &po_factor);
            glGetFloatv(GL_POLYGON_OFFSET_UNITS, &po_units);
            scissor = glIsEnabled(GL_SCISSOR_TEST);
            glGetBooleanv(GL_COLOR_WRITEMASK, color_mask);
            glGetFloatv(GL_COLOR_CLEAR_VALUE, clear_color);
        }
        void restore() {
            glBindFramebuffer(GL_DRAW_FRAMEBUFFER, (GLuint) draw_fbo);
            glBindFramebuffer(GL_READ_FRAMEBUFFER, (GLuint) read_fbo);
            glViewport(viewport[0], viewport[1], viewport[2], viewport[3]);
            glUseProgram((GLuint) program);
            glBindVertexArray((GLuint) vao);
            glBindBuffer(GL_ARRAY_BUFFER, (GLuint) array_buffer);
            glActiveTexture(GL_TEXTURE3);
            glBindTexture(GL_TEXTURE_2D, (GLuint) tex3);
            glActiveTexture(GL_TEXTURE2);
            glBindTexture(GL_TEXTURE_2D, (GLuint) tex2);
            glActiveTexture(GL_TEXTURE1);
            glBindTexture(GL_TEXTURE_2D, (GLuint) tex1);
            glActiveTexture(GL_TEXTURE0);
            glBindTexture(GL_TEXTURE_2D, (GLuint) tex0);
            glActiveTexture((GLenum) active_tex);
            glBlendFuncSeparate(blend_src_rgb, blend_dst_rgb, blend_src_a, blend_dst_a);
            blend ? glEnable(GL_BLEND) : glDisable(GL_BLEND);
            depth_test ? glEnable(GL_DEPTH_TEST) : glDisable(GL_DEPTH_TEST);
            glDepthMask(depth_mask);
            glDepthFunc((GLenum) depth_func);
            cull ? glEnable(GL_CULL_FACE) : glDisable(GL_CULL_FACE);
            poly_offset ? glEnable(GL_POLYGON_OFFSET_FILL) : glDisable(GL_POLYGON_OFFSET_FILL);
            glPolygonOffset(po_factor, po_units);
            scissor ? glEnable(GL_SCISSOR_TEST) : glDisable(GL_SCISSOR_TEST);
            glColorMask(color_mask[0], color_mask[1], color_mask[2], color_mask[3]);
            glClearColor(clear_color[0], clear_color[1], clear_color[2], clear_color[3]);
        }
    };

    // ---- settings UI -----------------------------------------------------------------------
    const char* kSec = "shadows";
    float clampf(float v, float lo, float hi) { return v < lo ? lo : (v > hi ? hi : v); }

    void load_settings() {
        s.enabled = config::get_int(kSec, "enabled", s.enabled) != 0;
        s.hide_blob = config::get_int(kSec, "hide_blob", s.hide_blob) != 0;
        s.darkness = clampf(config::get_float(kSec, "darkness", s.darkness), 0.0f, 1.0f);
        s.softness = clampf(config::get_float(kSec, "softness", s.softness), 0.0f, 6.0f);
        s.extent = clampf(config::get_float(kSec, "extent", s.extent), 30.0f, 800.0f);
        const int size = config::get_int(kSec, "map_size", s.map_size);
        s.map_size = (size == 1024 || size == 2048 || size == 4096) ? size : 2048;
        s.sun_azimuth = clampf(config::get_float(kSec, "sun_azimuth", s.sun_azimuth), 0.0f, 360.0f);
        s.sun_elevation = clampf(config::get_float(kSec, "sun_elevation", s.sun_elevation), 10.0f, 90.0f);
        s.bias = clampf(config::get_float(kSec, "bias", s.bias), 0.0f, 0.01f);
        s.sun_shading = clampf(config::get_float(kSec, "sun_shading", s.sun_shading), 0.0f, 1.0f);
        s.lights = config::get_int(kSec, "lights", s.lights) != 0;
        s.light_intensity = clampf(config::get_float(kSec, "light_intensity", s.light_intensity), 0.0f, 4.0f);
        s.light_glow = clampf(config::get_float(kSec, "light_glow", s.light_glow), 0.0f, 1.0f);
        s.exhaust_tint = clampf(config::get_float(kSec, "exhaust_tint", s.exhaust_tint), 0.0f, 1.0f);
    }
    void save_settings() {
        config::set_bool(kSec, "enabled", s.enabled);
        config::set_bool(kSec, "hide_blob", s.hide_blob);
        config::set_float(kSec, "darkness", s.darkness);
        config::set_float(kSec, "softness", s.softness);
        config::set_float(kSec, "extent", s.extent);
        config::set_int(kSec, "map_size", s.map_size);
        config::set_float(kSec, "sun_azimuth", s.sun_azimuth);
        config::set_float(kSec, "sun_elevation", s.sun_elevation);
        config::set_float(kSec, "bias", s.bias);
        config::set_float(kSec, "sun_shading", s.sun_shading);
        config::set_bool(kSec, "lights", s.lights);
        config::set_float(kSec, "light_intensity", s.light_intensity);
        config::set_float(kSec, "light_glow", s.light_glow);
        config::set_float(kSec, "exhaust_tint", s.exhaust_tint);
        config::save();
    }
    int g_last_casters = 0, g_last_tris = 0, g_last_lights = 0;

    void panel() {
        bool changed = false;
        auto slider = [&](const char* label, float* v, float lo, float hi, const char* fmt, const char* tip) {
            ImGui::SliderFloat(label, v, lo, hi, fmt);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", tip);
            changed |= ImGui::IsItemDeactivatedAfterEdit();
        };
        changed |= ImGui::Checkbox("Real-time pod shadows", &s.enabled);
        if (g_gl_failed)
            ImGui::TextColored(ImVec4(1, 0.4f, 0.3f, 1), "Shadow shaders failed to build - see hook.log.");
        ImGui::BeginDisabled(!s.enabled);
        changed |= ImGui::Checkbox("Hide the old blob shadows", &s.hide_blob);
        slider("Darkness", &s.darkness, 0.0f, 1.0f, "%.2f", "How dark the shadows are.");
        slider("Softness", &s.softness, 0.0f, 6.0f, "%.1f", "Edge blur (in shadow-map texels).");
        slider("Sun direction", &s.sun_azimuth, 0.0f, 360.0f, "%.0f deg", "Compass direction the sunlight comes from.");
        slider("Sun height", &s.sun_elevation, 10.0f, 90.0f, "%.0f deg", "Lower = longer shadows.");
        slider("Shadow range", &s.extent, 30.0f, 800.0f, "%.0f", "How far around the camera shadows are drawn.\nLarger = covers more but blurrier.");
        int size_idx = s.map_size == 1024 ? 0 : (s.map_size == 4096 ? 2 : 1);
        if (ImGui::Combo("Quality", &size_idx, "1024 (fast)\0" "2048\0" "4096 (sharp)\0")) {
            s.map_size = size_idx == 0 ? 1024 : (size_idx == 2 ? 4096 : 2048);
            changed = true;
        }
        float bias_k = s.bias * 10000.0f;
        ImGui::SliderFloat("Bias", &bias_k, 0.0f, 50.0f, "%.1f");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Raise if surfaces show stripy self-shadowing; lower if shadows detach from the pod.");
        s.bias = bias_k / 10000.0f;
        changed |= ImGui::IsItemDeactivatedAfterEdit();
        ImGui::EndDisabled();// the exhaust tint works even with shadows off
        slider("Exhaust tint", &s.exhaust_tint, 0.0f, 1.0f, "%.2f",
               "Fixed dim on the pod exhaust flames (they never get real shadow).\n"
               "1 = full brightness, lower = darker / more see-through look.\n"
               "Works with shadows on or off.");
        ImGui::BeginDisabled(!s.enabled);
        slider("Sun shading", &s.sun_shading, 0.0f, 1.0f, "%.2f", "Darken surfaces facing away from the sun.");
        ImGui::SeparatorText("Dynamic lights");
        changed |= ImGui::Checkbox("Exhaust & fire light on surroundings", &s.lights);
        slider("Light intensity", &s.light_intensity, 0.0f, 4.0f, "%.2fx", "Brightness of the exhaust spotlights and fire lights.");
        slider("Light glow", &s.light_glow, 0.0f, 1.0f, "%.2f", "Extra direct glow so dark surfaces still pick the light up.");
        ImGui::TextDisabled("Last frame: %d caster meshes, %d triangles, %d lights", g_last_casters, g_last_tris, g_last_lights);
        ImGui::EndDisabled();
        if (ImGui::Button("Reset to defaults")) {
            s = kDefaults;
            changed = true;
        }
        if (changed)
            save_settings();
    }
    DebugPanel g_panel = {.category = "Mods", .name = "Shadows", .draw = panel, .dev_only = false};
}// namespace

bool shadows_enabled() {
    return s.enabled && !g_gl_failed;
}

// The pod-exhaust tint works on its own, even with shadows switched off.
static bool exhaust_tint_active() {
    return !g_gl_failed && s.exhaust_tint < 0.999f;
}

bool shadows_capture_active() {
    return shadows_enabled() || exhaust_tint_active();
}

bool shadows_hide_blob() {
    return shadows_enabled() && s.hide_blob;
}

void shadows_begin_viewport() {
    g_frame.clear();
    g_frame_cables.clear();
    g_mask_frame[0].clear();
    g_mask_frame[1].clear();
    g_shadow_caster_depth = 0;
    // Forget instances not drawn for a couple of seconds (pods that left / moved meshes).
    if ((++g_frame_no & 63) == 0) {
        for (auto it = g_cache.begin(); it != g_cache.end();) {
            it->second.remove_if([](const CasterGeo& g) { return g_frame_no - g.last_used > 120; });
            it = it->second.empty() ? g_cache.erase(it) : std::next(it);
        }
    }
}

void shadows_add_caster(const swrModel_Mesh* mesh, const rdMatrix44& model_matrix,
                        const std::vector<ShadowCasterVertex>* fresh,
                        void (*reparse)(const rdMatrix44&, const swrModel_Mesh*, std::vector<ShadowCasterVertex>&),
                        const ShadowCasterTexture& texture, int role) {
    if (mesh == nullptr || ((role == 0 || role == 3) ? !shadows_enabled() : !shadows_capture_active()))
        return;
    std::list<CasterGeo>& instances = g_cache[mesh];
    // This exact instance (same matrix) already cached?
    CasterGeo* g = nullptr;
    for (CasterGeo& c: instances)
        if (memcmp(&c.matrix, &model_matrix, sizeof(rdMatrix44)) == 0) {
            g = &c;
            break;
        }
    if (g == nullptr) {
        // New instance or a moved one: reuse the slot not claimed yet this frame, else add one.
        for (CasterGeo& c: instances)
            if (c.last_used != g_frame_no) {
                g = &c;
                break;
            }
        if (g == nullptr) {
            instances.emplace_back();
            g = &instances.back();
        }
        g->matrix = model_matrix;
        g->pos.clear();
        if (fresh != nullptr)
            g->pos = *fresh;
        else if (reparse)
            reparse(model_matrix, mesh, g->pos);
    } else if (fresh != nullptr) {
        g->pos = *fresh;
    }
    g->tex = texture;
    g->last_used = g_frame_no;
    if (!g->pos.empty())
        (role == 0 ? g_frame : role == 3 ? g_frame_cables : g_mask_frame[role == 2 ? 1 : 0]).push_back(g);
}

namespace {
    rdVector3 g_cam_pos{}, g_cam_right{}, g_cam_vel{};
    std::chrono::steady_clock::time_point g_cam_time{};
    bool g_cam_valid = false;
}// namespace

void camera_record(const rdMatrix44& view) {
    float inv[16];
    if (!invert(&view.vA.x, inv))
        return;
    const rdVector3 pos = {inv[12], inv[13], inv[14]};
    const auto now = std::chrono::steady_clock::now();
    // Camera velocity (smoothed), for Doppler. A jump (cut to another camera) resets it.
    if (g_cam_valid) {
        const float dt = std::chrono::duration<float>(now - g_cam_time).count();
        if (dt > 1e-4f && dt < 0.25f) {
            const rdVector3 v = {(pos.x - g_cam_pos.x) / dt, (pos.y - g_cam_pos.y) / dt, (pos.z - g_cam_pos.z) / dt};
            const float sp2 = v.x * v.x + v.y * v.y + v.z * v.z;
            if (sp2 > 3000.0f * 3000.0f) {
                g_cam_vel = {0, 0, 0};
            } else {
                const float k = 1.0f - std::exp(-dt / 0.08f);
                g_cam_vel = {g_cam_vel.x + (v.x - g_cam_vel.x) * k, g_cam_vel.y + (v.y - g_cam_vel.y) * k,
                             g_cam_vel.z + (v.z - g_cam_vel.z) * k};
            }
        }
    }
    g_cam_pos = pos;
    g_cam_right = {inv[0], inv[1], inv[2]};// camera +x in world space
    g_cam_time = now;
    g_cam_valid = true;
}

bool camera_get_velocity(rdVector3* vel) {
    if (!g_cam_valid || std::chrono::steady_clock::now() - g_cam_time > std::chrono::milliseconds(500))
        return false;
    *vel = g_cam_vel;
    return true;
}

bool camera_get(rdVector3* pos, rdVector3* right) {
    if (!g_cam_valid || std::chrono::steady_clock::now() - g_cam_time > std::chrono::milliseconds(500))
        return false;
    if (pos)
        *pos = g_cam_pos;
    if (right)
        *right = g_cam_right;
    return true;
}

void shadows_clear_cache() {
    g_cache.clear();
    g_frame.clear();
    g_frame_cables.clear();
    g_mask_frame[0].clear();
    g_mask_frame[1].clear();
}

void shadows_render(const rdMatrix44& proj, const rdMatrix44& view, unsigned int scene_fbo, int width, int height) {
    if (!shadows_capture_active() || width <= 0 || height <= 0)
        return;
    // With shadows off only the exhaust tint runs (no casters, sun shading or lights).
    const bool shadows_on = shadows_enabled();
    const float sun_shading = shadows_on ? s.sun_shading : 0.0f;
    static std::vector<SceneLight> lights;
    lights.clear();
    if (shadows_on && s.lights)
        pod_fx_gather_lights(lights);
    const bool has_casters = shadows_on && (!g_frame.empty() || !g_frame_cables.empty());
    const bool has_mask = !g_mask_frame[0].empty() || !g_mask_frame[1].empty();
    if (!has_casters && lights.empty() && sun_shading <= 0.0f && !has_mask)
        return;
    SavedState st;
    st.save();
    if (!ensure_gl() || !ensure_scene_depth(width, height)) {
        st.restore();
        return;
    }

    // Camera position and forward from the inverse view matrix (rdMatrix44 == GL column-major).
    float inv_view[16];
    if (!invert(&view.vA.x, inv_view)) {
        st.restore();
        return;
    }
    const V3 cam = {inv_view[12], inv_view[13], inv_view[14]};
    const V3 fwd = v_norm({-inv_view[8], -inv_view[9], -inv_view[10]});

    // Sun: direction the light travels (from the sky toward the ground, world z up).
    const float az = s.sun_azimuth * 0.0174533f, el = s.sun_elevation * 0.0174533f;
    const V3 to_sun = v_norm({std::cos(el) * std::cos(az), std::cos(el) * std::sin(az), std::sin(el)});
    // Shadowed area: centred a bit ahead of the camera, where most of what's visible is.
    const float ext = s.extent;
    const V3 focus = {cam.x + fwd.x * ext * 0.5f, cam.y + fwd.y * ext * 0.5f, cam.z + fwd.z * ext * 0.5f};
    const V3 up = std::fabs(to_sun.z) > 0.98f ? V3{0, 1, 0} : V3{0, 0, 1};
    // Fixed-orientation light view through the origin; the box is placed in that space and its
    // centre snapped to whole shadow-map texels so the shadow edges don't shimmer as the camera moves.
    const M4 lview = look_at({to_sun.x, to_sun.y, to_sun.z}, {0, 0, 0}, up);
    const float fx = lview.m[0] * focus.x + lview.m[4] * focus.y + lview.m[8] * focus.z + lview.m[12];
    const float fy = lview.m[1] * focus.x + lview.m[5] * focus.y + lview.m[9] * focus.z + lview.m[13];
    const float fz = lview.m[2] * focus.x + lview.m[6] * focus.y + lview.m[10] * focus.z + lview.m[14];
    const float texel_world = 2.0f * ext / (float) s.map_size;
    const float cx = std::floor(fx / texel_world) * texel_world, cy = std::floor(fy / texel_world) * texel_world;
    const float depth_range = std::max(600.0f, ext * 3.0f);
    const M4 lproj = ortho(cx - ext, cx + ext, cy - ext, cy + ext, -fz - depth_range, -fz + depth_range);
    const M4 light_vp = mul(lproj, lview);

    // ---- 1) caster depth from the sun ----
    static std::vector<GpuVert> verts;
    static std::vector<TexRun> runs;
    static std::vector<const CasterGeo*> all_casters;
    all_casters = g_frame;
    all_casters.insert(all_casters.end(), g_frame_cables.begin(), g_frame_cables.end());
    build_batches(all_casters, verts, runs);
    g_last_casters = (int) all_casters.size();
    g_last_tris = (int) (verts.size() / 3);
    g_last_lights = (int) lights.size();
    // Body casters come first in `verts`; the body-only map draws just the runs covering them.
    size_t body_verts = 0;
    for (const CasterGeo* g: g_frame)
        body_verts += g->pos.size();

    glBindFramebuffer(GL_FRAMEBUFFER, g_shadow_fbo);
    glViewport(0, 0, g_shadow_size, g_shadow_size);
    glDisable(GL_SCISSOR_TEST);
    glDisable(GL_BLEND);
    glDisable(GL_CULL_FACE);// pod meshes are a mix of one- and two-sided
    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LESS);
    glDepthMask(GL_TRUE);
    glColorMask(GL_FALSE, GL_FALSE, GL_FALSE, GL_FALSE);
    glEnable(GL_POLYGON_OFFSET_FILL);
    glPolygonOffset(1.5f, 3.0f);
    glClear(GL_DEPTH_BUFFER_BIT);
    glUseProgram(g_depth_prog);
    glUniformMatrix4fv(glGetUniformLocation(g_depth_prog, "lightVP"), 1, GL_FALSE, light_vp.m);
    glUniform1i(glGetUniformLocation(g_depth_prog, "tex"), 0);
    glBindVertexArray(g_vao);
    glBindBuffer(GL_ARRAY_BUFFER, g_vbo);
    glBufferData(GL_ARRAY_BUFFER, (GLsizeiptr) (verts.size() * sizeof(GpuVert)), verts.data(), GL_STREAM_DRAW);
    draw_runs(runs);
    // Body-only map (no cables), sampled on pod surfaces.
    glBindFramebuffer(GL_FRAMEBUFFER, g_body_fbo);
    glClear(GL_DEPTH_BUFFER_BIT);
    {
        static std::vector<TexRun> body_runs;
        body_runs.clear();
        for (const TexRun& r: runs) {
            if ((size_t) r.first >= body_verts)
                break;
            TexRun b = r;
            b.count = (GLsizei) std::min<size_t>((size_t) r.count, body_verts - (size_t) r.first);
            body_runs.push_back(b);
        }
        draw_runs(body_runs);
    }
    glDisable(GL_POLYGON_OFFSET_FILL);
    glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);

    // ---- 2) resolve the scene's (multisampled) depth to a texture we can sample ----
    glBindFramebuffer(GL_READ_FRAMEBUFFER, scene_fbo);
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, g_scene_depth_fbo);
    glBlitFramebuffer(0, 0, width, height, 0, 0, width, height, GL_DEPTH_BUFFER_BIT, GL_NEAREST);

    // ---- 2b) screen mask of the pod exhaust (r) / energy binders (g) drawn this frame ----
    glBindFramebuffer(GL_FRAMEBUFFER, g_mask_fbo);
    glViewport(0, 0, width, height);
    glDisable(GL_BLEND);
    glDisable(GL_CULL_FACE);
    glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
    glClearColor(0, 0, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT);
    if (has_mask || (has_casters && !g_frame_cables.empty())) {
        glEnable(GL_DEPTH_TEST);
        glDepthFunc(GL_LEQUAL);
        glDepthMask(GL_FALSE);// test against the scene depth, never write it
        glEnable(GL_POLYGON_OFFSET_FILL);
        glPolygonOffset(-1.0f, -8.0f);// pull toward the camera so opaque exhaust passes against itself
        glUseProgram(g_mask_prog);
        glUniformMatrix4fv(glGetUniformLocation(g_mask_prog, "proj"), 1, GL_FALSE, &proj.vA.x);
        glUniformMatrix4fv(glGetUniformLocation(g_mask_prog, "view"), 1, GL_FALSE, &view.vA.x);
        glUniform1i(glGetUniformLocation(g_mask_prog, "tex"), 0);
        glBindVertexArray(g_vao);
        glBindBuffer(GL_ARRAY_BUFFER, g_vbo);
        // Overlapping layers keep the strongest coverage per channel.
        glEnable(GL_BLEND);
        glBlendEquation(GL_MAX);
        for (int k = 0; k < 3; k++) {
            // k: 0 = exhaust (r), 1 = binders (g), 2 = pod body (b: shadowed without the cables)
            const std::vector<const CasterGeo*>& list = k < 2 ? g_mask_frame[k] : g_frame;
            if (list.empty() || (k == 2 && !(has_casters && !g_frame_cables.empty())))
                continue;
            build_batches(list, verts, runs);
            glUniform4f(glGetUniformLocation(g_mask_prog, "maskColor"), k == 0 ? 1.0f : 0.0f, k == 1 ? 1.0f : 0.0f,
                        k == 2 ? 1.0f : 0.0f, 1);
            glUniform1i(glGetUniformLocation(g_mask_prog, "weighted"), k == 1 ? 1 : (k == 2 ? 2 : 0));
            glBufferData(GL_ARRAY_BUFFER, (GLsizeiptr) (verts.size() * sizeof(GpuVert)), verts.data(), GL_STREAM_DRAW);
            draw_runs(runs);
        }
        glBlendEquation(GL_FUNC_ADD);
        glDisable(GL_BLEND);
        glDisable(GL_POLYGON_OFFSET_FILL);
    }

    // ---- 3) darken shadowed scene pixels (multiplicative blend into the scene colour) ----
    glBindFramebuffer(GL_FRAMEBUFFER, scene_fbo);
    glViewport(0, 0, width, height);
    glDisable(GL_DEPTH_TEST);
    glDepthMask(GL_FALSE);
    glEnable(GL_BLEND);
    glBlendFuncSeparate(GL_DST_COLOR, GL_ZERO, GL_ZERO, GL_ONE);
    glUseProgram(g_apply_prog);
    glUniformMatrix4fv(glGetUniformLocation(g_apply_prog, "proj"), 1, GL_FALSE, &proj.vA.x);
    glUniformMatrix4fv(glGetUniformLocation(g_apply_prog, "view"), 1, GL_FALSE, &view.vA.x);
    glUniformMatrix4fv(glGetUniformLocation(g_apply_prog, "lightVP"), 1, GL_FALSE, light_vp.m);
    glUniform1f(glGetUniformLocation(g_apply_prog, "darkness"), s.darkness);
    glUniform1f(glGetUniformLocation(g_apply_prog, "softness"), s.softness);
    glUniform1f(glGetUniformLocation(g_apply_prog, "texel"), 1.0f / (float) g_shadow_size);
    glUniform1f(glGetUniformLocation(g_apply_prog, "bias"), s.bias);
    glUniform1i(glGetUniformLocation(g_apply_prog, "sceneDepth"), 0);
    glUniform1i(glGetUniformLocation(g_apply_prog, "shadowMap"), 1);
    glUniform1i(glGetUniformLocation(g_apply_prog, "shadowMapBody"), 3);
    glUniform3f(glGetUniformLocation(g_apply_prog, "camPos"), cam.x, cam.y, cam.z);
    glUniform3f(glGetUniformLocation(g_apply_prog, "toSun"), to_sun.x, to_sun.y, to_sun.z);
    glUniform1f(glGetUniformLocation(g_apply_prog, "sunShading"), sun_shading);
    glUniform1i(glGetUniformLocation(g_apply_prog, "hasCasters"), has_casters ? 1 : 0);
    glUniform1i(glGetUniformLocation(g_apply_prog, "podMask"), 2);
    glUniform1f(glGetUniformLocation(g_apply_prog, "exhaustTint"), s.exhaust_tint);
    glActiveTexture(GL_TEXTURE3);
    glBindTexture(GL_TEXTURE_2D, g_body_tex);
    glActiveTexture(GL_TEXTURE2);
    glBindTexture(GL_TEXTURE_2D, g_mask_tex);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, g_scene_depth_tex);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, g_shadow_tex);
    glBindVertexArray(g_empty_vao);
    if (has_casters || sun_shading > 0.0f || !g_mask_frame[0].empty())
        glDrawArrays(GL_TRIANGLES, 0, 3);

    // ---- 4) dynamic lights: exhaust spotlights + damage-fire point lights ----
    if (!lights.empty()) {
        // Keep the 32 nearest the camera.
        if (lights.size() > 32) {
            std::partial_sort(lights.begin(), lights.begin() + 32, lights.end(), [&](const SceneLight& a, const SceneLight& b) {
                auto d2 = [&](const SceneLight& l) {
                    const float dx = l.pos.x - cam.x, dy = l.pos.y - cam.y, dz = l.pos.z - cam.z;
                    return dx * dx + dy * dy + dz * dz;
                };
                return d2(a) < d2(b);
            });
            lights.resize(32);
        }
        float lp[32 * 4], ld[32 * 4], lc[32 * 4];
        for (size_t i = 0; i < lights.size(); i++) {
            const SceneLight& l = lights[i];
            const float k = l.intensity * s.light_intensity;
            lp[i * 4 + 0] = l.pos.x, lp[i * 4 + 1] = l.pos.y, lp[i * 4 + 2] = l.pos.z, lp[i * 4 + 3] = l.radius;
            ld[i * 4 + 0] = l.dir.x, ld[i * 4 + 1] = l.dir.y, ld[i * 4 + 2] = l.dir.z, ld[i * 4 + 3] = l.cos_outer;
            lc[i * 4 + 0] = l.r * k, lc[i * 4 + 1] = l.g * k, lc[i * 4 + 2] = l.b * k, lc[i * 4 + 3] = l.cos_inner;
        }
        glUseProgram(g_light_prog);
        glUniformMatrix4fv(glGetUniformLocation(g_light_prog, "proj"), 1, GL_FALSE, &proj.vA.x);
        glUniformMatrix4fv(glGetUniformLocation(g_light_prog, "view"), 1, GL_FALSE, &view.vA.x);
        glUniform1i(glGetUniformLocation(g_light_prog, "sceneDepth"), 0);
        glUniform1i(glGetUniformLocation(g_light_prog, "podMask"), 2);
        glUniform3f(glGetUniformLocation(g_light_prog, "camPos"), cam.x, cam.y, cam.z);
        glUniform1i(glGetUniformLocation(g_light_prog, "numLights"), (int) lights.size());
        glUniform4fv(glGetUniformLocation(g_light_prog, "lightPos"), (GLsizei) lights.size(), lp);
        glUniform4fv(glGetUniformLocation(g_light_prog, "lightDir"), (GLsizei) lights.size(), ld);
        glUniform4fv(glGetUniformLocation(g_light_prog, "lightCol"), (GLsizei) lights.size(), lc);
        glUniform1f(glGetUniformLocation(g_light_prog, "glow"), s.light_glow);
        // Pass 1: lit = surface colour * (1 + light).
        glBlendFuncSeparate(GL_DST_COLOR, GL_ONE, GL_ZERO, GL_ONE);
        glUniform1i(glGetUniformLocation(g_light_prog, "mode"), 0);
        glDrawArrays(GL_TRIANGLES, 0, 3);
        // Pass 2: a little direct glow so dark surfaces still catch the light.
        if (s.light_glow > 0.0f) {
            glBlendFuncSeparate(GL_ONE, GL_ONE, GL_ZERO, GL_ONE);
            glUniform1i(glGetUniformLocation(g_light_prog, "mode"), 1);
            glDrawArrays(GL_TRIANGLES, 0, 3);
        }
    }

    st.restore();
}

void shadows_register_panel() {
    load_settings();
    debug_ui_register(&g_panel);
}
