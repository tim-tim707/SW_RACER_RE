#include "sdf_text.h"

#include <glad/glad.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>// MultiByteToWideChar for Unicode font paths

#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#define STB_TRUETYPE_IMPLEMENTATION
#include "stb/stb_truetype.h"

extern "C" {
#include <types.h>
#include <globals.h>
}

extern FILE* hook_log;

// ---- atlas / rasterization parameters ------------------------------------------------
static const int ATLAS_W = 2048;
static const int ATLAS_H = 2048;
static const int EM_PX = 128;// glyph render height in the atlas (decoupled from draw size)
// Distance-field reach (atlas px). This caps how far the ~o outline can extend at small draw
// sizes: at scale s, the border can reach at most SDF_PADDING*s screen px before saturating, so a
// thin look on small body numbers means too little padding. 12 keeps small-text outlines crisp.
static const int SDF_PADDING = 12;
static const unsigned char SDF_ONEDGE = 128;
static const float SDF_PIXEL_DIST = SDF_ONEDGE / (float) SDF_PADDING;
static const int DISPLAY_FONT_CAP = 14;// cap height (texels) at/above which a font is display
static const int FIRST_CP = 0x20;
static const int LAST_CP = 0x7e;
static const int GLYPH_COUNT = LAST_CP - FIRST_CP + 1;

// Built-in defaults substituted when a slot has no user-picked font. Body role = DejaVu Sans
// (Verdana), display role = Anton (Impact), matching the shipped feature.
static const char* BODY_TTF = "./assets/fonts/DejaVuSans.ttf";
static const char* DISPLAY_TTF = "./assets/fonts/Anton-Regular.ttf";

// Role-based tunable defaults (reproduce the values that were dialed in by playtest). See
// resolve_slot_defaults; kept here so the default config renders identically to before the panel.
static const float DEFAULT_DISPLAY_SHEAR = 0.20f;// faux-italic slant for the Impact/Anton face
static const float DEFAULT_BODY_WEIGHT = 0.08f;  // fatten DejaVu toward a semibold weight
static const float DEFAULT_BODY_TRACKING_EM = 0.03f;// open body letter-spacing a touch (~3% em)
static const float DISPLAY_DIGIT_WIDEN = 1.12f;  // widen the display face's tabular digit cell
static const float SLOT2_SCALE = 0.92f;          // in-race number face renders a little large
static const float SLOT2_OFFSET_Y = 0.04f;       // ...and a touch high (net of the shear nudge)
static const float DISPLAY_OFFSET_Y = -0.38f;    // Anton sits low vs the game's Impact; lift it

// The stock fonts substitute symbols at a few ASCII slots; reproduce them with the real
// codepoints (these live outside ASCII so they are stored as atlas "extras").
static const int EXTRA_CPS[] = {0x00A9, 0x00AE, 0x2122};// (c)  (r)  (tm)
static const int NUM_EXTRAS = (int) (sizeof(EXTRA_CPS) / sizeof(EXTRA_CPS[0]));

struct Glyph {
    float u0, v0, u1, v1;// atlas UVs
    float w, h;          // SDF bitmap size in atlas px
    float xoff, yoff;    // bitmap top-left relative to pen/baseline, atlas px
    float advance;       // advance in atlas px
    bool present;
};

struct Vert {
    float x, y, u, v, r, g, b, a;
    float ow;// outline width in screen px (0 = no outline); the SDF shader dilates the edge by it
};

// A built font atlas keyed by (path, shear). Slots that share a file+shear share one Face, so the
// default two-face config stays two atlases. The CPU raster runs on a detached worker thread; the
// GL upload happens on the main thread once the raster finishes.
struct Face {
    std::string path; // key part 1: resolved TTF path
    float shear = 0;  // key part 2: baked faux-italic slant (0 = upright)

    std::vector<unsigned char> ttf;
    stbtt_fontinfo info;
    GLuint atlas = 0;
    float atlasScale = 0;     // stbtt scale used at EM_PX
    float linePx = 0;         // line advance in atlas px
    float capInkPx = 1;       // ink height of 'A' in atlas px (for sizing)
    float digitAdvance = 0;   // advance of '0' in atlas px (tabular/monospace digits)
    Glyph glyphs[GLYPH_COUNT];// ASCII FIRST_CP..LAST_CP
    Glyph extras[NUM_EXTRAS]; // EXTRA_CPS glyphs
    std::vector<unsigned char> atlasBytes;// CPU raster (worker thread) held until the GL upload

    // build state machine (see faces_pump); raster_done gates the CPU->GL handoff.
    enum State { Loading, Rastering, Uploaded, Failed };
    std::atomic<int> state{Loading};
    std::atomic<bool> raster_done{false};
    bool worker_launched = false;// a detached worker touches atlasBytes -> don't free until done
};

// The atlas cache. unique_ptr keeps each Face's address stable (stbtt_fontinfo points into its
// ttf bytes, and slots/workers hold raw Face*) across vector growth and sweeps.
static std::vector<std::unique_ptr<Face>> g_faces;

// One editable font slot (per swrText_fonts[0..4]): the user-facing config plus the resolved
// face(s) and the classification anchors the renderer needs.
struct Slot {
    SdfFontSlot cfg;      // panel-edited config (zero-initialized; cfg.scale==0 => unresolved)
    Face* face = nullptr; // currently rendering (null until the first face is ready)
    Face* pending = nullptr;// building; swapped into face when it reaches Uploaded (no flicker)
    float targetCap = 10; // vanilla cap height in game-2D units (size anchor)
    bool uppercaseOnly = false;
    bool display = false; // classified role (cap >= DISPLAY_FONT_CAP)
};
static Slot g_slots[SDF_SLOT_COUNT];

// One-time engine setup flags. The GL program builds once; slot classification waits for the
// game's fonts, then resolves defaults + kicks the initial face builds.
static bool g_program_built = false;
static bool g_program_failed = false;
static bool g_classified = false;

// All glyph quads queued this frame, in submission (draw) order, plus the per-string runs that
// index into them. Flushed at scene end. Keeping one ordered buffer (rather than one per face)
// preserves the game's painter order across faces so e.g. a shadowed display word still layers
// correctly over body text drawn before it.
static std::vector<Vert> g_verts;
struct DrawBatch {
    Face* face;
    float weight;// SDF weight bias for this run (per-slot; set the shader uniform per batch)
    size_t start;
    size_t count;
};
static std::vector<DrawBatch> g_batches;

static GLuint g_program = 0;
static GLint g_proj_loc = -1;
static GLint g_wbias_loc = -1;
static GLuint g_vao = 0, g_vbo = 0;

// World-locked labels (overhead racer position numbers / MP names) arrive as a framebuffer pixel
// that the caller rounds to an integer design coordinate before storing it in the text-entry list;
// at high res one design unit spans several px, so the label snaps to a coarse grid as the pod
// moves. The label path registers the exact (fractional) design coordinate here, keyed by the
// rounded value the entry stores; when a string later renders from that rounded pen position the
// layout uses the exact value instead, so the label tracks smoothly. Reset per frame in the flush.
struct SubPos {
    int16_t rx, ry;// rounded design coord in the text entry (== currentTextPos when it renders)
    float ex, ey;  // exact fractional design coord to place the pen at instead
};
static SubPos g_subpos[64];
static int g_subposCount = 0;

void sdf_text_set_subpos(int rx, int ry, float ex, float ey) {
    if (g_subposCount < (int) (sizeof(g_subpos) / sizeof(g_subpos[0])))
        g_subpos[g_subposCount++] = {(int16_t) rx, (int16_t) ry, ex, ey};
}

static bool subpos_lookup(int16_t rx, int16_t ry, float* ex, float* ey) {
    for (int i = 0; i < g_subposCount; i++)
        if (g_subpos[i].rx == rx && g_subpos[i].ry == ry) {
            *ex = g_subpos[i].ex;
            *ey = g_subpos[i].ey;
            return true;
        }
    return false;
}

// ---- ttf loading + atlas build -------------------------------------------------------
// Open a font by UTF-8 path (handles non-ASCII paths, e.g. a user's profile folder).
static FILE* open_font_file(const char* path) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, nullptr, 0);
    if (wlen <= 0)
        return fopen(path, "rb");
    std::wstring w((size_t) wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path, -1, w.data(), wlen);
    return _wfopen(w.c_str(), L"rb");
}

static bool load_ttf(const char* path, Face& f) {
    FILE* fp = open_font_file(path);
    if (!fp) {
        // Portability: a shared profile may reference a font by an absolute path that differs
        // between machines. Fall back to the same filename under ./assets/fonts, so bundled fonts
        // travel with a profile even when the original path does not exist here.
        const char* base = path;
        for (const char* q = path; *q; q++)
            if (*q == '/' || *q == '\\')
                base = q + 1;
        if (base != path && *base) {
            std::string alt = std::string("./assets/fonts/") + base;
            fp = open_font_file(alt.c_str());
            if (fp)
                fprintf(hook_log, "sdf_text: %s not found; using %s\n", path, alt.c_str());
        }
    }
    if (!fp) {
        fprintf(hook_log, "sdf_text: cannot open %s\n", path);
        return false;
    }
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    f.ttf.resize(n);
    size_t got = fread(f.ttf.data(), 1, n, fp);
    fclose(fp);
    if ((long) got != n || !stbtt_InitFont(&f.info, f.ttf.data(),
                                           stbtt_GetFontOffsetForIndex(f.ttf.data(), 0))) {
        fprintf(hook_log, "sdf_text: failed to init %s\n", path);
        f.ttf.clear();
        return false;
    }
    return true;
}

// Rasterize one codepoint's SDF (upright) and shelf-pack it into the atlas, filling *out.
static void pack_glyph(Face& f, std::vector<unsigned char>& atlas, int cp, Glyph* out, int& penX,
                       int& penY, int& rowH) {
    *out = (Glyph) {0};
    int adv = 0, lsb = 0;
    stbtt_GetCodepointHMetrics(&f.info, cp, &adv, &lsb);
    out->advance = adv * f.atlasScale;

    int w = 0, h = 0, xoff = 0, yoff = 0;
    unsigned char* sdf = stbtt_GetCodepointSDF(&f.info, f.atlasScale, cp, SDF_PADDING, SDF_ONEDGE,
                                               SDF_PIXEL_DIST, &w, &h, &xoff, &yoff);
    if (!sdf || w <= 0 || h <= 0) {
        if (sdf)
            stbtt_FreeSDF(sdf, nullptr);
        return;// advance-only (e.g. space)
    }

    // For sheared (faux-italic) faces, bake the slant into the bitmap with a sub-pixel (bilinear)
    // per-row horizontal shift. Doing it here (upright quad at draw time) keeps the SDF
    // antialiasing uniform; skewing the quad instead makes acute corners ragged.
    int srcW = w;
    const unsigned char* src = sdf;
    std::vector<unsigned char> sheared;
    if (f.shear != 0.0f) {
        int margin = (int) ceilf(h * 0.5f * f.shear) + 1;
        int ow = w + 2 * margin;
        sheared.assign((size_t) ow * h, 0);
        for (int y = 0; y < h; y++) {
            float shift = (h * 0.5f - y) * f.shear;// +right at top, -left at bottom
            for (int ox = 0; ox < ow; ox++) {
                float ix = ox - margin - shift;
                int ix0 = (int) floorf(ix);
                float frac = ix - ix0;
                float a = (ix0 >= 0 && ix0 < w) ? sdf[y * w + ix0] : 0.0f;
                float b = (ix0 + 1 >= 0 && ix0 + 1 < w) ? sdf[y * w + ix0 + 1] : 0.0f;
                sheared[(size_t) y * ow + ox] = (unsigned char) (a * (1.0f - frac) + b * frac + 0.5f);
            }
        }
        src = sheared.data();
        srcW = ow;
        xoff -= margin;
    }

    if (penX + srcW + 1 > ATLAS_W) {
        penX = 0;
        penY += rowH + 1;
        rowH = 0;
    }
    if (penY + h > ATLAS_H) {
        stbtt_FreeSDF(sdf, nullptr);
        return;
    }
    for (int y = 0; y < h; y++)
        for (int x = 0; x < srcW; x++)
            atlas[(size_t) (penY + y) * ATLAS_W + (penX + x)] = src[y * srcW + x];
    out->present = true;
    out->u0 = (float) penX / ATLAS_W;
    out->v0 = (float) penY / ATLAS_H;
    out->u1 = (float) (penX + srcW) / ATLAS_W;
    out->v1 = (float) (penY + h) / ATLAS_H;
    out->w = (float) srcW;
    out->h = (float) h;
    out->xoff = (float) xoff;
    out->yoff = (float) yoff;
    if (cp == 'A')
        f.capInkPx = (float) (h - 2 * SDF_PADDING);
    penX += srcW + 1;
    if (h > rowH)
        rowH = h;
    stbtt_FreeSDF(sdf, nullptr);
}

// CPU half of the face build: rasterize every glyph's SDF into f.atlasBytes and record its metrics.
// Pure stbtt + memory (no GL, no game state), so it is safe to run on a worker thread.
static void build_face_cpu(Face& f) {
    f.atlasScale = stbtt_ScaleForPixelHeight(&f.info, (float) EM_PX);
    int asc = 0, desc = 0, gap = 0;
    stbtt_GetFontVMetrics(&f.info, &asc, &desc, &gap);
    f.linePx = (asc - desc + gap) * f.atlasScale;

    f.atlasBytes.assign((size_t) ATLAS_W * ATLAS_H, 0);
    int penX = 0, penY = 0, rowH = 0;
    for (int i = 0; i < GLYPH_COUNT; i++)
        pack_glyph(f, f.atlasBytes, FIRST_CP + i, &f.glyphs[i], penX, penY, rowH);
    for (int i = 0; i < NUM_EXTRAS; i++)
        pack_glyph(f, f.atlasBytes, EXTRA_CPS[i], &f.extras[i], penX, penY, rowH);
    if (f.capInkPx < 1)
        f.capInkPx = EM_PX * 0.7f;
    f.digitAdvance = f.glyphs['0' - FIRST_CP].advance;
    // Sheared faces are the display/number role; their tabular digits sit tight, so widen the
    // fixed digit cell a little (digits stay centered in the wider cell).
    if (f.shear != 0.0f)
        f.digitAdvance *= DISPLAY_DIGIT_WIDEN;
}

// GL half: upload the rasterized atlas as a texture, then free the CPU copy. Main thread only.
static void build_face_gl(Face& f) {
    glGenTextures(1, &f.atlas);
    glBindTexture(GL_TEXTURE_2D, f.atlas);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_R8, ATLAS_W, ATLAS_H, 0, GL_RED, GL_UNSIGNED_BYTE,
                 f.atlasBytes.data());
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glBindTexture(GL_TEXTURE_2D, 0);
    f.atlasBytes = std::vector<unsigned char>();// release the ~4 MB CPU copy
}

// Find an existing atlas for (path, shear) or create one and kick its worker. Never returns null;
// a load failure yields a Face in the Failed state so the caller can fall back.
static Face* face_get_or_create(const std::string& path, float shear) {
    for (auto& up: g_faces) {
        Face* f = up.get();
        if (f->state.load() == Face::Failed)
            continue;
        if (f->path == path && fabsf(f->shear - shear) < 1e-4f)
            return f;
    }

    auto up = std::make_unique<Face>();
    Face* f = up.get();
    f->path = path;
    f->shear = shear;
    g_faces.push_back(std::move(up));

    if (!load_ttf(path.c_str(), *f)) {
        f->state.store(Face::Failed);
        return f;
    }
    f->state.store(Face::Rastering);
    f->worker_launched = true;
    std::thread([f] {
        build_face_cpu(*f);
        f->raster_done.store(true, std::memory_order_release);
    }).detach();
    return f;
}

// The resolved (path, shear) a slot wants right now (built-in default when the slot is on auto).
static std::string slot_resolved_path(int i) {
    const SdfFontSlot& c = g_slots[i].cfg;
    if (!c.fileAuto && c.file[0])
        return c.file;
    return g_slots[i].display ? DISPLAY_TTF : BODY_TTF;
}

// Re-resolve slot i's face from its config and (re)build its atlas if the target changed. The old
// atlas keeps rendering until the new one is ready (set as `pending`, swapped in faces_pump).
void sdf_text_apply_slot(int i) {
    if (i < 0 || i >= SDF_SLOT_COUNT || !g_classified)
        return;
    Slot& s = g_slots[i];
    Face* want = face_get_or_create(slot_resolved_path(i), s.cfg.shear);
    if (want == s.face) {
        s.pending = nullptr;// already current
        return;
    }
    int st = want->state.load();
    if (st == Face::Uploaded) {
        s.face = want;
        s.pending = nullptr;
    } else if (st == Face::Failed) {
        s.pending = nullptr;// keep the old face (or none -> bitmap fallback)
    } else {
        s.pending = want;// still building; swap when ready
    }
}

// Pump face build state each frame: upload finished rasters, swap ready pending faces into their
// slots, then free faces no slot references (deferring any whose worker is still running).
static void faces_pump() {
    for (auto& up: g_faces) {
        Face* f = up.get();
        if (f->state.load() == Face::Rastering &&
            f->raster_done.load(std::memory_order_acquire)) {
            build_face_gl(*f);
            f->state.store(Face::Uploaded);
        }
    }

    for (int i = 0; i < SDF_SLOT_COUNT; i++) {
        Slot& s = g_slots[i];
        if (!s.pending)
            continue;
        int st = s.pending->state.load();
        if (st == Face::Uploaded) {
            s.face = s.pending;
            s.pending = nullptr;
        } else if (st == Face::Failed) {
            s.pending = nullptr;
        }
    }

    // Sweep unreferenced faces. Keep any face still being rastered by a worker (freeing it would
    // dangle the worker's Face*); it becomes collectable once raster_done + unreferenced.
    for (size_t k = 0; k < g_faces.size();) {
        Face* f = g_faces[k].get();
        bool referenced = false;
        for (int i = 0; i < SDF_SLOT_COUNT && !referenced; i++)
            referenced = (g_slots[i].face == f || g_slots[i].pending == f);
        bool worker_busy =
            f->state.load() == Face::Rastering && !f->raster_done.load(std::memory_order_acquire);
        if (!referenced && !worker_busy) {
            if (f->atlas)
                glDeleteTextures(1, &f->atlas);
            g_faces.erase(g_faces.begin() + k);
        } else {
            k++;
        }
    }
}

// Fill slot i's config with the role-based built-in defaults (reproducing the shipped look). Used
// for slots the ini did not customize, and by sdf_text_reset_slot.
static void resolve_slot_defaults(int i) {
    Slot& s = g_slots[i];
    SdfFontSlot& c = s.cfg;
    c.file[0] = '\0';
    c.fileAuto = true;
    c.shearAuto = true;
    c.shear = s.display ? DEFAULT_DISPLAY_SHEAR : 0.0f;
    c.weight = s.display ? 0.0f : DEFAULT_BODY_WEIGHT;
    c.scale = (i == 2) ? SLOT2_SCALE : 1.0f;
    c.offsetX = 0.0f;
    c.offsetY = s.display ? (i == 2 ? SLOT2_OFFSET_Y : DISPLAY_OFFSET_Y) : 0.0f;
    c.lineHeight = 1.0f;
    c.letterSpacing = s.display ? 0.0f : DEFAULT_BODY_TRACKING_EM;
    c.shadowForceOff = false;
    c.shadowDx = 1.0f;
    c.shadowDy = 1.0f;
}

// Classify each slot from the game's font descriptor (size anchor + role), like the shipped
// engine did, then resolve defaults for slots the ini did not customize (cfg.scale==0 sentinel)
// and kick the initial face builds.
static void classify_slots() {
    for (int fi = 0; fi < SDF_SLOT_COUNT; fi++) {
        swrFont* font = &swrText_fonts[fi];
        int maxH = 0, capH = 0;
        if (font->glyphs) {
            for (int c = font->firstChar; c <= font->lastChar; c++) {
                swrTextGlyph* gl = &font->glyphs[c - font->firstChar];
                if (gl->atlasX >= 0 && gl->height > maxH)
                    maxH = gl->height;
            }
            // representative cap height = the game's 'A' (or '0') glyph, to match vanilla size
            const int probes[2] = {'A', '0'};
            for (int pi = 0; pi < 2 && capH == 0; pi++) {
                int probe = probes[pi];
                if (probe >= font->firstChar && probe <= font->lastChar) {
                    swrTextGlyph* gl = &font->glyphs[probe - font->firstChar];
                    if (gl->atlasX >= 0 && gl->height > 0)
                        capH = gl->height;
                }
            }
        }
        if (capH == 0)
            capH = maxH;
        Slot& s = g_slots[fi];
        s.display = capH >= DISPLAY_FONT_CAP;// classify by letter/cap height, not tallest glyph
        s.targetCap = (float) (capH > 0 ? capH : 10);
        if (s.display)
            s.targetCap *= 0.95f;// Anton renders ~5% larger than the game's Impact
        s.uppercaseOnly = font->lastChar < 'a';
        if (s.cfg.scale == 0.0f)// sentinel: not loaded from the ini -> use built-in defaults
            resolve_slot_defaults(fi);
        fprintf(hook_log, "sdf_text: font[%d] capH=%d range=%d..%d -> %s\n", fi, capH,
                font->firstChar, font->lastChar, s.display ? "display" : "body");
    }
}

// ---- shader --------------------------------------------------------------------------
static const char* VS =
    "#version 330 core\n"
    "layout(location=0) in vec2 aPos;\n"
    "layout(location=1) in vec2 aUV;\n"
    "layout(location=2) in vec4 aCol;\n"
    "layout(location=3) in float aOutline;\n"
    "uniform mat4 proj;\n"
    "out vec2 vUV; out vec4 vCol; out float vOutline;\n"
    "void main(){ gl_Position = proj * vec4(aPos,0.0,1.0); vUV=aUV; vCol=aCol; vOutline=aOutline; }\n";

static const char* FS =
    "#version 330 core\n"
    "in vec2 vUV; in vec4 vCol; in float vOutline;\n"
    "uniform sampler2D tex;\n"
    "uniform float wbias;\n"// >0 fattens (synthesize heavier weight), <0 thins
    "out vec4 o;\n"
    "void main(){\n"
    "  float d = texture(tex, vUV).r;\n"
    "  float w = fwidth(d);\n"
    "  float thr = 0.5 - wbias;\n"
    "  float fill = smoothstep(thr - w, thr + w, d);\n"
    "  if (vOutline > 0.0) {\n"
    // Push the visible edge out by vOutline screen px (w = d-change per screen px) so a single
    // quad yields a continuous black border, then the glyph color fills the interior. No
    // per-stamp gaps, and the border width is constant in screen px at any scale.
    "    float outer = thr - vOutline * w;\n"
    "    float sil = smoothstep(outer - w, outer + w, d);\n"
    "    if (sil <= 0.0) discard;\n"
    "    o = vec4(vCol.rgb * fill, vCol.a * sil);\n"
    "    return;\n"
    "  }\n"
    "  if (fill <= 0.0) discard;\n"
    "  o = vec4(vCol.rgb, vCol.a * fill);\n"
    "}\n";

static GLuint compile(GLenum type, const char* src) {
    GLuint s = glCreateShader(type);
    glShaderSource(s, 1, &src, nullptr);
    glCompileShader(s);
    GLint ok = 0;
    glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
    if (!ok) {
        char log[512];
        glGetShaderInfoLog(s, sizeof(log), nullptr, log);
        fprintf(hook_log, "sdf_text: shader compile error: %s\n", log);
    }
    return s;
}

static bool build_program() {
    GLuint vs = compile(GL_VERTEX_SHADER, VS);
    GLuint fs = compile(GL_FRAGMENT_SHADER, FS);
    g_program = glCreateProgram();
    glAttachShader(g_program, vs);
    glAttachShader(g_program, fs);
    glLinkProgram(g_program);
    GLint ok = 0;
    glGetProgramiv(g_program, GL_LINK_STATUS, &ok);
    glDeleteShader(vs);
    glDeleteShader(fs);
    if (!ok) {
        fprintf(hook_log, "sdf_text: program link failed\n");
        return false;
    }
    g_proj_loc = glGetUniformLocation(g_program, "proj");
    g_wbias_loc = glGetUniformLocation(g_program, "wbias");
    glGenVertexArrays(1, &g_vao);
    glGenBuffers(1, &g_vbo);
    return true;
}

// One-time GL program build + one-time slot classification/default-resolve (deferred until the
// game's fonts exist), then per-frame face state pumping. Returns true once the engine can render.
static bool sdf_engine_pump() {
    if (g_program_failed)
        return false;
    if (!g_program_built) {
        g_program_built = true;
        if (!build_program()) {
            g_program_failed = true;
            return false;
        }
    }
    if (!g_classified) {
        if (swrText_fontCount <= 0)
            return false;// game fonts not built yet
        classify_slots();
        g_classified = true;
        for (int i = 0; i < SDF_SLOT_COUNT; i++)
            sdf_text_apply_slot(i);
        fprintf(hook_log, "sdf_text: typography engine ready\n");
        fflush(hook_log);
    }
    faces_pump();
    return true;
}

// ---- layout + draw -------------------------------------------------------------------
static Slot* current_slot() {
    for (int i = 0; i < SDF_SLOT_COUNT; i++)
        if (swrText_currentFont == &swrText_fonts[i])
            return &g_slots[i];
    return &g_slots[0];
}

// Map an input byte to the codepoint to render: '_' -> space, the stock font's symbol
// substitutions, and upper-casing for upper-only fonts.
static int remap_char(int c, bool uppercaseOnly) {
    switch (c) {
    case '_': return ' ';
    case '%': return 0x00AE;// (r)
    case '#': return 0x2122;// (tm)
    case '$': return 0x00A9;// (c)
    default: break;
    }
    if (uppercaseOnly && c >= 'a' && c <= 'z')
        return c - 0x20;
    return c;
}

// Resolve a codepoint to its atlas glyph (ASCII fast path, then extras); null if unknown.
static const Glyph* face_glyph(const Face* f, int cp) {
    if (cp >= FIRST_CP && cp <= LAST_CP)
        return &f->glyphs[cp - FIRST_CP];
    for (int i = 0; i < NUM_EXTRAS; i++)
        if (EXTRA_CPS[i] == cp)
            return &f->extras[i];
    return nullptr;
}

// advance width (game-2D units) of one line of text starting at p, stopping at ~n / end.
static float measure_line(const char* p, const Face* face, float drawScale, bool upper,
                          float tracking) {
    float w = 0;
    int prev = 0;
    while (*p && !(p[0] == '~' && p[1] == 'n')) {
        if (p[0] == '~' && p[1]) {
            p += 2;
            continue;
        }
        int c = remap_char((unsigned char) *p++, upper);
        const Glyph* g = face_glyph(face, c);
        if (!g) {
            prev = 0;
            continue;
        }
        // match the render loop's tabular digit advance so right/centre alignment is stable
        bool isDigit = (c >= '0' && c <= '9');
        float kern = (prev && !isDigit)
                         ? stbtt_GetCodepointKernAdvance(&face->info, prev, c) * face->atlasScale
                         : 0;
        w += (kern + (isDigit ? face->digitAdvance : g->advance) + tracking) * drawScale;
        prev = c;
    }
    return w;
}

// Emit one glyph quad (screen px). shear slants it into a parallelogram about the baseline
// (faux-italic) so the slant is smooth instead of stair-stepped in the bitmap.
static void emit_quad(std::vector<Vert>& out, float x0, float y0, float x1, float y1, float u0,
                      float v0, float u1, float v1, float r, float g, float b, float a, float shear,
                      float baselineY, float ow) {
    float ts = (baselineY - y0) * shear;// horizontal shift of the top edge
    float bs = (baselineY - y1) * shear;// horizontal shift of the bottom edge
    out.push_back({x0 + ts, y0, u0, v0, r, g, b, a, ow});
    out.push_back({x1 + ts, y0, u1, v0, r, g, b, a, ow});
    out.push_back({x1 + bs, y1, u1, v1, r, g, b, a, ow});
    out.push_back({x0 + ts, y0, u0, v0, r, g, b, a, ow});
    out.push_back({x1 + bs, y1, u1, v1, r, g, b, a, ow});
    out.push_back({x0 + bs, y1, u0, v1, r, g, b, a, ow});
}

// Emit a positioned glyph (with optional drop shadow / outline) into the batch. shadowDx/Dy is the
// drop-shadow offset in screen px (already scaled from the slot's design-unit offset).
static void emit_glyph(std::vector<Vert>& out, const Glyph& gl, float penX, float baseline,
                       float drawScale, float scaleX, float scaleY, float cr, float cg, float cb,
                       float ca, bool shadow, bool outline, float shearAmt, float outlinePx,
                       float shadowDx, float shadowDy) {
    if (!gl.present)
        return;
    float gx = penX + gl.xoff * drawScale;
    float gy = baseline + gl.yoff * drawScale;
    float gw = gl.w * drawScale, gh = gl.h * drawScale;
    float x0 = gx * scaleX, y0 = gy * scaleY, x1 = (gx + gw) * scaleX, y1 = (gy + gh) * scaleY;
    float bScreenY = baseline * scaleY;
    if (outline) {// single quad; the SDF shader paints the black border + glyph color (matches ~o)
        emit_quad(out, x0, y0, x1, y1, gl.u0, gl.v0, gl.u1, gl.v1, cr, cg, cb, ca, shearAmt,
                  bScreenY, outlinePx);
        return;
    }
    if (shadow) {// black copy offset by the slot's shadow offset, drawn behind (matches ~s)
        emit_quad(out, x0 + shadowDx, y0 + shadowDy, x1 + shadowDx, y1 + shadowDy, gl.u0, gl.v0,
                  gl.u1, gl.v1, 0, 0, 0, ca, shearAmt, bScreenY + shadowDy, 0.0f);
    }
    emit_quad(out, x0, y0, x1, y1, gl.u0, gl.v0, gl.u1, gl.v1, cr, cg, cb, ca, shearAmt, bScreenY,
              0.0f);
}

bool sdf_text_render_string(const char* text) {
    if (!sdf_engine_pump())
        return false;

    Slot* slot = current_slot();
    Face* face = slot->face;
    if (!face || face->state.load() != Face::Uploaded)
        return false;// this slot's atlas isn't ready -> vanilla bitmap text this frame

    const SdfFontSlot& cfg = slot->cfg;
    // Use the game's own live 2D-design scale (the same factors rdProcEntry_Add2DQuad2 uses),
    // so text matches vanilla on every screen even though the recip varies per screen.
    float cap = slot->targetCap * cfg.scale;
    float drawScale = cap / face->capInkPx;
    float tracking = cfg.letterSpacing * EM_PX;// extra advance per glyph, atlas px
    float scaleX = (float) (swrDisplay_screenWidth * swrText_designWidthRecip);
    float scaleY = (float) (swrDisplay_screenHeight * swrText_designHeightRecip);
    if (scaleX < 1.0f)
        scaleX = 1.0f;
    if (scaleY < 1.0f)
        scaleY = 1.0f;
    // ~F half-scale flag: rdProcEntry_Add2DQuad2 multiplies the scale by 0.5 when set
    // (front-end menus use this; in-race text does not).
    if (swrText_halfScale) {
        scaleX *= 0.5f;
        scaleY *= 0.5f;
    }
    float shearAmt = 0.0f;// italic slant is baked into the atlas, so draw upright quads
    // ~o outline width in screen px: track the game's resolution-scaled re-stamp (~1 design
    // unit), clamped, but rendered as one continuous SDF border instead of 8 offset copies.
    float outlinePx = (scaleX > scaleY) ? scaleX : scaleY;
    if (outlinePx > 4.0f)
        outlinePx = 4.0f;
    // per-slot drop-shadow offset (design units -> screen px)
    float shadowDx = cfg.shadowDx * scaleX;
    float shadowDy = cfg.shadowDy * scaleY;

    // World-locked labels register their exact fractional design coordinate (see g_subpos); use it
    // instead of the design-grid-rounded pen so the label tracks the pod smoothly at high res.
    float posX = (float) currentTextPosX;
    float posY = (float) currentTextPosY;
    {
        float ex, ey;
        if (subpos_lookup(currentTextPosX, currentTextPosY, &ex, &ey)) {
            posX = ex;
            posY = ey;
        }
    }
    float startX = posX + cfg.offsetX * cap;// per-slot horizontal nudge
    float penX = startX;
    float baseline = posY + cap;               // game-2D: cap-top approx at pen y
    baseline += cfg.offsetY * cap;             // per-slot vertical nudge (positive = down)

    float cr = currentSpriteColor[0] / 255.0f;
    float cg = currentSpriteColor[1] / 255.0f;
    float cb = currentSpriteColor[2] / 255.0f;
    float ca = currentSpriteColor[3] / 255.0f;
    bool shadow = false;
    bool outline = false;

    std::vector<Vert>& verts = g_verts;
    size_t batchStart = verts.size();// this string's run in the shared, submission-ordered buffer
    int prev = 0;

    for (const char* p = text; *p;) {
        if (p[0] == '~' && p[1]) {
            char code = p[1];
            p += 2;
            if (code >= '0' && code <= '9') {
                int d = code - '0';
                cr = swrText_colorPalette[3 * d + 0] / 255.0f;
                cg = swrText_colorPalette[3 * d + 1] / 255.0f;
                cb = swrText_colorPalette[3 * d + 2] / 255.0f;
                continue;
            }
            if (code == 'n') {
                penX = startX;
                baseline += cfg.lineHeight * face->linePx * drawScale;
                prev = 0;
                continue;
            }
            if (code == 'c') {
                penX = startX -
                       measure_line(p, face, drawScale, slot->uppercaseOnly, tracking) / 2.0f;
                prev = 0;
                continue;
            }
            if (code == 'r') {
                penX = startX - measure_line(p, face, drawScale, slot->uppercaseOnly, tracking);
                prev = 0;
                continue;
            }
            if (code == 's') {
                shadow = !shadow;
                continue;
            }
            if (code == 'o') {
                outline = !outline;
                continue;
            }
            if (code == 'p') {// reset styles
                shadow = false;
                outline = false;
                continue;
            }
            if (code == 'k' || code == 'b' || code == 'f' || code == '~') {
                // styles not yet reproduced; '~~' renders nothing (used as a name sentinel)
                continue;
            }
            // ~t -> literal tilde; any other code -> render that char (vanilla behaviour)
            int lit = (code == 't') ? '~' : (unsigned char) code;
            const Glyph* gl = face_glyph(face, lit);
            if (gl) {
                float kern =
                    prev ? stbtt_GetCodepointKernAdvance(&face->info, prev, lit) * face->atlasScale
                         : 0;
                penX += kern * drawScale;
                emit_glyph(verts, *gl, penX, baseline, drawScale, scaleX, scaleY, cr, cg, cb, ca,
                           shadow && !cfg.shadowForceOff, outline, shearAmt, outlinePx, shadowDx,
                           shadowDy);
                penX += (gl->advance + tracking) * drawScale;
                prev = lit;
            }
            continue;
        }

        int c = remap_char((unsigned char) *p++, slot->uppercaseOnly);
        const Glyph* gl = face_glyph(face, c);
        if (!gl) {
            prev = 0;
            continue;
        }
        // Digits use a fixed (tabular) advance so times/speed/scores don't jitter.
        bool isDigit = (c >= '0' && c <= '9');
        float kern = (prev && !isDigit)
                         ? stbtt_GetCodepointKernAdvance(&face->info, prev, c) * face->atlasScale
                         : 0;
        penX += kern * drawScale;
        float glyphPenX = penX;
        if (isDigit)// center the glyph within the tabular cell
            glyphPenX += (face->digitAdvance - gl->advance) * 0.5f * drawScale;
        emit_glyph(verts, *gl, glyphPenX, baseline, drawScale, scaleX, scaleY, cr, cg, cb, ca,
                   shadow && !cfg.shadowForceOff, outline, shearAmt, outlinePx, shadowDx, shadowDy);
        penX += ((isDigit ? face->digitAdvance : gl->advance) + tracking) * drawScale;
        prev = c;
    }

    // Record this string's run, merged with the previous batch when the face+weight are unchanged
    // and contiguous, so the flush draws in submission order with the fewest state switches.
    if (verts.size() > batchStart) {
        if (!g_batches.empty() && g_batches.back().face == face &&
            g_batches.back().weight == cfg.weight &&
            g_batches.back().start + g_batches.back().count == batchStart)
            g_batches.back().count += verts.size() - batchStart;
        else
            g_batches.push_back({face, cfg.weight, batchStart, verts.size() - batchStart});
    }
    return true;// the accumulated quads are drawn in sdf_text_flush()
}

// Draw everything queued this frame, then clear. Called at scene end (std3D_EndScene) so the
// text lands on the same framebuffer as the game's 2D content, after it, on top.
void sdf_text_flush() {
    g_subposCount = 0;// world-locked label sub-positions are per-frame (populated + consumed above)
    if (!g_program_built || g_program_failed || g_verts.empty()) {
        g_verts.clear();
        g_batches.clear();
        return;
    }

    // orthographic projection: screen px (y-down, top-left origin) -> NDC (column-major)
    float L = 0, R = (float) swrDisplay_screenWidth, B = (float) swrDisplay_screenHeight, T = 0;
    float proj[16] = {
        2.0f / (R - L), 0, 0, 0,
        0, 2.0f / (T - B), 0, 0,
        0, 0, -1, 0,
        -(R + L) / (R - L), -(T + B) / (T - B), 0, 1,
    };

    GLboolean depth = glIsEnabled(GL_DEPTH_TEST);
    glDisable(GL_DEPTH_TEST);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    glUseProgram(g_program);
    glUniformMatrix4fv(g_proj_loc, 1, GL_FALSE, proj);
    glActiveTexture(GL_TEXTURE0);
    glBindVertexArray(g_vao);
    glBindBuffer(GL_ARRAY_BUFFER, g_vbo);
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, sizeof(Vert), (void*) 0);
    glEnableVertexAttribArray(1);
    glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, sizeof(Vert), (void*) (2 * sizeof(float)));
    glEnableVertexAttribArray(2);
    glVertexAttribPointer(2, 4, GL_FLOAT, GL_FALSE, sizeof(Vert), (void*) (4 * sizeof(float)));
    glEnableVertexAttribArray(3);
    glVertexAttribPointer(3, 1, GL_FLOAT, GL_FALSE, sizeof(Vert), (void*) (8 * sizeof(float)));

    // One upload for the whole frame; draw the runs in submission order, switching the atlas /
    // weight only at batch boundaries (kept minimal by the merge in sdf_text_render_string).
    glBufferData(GL_ARRAY_BUFFER, g_verts.size() * sizeof(Vert), g_verts.data(), GL_DYNAMIC_DRAW);
    for (const DrawBatch& b: g_batches) {
        glUniform1f(g_wbias_loc, b.weight);
        glBindTexture(GL_TEXTURE_2D, b.face->atlas);
        glDrawArrays(GL_TRIANGLES, (GLint) b.start, (GLsizei) b.count);
    }
    g_verts.clear();
    g_batches.clear();
    glBindVertexArray(0);
    if (depth)
        glEnable(GL_DEPTH_TEST);
}

// ---- per-slot config accessors (for the SDF Fonts panel) -----------------------------
int sdf_text_slot_count() {
    return SDF_SLOT_COUNT;
}

SdfFontSlot* sdf_text_slot(int i) {
    if (i < 0 || i >= SDF_SLOT_COUNT)
        return nullptr;
    return &g_slots[i].cfg;
}

bool sdf_text_slot_ready(int i, const char** status_out) {
    static const char* s_waiting = "waiting for fonts";
    static const char* s_ready = "ready";
    static const char* s_rebuilding = "rebuilding...";
    static const char* s_building = "building...";
    static const char* s_missing = "missing font file";
    if (i < 0 || i >= SDF_SLOT_COUNT) {
        if (status_out)
            *status_out = s_missing;
        return false;
    }
    Slot& s = g_slots[i];
    if (!g_classified) {
        if (status_out)
            *status_out = s_waiting;
        return false;
    }
    if (s.face && s.face->state.load() == Face::Uploaded) {
        if (status_out)
            *status_out = s.pending ? s_rebuilding : s_ready;
        return true;
    }
    if (s.pending) {
        int st = s.pending->state.load();
        if (st == Face::Loading || st == Face::Rastering) {
            if (status_out)
                *status_out = s_building;
            return false;
        }
    }
    if (status_out)
        *status_out = s_missing;
    return false;
}

const char* sdf_text_slot_desc(int i) {
    static char buf[96];
    if (i < 0 || i >= SDF_SLOT_COUNT) {
        buf[0] = '\0';
        return buf;
    }
    if (!g_classified) {
        snprintf(buf, sizeof(buf), "Slot %d", i);
        return buf;
    }
    // ~f codes that reach this descriptor (the 7-entry runtime table aliases into the 5 fonts)
    char codes[32] = {0};
    int n = 0;
    for (int f = 0; f < 7 && n < (int) sizeof(codes) - 4; f++) {
        if (swrText_fontTable[f] == &swrText_fonts[i])
            n += snprintf(codes + n, sizeof(codes) - n, "%s~f%d", n ? " " : "", f);
    }
    snprintf(buf, sizeof(buf), "Slot %d  [%s]  %s  cap %d", i, n ? codes : "-",
             g_slots[i].display ? "Display" : "Body", (int) (g_slots[i].targetCap + 0.5f));
    return buf;
}

void sdf_text_reset_slot(int i) {
    if (i < 0 || i >= SDF_SLOT_COUNT || !g_classified)
        return;
    resolve_slot_defaults(i);
    sdf_text_apply_slot(i);
}
