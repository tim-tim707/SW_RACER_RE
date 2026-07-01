#include "sdf_text.h"

#include <glad/glad.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
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
static const float SDF_SHEAR = 0.20f;// faux-italic slant for the Impact/Anton display face
static const int DISPLAY_FONT_CAP = 14;// cap height (texels) at/above which a font is display
static const int FIRST_CP = 0x20;
static const int LAST_CP = 0x7e;
static const int GLYPH_COUNT = LAST_CP - FIRST_CP + 1;

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

struct Face {
    std::vector<unsigned char> ttf;
    stbtt_fontinfo info;
    GLuint atlas = 0;
    float atlasScale = 0;     // stbtt scale used at EM_PX
    float linePx = 0;         // line advance in atlas px
    float capInkPx = 1;       // ink height of 'A' in atlas px (for sizing)
    float digitAdvance = 0;   // advance of '0' in atlas px (tabular/monospace digits)
    Glyph glyphs[GLYPH_COUNT];// ASCII FIRST_CP..LAST_CP
    Glyph extras[NUM_EXTRAS]; // EXTRA_CPS glyphs
    float weight = 0;         // SDF threshold bias (>0 fattens; synthesize semibold)
    bool ok = false;
    bool shear = false;
};

static Face g_body;   // DejaVu Sans (Verdana role)
static Face g_display;// Anton (Impact role)

// per stock font (swrText_fonts[0..4]): which face + target cap height in game-2D units
struct FontMap {
    Face* face;
    float targetCap;
    bool uppercaseOnly;
    float sizeScale;   // per-slot size multiplier (1.0 = match vanilla cap height)
    float baselineBias;// per-slot vertical nudge, fraction of cap (positive = down)
};
static FontMap g_fontmap[5];

// All glyph quads queued this frame, in submission (draw) order, plus the per-string runs that
// index into them. Flushed at scene end. Keeping one ordered buffer (rather than one per face)
// preserves the game's painter order across faces so e.g. a shadowed display word still layers
// correctly over body text drawn before it.
static std::vector<Vert> g_verts;
struct DrawBatch {
    Face* face;
    size_t start;
    size_t count;
};
static std::vector<DrawBatch> g_batches;

static bool g_built = false;
static bool g_ok = false;

static GLuint g_program = 0;
static GLint g_proj_loc = -1;
static GLint g_wbias_loc = -1;
static GLuint g_vao = 0, g_vbo = 0;

// ---- ttf loading + atlas build -------------------------------------------------------
static bool load_ttf(const char* path, Face& f) {
    FILE* fp = fopen(path, "rb");
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

    // For display faces, bake the italic slant into the bitmap with a sub-pixel (bilinear)
    // per-row horizontal shift. Doing it here (upright quad at draw time) keeps the SDF
    // antialiasing uniform; skewing the quad instead makes acute corners ragged.
    int srcW = w;
    const unsigned char* src = sdf;
    std::vector<unsigned char> sheared;
    if (f.shear) {
        int margin = (int) ceilf(h * 0.5f * SDF_SHEAR) + 1;
        int ow = w + 2 * margin;
        sheared.assign((size_t) ow * h, 0);
        for (int y = 0; y < h; y++) {
            float shift = (h * 0.5f - y) * SDF_SHEAR;// +right at top, -left at bottom
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

static void build_face(Face& f, bool shear) {
    f.shear = shear;
    f.atlasScale = stbtt_ScaleForPixelHeight(&f.info, (float) EM_PX);
    int asc = 0, desc = 0, gap = 0;
    stbtt_GetFontVMetrics(&f.info, &asc, &desc, &gap);
    f.linePx = (asc - desc + gap) * f.atlasScale;

    std::vector<unsigned char> atlas((size_t) ATLAS_W * ATLAS_H, 0);
    int penX = 0, penY = 0, rowH = 0;
    for (int i = 0; i < GLYPH_COUNT; i++)
        pack_glyph(f, atlas, FIRST_CP + i, &f.glyphs[i], penX, penY, rowH);
    for (int i = 0; i < NUM_EXTRAS; i++)
        pack_glyph(f, atlas, EXTRA_CPS[i], &f.extras[i], penX, penY, rowH);
    if (f.capInkPx < 1)
        f.capInkPx = EM_PX * 0.7f;
    f.digitAdvance = f.glyphs['0' - FIRST_CP].advance;

    glGenTextures(1, &f.atlas);
    glBindTexture(GL_TEXTURE_2D, f.atlas);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_R8, ATLAS_W, ATLAS_H, 0, GL_RED, GL_UNSIGNED_BYTE,
                 atlas.data());
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glBindTexture(GL_TEXTURE_2D, 0);
    f.ok = true;
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

static void ensure_built() {
    if (g_built)
        return;
    if (swrText_fontCount <= 0)
        return;// game fonts not built yet
    g_built = true;

    if (!load_ttf("./assets/fonts/DejaVuSans.ttf", g_body) ||
        !load_ttf("./assets/fonts/Anton-Regular.ttf", g_display))
        return;
    build_face(g_body, false);
    build_face(g_display, true);
    // weight is a distance-field threshold offset, so it scales with SDF_ONEDGE/SDF_PADDING; this
    // 0.08 at SDF_PADDING 12 is the same visual semibold as 0.16 was at SDF_PADDING 6.
    g_body.weight = 0.08f;// fatten DejaVu regular toward a semibold weight (a touch heavier)
    g_display.weight = 0.0f;
    // Anton's tabular digits sit too tight; widen the fixed digit cell a little so number readouts
    // (lap / time / position) breathe. Digits stay centered in the wider cell.
    g_display.digitAdvance *= 1.12f;
    if (!build_program())
        return;

    for (int fi = 0; fi < 5; fi++) {
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
        bool display = capH >= DISPLAY_FONT_CAP;// classify by letter/cap height, not tallest glyph
        g_fontmap[fi].face = display ? &g_display : &g_body;
        g_fontmap[fi].targetCap = (float) (capH > 0 ? capH : 10);
        if (display)
            g_fontmap[fi].targetCap *= 0.95f;// Anton renders ~5% larger than the game's Impact
        g_fontmap[fi].uppercaseOnly = font->lastChar < 'a';
        g_fontmap[fi].sizeScale = 1.0f;
        g_fontmap[fi].baselineBias = 0.0f;
        fprintf(hook_log, "sdf_text: font[%d] maxH=%d capH=%d range=%d..%d -> %s\n", fi, maxH, capH,
                font->firstChar, font->lastChar, display ? "Anton(display)" : "DejaVu(body)");
    }

    // swrText_fonts[2] is the big italic number/time face (selected by ~f1 and ~f3): the
    // in-race lap / time / position readouts. It renders a little large and high vs vanilla, so
    // shrink it slightly and drop the baseline. The bias more than cancels the Anton shear nudge
    // (-0.38) so the baseline lands just past cap-top + cap. TUNE these against the in-race HUD.
    g_fontmap[2].sizeScale = 0.92f;
    g_fontmap[2].baselineBias = 0.42f;

    g_ok = true;
    fprintf(hook_log, "sdf_text: typography engine ready\n");
    fflush(hook_log);
}

// ---- layout + draw -------------------------------------------------------------------
static const FontMap* current_fontmap() {
    for (int i = 0; i < 5; i++)
        if (swrText_currentFont == &swrText_fonts[i])
            return &g_fontmap[i];
    return &g_fontmap[0];
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
static float measure_line(const char* p, const Face* face, float drawScale, bool upper) {
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
        w += (kern + (isDigit ? face->digitAdvance : g->advance)) * drawScale;
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

// Emit a positioned glyph (with optional drop shadow / outline) into the batch.
static void emit_glyph(std::vector<Vert>& out, const Glyph& gl, float penX, float baseline,
                       float drawScale, float scaleX, float scaleY, float cr, float cg, float cb,
                       float ca, bool shadow, bool outline, float shearAmt, float outlinePx) {
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
    if (shadow) {// black copy offset +1 game-2D unit, drawn behind (matches ~s)
        emit_quad(out, x0 + scaleX, y0 + scaleY, x1 + scaleX, y1 + scaleY, gl.u0, gl.v0, gl.u1,
                  gl.v1, 0, 0, 0, ca, shearAmt, bScreenY + scaleY, 0.0f);
    }
    emit_quad(out, x0, y0, x1, y1, gl.u0, gl.v0, gl.u1, gl.v1, cr, cg, cb, ca, shearAmt, bScreenY,
              0.0f);
}

bool sdf_text_render_string(const char* text) {
    ensure_built();
    if (!g_ok)
        return false;

    const FontMap* fm = current_fontmap();
    Face* face = fm->face;
    if (!face->ok)
        return false;

    // Use the game's own live 2D-design scale (the same factors rdProcEntry_Add2DQuad2 uses),
    // so text matches vanilla on every screen even though the recip varies per screen.
    float cap = fm->targetCap * fm->sizeScale;
    float drawScale = cap / face->capInkPx;
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

    float startX = (float) currentTextPosX;
    float penX = startX;
    float baseline = (float) currentTextPosY + cap;// game-2D: cap-top approx at pen y
    if (face->shear)
        baseline -= cap * 0.38f;// Anton sits low vs the game's Impact; nudge up
    baseline += fm->baselineBias * cap;// per-slot vertical nudge (positive = down)

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
                baseline += face->linePx * drawScale;
                prev = 0;
                continue;
            }
            if (code == 'c') {
                penX = startX - measure_line(p, face, drawScale, fm->uppercaseOnly) / 2.0f;
                prev = 0;
                continue;
            }
            if (code == 'r') {
                penX = startX - measure_line(p, face, drawScale, fm->uppercaseOnly);
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
                           shadow, outline, shearAmt, outlinePx);
                penX += gl->advance * drawScale;
                prev = lit;
            }
            continue;
        }

        int c = remap_char((unsigned char) *p++, fm->uppercaseOnly);
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
                   shadow, outline, shearAmt, outlinePx);
        penX += (isDigit ? face->digitAdvance : gl->advance) * drawScale;
        prev = c;
    }

    // Record this string's run, merged with the previous batch when the face is unchanged and
    // contiguous, so the flush draws in submission order with the fewest face/atlas switches.
    if (verts.size() > batchStart) {
        if (!g_batches.empty() && g_batches.back().face == face &&
            g_batches.back().start + g_batches.back().count == batchStart)
            g_batches.back().count += verts.size() - batchStart;
        else
            g_batches.push_back({face, batchStart, verts.size() - batchStart});
    }
    return true;// the accumulated quads are drawn in sdf_text_flush()
}

// Draw everything queued this frame, then clear. Called at scene end (std3D_EndScene) so the
// text lands on the same framebuffer as the game's 2D content, after it, on top.
void sdf_text_flush() {
    if (!g_ok)
        return;
    if (g_verts.empty()) {
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
        glUniform1f(g_wbias_loc, b.face->weight);
        glBindTexture(GL_TEXTURE_2D, b.face->atlas);
        glDrawArrays(GL_TRIANGLES, (GLint) b.start, (GLsizei) b.count);
    }
    g_verts.clear();
    g_batches.clear();
    glBindVertexArray(0);
    if (depth)
        glEnable(GL_DEPTH_TEST);
}
