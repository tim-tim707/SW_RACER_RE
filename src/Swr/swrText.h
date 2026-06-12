#ifndef SWRTEXT_H
#define SWRTEXT_H

#include <stddef.h>

#define swrText_FormatPodName_ADDR (0x004208e0)

#define swrText_ParseRacerTab_ADDR (0x00421120)
#define swrText_CmpRacerTab_ADDR (0x004212f0)
#define swrText_Shutdown_ADDR (0x00421330)
#define swrText_Translate_ADDR (0x00421360)

// Font system: builds the 7 font pages at startup; current font selected by index
// into the font table (DAT_00e99720, count DAT_0050c0c0).
#define swrText_InitFonts_ADDR (0x0042d720)
#define swrText_SetCurrentFont_ADDR (0x0042d8d0)
#define swrText_SetFont_ADDR (0x0042d900)

// Low-level glyph metrics + string rendering. The font pointer has: page-material
// count @0x04, page-material array @0x08, firstChar @0x5a, lastChar @0x5b,
// glyph table @0x5c (0x10 bytes/glyph: advance @+2, height @+0xe), extended-glyph table @0x60.
#define swrText_BindFontPage_ADDR (0x0042ddf0)
#define swrText_GetStringWidth_ADDR (0x0042de30)
#define swrText_GetStringHeight_ADDR (0x0042df70)
#define swrText_GetCharSize_ADDR (0x0042e0e0)
#define swrText_DrawString_ADDR (0x0042e150)
#define swrText_GetStringWidthByFont_ADDR (0x0042de10)
#define swrText_RenderString_ADDR (0x0042ec50)
#define swrText_SetupGlyph_ADDR (0x0042edc0)
#define swrText_DrawGlyph_ADDR (0x0042eeb0)

#define DrawTextEntries_ADDR (0x00450280)
#define DrawTextEntries2_ADDR (0x004502B0)

#define swrText_CreateEntry_ADDR (0x004503e0)

#define swrText_CreateTextEntry1_ADDR (0x00450530)

#define swrText_CreateColorlessEntry1_ADDR (0x00450560)

#define swrText_CreateColorlessFormattedEntry1_ADDR (0x00450590)

#define swrText_CreateEntry2_ADDR (0x004505c0)

#define swrText_CreateTimeEntryFormat_ADDR (0x004505f0)

#define swrText_CreateTimeEntry_ADDR (0x00450670)

#define swrText_CreateTimeEntryPrecise_ADDR (0x00450760)

void swrText_FormatPodName(int podIndex, char* out_buffer, size_t count);

int swrText_ParseRacerTab(char* filepath);
int swrText_CmpRacerTab(char** a, char** b);
void swrText_Shutdown(void);
char* swrText_Translate(char* text);

// Build the 7 font pages at startup; select the current font by index into the font table.
void swrText_InitFonts(void);
void swrText_SetCurrentFont(int fontIndex);
void swrText_SetFont(int fontIndex);

// Bind the GL material for one of the font's glyph pages (page < font page count).
void swrText_BindFontPage(void* font, int page);
// Width of the first line of text (stops at a "~n" newline marker); honors "~" format codes.
int swrText_GetStringWidth(char* text, void* font);
// Average glyph height across the glyphs in the string.
int swrText_GetStringHeight(char* text, void* font);
// Look up one glyph's advance width + height for the font; writes -1 if the glyph is absent.
void swrText_GetCharSize(char c, void* font, int* outWidth, int* outHeight);
// Render a string: walks "~" format codes (0-9 = palette color, c = center, r = right-align,
// k/o/s = strike/outline/shadow, n = newline) and emits the glyph quads for the given pass.
void swrText_DrawString(char* text, void* font, short pass);

// Width of a string for a font given by index (wraps swrText_GetStringWidth + font-table lookup).
int swrText_GetStringWidthByFont(char* text, int fontIndex);
// Render a full formatted string: handles "~b"/"~f"/"~F" prefix codes, draws all font pages.
void swrText_RenderString(char* text);
// Set up one glyph's metrics/UV + bind its page (used per character by the renderer).
void swrText_SetupGlyph(char c);
// Emit the current glyph's quads at (x, y); style 'o' outline / 's' shadow / 'f' bold.
void swrText_DrawGlyph(short x, short y, char style);

void DrawTextEntries();
void DrawTextEntries2();

void swrText_CreateEntry(short x, short y, char r, char g, char b, char a, char* screenText, int formatInt, int isEntry2);

void swrText_CreateTextEntry1(int x, int y, int r, int g, int b, int a, char* screenText);

void swrText_CreateColorlessEntry1(short x, short y, char* screenText);

void swrText_CreateColorlessFormattedEntry1(int formatInt, short x, short y, char* screenText);

void swrText_CreateEntry2(short x, short y, char r, char g, char b, char a, char* screenText);

void swrText_CreateTimeEntryFormat(int x, int y, int unused, int r, int g, int b, int a, int bFormat);

void swrText_CreateTimeEntry(int x, int y, int unused, int r, int g, int b, int a, char* screenText);

void swrText_CreateTimeEntryPrecise(int x, int y, int unused, int r, int g, int b, int a, char* screenText);

#endif // SWRTEXT_H
