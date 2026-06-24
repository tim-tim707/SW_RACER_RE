#include "swrText_delta.h"

#include "../imgui_utils.h"
#include "../sdf_text.h"

extern "C" {
#include <globals.h>
#include <Swr/swrText.h>
#include <Swr/swrRender.h>
}

// swrText_SetCurrentFont / swrText_DrawString are not reimplemented (header-only), so call
// the originals through their addresses rather than the (undefined) symbols.
typedef void (*swrText_SetCurrentFont_fn)(int fontIndex);
typedef void (*swrText_DrawString_fn)(char* text, void* font, short pass);
static const swrText_SetCurrentFont_fn orig_SetCurrentFont =
    (swrText_SetCurrentFont_fn) swrText_SetCurrentFont_ADDR;
static const swrText_DrawString_fn orig_DrawString = (swrText_DrawString_fn) swrText_DrawString_ADDR;

// 0x0042ec50 reimplemented; OFF path mirrors the original (page loop over the bitmap font),
// ON path renders proper TTF typography. Registered manually in init_renderer_hooks so the
// generator does not also hook it.
void swrText_RenderString_delta(char* text) {
    orig_SetCurrentFont(0);

    // ~b anywhere in the string requests a bold pass
    swrText_boldPass = 0;
    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] == '~' && text[i + 1] == 'b') {
            swrText_boldPass = 1;
            break;
        }
    }

    // ~f<n> / ~F<n> prefix selects the font (and ~F sets fixed-width mode)
    int offset = 0;
    if (text[0] == '~' && text[1] == 'f') {
        orig_SetCurrentFont(text[2] - '0');
        offset = 3;
    }
    swrText_halfScale = 0;
    if (text[0] == '~' && text[1] == 'F') {
        swrText_halfScale = 1;
        orig_SetCurrentFont(text[2] - '0');
        offset = 3;
    }

    if (imgui_state.sdf_text && sdf_text_render_string(text + offset)) {
        currentTextPosX = previousTextPosX;
        currentTextPosY = previousTextPosY;
        return;
    }

    // vanilla bitmap path: draw the string once per glyph page
    short startX = currentTextPosX;
    short startY = currentTextPosY;
    rdProcEntry_SetCurrentColor(0, 0, currentSpriteColor[0], currentSpriteColor[1],
                                currentSpriteColor[2], currentSpriteColor[3]);
    for (int page = 0; page < swrText_currentFont->pageCount; page++) {
        currentTextPosX = startX;
        currentTextPosY = startY;
        orig_DrawString(text + offset, swrText_currentFont, (short) page);
    }

    currentTextPosX = previousTextPosX;
    currentTextPosY = previousTextPosY;
}
