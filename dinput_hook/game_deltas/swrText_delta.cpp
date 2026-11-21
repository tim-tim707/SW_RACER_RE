#include "swrText_delta.h"

#include "../hook_helper.h"
#include "../imgui_utils.h"
#include "../sdf_text.h"

extern "C" {
#include <globals.h>
#include <Swr/swrText.h>
}

typedef void(swrText_RenderString_t)(char *text);

void swrText_RenderString_delta(char *text) {
    if (imgui_state.sdf_text) {
        swrText_SetCurrentFont(0);

        swrText_hasBoldCode = 0;
        for (int i = 0; text[i] != '\0'; i++) {
            if (text[i] == '~' && text[i + 1] == 'b') {
                swrText_hasBoldCode = 1;
                break;
            }
        }

        int offset = 0;
        if (text[0] == '~' && text[1] == 'f') {
            swrText_SetCurrentFont(text[2] - '0');
            offset = 3;
        }
        swrText_halfScale = 0;
        if (text[0] == '~' && text[1] == 'F') {
            swrText_halfScale = 1;
            swrText_SetCurrentFont(text[2] - '0');
            offset = 3;
        }

        if (sdf_text_render_string(text + offset)) {
            currentTextPosX = previousTextPosX;
            currentTextPosY = previousTextPosY;
            return;
        }
    }

    hook_call_original((swrText_RenderString_t *) swrText_RenderString_ADDR, text);
}
