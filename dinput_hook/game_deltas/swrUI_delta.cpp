#include "swrUI_delta.h"

#include <cstdio>

extern "C" {
#include <Swr/swrUI.h>

extern FILE *hook_log;
}

#include "../hook_helper.h"

// Vanilla crash: swrUI_FocusFirstOnNav (a nav key pressed on the 2D front-end shell with nothing
// focused) hands swrUI_NextFocusable's result straight to swrUI_FocusElement without a NULL check,
// and FocusElement's very first call is swrUI_IsFocusable(element) -- which dereferences
// element->flags unguarded. On a page with no focusable element left (observed on the multiplayer
// race-setup page while the session was tearing down after peers dropped; 1 of 9 dumps from the
// 2026-07-25 playtest) NextFocusable returns NULL and the game crashes on the NULL+0x18 read.
// A NULL element is simply "not focusable": guard the one primitive every focus-navigation path
// funnels through instead of patching each caller.
typedef int(swrUI_IsFocusable_t)(swrUI_unk *element);

int swrUI_IsFocusable_delta(swrUI_unk *element) {
    if (element == NULL)
        return 0;
    return hook_call_original((swrUI_IsFocusable_t *) swrUI_IsFocusable_ADDR, element);
}
