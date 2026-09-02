#include "swrUI_delta.h"

#include <cstdio>

extern "C" {
#include <Swr/swrUI.h>

extern FILE *hook_log;
}

#include "../hook_helper.h"

// Vanilla crash: swrUI_FocusFirstOnNav hands swrUI_NextFocusable's result straight to
// swrUI_FocusElement, whose first call is swrUI_IsFocusable(element) -- an unguarded
// element->flags read. On a page with no focusable element left (seen on the MP race-setup page
// during session teardown) that is a NULL+0x18 read. A NULL element is simply "not focusable", so
// guard the one primitive every focus-navigation path funnels through.
typedef int(swrUI_IsFocusable_t)(swrUI_unk *element);

int swrUI_IsFocusable_delta(swrUI_unk *element) {
    if (element == NULL)
        return 0;
    return hook_call_original((swrUI_IsFocusable_t *) swrUI_IsFocusable_ADDR, element);
}
