#pragma once

#include "ui_transform.h"

#include <cstdint>

// Screen anchors for swrUI menu elements. An element's anchor is looked up once, when it is created
// (by the EXE call site of its ctor) or, for elements with no creation hook, by element id at render
// time. The anchored element is then moved as a whole (position, child sprites, clip bbox) so its
// sprites, label and hit-test stay together; see swrUI_RenderElementSprites_delta.
struct MenuAnchor {
    UiAnchorH h;
    UiAnchorV v;
};

// Anchor for a button swrUI_NewButton creates when called from this call site.
bool ui_menu_button_anchor(uintptr_t create_site, MenuAnchor *out);

// Anchor for an element identified by its element id.
bool ui_menu_element_anchor(int element_id, MenuAnchor *out);
