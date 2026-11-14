#include "ui_menu.h"

namespace {

struct CreateSite {
    uintptr_t site;
    MenuAnchor anchor;
};

// Return address of each swrUI_NewButton / swrUI_NewLabel call whose element is anchored.
constexpr CreateSite kCreateSites[] = {
    // swrUI_AddNavButton: every page's Back / Cancel / Quit, authored at x 0, y 390-430.
    {0x00411204, {UI_H_LEFT, UI_V_BOTTOM}},
    // swrUI_AddOkButton: every page's OK, authored at (520, 380-385).
    {0x00411268, {UI_H_RIGHT, UI_V_BOTTOM}},
    // swrUI_BuildMenuPages: the main-menu and aux-page Settings buttons (element id 0xf, x 0, y 350).
    {0x00411999, {UI_H_LEFT, UI_V_BOTTOM}},
    {0x00411ad3, {UI_H_LEFT, UI_V_BOTTOM}},
    // swrUI_AddDefaultButton / swrUI_AddRestoreButton: the settings pages' bottom row (x 205 / 355,
    // y 420-430).
    {0x0041135d, {UI_H_CENTER, UI_V_BOTTOM}},
    {0x004112dd, {UI_H_CENTER, UI_V_BOTTOM}},
    // swrUI_BuildMenuPages: main-menu copyright label (swrUI_NewLabel, x 320, y 470).
    {0x00411b13, {UI_H_CENTER, UI_V_BOTTOM}},
};

struct ElementId {
    int id;
    MenuAnchor anchor;
};

// Elements with no creation hook, matched by id when they are first rendered.
constexpr ElementId kElementIds[] = {
    // Splash title-logo trademarks; they ride the left-anchored logo art.
    {0x272a, {UI_H_LEFT, UI_V_TOP}}, // STAR WARS trademark
    {0x272b, {UI_H_LEFT, UI_V_TOP}}, // RACER trademark
};

} // namespace

bool ui_menu_create_anchor(uintptr_t create_site, MenuAnchor *out) {
    for (const CreateSite &b : kCreateSites) {
        if (b.site == create_site) {
            *out = b.anchor;
            return true;
        }
    }
    return false;
}

bool ui_menu_element_anchor(int element_id, MenuAnchor *out) {
    for (const ElementId &e : kElementIds) {
        if (e.id == element_id) {
            *out = e.anchor;
            return true;
        }
    }
    return false;
}
