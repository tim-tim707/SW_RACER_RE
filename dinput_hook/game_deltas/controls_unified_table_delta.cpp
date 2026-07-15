// Unified controls table (CONTROLLER_CONFIG_ROADMAP wishlist #1) -- WIP, mouse page.
//
// Replaces the mouse controls page's two separate lists ("Button Settings" + "Axis Settings")
// with ONE table: one row per function (deduped), three columns so a function can be bound up to
// three times. Session decisions: preserve analog capture per-row (Turn/Pitch/Throttle stay
// proportional); mouse page first.
//
// WHY A FULL REBUILD (not injecting columns into the stock page): the stock page rows live in a
// swrUI list, and swrUI_RefreshListLayout force-positions every list item into a single stacked
// column AND gives each a full-row-width click bbox -- so a list fundamentally can't host multiple
// clickable columns. The KEYBOARD page already renders a real 3-column table, and it does so with
// a swrUI_NewPanel + free page-child cells (each cell has its own bbox and is individually
// clickable). This mirrors that: a panel + per-row {label+slot1 cell, slot2 cell, slot3 cell},
// with the mouse-only controls (enable / flip-axis / sensitivity) moved BELOW the table (the
// keyboard page has nothing on the right, which is what frees the width for 3 columns).
//
// Column-0 cells reuse the stock widget ids, so the stock RefreshMappingMenu fills slot 1 and the
// stock MappingsMenu dispatches slot-1 clicks for free; this file's detours only add slots 2/3.
//
// Gated behind ENABLE_UNIFIED_CONTROLS (default 0; build with -DENABLE_UNIFIED_CONTROLS=1).

#ifndef ENABLE_UNIFIED_CONTROLS
#define ENABLE_UNIFIED_CONTROLS 0
#endif

#if ENABLE_UNIFIED_CONTROLS

#include <windows.h>
#include <detours.h>
#include <cstdio>
#include <cstring>

extern FILE *hook_log; // shared hook.log stream (see other game_deltas)

// --- vanilla entry points / data (image base 0x400000) ---
#define swrConfig_BuildMouseMenu_ADDR (0x0040d2c0)
#define swrConfig_BuildJoystickMenu_ADDR (0x0040c7a0)
#define swrConfig_RefreshMappingMenu_ADDR (0x0040b740)
#define swrControl_MappingsMenu_ADDR (0x00402250)
#define swrConfig_SetMappingRowText_ADDR (0x0040c670)
#define swrControl_CaptureBinding_ADDR (0x00406cc0)
#define swrConfig_WriteMappings_ADDR (0x00406080)
#define swrText_ShowTimedMessage_ADDR (0x0044fce0)
#define swrText_Translate_ADDR (0x00421360)
// swrControl_MappingsMenu state globals (see the decompile): configDirty gates save-on-exit --
// if it is 0 when leaving the page, the stock handler RELOADS from disk and discards the changes.
#define configDirty_ADDR (0x004d554c)       // DAT_004d554c: bindings changed since load
#define lastCaptureResult_ADDR (0x004d55ac) // DAT_004d55ac: last CaptureBinding return (bit 0x4 = changed)
#define inputActiveGuard_ADDR (0x004b2034)  // DAT_004b2034: 0 suppresses gameplay input during capture
#define MappingsMenu_LO (0x00402250)        // WriteMappings toast is scoped to this fn's save-on-exit
#define MappingsMenu_HI (0x00402f70)
#define STR_SAVED_ADDR (0x004b2308) // "Saved settings!"

// Input-capture primitives (ported from capture_binding_delta.cpp) so the unified columns can
// bind/clear against a specific binding-table entry rather than a per-type slot.
#define swrControl_AddMapping_ADDR (0x004078e0)
#define swrUI_GetValueText_ADDR (0x00414af0)
#define rdCache_AdvanceFrame_ADDR (0x0048db60)
#define stdDisplay_FillMainSurface_ADDR (0x00489bc0)
#define swrControl_ProcessInputs_ADDR (0x00404dd0)
#define swrMain_RunFrame_ADDR (0x00445980)
#define swrUI_RenderTree_ADDR (0x00415020)
#define swr_noop2_ADDR (0x00426910)
#define rdCache_Flush_ADDR (0x0048dce0)
#define rdCache_FlushAlpha_ADDR (0x0048dd80)
#define stdDisplay_Update_ADDR (0x00489ab0)
#define swrControl_PollCancel_ADDR (0x00407f80)
#define swrControl_ScanPressedButtons_ADDR (0x00405dd0)
#define swrControl_FindMovedAxis_ADDR (0x00407700)
#define stdControl_ReadKey_ADDR (0x00485880)
#define STR_PLACEHOLDER_ADDR (0x004b4270) // "..."
#define STR_CANCELLED_ADDR (0x004b3ef0)   // "Cancelled"
#define DIK_DELETE (0xd3)
#define swrText_GetStringHeight_ADDR (0x0042df70)
#define swrText_GetStringWidthByFont_ADDR (0x0042de10)
#define swrConfig_currentInputDeviceType_ADDR (0x004b2030) // swrConfig_DEVICE (0=joy,1=mouse,2=kbd)
#define swrUI_GetById_ADDR (0x00414d90)
#define swrUI_SetValueText_ADDR (0x00414ab0)
#define swrConfig_ControlToString_ADDR (0x00407b00)
#define keyMapping0_ADDR (0x004b2af0) // axis-name table
#define keyMapping1_ADDR (0x004b2b28) // button-name table
#define STR_BUTTON_FMT_ADDR (0x004b3ed0) // "BUTTON %s" (capture delta's Translate hook -> "%s")
#define STR_UNBOUND_ADDR (0x004b3eec)    // "---"
// Binding-table entry flag bits (12-byte entries {u32 flags; i32 input; i32 action}).
#define BIND_ANALOG_AXIS (0x04) // axis binding
#define BIND_BUTTON (0x08)      // button binding
#define BIND_AXIS_POS (0x10)    // axis-as-button, positive direction (FormatBinding shows "+")
#define BIND_AXIS_NEG (0x20)    // axis-as-button, negative direction (FormatBinding shows "-")
#define BIND_AXIS_RANGE (0x30)  // either direction -> used as a digital trigger
#define swrText_fontsByIndex_ADDR (0x00e99720)              // swrFont*[7]
#define wuRegistry_lpClass_ADDR (0x004d55cc)                // shared empty string

// swrUI helpers (see src/Swr/swrUI.h).
#define swrUI_NewScreenText_ADDR (0x00413340)
#define swrUI_NewPanel_ADDR (0x0041b260)
#define swrUI_New3PatchBox_ADDR (0x00413fc0)
#define swrUI_NewLabel_ADDR (0x004131c0)
#define swrUI_NewFramedText_ADDR (0x00413c50)
#define swrUI_NewNumberField_ADDR (0x00413a90)
#define swrUI_SetColorUnk_ADDR (0x00414be0)
#define swrUI_AddNavButton_ADDR (0x00411170)
#define swrUI_AddOkButton_ADDR (0x00411210)
#define swrUI_AddRestoreButton_ADDR (0x00411270)
#define swrUI_AddDefaultButton_ADDR (0x004112f0)
#define swrUI_GetFrameTextureDim_ADDR (0x00419070)
#define swrUI_SetSpriteSelectionBBox_Maybe_ADDR (0x004197f0)
#define swrSprite_GetTextureDimFromId_ADDR (0x00417120)
#define SPR_EDITWINDOW_SEGMENTED (3009) // label-cell (0x400000) border sprite
#define SPR_SEGMENT (3011)              // value-cell (0x800000) border sprite

// Capture fnStr keys (the localized action-name strings the stock MappingsMenu feeds to
// CaptureBinding -- ParseFunctionName resolves them, so reuse the SAME strings).
#define STR_CAMERA_CYCLE_ADDR (0x004b284c)
#define STR_LOOK_BACK_ADDR (0x004b2830)
#define STR_BRAKE_ADDR (0x004b2818)
#define STR_THRUST_ADDR (0x004b27fc)
#define STR_BOOST_ADDR (0x004b27e4)
#define STR_SLIDE_ADDR (0x004b27cc)
#define STR_ROLL_LEFT_ADDR (0x004b27b0)
#define STR_ROLL_RIGHT_ADDR (0x004b2790)
#define STR_SPECIAL_ADDR (0x004b2774) // Taunt / Flamejet
#define STR_REPAIR_ADDR (0x004b2758)
#define STR_ANALOG_THROTTLE_ADDR (0x004b2734)
#define STR_TURN_ADDR (0x004b271c)
#define STR_PITCH_ADDR (0x004b2704)

// Menu DISPLAY labels (may differ from the capture fnStr above -- e.g. Camera).
#define LBL_TURN_ADDR (0x004b50cc)     // "Turn Left/Right"
#define LBL_PITCH_ADDR (0x004b50a8)    // "Nose Up/Down"
#define LBL_THROTTLE_ADDR (0x004b508c) // "Throttle"
#define LBL_THRUST_ADDR (0x004b27fc)
#define LBL_BRAKE_ADDR (0x004b2818)
#define LBL_BOOST_ADDR (0x004b27e4)
#define LBL_SLIDE_ADDR (0x004b27cc)
#define LBL_ROLL_LEFT_ADDR (0x004b27b0)
#define LBL_ROLL_RIGHT_ADDR (0x004b2790)
#define LBL_CAMERA_ADDR (0x004b5174) // "Cycle Camera"
#define LBL_LOOK_BACK_ADDR (0x004b2830)
#define LBL_TAUNT_ADDR (0x004b5150) // "Taunt/Flamejet"
#define LBL_REPAIR_ADDR (0x004b2758)
#define STR_TITLE_MOUSE_ADDR (0x004b522c)    // "MOUSE SETTINGS"
#define STR_TITLE_JOY_ADDR (0x004b5204)      // "JOYSTICK SETTINGS"
#define STR_MOUSE_ENABLED_ADDR (0x004b52a4)  // "Mouse Enabled"
#define STR_JOY_ENABLED_ADDR (0x004b5040)    // "Joystick Enabled"
#define STR_FLIP_AXIS_ADDR (0x004b5020)      // "Flip Axis"
#define STR_FLIP_X_ADDR (0x004b5008)
#define STR_FLIP_Y_ADDR (0x004b4ff0)
#define STR_FLIP_Z_ADDR (0x004b4fd8)
#define STR_SENSITIVITY_ADDR (0x004b4fb8)
#define STR_DEADZONE_ADDR (0x004b4f98)
#define STR_TITLE_KBD_ADDR (0x004b52e8) // "KEYBOARD SETTINGS"
// Keyboard directional function-name keys (capture fnStr) + display labels. On the keyboard the
// analog Turn/Pitch axes are split into two discrete-key rows each, distinguished by the direction
// bit passed as SetMappingRowText's param6 (0x20 vs 0x10) since e.g. Nose Up/Down share control 3.
#define FN_PITCH_UP_ADDR (0x004b26c8)
#define FN_PITCH_DOWN_ADDR (0x004b26e4)
#define FN_TURN_LEFT_ADDR (0x004b26ac)
#define FN_TURN_RIGHT_ADDR (0x004b268c)
#define LBL_NOSE_UP_ADDR (0x004b5134)
#define LBL_NOSE_DOWN_ADDR (0x004b5114)

// Fresh widget-id block for the extra column cells (slots 2 and 3), clear of the stock mapping id
// space (0x27..0x58) and the list ids (0x30d4d/0x30d4e).
#define UNIFIED_CELL_ID_BASE (0x3600)

typedef void(__cdecl *BuildMouseMenu_t)(void *page);
typedef void(__cdecl *RefreshMappingMenu_t)(int device, void *page);
typedef int(__cdecl *MappingsMenu_t)(void *page, unsigned int msg, unsigned int widgetId, int widget);
typedef unsigned char(__cdecl *CaptureBinding_t)(int analog, void *device, void *row, char *fnStr,
                                                 int slot);

#define swrConfig_BuildKeyboardMenu_ADDR (0x0040dd10)
static BuildMouseMenu_t orig_BuildMouseMenu = (BuildMouseMenu_t) swrConfig_BuildMouseMenu_ADDR;
static BuildMouseMenu_t orig_BuildJoystickMenu = (BuildMouseMenu_t) swrConfig_BuildJoystickMenu_ADDR;
static BuildMouseMenu_t orig_BuildKeyboardMenu = (BuildMouseMenu_t) swrConfig_BuildKeyboardMenu_ADDR;
static RefreshMappingMenu_t orig_RefreshMappingMenu =
    (RefreshMappingMenu_t) swrConfig_RefreshMappingMenu_ADDR;
static MappingsMenu_t orig_MappingsMenu = (MappingsMenu_t) swrControl_MappingsMenu_ADDR;
typedef int(__cdecl *WriteMappings_t)(char *dir);
static WriteMappings_t orig_WriteMappings = (WriteMappings_t) swrConfig_WriteMappings_ADDR;

static char *xlate(const char *s) {
    return ((char *(__cdecl *) (const char *) ) swrText_Translate_ADDR)(s);
}
static void toast(const char *s, float secs) {
    ((void(__cdecl *)(const char *, float)) swrText_ShowTimedMessage_ADDR)(s, secs);
}
static int str_w(const char *s) { // width in the default (index 0) UI font
    return ((int(__cdecl *)(char *, int)) swrText_GetStringWidthByFont_ADDR)((char *) s, 0);
}
static int str_h(const char *s) { // height in the title/body font (index 6)
    void *font6 = *(void **) (swrText_fontsByIndex_ADDR + 6 * 4);
    return ((int(__cdecl *)(char *, void *)) swrText_GetStringHeight_ADDR)((char *) s, font6);
}
static void set_color(void *ui, int r, int g, int b, int a) {
    ((void(__cdecl *)(void *, char, char, char, char)) swrUI_SetColorUnk_ADDR)(
        ui, (char) r, (char) g, (char) b, (char) a);
}
static void set_row_text(int device, void *page, int rowId, int control, int p5, int p6, int slot) {
    ((void(__cdecl *)(int, void *, int, int, int, int, int)) swrConfig_SetMappingRowText_ADDR)(
        device, page, rowId, control, p5, p6, slot);
}
static void *ui_by_id(void *page, int id) {
    return ((void *(__cdecl *) (void *, int) ) swrUI_GetById_ADDR)(page, id);
}
static void set_value(void *cell, const char *text) {
    if (cell)
        ((void(__cdecl *)(void *, const char *, int)) swrUI_SetValueText_ADDR)(cell, text, 0);
}
// swrConfig_ControlToString returns the name pointer in EAX (friendly-names hook applies here).
static char *control_name(unsigned int id, int table) {
    return ((char *(__cdecl *) (unsigned int, int) ) swrConfig_ControlToString_ADDR)(id, table);
}
// swrUI_NewScreenText(parent,id,index,text,unk5,x,y,width,height,unk10,flags,sizeUnk).
static void *screen_text(void *page, int id, const char *text, int x, int y, int w, int h,
                         int unk10, int flags) {
    return ((void *(__cdecl *) (void *, int, int, const char *, int, int, int, int, int, int, int,
                                int) ) swrUI_NewScreenText_ADDR)(
        page, id, 0, text, wuRegistry_lpClass_ADDR, x, y, w, h, unk10, flags, 0);
}
// swrUI_unk geometry (src/types.h): x@0x24 y@0x28 width@0x2c height@0x30. Read back to verify layout.
static int ui_x(void *w) { return w ? *(int *) ((char *) w + 0x24) : -1; }
static int ui_y(void *w) { return w ? *(int *) ((char *) w + 0x28) : -1; }
static int ui_w(void *w) { return w ? *(int *) ((char *) w + 0x2c) : -1; }
static int ui_h(void *w) { return w ? *(int *) ((char *) w + 0x30) : -1; }

// One row of the unified table. col[0] reuses the stock widget id (stock Refresh fills slot 1);
// col[1]/col[2] are this file's new slot-2/slot-3 cells. control/p5/p6 mirror what the stock
// RefreshMappingMenu passes to SetMappingRowText for that action; analog selects capture mode.
struct UnifiedRow {
    const char *labelAddr;  // menu display label
    const char *fnStrAddr;  // capture fnStr key
    int control;            // SetMappingRowText control (action id)
    int p5;                 // SetMappingRowText param5 (flag mask: 10=button, 5=axis)
    int p6;                 // SetMappingRowText param6
    bool analog;            // bAnalogCapture
    int col[3];             // widget ids for slots 1/2/3
};

// Deduped mouse function table (union of the stock button + axis lists, one row per function).
// Dedup decision: Brake and Roll -- listed once each as digital rows; the stock analog-only Brake
// and Roll axis rows are dropped (a stick/pedal can still be bound to them as a direction via the
// axis-aware capture delta). Turn/Pitch/Throttle keep analog capture. (Open to revisiting.)
#define U (UNIFIED_CELL_ID_BASE)
static UnifiedRow g_rows[] = {
    {(const char *) LBL_TURN_ADDR, (const char *) STR_TURN_ADDR, 2, 5, 0, true, {0x3e, U + 0, U + 1}},
    {(const char *) LBL_PITCH_ADDR, (const char *) STR_PITCH_ADDR, 3, 5, 0, true, {0x3f, U + 2, U + 3}},
    {(const char *) LBL_THROTTLE_ADDR, (const char *) STR_ANALOG_THROTTLE_ADDR, 0, 5, 0, true, {0x3d, U + 4, U + 5}},
    {(const char *) LBL_THRUST_ADDR, (const char *) STR_THRUST_ADDR, 3, 10, 0, false, {0x2d, U + 6, U + 7}},
    {(const char *) LBL_BRAKE_ADDR, (const char *) STR_BRAKE_ADDR, 2, 10, 0, false, {0x2b, U + 8, U + 9}},
    {(const char *) LBL_BOOST_ADDR, (const char *) STR_BOOST_ADDR, 4, 10, 0, false, {0x2f, U + 10, U + 11}},
    {(const char *) LBL_SLIDE_ADDR, (const char *) STR_SLIDE_ADDR, 5, 10, 0, false, {0x31, U + 12, U + 13}},
    {(const char *) LBL_ROLL_LEFT_ADDR, (const char *) STR_ROLL_LEFT_ADDR, 6, 10, 0, false, {0x33, U + 14, U + 15}},
    {(const char *) LBL_ROLL_RIGHT_ADDR, (const char *) STR_ROLL_RIGHT_ADDR, 7, 10, 0, false, {0x35, U + 16, U + 17}},
    {(const char *) LBL_CAMERA_ADDR, (const char *) STR_CAMERA_CYCLE_ADDR, 0, 10, 0, false, {0x27, U + 18, U + 19}},
    {(const char *) LBL_LOOK_BACK_ADDR, (const char *) STR_LOOK_BACK_ADDR, 1, 10, 0, false, {0x29, U + 20, U + 21}},
    {(const char *) LBL_TAUNT_ADDR, (const char *) STR_SPECIAL_ADDR, 8, 10, 0, false, {0x37, U + 22, U + 23}},
    {(const char *) LBL_REPAIR_ADDR, (const char *) STR_REPAIR_ADDR, 9, 10, 0, false, {0x39, U + 24, U + 25}},
};
#undef U
static const int g_rowCount = sizeof(g_rows) / sizeof(g_rows[0]);

// Keyboard function table: the stock keyboard page splits each analog axis into two discrete-key
// rows (Nose Up/Down, Turn Left/Right), so there are no analog rows -- every row is 3 key slots.
// Uses its own id block; all three columns are new cells driven by this file's Refresh/dispatch via
// the stock slot model (SetMappingRowText + CaptureBinding(fnStr, slot)). p5=10 buttons, p5=9 +
// p6=direction for the split axis rows. col = {K+i*3, +1, +2}.
// Same canonical order as g_rows (steering -> pitch -> [throttle: n/a] -> thrust/brake -> boost ->
// slide -> roll -> camera -> look-back -> taunt -> repair), with the keyboard's analog axes split
// into two discrete-key rows each so the pages read consistently top-to-bottom.
#define K (0x3700)
static UnifiedRow g_kbdRows[] = {
    {(const char *) FN_TURN_LEFT_ADDR, (const char *) FN_TURN_LEFT_ADDR, 2, 9, 0x20, false, {K + 0, K + 1, K + 2}},
    {(const char *) FN_TURN_RIGHT_ADDR, (const char *) FN_TURN_RIGHT_ADDR, 2, 9, 0x10, false, {K + 3, K + 4, K + 5}},
    {(const char *) LBL_NOSE_UP_ADDR, (const char *) FN_PITCH_UP_ADDR, 3, 9, 0x20, false, {K + 6, K + 7, K + 8}},
    {(const char *) LBL_NOSE_DOWN_ADDR, (const char *) FN_PITCH_DOWN_ADDR, 3, 9, 0x10, false, {K + 9, K + 10, K + 11}},
    {(const char *) LBL_THRUST_ADDR, (const char *) STR_THRUST_ADDR, 3, 10, 0, false, {K + 12, K + 13, K + 14}},
    {(const char *) LBL_BRAKE_ADDR, (const char *) STR_BRAKE_ADDR, 2, 10, 0, false, {K + 15, K + 16, K + 17}},
    {(const char *) LBL_BOOST_ADDR, (const char *) STR_BOOST_ADDR, 4, 10, 0, false, {K + 18, K + 19, K + 20}},
    {(const char *) LBL_SLIDE_ADDR, (const char *) STR_SLIDE_ADDR, 5, 10, 0, false, {K + 21, K + 22, K + 23}},
    {(const char *) LBL_ROLL_LEFT_ADDR, (const char *) STR_ROLL_LEFT_ADDR, 6, 10, 0, false, {K + 24, K + 25, K + 26}},
    {(const char *) LBL_ROLL_RIGHT_ADDR, (const char *) STR_ROLL_RIGHT_ADDR, 7, 10, 0, false, {K + 27, K + 28, K + 29}},
    {(const char *) LBL_CAMERA_ADDR, (const char *) STR_CAMERA_CYCLE_ADDR, 0, 10, 0, false, {K + 30, K + 31, K + 32}},
    {(const char *) LBL_LOOK_BACK_ADDR, (const char *) STR_LOOK_BACK_ADDR, 1, 10, 0, false, {K + 33, K + 34, K + 35}},
    {(const char *) LBL_TAUNT_ADDR, (const char *) STR_SPECIAL_ADDR, 8, 10, 0, false, {K + 36, K + 37, K + 38}},
    {(const char *) LBL_REPAIR_ADDR, (const char *) STR_REPAIR_ADDR, 9, 10, 0, false, {K + 39, K + 40, K + 41}},
};
#undef K
static const int g_kbdRowCount = sizeof(g_kbdRows) / sizeof(g_kbdRows[0]);

// Row table + count for a device's unified page (keyboard has its own; joystick/mouse share g_rows).
static UnifiedRow *rows_for_device(int device, int *count) {
    if (device == 2) {
        *count = g_kbdRowCount;
        return g_kbdRows;
    }
    *count = g_rowCount;
    return g_rows;
}

// Per-device page differences (the table + column math are identical across devices).
struct DeviceUI {
    int device;             // 0 = joystick, 1 = mouse, 2 = keyboard
    const char *titleAddr;  // page title string
    int titleX;             // title box x (stock value)
    const char *enableAddr; // enable-checkbox label (unused when !hasRightControls)
    bool hasFlipZ;          // joystick has an X/Y/Z flip group; mouse only X/Y
    bool hasDeadzone;       // joystick has a deadzone slider; mouse does not
    bool hasRightControls;  // joystick/mouse have enable/flip/sensitivity; keyboard has none
};

// --- Build: one panel, one row per function, three columns ------------------------------------
// Column math mirrors swrConfig_BuildKeyboardMenu (the known-good 3-column layout): a label cell
// that holds the label (left) + slot-1 value (right, offset by the label width), then two narrow
// value cells flush after it. Rows are compacted so all 13 rows fit without scrolling, and the
// per-device controls sit to the right. Emits the resolved geometry to hook.log for tuning.
static void build_unified(void *page, const DeviceUI &d, UnifiedRow *rows, int rowCount) {
    // Title + standard buttons (verbatim from the stock builder).
    char titleBuf[256];
    const int titleH = str_h(d.titleAddr);
    snprintf(titleBuf, sizeof(titleBuf), "%s", xlate(d.titleAddr));
    const int titleW = str_w(d.titleAddr);
    void *title = ((void *(__cdecl *) (void *, int, int, char *, int, int, int, int, int, int,
                                       int) ) swrUI_New3PatchBox_ADDR)(
        page, 1, 6, titleBuf, d.titleX, titleH * 3 + 5, titleW, 0x80000, 1, 0, 0);
    set_color(title, 0xff, 0, 0, 0xff);
    ((void(__cdecl *)(void *, int, int, int, int)) swrUI_AddNavButton_ADDR)(page, 4, 0, 0x1a4, 1);
    ((void(__cdecl *)(void *, int, int)) swrUI_AddDefaultButton_ADDR)(page, 0xcd, 0x1a4);
    ((void(__cdecl *)(void *, int, int)) swrUI_AddRestoreButton_ADDR)(page, 0x163, 0x1a4);
    ((void(__cdecl *)(void *, int, int)) swrUI_AddOkButton_ADDR)(page, 0x208, 0x17c);

    // Column metrics (keyboard-page formula).
    int maxLabelW = 0;
    for (int i = 0; i < rowCount; ++i) {
        int w = str_w(xlate(rows[i].labelAddr));
        if (w > maxLabelW)
            maxLabelW = w;
    }
    // Each cell draws a fixed-size border sprite at its x (swrUI_BuildHighlightSprites): the label
    // cell (flag 0x400000) uses editwindow_segmented; value cells (0x800000) use segment, each
    // drawn at its TEXTURE size (not the cell's width param) with a -4 y shift and a 1px right
    // overlap (right = x + texW - 1). So columns are spaced by (spriteW - 1) and rows by
    // (spriteH - 1) to share the seam and tile with no gap -- the keyboard page's scheme.
    int labelSprW = 0, labelSprH = 0, segSprW = 0, segSprH = 0;
    ((void(__cdecl *)(int, int *, int *)) swrSprite_GetTextureDimFromId_ADDR)(
        SPR_EDITWINDOW_SEGMENTED, &labelSprW, &labelSprH);
    ((void(__cdecl *)(int, int *, int *)) swrSprite_GetTextureDimFromId_ADDR)(SPR_SEGMENT, &segSprW,
                                                                              &segSprH);
    const int labelCellW = labelSprW;                                    // label border width
    const int valueW = segSprW;                                          // value border width
    const int sprH = (labelSprH > segSprH ? labelSprH : segSprH);
    const int spriteYOff = -4;                                           // BuildHighlightSprites shift
    const int valueOff = str_w(xlate((const char *) STR_FLIP_X_ADDR)) * 2; // value-text inset
    // Put slot-1 value in col0's rightmost segment-width region so all three bindings align.
    const int col0ValueOff = (labelCellW - valueW) + valueOff;
    const int rowH = sprH - 1;                                           // share the row seam

    int bbox[4] = {0, 0, 0, 0};
    ((void(__cdecl *)(int *, int)) swrUI_SetSpriteSelectionBBox_Maybe_ADDR)(bbox, 0);
    const int labelX = 0xc;                         // col0 x (kept left to stay in the 4:3 safe area)
    const int slot2X = labelX + labelCellW - 1;     // share the col0/col1 seam
    const int slot3X = slot2X + valueW - 1;         // share the col1/col2 seam
    const int y0 = 90;                              // below the logo + "MOUSE SETTINGS" title

    // Panel frame wraps the cell grid, grown outward by panelPad so its 9-slice border sits
    // OUTSIDE the cells rather than drawing inward over them (cell borders draw at y-4, right x+w-1).
    const int panelPadX = 8;
    const int panelPadY = 14;
    int rect[4];
    rect[0] = labelX - panelPadX;
    rect[1] = (y0 + spriteYOff) - panelPadY;
    rect[2] = (slot3X + valueW - 1) + panelPadX;
    rect[3] = (y0 + (rowCount - 1) * rowH + sprH + spriteYOff) + panelPadY;
    ((void(__cdecl *)(void *, int, int *, int)) swrUI_NewPanel_ADDR)(page, 1, rect, 0);

    if (hook_log) {
        fprintf(hook_log,
                "[unified] metrics labelSpr=%dx%d segSpr=%dx%d maxLabelW=%d rowH=%d col0ValOff=%d "
                "bbox0=%d labelX=%d slot2X=%d slot3X=%d panel=[%d,%d,%d,%d]\n",
                labelSprW, labelSprH, segSprW, segSprH, maxLabelW, rowH, col0ValueOff, bbox[0],
                labelX, slot2X, slot3X, rect[0], rect[1], rect[2], rect[3]);
    }

    for (int i = 0; i < rowCount; ++i) {
        UnifiedRow &r = rows[i];
        const int y = y0 + i * rowH;
        void *c0 = screen_text(page, r.col[0], xlate(r.labelAddr), labelX, y, labelCellW, rowH,
                               col0ValueOff, 0x400000);
        void *c1 = screen_text(page, r.col[1], nullptr, slot2X, y, valueW, rowH, valueOff, 0x800000);
        void *c2 = screen_text(page, r.col[2], nullptr, slot3X, y, valueW, rowH, valueOff, 0x800000);
        if (hook_log) {
            fprintf(hook_log, "[unified] row %2d col0(%dx%d @%d,%d) col1(@%d,%d) col2(@%d,%d)\n", i,
                    ui_w(c0), ui_h(c0), ui_x(c0), ui_y(c0), ui_x(c1), ui_y(c1), ui_x(c2), ui_y(c2));
        }
    }

    // Keyboard has no enable/flip/sensitivity controls -- the table is the whole page.
    if (!d.hasRightControls) {
        if (hook_log)
            fflush(hook_log);
        return;
    }

    // Per-device controls to the RIGHT of the (narrower) table, stacked vertically -- stock ids so
    // the stock Refresh/MappingsMenu still drive them. The table only reaches rect[2], so there is
    // room on the right and no vertical overflow into the OK/nav buttons.
    const int cx = rect[2] + 12;
    int cy = y0;
    void *lbl;
    lbl = ((void *(__cdecl *) (void *, int, int, char *, int, int, int, int) ) swrUI_NewLabel_ADDR)(
        page, 0x58, 0, (char *) wuRegistry_lpClass_ADDR, cx, cy, 0, 0); // "Detected ..." (Refresh)
    set_color(lbl, 0xff, 0xff, 0, 200);
    cy += rowH * 2;
    ((void(__cdecl *)(void *, int, int, char *, int, int, int, int, int, int)) swrUI_NewFramedText_ADDR)(
        page, 0x54, 0, xlate(d.enableAddr), cx, cy, str_w(xlate(d.enableAddr)) + 20, rowH, 0x20000,
        0);
    cy += rowH * 2;
    lbl = ((void *(__cdecl *) (void *, int, int, char *, int, int, int, int) ) swrUI_NewLabel_ADDR)(
        page, 1, 0, xlate((const char *) STR_FLIP_AXIS_ADDR), cx, cy, 0, 0);
    set_color(lbl, 0xff, 0x7d, 0, 0xff);
    cy += rowH;
    {
        const int fx = cx + 10;
        ((void(__cdecl *)(void *, int, int, char *, int, int, int, int, int, int)) swrUI_NewFramedText_ADDR)(
            page, 0x55, 0, xlate((const char *) STR_FLIP_X_ADDR), fx, cy, 40, rowH, 0x40000, 0);
        ((void(__cdecl *)(void *, int, int, char *, int, int, int, int, int, int)) swrUI_NewFramedText_ADDR)(
            page, 0x56, 0, xlate((const char *) STR_FLIP_Y_ADDR), fx + 50, cy, 40, rowH, 0x40000, 0);
        if (d.hasFlipZ)
            ((void(__cdecl *)(void *, int, int, char *, int, int, int, int, int, int)) swrUI_NewFramedText_ADDR)(
                page, 0x57, 0, xlate((const char *) STR_FLIP_Z_ADDR), fx + 100, cy, 40, rowH,
                0x40000, 0);
    }
    cy += rowH * 2;
    lbl = ((void *(__cdecl *) (void *, int, int, char *, int, int, int, int) ) swrUI_NewLabel_ADDR)(
        page, 1, 0, xlate((const char *) STR_SENSITIVITY_ADDR), cx, cy, 0, 0);
    ((void(__cdecl *)(void *, int, int, int, int, int, int)) swrUI_NewNumberField_ADDR)(
        page, 0x4e, cx, cy + rowH, 150, 0x80000, 0);
    if (d.hasDeadzone) {
        cy += rowH * 3;
        lbl = ((void *(__cdecl *) (void *, int, int, char *, int, int, int, int) ) swrUI_NewLabel_ADDR)(
            page, 1, 0, xlate((const char *) STR_DEADZONE_ADDR), cx, cy, 0, 0);
        ((void(__cdecl *)(void *, int, int, int, int, int, int)) swrUI_NewNumberField_ADDR)(
            page, 0x4d, cx, cy + rowH, 150, 0xdc0000, 0);
    }
    if (hook_log)
        fflush(hook_log);
}

static void __cdecl BuildMouseMenu_unified(void *page) {
    static const DeviceUI mouse = {1, (const char *) STR_TITLE_MOUSE_ADDR, 0x1d1,
                                   (const char *) STR_MOUSE_ENABLED_ADDR, false, false, true};
    build_unified(page, mouse, g_rows, g_rowCount);
}

static void __cdecl BuildJoystickMenu_unified(void *page) {
    static const DeviceUI joy = {0, (const char *) STR_TITLE_JOY_ADDR, 0x1d1,
                                 (const char *) STR_JOY_ENABLED_ADDR, true, true, true};
    build_unified(page, joy, g_rows, g_rowCount);
}

static void __cdecl BuildKeyboardMenu_unified(void *page) {
    static const DeviceUI kbd = {2, (const char *) STR_TITLE_KBD_ADDR, 0x1d1, nullptr, false, false,
                                 false};
    build_unified(page, kbd, g_kbdRows, g_kbdRowCount);
}

// Does a binding-table entry belong on this row? `control` is NOT unique -- e.g. Thrust and Pitch
// are both control 3, separated only by type -- so match on the flag pattern too: analog rows take
// pure analog axes; digital rows take buttons AND axis-as-button (axis-range) bindings. This is
// what lets a digital action like Boost show a stick/trigger binding, which FormatBinding's single
// type mask cannot.
static bool entry_matches_row(unsigned int flags, const UnifiedRow &r) {
    if (r.analog)
        return (flags & BIND_ANALOG_AXIS) && !(flags & BIND_AXIS_RANGE);
    return (flags & BIND_BUTTON) || ((flags & BIND_ANALOG_AXIS) && (flags & BIND_AXIS_RANGE));
}

// Format one binding entry the way the menu shows it. A full analog axis (no direction bit) gets
// no prefix ("RY AXIS"); an axis-as-button single direction gets "+"/"-" ("+RY AXIS").
static void format_entry(unsigned int flags, int input, char *out, int outsz) {
    if (flags & BIND_BUTTON) {
        char *nm = xlate(control_name(input, keyMapping1_ADDR));
        snprintf(out, outsz, xlate((const char *) STR_BUTTON_FMT_ADDR), nm);
    } else if (flags & BIND_ANALOG_AXIS) {
        const char *pre =
            (flags & BIND_AXIS_POS) ? "+" : (flags & BIND_AXIS_NEG) ? "-" : "";
        char *nm = xlate(control_name(input, keyMapping0_ADDR));
        snprintf(out, outsz, "%s%s AXIS", pre, nm);
    } else {
        snprintf(out, outsz, "%s", (const char *) STR_UNBOUND_ADDR);
    }
}

// --- Refresh: fill all three columns from the live binding table ------------------------------
// Scans the device table directly (rather than SetMappingRowText's type-filtered slot counting) so
// each column shows the next binding of the action -- button OR axis-as-button -- in table order.
static void __cdecl RefreshMappingMenu_unified(int device, void *page) {
    orig_RefreshMappingMenu(device, page);
    if (device == 2) {
        // Keyboard: all keys, no axis-as-button ambiguity, so the stock type+direction-filtered
        // slot model is exact -- fill each column via SetMappingRowText (buttons p5=10; the split
        // axis rows use p5=9 + p6 = the direction bit that separates e.g. Nose Up from Nose Down).
        for (int i = 0; i < g_kbdRowCount; ++i) {
            const UnifiedRow &r = g_kbdRows[i];
            for (int c = 0; c < 3; ++c)
                set_row_text(2, page, r.col[c], r.control, r.p5, r.p6, c + 1);
        }
        return;
    }
    if (device != 0 && device != 1) // joystick + mouse
        return;
    unsigned char *table = (unsigned char *) ((device == 0) ? 0x004d5fc0 : 0x004d6518);
    const int count = ((int *) 0x004d5e20)[device];
    for (int i = 0; i < g_rowCount; ++i) {
        const UnifiedRow &r = g_rows[i];
        int col = 0;
        unsigned int shown[3] = {0, 0, 0}; // (input, type/direction bits) already placed -> dedup
        int shownN = 0;
        for (int e = 0; e < count && col < 3; ++e) {
            const unsigned int fl = *(unsigned int *) (table + e * 12);
            const int input = *(int *) (table + e * 12 + 4);
            const int action = *(int *) (table + e * 12 + 8);
            if (action != r.control || !entry_matches_row(fl, r))
                continue;
            // Skip an identical binding already shown for this row (same input + type/direction).
            const unsigned int key = ((unsigned int) input << 8) | (fl & 0x3c);
            bool dup = false;
            for (int s = 0; s < shownN; ++s)
                if (shown[s] == key)
                    dup = true;
            if (dup)
                continue;
            shown[shownN++] = key;
            char buf[64];
            format_entry(fl, input, buf, sizeof(buf));
            set_value(ui_by_id(page, r.col[col]), buf);
            ++col;
        }
        for (; col < 3; ++col)
            set_value(ui_by_id(page, r.col[col]), (const char *) STR_UNBOUND_ADDR);
    }
}

// --- Unified capture: bind/clear a specific binding-table entry (table-position model) ---------
static unsigned char *device_table(int device) {
    return (unsigned char *) ((device == 0) ? 0x004d5fc0 : 0x004d6518);
}
static int *device_count(int device) { return &((int *) 0x004d5e20)[device]; }

// Table index of the colIndex-th binding shown for this row (matching Refresh's scan + dedup), or
// -1 if that column is currently empty.
static int find_column_entry(int device, const UnifiedRow &r, int colIndex) {
    unsigned char *t = device_table(device);
    const int count = *device_count(device);
    int col = 0;
    unsigned int shown[3] = {0, 0, 0};
    int shownN = 0;
    for (int e = 0; e < count; ++e) {
        const unsigned int fl = *(unsigned int *) (t + e * 12);
        const int input = *(int *) (t + e * 12 + 4);
        const int action = *(int *) (t + e * 12 + 8);
        if (action != r.control || !entry_matches_row(fl, r))
            continue;
        const unsigned int key = ((unsigned int) input << 8) | (fl & 0x3c);
        bool dup = false;
        for (int s = 0; s < shownN; ++s)
            if (shown[s] == key)
                dup = true;
        if (dup)
            continue;
        if (col == colIndex)
            return e;
        shown[shownN++] = key;
        ++col;
    }
    return -1;
}

static void table_remove_at(int device, int idx) {
    unsigned char *t = device_table(device);
    int *count = device_count(device);
    if (idx < 0 || idx >= *count)
        return;
    for (int e = idx; e < *count; ++e) // shift entries + terminator down one
        memcpy(t + e * 12, t + (e + 1) * 12, 12);
    --*count;
}

static void advance_frame_head() {
    ((void(__cdecl *)(void)) rdCache_AdvanceFrame_ADDR)();
    ((void(__cdecl *)(void)) stdDisplay_FillMainSurface_ADDR)();
    ((void(__cdecl *)(void)) swrControl_ProcessInputs_ADDR)();
    ((void(__cdecl *)(int, int)) swrMain_RunFrame_ADDR)(0, 2);
    ((void(__cdecl *)(void *)) swrUI_RenderTree_ADDR)(nullptr);
}
static void advance_frame_tail() {
    ((void(__cdecl *)(void)) swr_noop2_ADDR)();
    ((void(__cdecl *)(void)) rdCache_Flush_ADDR)();
    ((void(__cdecl *)(void)) rdCache_FlushAlpha_ADDR)();
    ((void(__cdecl *)(void)) stdDisplay_Update_ADDR)();
}
static unsigned int scan_buttons(int device) {
    return ((unsigned int(__cdecl *)(int, int)) swrControl_ScanPressedButtons_ADDR)(device, 0);
}
static int find_axis(int device, int *dir) {
    return ((int(__cdecl *)(int, int *)) swrControl_FindMovedAxis_ADDR)(device, dir);
}
static int poll_cancel(int device) {
    return ((int(__cdecl *)(int)) swrControl_PollCancel_ADDR)(device);
}
static int read_del() {
    return ((int(__cdecl *)(int, int *)) stdControl_ReadKey_ADDR)(DIK_DELETE, nullptr);
}
static void add_mapping(int device, const char *fnStr, int input, int analog, int dir, int atIdx) {
    ((int(__cdecl *)(void *, const char *, int, int, int, int)) swrControl_AddMapping_ADDR)(
        (void *) device, fnStr, input, analog, dir, atIdx);
}

// Capture for one unified column: overwrite the entry it currently shows (or append), or clear it.
// Analog rows bind a FULL axis (direction ignored); digital rows bind a button or an axis-as-button
// direction. Returns nonzero if a change was made (so the caller marks the config dirty).
static bool unified_capture_column(int device, void *page, const UnifiedRow &r, int colIndex,
                                   void *cell) {
    char origText[64];
    ((void(__cdecl *)(void *, char *, int)) swrUI_GetValueText_ADDR)(cell, origText, 0x40);
    set_value(cell, (const char *) STR_PLACEHOLDER_ADDR);
    toast(xlate("Press a button or move an axis  (DEL clears, ESC cancels)"), 4.0f);

    const int targetIdx = find_column_entry(device, r, colIndex);
    bool primed = false, changed = false;
    for (;;) {
        advance_frame_head();
        const unsigned int btn = scan_buttons(device);
        int dir = 0;
        const int axis = find_axis(device, &dir);
        const int cancel = poll_cancel(device);
        const int del = read_del();
        const bool anyHeld = btn != 0xffff || (axis >= 0 && dir != 0) || cancel || del;
        bool done = false;
        if (!primed) {
            if (!anyHeld)
                primed = true;
        } else if (cancel) {
            set_value(cell, origText);
            toast(xlate((const char *) STR_CANCELLED_ADDR), 2.0f);
            done = true;
        } else if (del) {
            if (targetIdx >= 0)
                table_remove_at(device, targetIdx);
            set_value(cell, (const char *) STR_UNBOUND_ADDR);
            changed = done = true;
        } else if (btn != 0xffff) {
            add_mapping(device, r.fnStrAddr, btn, 0, 0, targetIdx); // button
            changed = done = true;
        } else if (axis >= 0 && dir != 0) {
            // analog row -> full axis (dir 0); digital row -> axis-as-button (dir +/-)
            add_mapping(device, r.fnStrAddr, axis, 1, r.analog ? 0 : dir, targetIdx);
            changed = done = true;
        }
        advance_frame_tail();
        if (done) {
            for (;;) { // drain: wait for release so the accept press isn't re-consumed
                advance_frame_head();
                const unsigned int b2 = scan_buttons(device);
                int d2 = 0;
                const int a2 = find_axis(device, &d2);
                const int c2 = poll_cancel(device);
                const int e2 = read_del();
                advance_frame_tail();
                if (b2 == 0xffff && !(a2 >= 0 && d2 != 0) && !c2 && !e2)
                    break;
            }
            RefreshMappingMenu_unified(device, page);
            return changed;
        }
    }
}

// --- Dispatch: a click on any unified column captures into that column -------------------------
static int __cdecl MappingsMenu_unified(void *page, unsigned int msg, unsigned int widgetId,
                                        int widget) {
    if (msg == 1000 || msg == 0x14) {
        const int device = *(int *) swrConfig_currentInputDeviceType_ADDR;
        if (device == 2) { // keyboard: capture a key into this column's slot (stock slot model)
            for (int i = 0; i < g_kbdRowCount; ++i) {
                UnifiedRow &r = g_kbdRows[i];
                for (int c = 0; c < 3; ++c) {
                    if (r.col[c] != (int) widgetId)
                        continue;
                    void *cell = widget ? (void *) widget : ui_by_id(page, widgetId);
                    *(int *) inputActiveGuard_ADDR = 0;
                    const unsigned char capres = ((CaptureBinding_t) swrControl_CaptureBinding_ADDR)(
                        0, (void *) 2, cell, (char *) r.fnStrAddr, c + 1);
                    *(int *) inputActiveGuard_ADDR = 1;
                    if (capres != 0 && capres != 3)
                        *(int *) configDirty_ADDR = 1;
                    RefreshMappingMenu_unified(2, page);
                    return 1;
                }
            }
        }
        if (device == 0 || device == 1) { // unified mouse/joystick pages
            for (int i = 0; i < g_rowCount; ++i) {
                UnifiedRow &r = g_rows[i];
                for (int c = 0; c < 3; ++c) {
                    if (r.col[c] != (int) widgetId)
                        continue;
                    void *cell = widget ? (void *) widget : ui_by_id(page, widgetId);
                    *(int *) inputActiveGuard_ADDR = 0;
                    const bool changed = unified_capture_column(device, page, r, c, cell);
                    *(int *) inputActiveGuard_ADDR = 1;
                    if (changed) // mark dirty so the change is saved on exit (not discarded)
                        *(int *) configDirty_ADDR = 1;
                    return 1;
                }
            }
        }
    }
    return orig_MappingsMenu(page, msg, widgetId, widget);
}

// Report the result of the controls-page auto-save so a rebind gives feedback (the stock page
// saves silently on exit). Scoped to WriteMappings calls from swrControl_MappingsMenu, so the
// profile Save/Load screen (which has its own toast) is untouched. WriteMappings returns 1 on
// success.
static int __cdecl WriteMappings_toast(char *dir) {
    const int r = orig_WriteMappings(dir);
    void *ret = __builtin_return_address(0);
    if (ret >= (void *) MappingsMenu_LO && ret < (void *) MappingsMenu_HI)
        toast(r == 1 ? xlate((const char *) STR_SAVED_ADDR) : "Save failed", 2.0f);
    return r;
}

extern "C" void controls_unified_table_install() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((void **) &orig_BuildMouseMenu, (void *) BuildMouseMenu_unified);
    DetourAttach((void **) &orig_BuildJoystickMenu, (void *) BuildJoystickMenu_unified);
    DetourAttach((void **) &orig_BuildKeyboardMenu, (void *) BuildKeyboardMenu_unified);
    DetourAttach((void **) &orig_RefreshMappingMenu, (void *) RefreshMappingMenu_unified);
    DetourAttach((void **) &orig_WriteMappings, (void *) WriteMappings_toast);
    DetourAttach((void **) &orig_MappingsMenu, (void *) MappingsMenu_unified);
    DetourTransactionCommit();
}

#endif // ENABLE_UNIFIED_CONTROLS
