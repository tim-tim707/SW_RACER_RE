#pragma once

#include <cstdint>

// UI call-site capture, for anchoring screens page by page. While a capture runs, every 2D UI placement
// (sprite SetPos, text entry, swrUI button/label creation) is recorded with the EXE call site that made
// it; when the capture window ends the unique sites are written to ui_callsites.txt in the game folder.
// Resolve each site to its function in Ghidra, then add it to the anchor tables (ui_hud.cpp, ui_menu.cpp).

void ui_inspect_start(float seconds);
bool ui_inspect_active(void);
// Status line for the overlay: the last written file and how many sites it held.
const char *ui_inspect_status(void);

void ui_inspect_note(const char *kind, uintptr_t site, int id, int x, int y, const char *text);
