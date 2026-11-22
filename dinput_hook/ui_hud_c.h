#pragma once

// C entry points into the UI cluster system (ui_hud.h), for the C reimplementations of front-end
// screens. Text and sprites placed between begin and end pin with the screen header (top-centre).

#ifdef __cplusplus
extern "C" {
#endif

void ui_hud_begin_screen_header(void);
void ui_hud_end_screen_header(void);

#ifdef __cplusplus
}
#endif
