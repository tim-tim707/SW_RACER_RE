#pragma once

// Hook on swrText_RenderString (0x0042ec50), the universal text chokepoint. When
// imgui_state.sdf_text is on, renders the string with the SDF typography engine; otherwise
// (or if the SDF path declines) runs the original. Registered in init_renderer_hooks.
#ifdef __cplusplus
extern "C" {
#endif

void swrText_RenderString_delta(char *text);

#ifdef __cplusplus
}
#endif
