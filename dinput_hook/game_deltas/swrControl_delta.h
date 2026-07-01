#pragma once

// Input-edge debounce (see swrControl_delta.cpp). Reverse-hooks swrControl_ProcessInputs so a held
// accept/cancel button produces exactly one transition per physical press.
void swrControl_ProcessInputs_delta(void);
