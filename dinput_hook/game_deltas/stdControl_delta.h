#pragma once

#include "types.h"

int stdControl_Startup_delta(void);

#if ENABLE_GLFW_INPUT_HANDLING
void stdControl_ReadControls_delta(void);

int stdControl_SetActivation_delta(int bActive);
#endif
