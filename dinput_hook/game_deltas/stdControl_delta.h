#pragma once

#if ENABLE_GLFW_INPUT_HANDLING
#include "types.h"

int stdControl_Startup_delta(void);

void stdControl_ReadControls_delta(void);

int stdControl_SetActivation_delta(int bActive);
#endif