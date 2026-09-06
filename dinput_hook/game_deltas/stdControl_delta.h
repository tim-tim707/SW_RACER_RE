#pragma once

#include "types.h"

// Null-safe reimplementation of swrControl_FindKeyName (see stdControl_delta.c).
const char *swrControl_FindKeyName_delta(int id, char otherId);

// Config-mapping loader reimplementation that skips a bad entry instead of wiping the whole
// device's bindings (see stdControl_delta.c).
int stdConfFile_readAndApplyConf_delta(int deviceFilter, char *configName, int useDefaultDir);

// swrControl_ClearBindings reimplementation that 0xff-terminates each cleared table so an
// empty table can never be walked off the end of (see stdControl_delta.c).
void swrControl_ClearBindings_delta(int deviceFilter);

int stdControl_Startup_delta(void);

#if ENABLE_GLFW_INPUT_HANDLING
void stdControl_ReadControls_delta(void);

int stdControl_SetActivation_delta(int bActive);
#endif
