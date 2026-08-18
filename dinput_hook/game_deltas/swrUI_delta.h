#pragma once

extern "C" {
#include <Swr/swrUI.h>
}

// NULL-guard for a vanilla menu-navigation crash (see swrUI_delta.cpp for the triage).
int swrUI_IsFocusable_delta(swrUI_unk *element);
