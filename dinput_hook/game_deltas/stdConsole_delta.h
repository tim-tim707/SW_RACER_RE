#pragma once

#include <windows.h>
#include <winuser.h>

#include "types.h"

int stdConsole_GetCursorPos_delta(int *out_x, int *out_y);
void stdConsole_SetCursorPos_delta(int X, int Y);
