#ifndef SWR_CONTROL_H
#define SWR_CONTROL_H

#include "types.h"

#define swrControl_MappingsMenu_ADDR (0x00402250)

#define swrControl_Initialize_ADDR (0x00404b10)
#define swrControl_Shutdown_ADDR (0x00404da0)
#define swrControl_ProcessInputs_ADDR (0x00404dd0)
#define swrControl_ClearDeviceState_ADDR (0x00405cf0)
#define swrControl_SetDefaultMappings_ADDR (0x00405ea0)
#define swrControl_LoadMappings_ADDR (0x00406470)

#define swrControl_RemoveMapping_ADDR (0x00407500)
#define swrControl_ApplyAxisConfig_ADDR (0x00407630)
#define swrControl_ClearBindings_ADDR (0x00407800)

#define swrControl_ReplaceMapping_ADDR (0x004078a0)

#define swrControl_AddMapping_ADDR (0x004078e0)

// Config parsers + per-frame input helpers.
#define swrControl_ParseKeyName_ADDR (0x00407a90)
#define swrControl_ParseFunctionName_ADDR (0x00407cd0)
#define swrControl_PollAccept_ADDR (0x00407ea0)
#define swrControl_PollCancel_ADDR (0x00407f80)
#define swrControl_AxisAsButton_ADDR (0x00408040)
#define swrControl_SnapshotKeyboard_ADDR (0x00408120)

// Force feedback (DirectInput effects loaded from data/bundle*.fcr via cifr_*).
#define swrControl_LoadForceEffects_ADDR (0x00409d70)
#define swrControl_PlayForceEffect_ADDR (0x00409ee0)
#define swrControl_StopForceEffect_ADDR (0x0040a0b0)
#define swrControl_StopAllForceEffects_ADDR (0x0040a120)
#define swrControl_PrepareForceEffect_ADDR (0x0040a240)

#define swrControl_Startup_ADDR (0x00423efd)

int swrControl_MappingsMenu(swrUI_unk* param_1, unsigned int param_2, unsigned int param_3, int param_4);

// Initialize the control system: start/open stdControl, enable joystick + mouse
// axes, load force-feedback config and key bindings (default fallback). 0 = ok.
int swrControl_Initialize(void);

int swrControl_Shutdown(void);
void swrControl_ProcessInputs(void);

// Clear a device class's accumulated input state (-1 = final outputs too,
// 0 = joystick, 1 = mouse, 2 = keyboard).
void swrControl_ClearDeviceState(int deviceClass);

// Build a device's default binding table from the hardcoded list
// (device 0 = joystick, 1 = mouse, 2 = keyboard).
void swrControl_SetDefaultMappings(int device);

// Parse a config file into the binding tables (KEY/BUTTON/FUNCTION/AXIS_RANGE/
// FLIP_AXIS/SENSITIVITY/DEADZONE/ENABLED). deviceFilter -1 = all devices.
int swrControl_LoadMappings(int deviceFilter, char* configName, int useDefaultDir);

int swrControl_RemoveMapping(void* cid, char* mondo_text, int param_3, int whichone, int bool_unk);

// Push the parsed sensitivity/deadzone for an axis into its stdControl registration.
void swrControl_ApplyAxisConfig(int axis);

// Clear binding tables + action outputs (deviceFilter -1 = all, 0/1/2 = device).
void swrControl_ClearBindings(int deviceFilter);

void swrControl_ReplaceMapping(void* cid, char* fnStr, int whichOne, int bAnalogCapture, int unk, int controllerBinding);

int swrControl_AddMapping(void* cid, char* fnStr, int controllerBinding, int bAnalogCapture, int unk, int unk2);

// Parse a key/button name (via keyMapping tables) to its input code.
int swrControl_ParseKeyName(char* name, void* keyTable);

// Parse a FUNCTION (action) name to its action id + flags, writing into outEntry.
int swrControl_ParseFunctionName(void* outEntry, char* name, int mode);

// Poll the unified accept action (Enter / Space / numpad-enter / a joystick
// button / forward axis); excludeDevice skips one source. Returns 1 if active.
int swrControl_PollAccept(int excludeDevice);

// Poll the unified cancel/back action (Escape + buttons). Returns 1 if active.
int swrControl_PollCancel(int excludeDevice);

// Return 1 if axis is pushed past threshold (direction 0 = either sign,
// +/-1 = that sign); reads axisId when >= 0, otherwise tests value.
int swrControl_AxisAsButton(int axisId, int direction, float value, float threshold);

// Snapshot all 256 key states and drain the buffered-key (WndProc) queue.
void swrControl_SnapshotKeyboard(void);

// Load the force-feedback effect bundle for a device (data/bundle*.fcr).
int swrControl_LoadForceEffects(int deviceType);

// Play/update a force-feedback effect (magnitude / direction / duration).
int swrControl_PlayForceEffect(int effectId, int magnitude, int direction, int duration);

// Stop one force-feedback effect.
int swrControl_StopForceEffect(int effectId);

// Stop all force-feedback effects (reInit != 0 re-plays the default).
void swrControl_StopAllForceEffects(int reInit);

// Bind a force-feedback effect to a DirectInput effect slot before playing.
int swrControl_PrepareForceEffect(int effectId, int param2);

int swrControl_Startup(void);

#endif // SWR_CONTROL_H
