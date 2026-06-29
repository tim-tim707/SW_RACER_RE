#ifndef SWR_CONTROL_H
#define SWR_CONTROL_H

#include "types.h"

#define swrControl_MappingsMenu_ADDR (0x00402250)

#define swrControl_Initialize_ADDR (0x00404b10)
#define swrControl_Shutdown_ADDR (0x00404da0)
#define swrControl_ProcessInputs_ADDR (0x00404dd0)
#define swrControl_ClearDeviceState_ADDR (0x00405cf0)
#define swrControl_SetDefaultMappings_ADDR (0x00405ea0)
#define stdConfFile_readAndApplyConf_ADDR (0x00406470)

#define swrControl_RemoveMapping_ADDR (0x00407500)
#define swrControl_ApplyAxisConfig_ADDR (0x00407630)
#define swrControl_ClearBindings_ADDR (0x00407800)

#define swrControl_ReplaceMapping_ADDR (0x004078a0)

#define swrControl_AddMapping_ADDR (0x004078e0)

// Config parsers + per-frame input helpers.
#define stdConfig_getKeymap_id_ADDR (0x00407a90)
#define swrControl_ParseFunctionName_ADDR (0x00407cd0)
#define swrControl_PollAccept_ADDR (0x00407ea0)
#define swrControl_PollCancel_ADDR (0x00407f80)
#define stdControl_isAxisAboveDeadzone_ADDR (0x00408040)
#define swrControl_SnapshotKeyboard_ADDR (0x00408120)

// Input rebinding / device-scan helpers (used by the mapping menu + config load):
#define swrControl_ScanPressedButtons_ADDR (0x00405dd0)
#define swrControl_FormatBinding_ADDR (0x00406a50)
#define swrControl_CaptureBinding_ADDR (0x00406cc0)
#define swrControl_FindMovedAxis_ADDR (0x00407700)
#define swrControl_FindMapping_ADDR (0x004079f0)
#define swrControl_FindKeyName_ADDR (0x00407d90)
#define swrControl_SelectSavedJoystick_ADDR (0x00407de0)
#define swrControl_IsKeyStringControl_ADDR (0x00408020)
#define swrControl_ClearPollState_Maybe_ADDR (0x004081c0)

// Force feedback (DirectInput effects loaded from data/bundle*.fcr via cifr_*).
#define swrControl_LoadForceEffects_ADDR (0x00409d70)
#define swrControl_PlayForceEffect_ADDR (0x00409ee0)
#define swrControl_StopForceEffect_ADDR (0x0040a0b0)
#define swrControl_StopAllForceEffects_ADDR (0x0040a120)
#define swrControl_PrepareForceEffect_ADDR (0x0040a240)
#define swrControl_FindForceEffectSlot_ADDR (0x0040a160)
#define swrControl_CheckForceEffectType_ADDR (0x0040a190)
#define swrControl_ConfigureForceEffect_ADDR (0x0040a330)
#define swrControl_UpdateForceEffect_ADDR (0x0040a500)

// Force-feedback runtime: per-frame rumble drivers from the player's pod state.
#define swrControl_SetForceFeedbackPlayer_ADDR (0x0040b110)
#define swrControl_UpdateForceFeedback_ADDR (0x0040b150)
#define swrControl_UpdateTractionForceEffect_ADDR (0x0040b1c0)
#define swrControl_UpdateSpeedForceEffect_ADDR (0x0040b3d0)
#define swrControl_UpdateImpactForceEffect_ADDR (0x0040b5e0)

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
int stdConfFile_readAndApplyConf(int deviceFilter, char* configName, int useDefaultDir);

int swrControl_RemoveMapping(void* cid, char* mondo_text, int param_3, int whichone, int bool_unk);

// Push the parsed sensitivity/deadzone for an axis into its stdControl registration.
void swrControl_ApplyAxisConfig(int axis);

// Clear binding tables + action outputs (deviceFilter -1 = all, 0/1/2 = device).
void swrControl_ClearBindings(int deviceFilter);

void swrControl_ReplaceMapping(void* cid, char* fnStr, int whichOne, int bAnalogCapture, int unk, int controllerBinding);

int swrControl_AddMapping(void* cid, char* fnStr, int controllerBinding, int bAnalogCapture, int unk, int unk2);

// Parse a key/button name (via keyMapping tables) to its input code.
int stdConfig_getKeymap_id(char* name, void* keyTable);

// Parse a FUNCTION (action) name to its action id + flags, writing into outEntry.
int swrControl_ParseFunctionName(void* outEntry, char* name, int mode);

// Poll the unified accept action (Enter / Space / numpad-enter / a joystick
// button / forward axis); excludeDevice skips one source. Returns 1 if active.
int swrControl_PollAccept(int excludeDevice);

// Poll the unified cancel/back action (Escape + buttons). Returns 1 if active.
int swrControl_PollCancel(int excludeDevice);

// Return 1 if axis is pushed past threshold (direction 0 = either sign,
// +/-1 = that sign); reads axisId when >= 0, otherwise tests value.
int stdControl_isAxisAboveDeadzone(int axisId, int direction, float value, float threshold);

// Snapshot all 256 key states and drain the buffered-key (WndProc) queue.
void swrControl_SnapshotKeyboard(void);

// Clears the unified accept/cancel control-poll accumulators and returns one (best guess).
int swrControl_ClearPollState_Maybe(void);

// Input rebinding / device-scan helpers:
unsigned int swrControl_ScanPressedButtons(int device, int returnBitmask); // scan kbd 0x200-3 / joystick buttons for presses
int swrControl_FormatBinding(char* out, int a2, unsigned char* a3, unsigned char a4, int a5, char* a6, unsigned int* a7); // binding -> display string
unsigned char swrControl_CaptureBinding(int a1, void* a2, swrUI_unk* a3, char* a4, int a5); // capture a new key/axis for a mapping row
int swrControl_FindMovedAxis(int device, void* param_2);          // which analog axis moved past the deadzone
int swrControl_FindMapping(unsigned char* device, int a2, int a3, unsigned char* a4); // look up a binding in a device table
int swrControl_FindKeyName(int id, char otherId);                 // key/button name string by (id, otherId)
void swrControl_SelectSavedJoystick(void);                        // select the joystick device from the saved registry GUID
int swrControl_IsKeyStringControl(int controlId);                 // is this control in the key-string table

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

// Force-feedback effect-table helpers:
int swrControl_FindForceEffectSlot(unsigned int effectId);        // effect id -> effect-table slot (-1 if none)
int swrControl_CheckForceEffectType(int slot, unsigned int type);
int swrControl_ConfigureForceEffect(int a1, int a2);
int swrControl_UpdateForceEffect(int a1, int a2);

// Force-feedback runtime: per-frame rumble drivers from the player's pod state.
void swrControl_SetForceFeedbackPlayer(swrRace* player); // cache the player + baseline for FF
void swrControl_UpdateForceFeedback(void);               // per-frame dispatcher (calls the 3 below)
void swrControl_UpdateTractionForceEffect(void);         // surface/traction rumble
void swrControl_UpdateSpeedForceEffect(void);            // speed-ratio rumble
void swrControl_UpdateImpactForceEffect(void);           // collision/impact rumble

int swrControl_Startup(void);

#endif // SWR_CONTROL_H
