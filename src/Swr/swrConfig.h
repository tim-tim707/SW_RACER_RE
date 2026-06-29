#ifndef SWRCONFIG_H
#define SWRCONFIG_H

#include "types.h"
#include <stdbool.h>

#define swrConfig_WriteMappings_ADDR (0x00406080)

#define swrConfig_ControlToString_ADDR (0x00407b00)

#define swrConfig_SetDefaultVideo_ADDR (0x00408820)

#define swrConfig_WriteVideoConfig_ADDR (0x00408880)
#define swrConfig_ReadVideoConfig_ADDR (0x00408b60)

#define swrConfig_AssignForceValues_ADDR (0x0040a680)

#define swrConfig_SetDefaultForce_ADDR (0x0040ab60)

#define swrConfig_WriteForceFeedbackConfig_ADDR (0x0040ab80)
#define swrConfig_ReadForceFeedbackConfig_ADDR (0x0040ae40)

#define swrConfig_WriteAudioConfig_ADDR (0x00422140)
#define swrConfig_ReadAudioConfig_ADDR (0x00422440)

#define swrConfig_Puts_ADDR (0x004879a0)
#define swrConfig_Printf_ADDR (0x004879f0)

// Settings-menu UI: Build* constructs the page widgets (called from swrUI_BuildMenuPages),
// Refresh* syncs those widgets from the current config globals.
#define swrConfig_BuildVideoMenu_ADDR (0x0040e6a0)
#define swrConfig_RefreshVideoMenu_ADDR (0x0040bbf0)
#define swrConfig_BuildAudioMenu_ADDR (0x0040ea70)
#define swrConfig_RefreshAudioMenu_ADDR (0x0040bc80)
#define swrConfig_BuildForceFeedbackMenu_ADDR (0x0040ef40)
#define swrConfig_RefreshForceFeedbackMenu_ADDR (0x0040c100)

// Input-mapping screens (joystick/mouse/keyboard rebinding); RefreshMappingMenu populates the
// binding rows for device 0=joystick/1=mouse/2=keyboard via swrConfig_SetMappingRowText.
#define swrConfig_BuildJoystickMenu_ADDR (0x0040c7a0)
#define swrConfig_BuildMouseMenu_ADDR (0x0040d2c0)
#define swrConfig_BuildKeyboardMenu_ADDR (0x0040dd10)
#define swrConfig_RefreshMappingMenu_ADDR (0x0040b740)
#define swrConfig_RefreshConfigListMenu_Maybe_ADDR (0x0040c260)
#define swrConfig_RefreshPlayerListMenu_Maybe_ADDR (0x0040c4e0)
#define swrConfig_SetMappingRowText_ADDR (0x0040c670)

int swrConfig_WriteMappings(char* dirname);

void swrConfig_ControlToString(unsigned int controlId, char* pDest);

void swrConfig_SetDefaultVideo(void);

int swrConfig_WriteVideoConfig(char* dirname);
int swrConfig_ReadVideoConfig(char* config_type);

void swrConfig_AssignForceValues(void);

void swrConfig_SetDefaultForce(void);

int swrConfig_WriteForceFeedbackConfig(char* filename);
int swrConfig_ReadForceFeedbackConfig(char* config_type);

int swrConfig_WriteAudioConfig(char* dirname);
int swrConfig_ReadAudioConfig(char* dirname);

size_t swrConfig_Puts(char* string);
size_t swrConfig_Printf(char* format, ...);

void swrConfig_BuildVideoMenu(swrUI_unk* page);
void swrConfig_RefreshVideoMenu(swrUI_unk* page);
void swrConfig_BuildAudioMenu(swrUI_unk* page);
void swrConfig_RefreshAudioMenu(swrUI_unk* page);
void swrConfig_BuildForceFeedbackMenu(swrUI_unk* page);
void swrConfig_RefreshForceFeedbackMenu(swrUI_unk* page);

// Refreshes the config-file selection list, enumerating config and wheel-map files (best guess).
void swrConfig_RefreshConfigListMenu_Maybe(swrUI_unk* page);

// Refreshes the player-profile selection list and sets the Current Player screen text (best guess).
void swrConfig_RefreshPlayerListMenu_Maybe(swrUI_unk* page);

void swrConfig_BuildJoystickMenu(swrUI_unk* page);
void swrConfig_BuildMouseMenu(swrUI_unk* page);
void swrConfig_BuildKeyboardMenu(swrUI_unk* page);
void swrConfig_RefreshMappingMenu(int deviceIndex, swrUI_unk* page);
void swrConfig_SetMappingRowText(int deviceIndex, swrUI_unk* page, int rowId, int control, int param5, int param6, int param7);

#endif // SWRCONFIG_H
