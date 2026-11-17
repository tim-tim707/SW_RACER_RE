#ifndef CIFR_H
#define CIFR_H

#include "types.h"

// Force-feedback effect wrapper over the Immersion IFORCE / TouchSense SDK
// (the _IF* imports). Effects are authored in an Immersion .fcr project file
// (data/bundle.fcr / bundle2.fcr) and driven as DirectInput effects. An "effect"
// is a ~0x174 byte slot holding up to N DirectInput effect interface pointers;
// the controller owns an array of 6 effect slots. Used by the swrControl force
// feedback layer (swrControl_PlayForceEffect etc.).

#define cifr_Init_ADDR (0x00403e10)
#define cifr_ReinitEffects_Maybe_ADDR (0x00403f00)
#define cifr_LoadProjectFile_ADDR (0x00403f30)
#define cifr_LoadAllEffects_ADDR (0x00403fd0)
#define cifr_ReleaseAllEffects_ADDR (0x00404040)
#define cifr_CreateEffect_ADDR (0x004040a0)
#define cifr_ReleaseEffect_ADDR (0x00404190)
#define cifr_StartEffect_ADDR (0x004041c0)
#define cifr_StopEffect_ADDR (0x00404230)
#define cifr_IsPlaying_ADDR (0x00404280)
#define cifr_GetDirection_ADDR (0x004042f0)
#define cifr_SetDirection_ADDR (0x00404330)
#define cifr_GetMagnitude_ADDR (0x004043d0)
#define cifr_SetMagnitude_ADDR (0x00404400)
#define cifr_GetDuration_ADDR (0x004044a0)
#define cifr_SetDuration_ADDR (0x004044e0)
#define cifr_SetCustomForceData_Maybe_ADDR (0x00404590)
#define cifr_QueryEffectStatus_Maybe_ADDR (0x00404640)
#define cifr_GetForceFeedbackState_Maybe_ADDR (0x00404670)
#define cifr_InitEffectSlot_Maybe_ADDR (0x004046e0)

// Initialize the 6 effect slots and select the force-feedback device.
void cifr_Init(cifr_EffectSet* effects);

// Tears down and reinitializes the controller's force-feedback effect slots when enabled (best guess).
void cifr_ReinitEffects_Maybe(cifr_EffectSet* effects);

// Load an Immersion .fcr project file and give slot i the first effect after slotLastIds[i - 1].
int cifr_LoadProjectFile(cifr_EffectSet* effects, char* projectFile, int* slotLastIds, char** names);

// Create and download all of a controller's effects to the device.
int cifr_LoadAllEffects(cifr_EffectSet* effects);

// Releases every downloaded DirectInput effect across the six slots and counts the successes.
int cifr_ReleaseAllEffects(cifr_EffectSet* effects);

// Create the named project effect's DirectInput interfaces and read back their parameters.
int cifr_CreateEffect(cifr_Effect* effect, char* name, HIFORCEPROJECT project);

// Release one effect's downloaded DirectInput interfaces.
int cifr_ReleaseEffect(cifr_Effect* effect, HIFORCEPROJECT project);

// Start playing an effect (restart == 0 leaves an already-playing effect alone).
int cifr_StartEffect(cifr_Effect* effect, int restart);

// Stop an effect.
int cifr_StopEffect(cifr_Effect* effect);

// Return 1 if the effect is currently playing.
int cifr_IsPlaying(cifr_Effect* effect);

// Get / set the effect direction in degrees (0..360).
// start != 0 downloads with DIEP_START, else DIEP_NORESTART.
int cifr_GetDirection(cifr_Effect* effect);
int cifr_SetDirection(cifr_Effect* effect, int degrees, int start);

// Get / set the effect magnitude as a percent (0..100).
unsigned int cifr_GetMagnitude(cifr_Effect* effect);
int cifr_SetMagnitude(cifr_Effect* effect, int percent, int start);

// Get / set the effect duration in milliseconds (-1 = infinite).
int cifr_GetDuration(cifr_Effect* effect);
int cifr_SetDuration(cifr_Effect* effect, int durationMs, int start);

// Replace the effect's type-specific parameters and download them to its first interface.
int cifr_SetCustomForceData_Maybe(cifr_Effect* effect, unsigned int size, void* data, int start);

// Get the effect GUID of the effect's first interface.
int cifr_QueryEffectStatus_Maybe(cifr_Effect* effect, GUID* outGuid);

// Get the low byte of the effect's DIEFFECTINFOA.dwEffType (DIEFT_*).
int cifr_GetForceFeedbackState_Maybe(cifr_Effect* effect, char* outEffType);

// Reset an effect's DIEFFECT/envelope to defaults and free its type-specific buffer.
void cifr_InitEffectSlot_Maybe(cifr_Effect* effect);

#endif // CIFR_H
