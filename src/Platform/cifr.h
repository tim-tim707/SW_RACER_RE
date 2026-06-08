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
#define cifr_LoadProjectFile_ADDR (0x00403f30)
#define cifr_LoadAllEffects_ADDR (0x00403fd0)
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

// Initialize the 6 effect slots and select the force-feedback device.
void cifr_Init(void* effects);

// Load an Immersion .fcr project file and record each effect's name per slot.
int cifr_LoadProjectFile(void* effects, char* projectFile, void* nameIndices, void* nameTable);

// Create and download all of a controller's effects to the device.
int cifr_LoadAllEffects(void* controller);

// Create + download one effect (its DirectInput effect interfaces) to device.
int cifr_CreateEffect(void* effect, void* params, void* device);

// Release one effect's downloaded DirectInput interfaces.
int cifr_ReleaseEffect(void* effect, void* device);

// Start playing an effect (checkPlaying != 0 skips if already playing).
int cifr_StartEffect(void* effect, int checkPlaying);

// Stop an effect.
int cifr_StopEffect(void* effect);

// Return 1 if the effect is currently playing.
int cifr_IsPlaying(void* effect);

// Get / set the effect direction in degrees (0..360).
int cifr_GetDirection(void* effect);
int cifr_SetDirection(void* effect, int degrees, int deferred);

// Get / set the effect magnitude as a percent (0..100).
unsigned int cifr_GetMagnitude(void* effect);
int cifr_SetMagnitude(void* effect, int percent, int deferred);

// Get / set the effect duration in milliseconds (-1 = infinite).
int cifr_GetDuration(void* effect);
int cifr_SetDuration(void* effect, int durationMs, int deferred);

#endif // CIFR_H
