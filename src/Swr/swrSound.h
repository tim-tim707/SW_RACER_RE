#ifndef SWRSOUND_H
#define SWRSOUND_H

#include "types.h"

#define swrSound_Startup_ADDR (0x00421D90)

// Sound resource cache. A "bank" of 0x4c-byte sound descriptors lives at
// PTR_DAT_004b6d34 (count +0x20, capacity +0x24, descriptor array +0x28). Each
// descriptor: name +0x00, index +0x20, flags +0x24, dataSize +0x28, rate +0x2c,
// bits +0x30, channels +0x34, durationMs +0x38, dataOffset +0x3c, source +0x48.
// Audio data is loaded on demand within a byte budget with clock eviction.
#define swrSound_Teardown_ADDR (0x00421eb0)
#define swrSound_LoadSoundMap_ADDR (0x00421f30)
#define swrSound_LoadDefaultBank_ADDR (0x00422060)
#define swrSound_SetDefaultConfig_ADDR (0x004220b0)
#define swrSound_FreeBank_ADDR (0x004226c0)
#define swrSound_AllocBank_ADDR (0x00422770)
#define swrSound_RegisterSound_ADDR (0x004227e0)
#define swrSound_GetEntry_ADDR (0x00422a90)
#define swrSound_LoadSound_ADDR (0x00422ac0)
#define swrSound_UnloadSound_ADDR (0x00422d10)
#define swrSound_UnloadAll_ADDR (0x00422da0)
#define swrSound_AcquireSource_ADDR (0x00422e30)
#define swrSound_LoadIntoSource_ADDR (0x00422f00)
#define swrSound_EvictSounds_ADDR (0x00422f60)

#define swrSound_CreateSourceFromFile_ADDR (0x00423050)

#define swrSound_Find_ADDR (0x004231b0)
#define swrSound_Add_ADDR (0x004231d0)
#define swrSound_Remove_ADDR (0x004231f0)
#define swrSound_CreateThread_ADDR (0x00423210)
#define swrSound_TerminateThread_ADDR (0x004232c0)
#define swrSound_ThreadRoutine_ADDR (0x00423330)
#define swrSound_FillStreamBuffer_ADDR (0x004233a0)
#define swrSound_UpdateStreaming_ADDR (0x004234c0)

#define swrSound_SetPlayEvent_ADDR (0x00423350)

// High-level SFX playback. A (category, id) pair is resolved to a bank index,
// then played 3D-positionally (distance-attenuated) via playASoundImpl.
#define swrSound_PlaySpatialRange_ADDR (0x00426d10)
#define swrSound_PlaySpatial_ADDR (0x00426d80)
#define swrSound_ResolveSfxId_ADDR (0x00427110)
// Throttled one-shot SFX play: a (category, variant) cooldown plus a 3-entry recently-played
// ring guard against retriggering the same sound too often (announcer lines, one-shots).
#define swrSound_IsSfxOnCooldown_ADDR (0x00427360)
#define swrSound_PushRecentSfx_ADDR (0x004273b0)
#define swrSound_WasSfxRecentlyPlayed_ADDR (0x004273e0)
#define swrSound_PlaySfxThrottled_ADDR (0x00427410)
#define swrSound_MarkSfxPlayed_ADDR (0x00427530)
#define swrSound_UpdateEngineAudio_ADDR (0x00427b20)
#define swrSound_PreloadSoundSet_ADDR (0x00427d90)
#define swrSound_PreloadRacerSounds_ADDR (0x00427f10)
#define swrSound_PreloadSfx_ADDR (0x00427fb0)

// Runtime channel mixer: 8 channels (DAT_00e67e40, stride 0x44). swrSound_Update
// is the per-frame tick (acquire/position/play/release each channel + listener).
#define swrSound_ResetChannel_ADDR (0x00449e00)
#define swrSound_RewindChannels_ADDR (0x00449e50)
#define swrSound_ResetChannels_ADDR (0x00449ea0)
#define swrSound_Update_ADDR (0x00449ef0)

#define swrSound_Init_ADDR (0x004848a0)
#define swrSound_Shutdown_ADDR (0x00484a20)
#define swrSound_SetOutputGain_ADDR (0x00484a80)
#define swrSound_NewSource_ADDR (0x00484aa0)
#define swrSound_DuplicateSource_ADDR (0x00484bb0)
#define swrSound_Play_ADDR (0x00484be0)
#define swrSound_SetPanValues_ADDR (0x00484c30)
#define swrSound_SetMainGain_ADDR (0x00484d40)
#define swrSound_SetGain_ADDR (0x00484d90)
#define swrSound_SetPitch_ADDR (0x00484dd0)
#define swrSound_SetMinMaxDistance_ADDR (0x00484df0)
#define swrSound_SetPosition_ADDR (0x00484e10)
#define swrSound_SetVelocityClamped_ADDR (0x00484e40)
#define swrSound_SetVelocity_ADDR (0x00484f10)
#define swrSound_SetTransforms_ADDR (0x00484f40)
#define swrSound_Flush_ADDR (0x00484fa0)
#define swrSound_SetDistanceModelScale_ADDR (0x00484fb0)
#define swrSound_SetRenderMode_ADDR (0x00485020)
#define swrSound_GetRenderMode_ADDR (0x00485040)
#define swrSound_Rewind_ADDR (0x00485070)
#define swrSound_ReleaseSource_ADDR (0x004850a0)
#define swrSound_GetWavePosition_ADDR (0x004850c0)
#define swrSound_WriteLocked_ADDR (0x00485110)
#define swrSound_UnlockSource_ADDR (0x00485170)
#define swrSound_ParseWave_ADDR (0x004851a0)
#define swrSound_GetHardwareFlags_ADDR (0x00485340)

int swrSound_Startup();

// Tear down the sound manager (free bank, stop/terminate the streaming thread,
// free the index). fullShutdown != 0 also releases A3D; == 0 only suspends.
int swrSound_Teardown(int fullShutdown);

// Parse data/sounds.map (NUMSOUNDS / NUMVOICES) and register every listed sound.
int swrSound_LoadSoundMap(void);

// Fallback when sounds.map is absent: register a hardcoded list of wavs.
int swrSound_LoadDefaultBank(void);

// Reset the audio config globals (master/hi-res/doppler/gain/voices) to defaults.
void swrSound_SetDefaultConfig(void);

// Free every descriptor's audio source and the bank array.
void swrSound_FreeBank(void);

// Allocate the descriptor bank for count entries.
int swrSound_AllocBank(int count);

// Register a sound by name: locate its wav, parse the header into a new
// descriptor, and index it. Returns the descriptor; load != 0 also loads audio.
void* swrSound_RegisterSound(char* name, int load);

// Return the descriptor at index (bounds-checked), or NULL.
void* swrSound_GetEntry(int index);

// Load a descriptor's audio into a new A3D source on demand, evicting other
// sounds first if the byte budget would be exceeded.
int swrSound_LoadSound(void* entry);

// Release a descriptor's A3D source and reclaim its bytes (keeps the descriptor).
int swrSound_UnloadSound(void* entry);

// Unload every loaded sound's audio (keeps descriptors) and reset all channels.
void swrSound_UnloadAll(void);

// Ensure the sound is loaded and return a playable A3D source, duplicating it
// for polyphony if the existing source is already playing (under the voice cap).
IA3dSource* swrSound_AcquireSource(void* entry, int context, int* createDedicated);

// Lock the descriptor's source buffer, read its wav data from file, unlock.
int swrSound_LoadIntoSource(stdFile_t file, void* entry);

// Reclaim at least bytesNeeded by unloading idle (non-playing) sounds; returns bytes freed.
unsigned int swrSound_EvictSounds(unsigned int bytesNeeded);

IA3dSource* swrSound_CreateSourceFromFile(char* wave_filename);

char* swrSound_Find(char* filename_wav);
int swrSound_Add(char* data);
int swrSound_Remove(char* name);
int swrSound_CreateThread(void);
int swrSound_TerminateThread(void);
DWORD swrSound_ThreadRoutine(LPVOID lpThreadParameter);
unsigned int swrSound_FillStreamBuffer(void* entry, unsigned int writeCursor, unsigned int nbBytes);

void swrSound_SetPlayEvent(void);

// Streaming pump: refills the active streamed (large) sound's buffer by reading the next
// ~0x15888-byte chunk from its source. Driven by the audio thread / play-event signal.
void swrSound_UpdateStreaming(void);

// Resolve a (category 0..7, id) pair to a bank sound index via per-category
// lookup tables; returns the index or -1.
int swrSound_ResolveSfxId(int category, int variant, int id);

// Throttled one-shot SFX: skip if voices are disabled, the (category, variant) is on
// cooldown, the sound was recently played, or it is already active on a channel; otherwise
// resolve, play (positional via PlaySpatialRange if position != NULL, else playASound), and
// record the play. Guards announcer / one-shot lines against spamming.
void swrSound_PlaySfxThrottled(int category, int variant, int id, rdVector3* position);
// True if (category, variant) is still within its post-play cooldown window.
int swrSound_IsSfxOnCooldown(int category, int variant);
// Push a sound index into the 3-entry recently-played ring buffer; returns the wrap count.
int swrSound_PushRecentSfx(short soundId);
// True if the sound index is currently in the recently-played ring.
int swrSound_WasSfxRecentlyPlayed(int soundId);
// Record the play time/category so later calls can apply the cooldown + recent-played checks.
void swrSound_MarkSfxPlayed(int category, int variant, int soundId, int param4);

// Per-frame engine/surface SFX: select and play loop sounds keyed by speed.
void swrSound_UpdateEngineAudio(int param1, int param2, float* param3);

// Play a sound 3D-positionally: attenuate gain by distance from the listener,
// cull if out of range, then dispatch to playASoundImpl.
void swrSound_PlaySpatial(int soundId, short param2, float param3, float gain, rdVector3* position, int param6, unsigned int flags);

// As swrSound_PlaySpatial, but with explicit min/max audible distances.
void swrSound_PlaySpatialRange(int soundId, short param2, float param3, float gain, rdVector3* position, int param6, unsigned int flags, float minDist, float maxDist);

// Resolve and preload (acquire an A3D source for) a single SFX.
void swrSound_PreloadSfx(int category, int variant, int id);

// Preload every racer's per-pod sound list.
void swrSound_PreloadRacerSounds(void);

// Preload the sound set for a scenario/context.
void swrSound_PreloadSoundSet(int scenario, int param2);

// Reset one channel slot (index -1, default gain/pitch/pan).
void swrSound_ResetChannel(void* channel);

// Rewind every active channel's source.
void swrSound_RewindChannels(void);

// Reset all 8 channels.
void swrSound_ResetChannels(void);

// Per-frame audio tick: drive all 8 channels (acquire/position/doppler/play/
// release) and update the listener transform, then flush.
void swrSound_Update(void);

int swrSound_Init(void);
void swrSound_Shutdown(void);
void swrSound_SetOutputGain(float gain);
IA3dSource* swrSound_NewSource(int mono_stereo, int samplesPerSec, uint32_t param3, int nSizeWaveData, char param5);
unsigned int swrSound_DuplicateSource(IA3dSource* source);
bool swrSound_Play(IA3dSource* source, int loop);
void swrSound_SetPanValues(IA3dSource* source, float f);
void swrSound_SetMainGain(float gain);
void swrSound_SetGain(IA3dSource* source, float gain);
void swrSound_SetPitch(IA3dSource* source, int unused, float pitch);
void swrSound_SetMinMaxDistance(IA3dSource* source, float min, float max);
void swrSound_SetPosition(IA3dSource* source, rdVector3* position);
void swrSound_SetVelocityClamped(IA3dSource* source, rdVector3* v);
void swrSound_SetVelocity(rdVector3* speed);
void swrSound_SetTransforms(rdVector3* position, rdVector3* orientation1, rdVector3* orientation2);
void swrSound_Flush(void);
void swrSound_SetDistanceModelScale(IA3dSource* source, float scale);
void swrSound_SetRenderMode(IA3dSource* source, DWORD renderMode);
int swrSound_GetRenderMode(IA3dSource* source);
int swrSound_Rewind(IA3dSource* source);
void swrSound_ReleaseSource(IA3dSource* source);
int swrSound_GetWavePosition(IA3dSource* source, DWORD* out_pos);
void* swrSound_WriteLocked(IA3dSource* source, int nbBytes, int* firstBlockLen);
bool swrSound_UnlockSource(IA3dSource* source, LPVOID unk, DWORD unk2);
int swrSound_ParseWave(stdFile_t file, int* out_param2, int* out_param3, unsigned int* out_param4, char* out_dataOffset);
unsigned int swrSound_GetHardwareFlags(void);

#endif // SWRSOUND_H
