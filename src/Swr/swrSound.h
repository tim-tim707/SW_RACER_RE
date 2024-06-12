#ifndef SWRSOUND_H
#define SWRSOUND_H

#include "types.h"

#define swrSound_Startup_ADDR (0x00421D90)

#define swrSound_CreateSourceFromFile_ADDR (0x00423050)

#define swrSound_Find_ADDR (0x004231b0)
#define swrSound_Add_ADDR (0x004231d0)
#define swrSound_Remove_ADDR (0x004231f0)
#define swrSound_CreateThread_ADDR (0x00423210)
#define swrSound_TerminateThread_ADDR (0x004232c0)
#define swrSound_ThreadRoutine_ADDR (0x00423330)

#define swrSound_SetPlayEvent_ADDR (0x00423350)

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

IA3dSource* swrSound_CreateSourceFromFile(char* wave_filename);

char* swrSound_Find(char* filename_wav);
int swrSound_Add(char* data);
int swrSound_Remove(char* name);
int swrSound_CreateThread(void);
int swrSound_TerminateThread(void);
DWORD swrSound_ThreadRoutine(LPVOID lpThreadParameter);

void swrSound_SetPlayEvent(void);

int swrSound_Init(void);
void swrSound_Shutdown(void);
void swrSound_SetOutputGain(float gain);
IA3dSource* swrSound_NewSource(int mono_stereo, int samplesPerSec, uint32_t param3, int nSizeWaveData, char param5);
unsigned int swrSound_DuplicateSource(IA3dSource* source);
bool swrSound_Play(IA3dSource* source);
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
int swrSound_GetWavePosition(IA3dSource* source);
void* swrSound_WriteLocked(IA3dSource* source, int nbBytes, int* firstBlockLen);
bool swrSound_UnlockSource(IA3dSource* source, LPVOID unk, DWORD unk2);
int swrSound_ParseWave(stdFile_t file, int* out_param2, int* out_param3, unsigned int* out_param4, char* out_dataOffset);
unsigned int swrSound_GetHardwareFlags(void);

#endif // SWRSOUND_H
