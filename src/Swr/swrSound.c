#include "swrSound.h"

#include "types.h"
#include "globals.h"

#include <macros.h>

#include <string.h>

// 0x00421D90
int swrSound_Startup()
{
    HANG("TODO");
}

// 0x00423050
// Load a sound effect: open data\wavs\{22K|11K}\<wave_filename>, parse its WAVE
// header, allocate a matching IA3dSource and stream the PCM data into it.
// Returns the ready-to-play source, or NULL on any failure.
//
// Two latent bugs in the original are fixed here (see policy note): on a parse
// failure it read an uninitialised stack slot as `source` and could release a
// garbage pointer, and on a WriteLocked failure it returned without closing the
// file. This version keeps `source` NULL until it is really created and always
// closes the file on the cleanup path.
IA3dSource* swrSound_CreateSourceFromFile(char* wave_filename)
{
    HostServices* hs = stdPlatform_hostServices_ptr;
    const char* dir;
    char path[128];
    stdFile_t file;
    int samplesPerSec;
    uint32_t bitsPerSample;
    unsigned int isStereo;
    int dataOffset;
    int nSizeWaveData;
    IA3dSource* source = NULL;
    int firstBlockLen;
    void* buffer;
    size_t bytesRead;

    if (wave_filename == NULL)
        return NULL;

    dir = Main_hiRes_sound ? ".\\data\\wavs\\22K" : ".\\data\\wavs\\11K";
    sprintf(path, "%s%c%s", dir, '\\', wave_filename);

    file = (stdFile_t)hs->fileOpen(path, "rb");
    if (file == 0)
        return NULL;

    nSizeWaveData = swrSound_ParseWave(file, &samplesPerSec, (int*)&bitsPerSample, &isStereo, (char*)&dataOffset);
    if (nSizeWaveData != 0)
    {
        source = swrSound_NewSource(isStereo, samplesPerSec, bitsPerSample, nSizeWaveData, '\0');
        if (source != NULL)
        {
            // ParseWave left the file positioned at the first PCM sample.
            buffer = swrSound_WriteLocked(source, nSizeWaveData, &firstBlockLen);
            if (buffer != NULL)
            {
                bytesRead = hs->fileRead(file, buffer, firstBlockLen);
                if (swrSound_UnlockSource(source, buffer, bytesRead))
                {
                    hs->fileClose(file);
                    return source;
                }
            }
        }
    }

    hs->fileClose(file);
    if (source != NULL)
        swrSound_ReleaseSource(source);
    return NULL;
}

// 0x004231b0
char* swrSound_Find(char* filename_wav)
{
    HANG("TODO");
}

// 0x004231d0
int swrSound_Add(char* data)
{
    HANG("TODO");
}

// 0x004231f0
int swrSound_Remove(char* name)
{
    HANG("TODO");
}

// 0x00423210
int swrSound_CreateThread(void)
{
    HANG("TODO");
    return 1;
}

// 0x004232c0
int swrSound_TerminateThread(void)
{
    CloseHandle(ia3dSourceEventHandle2);
    ia3dSourceEventHandle2 = NULL;
    swrSound_ReleaseSource(iA3DSource_ptr);
    iA3DSource_ptr = NULL;
    if (ia3dSourceEventHandle != NULL)
    {
        CloseHandle(ia3dSourceEventHandle);
    }
    ia3dSourceEventHandle = NULL;
    TerminateThread(ia3dSourceThreadHandle, 0);
    ia3dSourceThreadHandle = NULL;
    ia3d_thread_running = 0;

    return 1;
}

// 0x00423350
void swrSound_SetPlayEvent(void)
{
    HANG("TODO, easy");
}

// 0x00423330
DWORD swrSound_ThreadRoutine(LPVOID lpThreadParameter)
{
    do
    {
        WaitForSingleObject(ia3dSourceEventHandle2, 0xffffffff);
        EnterCriticalSection((LPCRITICAL_SECTION)&swrSound_criticalSection);
        HANG("TODO");
        // FUN_004234c0();
        LeaveCriticalSection((LPCRITICAL_SECTION)&swrSound_criticalSection);
    } while (true);
}

// 0x004234c0
// TODO

// 0x004848a0
int swrSound_Init(void)
{
    HANG("TODO");
    return 0;
}

// 0x00484a20
void swrSound_Shutdown(void)
{
    HANG("TODO");
}

// 0x00484a80
void swrSound_SetOutputGain(float gain)
{
    if (IA3d4_ptr != NULL)
    {
        (*IA3d4_ptr->lpVtbl->SetOutputGain)(IA3d4_ptr, gain);
    }
}

// 0x00484aa0
// Allocate and configure an empty IA3dSource holding nSizeWaveData bytes of PCM.
// Builds a WAVE_FORMAT_PCM WAVEFORMATEX from the format params, creates the
// source through the A3D engine, forces the native render mode when 3D output
// is unavailable, sets the format and allocates the audio buffer. Returns the
// source, or NULL on any failure (releasing a partially-created source).
//   mono_stereo = 0 for mono, non-zero for stereo
//   param3      = bits per sample
//   param5      = extra A3D source-creation flags (bit 2 is forwarded)
IA3dSource* swrSound_NewSource(int mono_stereo, int samplesPerSec, uint32_t param3, int nSizeWaveData, char param5)
{
    IA3dSource* source = NULL;
    DWORD flags;
    struct
    {
        uint16_t wFormatTag;
        uint16_t nChannels;
        uint32_t nSamplesPerSec;
        uint32_t nAvgBytesPerSec;
        uint16_t nBlockAlign;
        uint16_t wBitsPerSample;
        uint16_t cbSize;
    } format; // WAVE_FORMAT_PCM WAVEFORMATEX

    if (IA3d4_ptr == NULL)
        return NULL;

    flags = (mono_stereo != 0);
    if ((param5 & 4) != 0)
        flags |= 4;

    if ((*IA3d4_ptr->lpVtbl->NewSource)(IA3d4_ptr, flags, &source) < 0)
        goto fail;

    // When 3D output is unavailable, force the native (2D) render mode.
    if (Sound_enabled_3d == 0)
    {
        if ((*source->lpVtbl->SetRenderMode)(source, 0x20) < 0)
            goto fail;
    }

    format.wFormatTag = 1; // WAVE_FORMAT_PCM
    format.nChannels = 1 + (mono_stereo != 0);
    format.nSamplesPerSec = samplesPerSec;
    format.nBlockAlign = (format.nChannels * param3) / 8;
    format.nAvgBytesPerSec = format.nBlockAlign * samplesPerSec;
    format.wBitsPerSample = param3;
    format.cbSize = 0;

    if ((*source->lpVtbl->SetAudioFormat)(source, &format) < 0)
        goto fail;
    if ((*source->lpVtbl->AllocateAudioData)(source, nSizeWaveData) < 0)
        goto fail;

    return source;

fail:
    if (source != NULL)
        (*source->lpVtbl->Release)(source);
    return NULL;
}

// 0x00484bb0
unsigned int swrSound_DuplicateSource(IA3dSource* source)
{
    if (IA3d4_ptr == NULL)
    {
        return 0;
    }

    HRESULT res = (*IA3d4_ptr->lpVtbl->DuplicateSource)(IA3d4_ptr, source, &source);
    return (unsigned int)source & ((res < 0) - 1);
}

// 0x00484be0
// Start playback of a source. The loop flag is forced on when the source's
// type reports bit 2 (an inherently looping source); otherwise the caller's
// `loop` argument is used. Returns true if Play succeeded.
bool swrSound_Play(IA3dSource* source, int loop)
{
    DWORD type;

    if (source == NULL)
        return false;

    (*source->lpVtbl->GetType)(source, &type);
    if ((type & 4) != 0)
        loop = 1;
    return (*source->lpVtbl->Play)(source, loop != 0) >= 0;
}

// 0x00484c30
void swrSound_SetPanValues(IA3dSource* source, float f)
{
    float channels[2];

    if (IA3d4_ptr != NULL)
    {
        channels[0] = 1.0 - f;
        channels[1] = f - -1.0;
        if (channels[0] <= 1.0)
        {
            if (1.0 < channels[1])
            {
                channels[0] = channels[0] / channels[1];
                channels[1] = 1.0;
            }
        }
        else
        {
            channels[1] = channels[1] / channels[0];
            channels[0] = 1.0;
        }
        if (channels[0] < -1.0)
        {
            channels[0] = -1.0;
        }
        else if (1.0 < channels[0])
        {
            channels[0] = 1.0;
        }
        if (channels[1] < -1.0)
        {
            channels[1] = -1.0;
        }
        else if (1.0 < channels[1])
        {
            channels[1] = 1.0;
        }
        (*source->lpVtbl->SetPanValues)(source, 2, channels);
    }
}

// 0x00484d40
void swrSound_SetMainGain(float gain)
{
    if (gain < 0.0)
    {
        Main_sound_gain = 0.0;
        return;
    }
    if (gain <= 10.0)
    {
        Main_sound_gain = gain;
        return;
    }
    Main_sound_gain = 10.0;
}

// 0x00484d90
void swrSound_SetGain(IA3dSource* source, float gain)
{
    unsigned int renderMode;

    if (IA3d4_ptr != NULL)
    {
        renderMode = swrSound_GetRenderMode(source);
        if ((renderMode & 0x20) != 0)
        {
            gain = gain * Main_sound_gain_adjust;
        }
        (*source->lpVtbl->SetGain)(source, gain);
    }
}

// 0x00484dd0
void swrSound_SetPitch(IA3dSource* source, int unused, float pitch)
{
    (void)unused;

    if (IA3d4_ptr != NULL)
    {
        (*source->lpVtbl->SetPitch)(source, pitch);
    }
}

// 0x00484df0
void swrSound_SetMinMaxDistance(IA3dSource* source, float min, float max)
{
    (*source->lpVtbl->SetMinMaxDistance)(source, min, max, 1);
}

// 0x00484e10
void swrSound_SetPosition(IA3dSource* source, rdVector3* position)
{
    (*source->lpVtbl->SetPosition3f)(source, position->x, position->z, -position->y);
}

// 0x00484e40
void swrSound_SetVelocityClamped(IA3dSource* source, rdVector3* v)
{
    A3DVAL x;
    float y;
    A3DVAL z;

    if (v->x < -340.0)
    {
        x = -340.0;
    }
    else if (340.0 < v->x)
    {
        x = 340.0;
    }
    else
    {
        x = v->x;
    }
    v->x = x;
    if (v->y < -10.0)
    {
        y = -10.0;
    }
    else if (10.0 < v->y)
    {
        y = 10.0;
    }
    else
    {
        y = v->y;
    }
    v->y = y;
    if (v->z < -340.0)
    {
        z = -340.0;
    }
    else if (340.0 < v->z)
    {
        z = 340.0;
    }
    else
    {
        z = v->z;
    }
    v->z = z;
    (*source->lpVtbl->SetVelocity3f)(source, x, z, -y);
}

// 0x00484f10
void swrSound_SetVelocity(rdVector3* speed)
{
    if (IA3dListener_ptr != NULL)
    {
        (*IA3dListener_ptr->lpVtbl->SetVelocity3f)(IA3dListener_ptr, speed->x, speed->z, -speed->y);
    }
}

// 0x00484f40
void swrSound_SetTransforms(rdVector3* position, rdVector3* orientation1, rdVector3* orientation2)
{
    if (IA3dListener_ptr != NULL)
    {
        (*IA3dListener_ptr->lpVtbl->SetPosition3f)(IA3dListener_ptr, position->x, position->z, -position->y);
        (*IA3dListener_ptr->lpVtbl->SetOrientation6f)(IA3dListener_ptr, orientation1->x, orientation1->z, -orientation1->y, orientation2->x, orientation2->z, -orientation2->y);
    }
}

// 0x00484fa0
void swrSound_Flush(void)
{
    if (IA3d4_ptr != NULL)
    {
        (*IA3d4_ptr->lpVtbl->Flush)(IA3d4_ptr);
    }
}

// 0x00484fb0
void swrSound_SetDistanceModelScale(IA3dSource* source, float scale)
{
    if ((IA3d4_ptr != NULL) && (source != NULL))
    {
        if (scale < 0.0)
        {
            scale = 0.0;
        }
        else if (10.0 < scale)
        {
            (*source->lpVtbl->SetDistanceModelScale)(source, 10.0);
            return;
        }
        (*source->lpVtbl->SetDistanceModelScale)(source, scale);
    }
}

// 0x00485020
void swrSound_SetRenderMode(IA3dSource* source, DWORD renderMode)
{
    (*source->lpVtbl->SetRenderMode)(source, renderMode);
}

// 0x00485040
// Query a source's render mode. Returns the render-mode bitmask, or -1 if the
// COM call leaves it untouched (the value is pre-seeded with -1).
int swrSound_GetRenderMode(IA3dSource* source)
{
    DWORD renderMode = -1;
    (*source->lpVtbl->GetRenderMode)(source, &renderMode);
    return renderMode;
}

// 0x00485070
int swrSound_Rewind(IA3dSource* source)
{
    if (IA3d4_ptr == NULL)
    {
        return 0;
    }
    (*source->lpVtbl->Stop)(source);
    (*source->lpVtbl->Rewind)(source);
    return 1;
}

// 0x004850a0
void swrSound_ReleaseSource(IA3dSource* source)
{
    if (IA3d4_ptr != NULL)
    {
        (*source->lpVtbl->Release)(source);
    }
    return;
}

// 0x004850c0
// Report a source's play status: -1 on error or NULL source, 0 if the source
// is not currently playing, 1 if it is. When out_pos is non-NULL and the source
// is playing, the current wave (sample) position is also written into it.
int swrSound_GetWavePosition(IA3dSource* source, DWORD* out_pos)
{
    DWORD status;

    if (source == NULL)
        return -1;
    if ((*source->lpVtbl->GetStatus)(source, &status) < 0)
        return -1;
    if ((status & 1) == 0)
        return 0;
    if (out_pos != NULL)
        (*source->lpVtbl->GetWavePosition)(source, out_pos);
    return 1;
}

// 0x00485110
void* swrSound_WriteLocked(IA3dSource* source, int nbBytes, int* firstBlockLen)
{
    // this calls a wrapper function that calls IDirectSoundBuffer::Lock
    // See https://learn.microsoft.com/en-us/previous-versions/windows/desktop/mt708932(v=vs.85)
    // Wrapper is here: https://github.com/RazorbladeByte/A3D-Live-/blob/88071a0ca7bc981c8aa7d3aa9e7d72186c634c10/a3d_dll.cpp#L2542
    //
    // There are two audio pointers returned as the audio buffer is circular
    // so its possible the audio wraps around. This never occurs in the execution
    // of this game, so generally the last two parameters can be ignored
    //
    // Parameters are:
    // This (as this is a C++ object)
    // dwWriteCursor offset of the start of the audio block < INPUT
    // dwWriteBytes How much of the audio buffer to lock < INPUT
    // lplpvAudioPtr1 pointer to the first part of the writable audio buffer < OUTPUT
    // lpwdAudioBytes1 length of this first buffer to write to < OUTPUT
    // lplpvAudioPtr2  pointer to the second part of the writable audio buffer < OUTPUT
    // lpdwAudioBytes2 length of the second buffer to write to < OUTPUT
    // dwFlags flags, none are set on this call

    // the decompilation does very strange things with the function call
    // as the values of the second pointers are always zero or nothing, the
    // compiler inserted firstBlockLen and source in those slots, rather than
    // make two new local variables. This causes a segmentation fault when
    // building a debug build, as those values are actually getting set
    // so instead, pass in two dummy values instead, as these values are never
    // going to be used

    void* outBlock = NULL;
    unsigned long secondBlockLen = 0; // dummy value for second parameter
    void* secondOutBlock = NULL; // dummy value for second out parameter
    if ((*source->lpVtbl->Lock)(source, 0, nbBytes, &outBlock, (unsigned long*)firstBlockLen, &secondOutBlock, &secondBlockLen, 0) == 0)
    {
        if (outBlock == NULL)
            return NULL;
        if (nbBytes == *firstBlockLen)
            return outBlock;
    }
    if (firstBlockLen != NULL)
        swrSound_UnlockSource(source, outBlock, nbBytes);

    return NULL;
}

// 0x00485170
bool swrSound_UnlockSource(IA3dSource* source, LPVOID unk, DWORD unk2)
{
    return (*source->lpVtbl->Unlock)(source, unk, unk2, NULL, 0) == 0;
}

// 0x004851a0
// Parse a RIFF/WAVE (PCM) header read through the host-services file vtable.
// On success returns the byte count of the "data" chunk and leaves `file`
// positioned at the first PCM sample; on any magic mismatch returns 0.
//   out_param2     = sample rate in Hz
//   out_param3     = bits per sample
//   out_param4     = 1 if stereo, 0 if mono
//   out_dataOffset = file offset (bytes) where the PCM data begins
int swrSound_ParseWave(stdFile_t file, int* out_param2, int* out_param3, unsigned int* out_param4, char* out_dataOffset)
{
    HostServices* hs = stdPlatform_hostServices_ptr;
    char magic[4];
    uint32_t chunkSize;
    struct
    {
        uint16_t wFormatTag;
        uint16_t nChannels;
        uint32_t nSamplesPerSec;
        uint32_t nAvgBytesPerSec;
        uint16_t nBlockAlign;
        uint16_t wBitsPerSample;
    } fmt; // 16-byte PCMWAVEFORMAT

    // "RIFF" <riffSize> "WAVE"
    hs->fileRead(file, magic, 4);
    if (memcmp(magic, "RIFF", 4) != 0)
        return 0;
    hs->fseek(file, 4, 1); // skip the RIFF chunk size

    hs->fileRead(file, magic, 4);
    if (memcmp(magic, "WAVE", 4) != 0)
        return 0;
    hs->fseek(file, 4, 1); // skip the "fmt " sub-chunk id

    // fmt sub-chunk: size followed by the 16-byte PCMWAVEFORMAT
    hs->fileRead(file, &chunkSize, 4);
    hs->fileRead(file, &fmt, 0x10);

    *out_param2 = fmt.nSamplesPerSec;                     // sample rate
    *out_param3 = (fmt.nBlockAlign / fmt.nChannels) << 3; // bits per sample
    *out_param4 = (fmt.nChannels == 2);                   // 1 = stereo, 0 = mono

    if (chunkSize > 0x10)
        hs->fseek(file, chunkSize - 0x10, 1); // skip any extended fmt bytes

    // Walk the remaining sub-chunks until the "data" chunk is reached.
    hs->fileRead(file, magic, 4);
    while (memcmp(magic, "data", 4) != 0)
    {
        hs->fileRead(file, &chunkSize, 4);
        // Faithful to the original: it advances chunkSize + 4 here. The extra 4
        // is a quirk of the shipped code and is never exercised in practice
        // because the game's WAVs place the "data" chunk right after "fmt ".
        hs->fseek(file, chunkSize + 4, 1);
        hs->fileRead(file, magic, 4);
    }

    hs->fileRead(file, &chunkSize, 4);            // data chunk size
    *(uint32_t*)out_dataOffset = hs->ftell(file); // PCM start offset
    return chunkSize;
}

// 0x00485340
unsigned int swrSound_GetHardwareFlags(void)
{
    return Sound_A3Dinitted ? a3dCaps_hardware.dwFlags : 0;
}
