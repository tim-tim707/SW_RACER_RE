#include "swrSound.h"

#include "types.h"
#include "globals.h"

#include <macros.h>

#include <General/stdHashTable.h>
#include <Platform/a3d.h>
#include <Win95/Window.h>

#include <stdio.h> // sprintf

#include <string.h>

// 0x00421D90
int swrSound_Startup()
{
    HANG("TODO");
}

// Load a sound effect: open data\wavs\{22K|11K}\<wave_filename>, parse its WAVE
// header, allocate a matching IA3dSource and stream the PCM data into it.
// Returns the ready-to-play source, or NULL on any failure.
//
// Two latent bugs in the original are fixed here (see policy note): on a parse
// failure it read an uninitialised stack slot as `source` and could release a
// garbage pointer, and on a WriteLocked failure it returned without closing the
// file. This version keeps `source` NULL until it is really created and always
// closes the file on the cleanup path.
// 0x00423050
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

// Look up a sound descriptor by wav filename in the sound-name hashtable.
// 0x004231b0
char* swrSound_Find(char* filename_wav)
{
    return (char*)stdHashtbl_Find(swrSoundHashTable, filename_wav);
}

// Register a sound descriptor in the hashtable, keyed by (and storing) `data`.
// 0x004231d0
int swrSound_Add(char* data)
{
    return stdHashtbl_Add(swrSoundHashTable, data, data);
}

// Remove a sound descriptor from the hashtable by name.
// 0x004231f0
int swrSound_Remove(char* name)
{
    return stdHashtbl_Remove(swrSoundHashTable, name);
}

// Spin up the background streaming thread: allocate the streaming IA3dSource
// (22050 Hz, 16-bit, stereo, 0x2b110-byte double buffer), create the buffer-
// position event, register the play events, start swrSound_ThreadRoutine, then
// mark the thread running and charge the buffer against the loaded-bytes budget.
// 0x00423210
int swrSound_CreateThread(void)
{
    swrSoundStream_bufferSize = 0x2b110;
    swrSoundStream_file = 0;
    swrSoundStream_bytesRemaining = 0;
    swrSoundStream_entry = NULL;
    swrSoundStream_loop = 0;
    iA3DSource_ptr = swrSound_NewSource(1, 0x5622, 0x10, 0x2b110, '\x04');
    ia3dSourceEventHandle2 = CreateEventA(NULL, FALSE, FALSE, NULL);
    swrSound_SetPlayEvent();
    ia3dSourceThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)swrSound_ThreadRoutine, NULL, 0, &ia3dSourceThreadId);
    ia3dSourceEventHandle = CreateEventA(NULL, FALSE, FALSE, NULL);
    ia3d_thread_running = 1;
    swrSound_loadedBytes += swrSoundStream_bufferSize;
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

// Register the streaming source's playback-position events so A3D signals
// ia3dSourceEventHandle2 when playback crosses the buffer midpoint and the end,
// waking the thread to refill the half that just finished.
// 0x00423350
void swrSound_SetPlayEvent(void)
{
    IA3dSource* source = iA3DSource_ptr;
    DWORD positions[2];
    int i;

    positions[0] = swrSoundStream_bufferSize >> 1;
    positions[1] = swrSoundStream_bufferSize - 1;
    for (i = 0; i < 2; i++)
        (*source->lpVtbl->SetPlayEvent)(source, positions[i], ia3dSourceEventHandle2);
}

// 0x00423330
DWORD swrSound_ThreadRoutine(LPVOID lpThreadParameter)
{
    do
    {
        WaitForSingleObject(ia3dSourceEventHandle2, 0xffffffff);
        EnterCriticalSection((LPCRITICAL_SECTION)&swrSound_criticalSection);
        swrSound_UpdateStreaming();
        LeaveCriticalSection((LPCRITICAL_SECTION)&swrSound_criticalSection);
    } while (true);
}

// Refill `nbBytes` of the streaming source's buffer at `writeCursor` from the
// open stream file. Zeroes the target region first, reads min(bytesRemaining,
// nbBytes) bytes; if that hit the end of the current chunk and looping is on,
// rewinds to the chunk's data offset, resets the remaining count and reads the
// rest. Returns the bytes consumed from the current chunk (0 on any failure).
// 0x004233a0
unsigned int swrSound_FillStreamBuffer(void* entry, unsigned int writeCursor, unsigned int nbBytes)
{
    HostServices* hs = stdPlatform_hostServices_ptr;
    IA3dSource* source = iA3DSource_ptr;
    void* buffer = NULL;
    DWORD lockedLen = 0;
    unsigned int nRead;
    HRESULT hr;

    if (entry == NULL)
        return 0;
    if (swrSoundStream_bytesRemaining == 0)
        return 0;

    if ((*source->lpVtbl->Lock)(source, writeCursor, nbBytes, &buffer, &lockedLen, NULL, NULL, 0) < 0)
        return 0;

    nRead = (unsigned int)swrSoundStream_bytesRemaining;
    if (nbBytes < nRead)
        nRead = nbBytes; // min(bytesRemaining, nbBytes)

    memset(buffer, 0, nbBytes);
    hs->fileRead(swrSoundStream_file, buffer, nRead);

    // Wrap to the start of the chunk when the read came up short and looping.
    if (nRead < nbBytes && swrSoundStream_loop != 0)
    {
        hs->fseek(swrSoundStream_file, *(int*)((char*)entry + 0x3c), 0);
        swrSoundStream_bytesRemaining = *(int*)((char*)entry + 0x28);
        hs->fileRead(swrSoundStream_file, (char*)buffer + nRead, nbBytes - nRead);
    }

    hr = (*source->lpVtbl->Unlock)(source, buffer, lockedLen, NULL, 0);
    if (hr < 0)
        hr = (*source->lpVtbl->Unlock)(source, buffer, lockedLen, NULL, 0); // retry once

    return (hr < 0) ? 0 : nRead;
}

// Streaming pump, run under the audio thread's critical section. If a sound is
// streaming: prime the chunk byte count (rewinding when looping), then refill
// whichever half of the double buffer is not currently being played.
// 0x004234c0
void swrSound_UpdateStreaming(void)
{
    HostServices* hs = stdPlatform_hostServices_ptr;
    IA3dSource* source;
    DWORD wavePos;
    unsigned int filled;

    if (swrSoundStream_entry == NULL)
        return;

    if (swrSoundStream_bytesRemaining == 0)
    {
        if (swrSoundStream_loop == 0)
            return;
        hs->fseek(swrSoundStream_file, *(int*)((char*)swrSoundStream_entry + 0x3c), 0);
        swrSoundStream_bytesRemaining = *(int*)((char*)swrSoundStream_entry + 0x28);
    }

    source = iA3DSource_ptr;
    // Parenthesised so the <assert.h> macro does not hijack the hostServices member.
    if (iA3DSource_ptr == NULL)
        (hs->assert)("pBuffer", "D:\\devel.QA5\\pc_gnome\\SpecPlat\\rdroid_gnome\\Source\\elfSound.c", 0x6ee);

    (*source->lpVtbl->GetWavePosition)(source, &wavePos);
    filled = swrSound_FillStreamBuffer(swrSoundStream_entry, (wavePos < 0x15888) ? 0x15888 : 0, 0x15888);
    swrSoundStream_bytesRemaining -= filled;
}

// Bring up the Aureal A3D engine: CoCreate the IA3d4 device, read its hardware
// caps, bind it to the game window, configure the coordinate system / fallback
// sources / output gain, then (when 3D is available) acquire the IA3dListener
// and set the world scale, distance-model and doppler scales. Returns 1 once the
// device is usable (even if the optional 3D listener could not be obtained), or
// 0 if the device itself could not be created.
// 0x004848a0
int swrSound_Init(void)
{
    HRESULT hr;
    HWND hwnd;

    if (IA3d4_ptr != NULL)
        return 0;

    a3d_CoInitialize();
    hr = a3d_CoCreateInstance(NULL, &IA3d4_ptr, NULL, 0x80);
    if (hr < 0 || IA3d4_ptr == NULL)
    {
        Sound_A3Dinitted = 0;
        Sound_enabled_3d = 0;
        if (hr < 0)
        {
            IA3d4_ptr = NULL;
            return 0;
        }
    }
    else
    {
        Sound_enabled_3d = 1;
    }

    a3dCaps_hardware.dwSize = 0x24;
    (*IA3d4_ptr->lpVtbl->GetHardwareCaps)(IA3d4_ptr, &a3dCaps_hardware);
    Sound_HardwareDetected = a3dCaps_hardware.dwFlags & 0x28;
    Sound_FirstReflexionsSupport = a3dCaps_hardware.dwFlags & 2;

    hwnd = Window_GetHWND();
    if ((*IA3d4_ptr->lpVtbl->SetCooperativeLevel)(IA3d4_ptr, hwnd, 1) < 0)
    {
        (*IA3d4_ptr->lpVtbl->Release)(IA3d4_ptr);
        IA3d4_ptr = NULL;
        return 0;
    }

    (*IA3d4_ptr->lpVtbl->SetCoordinateSystem)(IA3d4_ptr, 0);
    (*IA3d4_ptr->lpVtbl->SetNumFallbackSources)(IA3d4_ptr, 8);
    (*IA3d4_ptr->lpVtbl->GetOutputGain)(IA3d4_ptr, &a3dOutputGain);
    swrSound_SetOutputGain(Main_sound_gain_const);

    if (Sound_enabled_3d != 0)
    {
        if ((*IA3d4_ptr->lpVtbl->QueryInterface)(IA3d4_ptr, &IID_IA3dListener_GUID, (void**)&IA3dListener_ptr) < 0)
        {
            Sound_A3Dinitted = 0;
            Sound_enabled_3d = 0;
            IA3dListener_ptr = NULL;
            return 1;
        }
        (*IA3d4_ptr->lpVtbl->SetUnitsPerMeter)(IA3d4_ptr, 3.28f);
        (*IA3d4_ptr->lpVtbl->SetDistanceModelScale)(IA3d4_ptr, Main_sound_rolloff);
        (*IA3d4_ptr->lpVtbl->SetDopplerScale)(IA3d4_ptr, Main_sound_doppler_scale);
    }
    return 1;
}

// Tear down the A3D engine: release the optional geometry interface (always
// NULL in this game) and the listener, release the IA3d4 device, clear the
// interface pointers and uninitialise COM.
// 0x00484a20
void swrSound_Shutdown(void)
{
    if (IA3d4_ptr == NULL)
        return;

    // IA3dGeom_ptr (0x50d564) is never instantiated by the game, so this branch
    // is dead in practice; kept for faithfulness. It is typed IA3dListener* as a
    // stand-in -- only the shared IUnknown::Release slot is used here.
    if (IA3dGeom_ptr != NULL)
        (*IA3dGeom_ptr->lpVtbl->Release)(IA3dGeom_ptr);
    if (IA3dListener_ptr != NULL)
        (*IA3dListener_ptr->lpVtbl->Release)(IA3dListener_ptr);
    (*IA3d4_ptr->lpVtbl->Release)(IA3d4_ptr);

    IA3dGeom_ptr = NULL;
    IA3dListener_ptr = NULL;
    IA3d4_ptr = NULL;
    CoUninitialize();
}

// 0x00484a80
void swrSound_SetOutputGain(float gain)
{
    if (IA3d4_ptr != NULL)
    {
        (*IA3d4_ptr->lpVtbl->SetOutputGain)(IA3d4_ptr, gain);
    }
}

// Allocate and configure an empty IA3dSource holding nSizeWaveData bytes of PCM.
// Builds a WAVE_FORMAT_PCM WAVEFORMATEX from the format params, creates the
// source through the A3D engine, forces the native render mode when 3D output
// is unavailable, sets the format and allocates the audio buffer. Returns the
// source, or NULL on any failure (releasing a partially-created source).
//   mono_stereo = 0 for mono, non-zero for stereo
//   param3      = bits per sample
//   param5      = extra A3D source-creation flags (bit 2 is forwarded)
// 0x00484aa0
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

// Start playback of a source. The loop flag is forced on when the source's
// type reports bit 2 (an inherently looping source); otherwise the caller's
// `loop` argument is used. Returns true if Play succeeded.
// 0x00484be0
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

// Query a source's render mode. Returns the render-mode bitmask, or -1 if the
// COM call leaves it untouched (the value is pre-seeded with -1).
// 0x00485040
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

// Report a source's play status: -1 on error or NULL source, 0 if the source
// is not currently playing, 1 if it is. When out_pos is non-NULL and the source
// is playing, the current wave (sample) position is also written into it.
// 0x004850c0
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

// Parse a RIFF/WAVE (PCM) header read through the host-services file vtable.
// On success returns the byte count of the "data" chunk and leaves `file`
// positioned at the first PCM sample; on any magic mismatch returns 0.
//   out_param2     = sample rate in Hz
//   out_param3     = bits per sample
//   out_param4     = 1 if stereo, 0 if mono
//   out_dataOffset = file offset (bytes) where the PCM data begins
// 0x004851a0
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

// Maps a (category, variant, id) sfx request to a loaded sound's handle. The per-category remap
// table only validates the id (a negative entry -> no such sfx); the actual ".wav" filename is
// built from the category prefix (+ a variant prefix for categories 0-1) and the raw id, tried
// first plain then with an "a" suffix. Returns the sound's handle (swrSound_Find result +0x20)
// or -1 if unknown / not loaded.
// 0x00427110
int swrSound_ResolveSfxId(int category, int variant, int id)
{
    if (!swrSound_Initted || id == -1)
        return -1;

    int16_t remapped;
    switch (category) {
    case 0:
        if (variant < 0 || 0x16 < variant || id < 1 || 0x32 < (unsigned int) id)
            return -1;
        remapped = swrSound_sfxRemap0[id];
        break;
    case 1:
        if (variant < 0 || 0x16 < variant || id < 1 || 0x25 < (unsigned int) id)
            return -1;
        remapped = swrSound_sfxRemap1[id];
        break;
    case 2:
        if (id < 1 || 0x38 < (unsigned int) id)
            return -1;
        remapped = swrSound_sfxRemap2[id];
        break;
    case 3:
        if (id < 1 || 4 < (unsigned int) id)
            return -1;
        remapped = swrSound_sfxRemap3[id];
        break;
    case 4:
        if (id < 1 || 0x67 < (unsigned int) id)
            return -1;
        remapped = swrSound_sfxRemap4[id];
        break;
    case 5:
        if (id < 1 || 0xa8 < (unsigned int) id)
            return -1;
        remapped = swrSound_sfxRemap5[id];
        break;
    case 6:
        if (id < 1 || 0x68 < (unsigned int) id)
            return -1;
        remapped = swrSound_sfxRemap6[id];
        break;
    case 7:
        if (id < 1 || 0xa7 < (unsigned int) id)
            return -1;
        remapped = swrSound_sfxRemap7[id];
        break;
    default:
        return -1;
    }

    if (remapped < 0)
        return -1;

    const char* categoryPrefix = swrSound_sfxCategoryPrefixes[category];
    char name[64];
    char* found;
    if (category < 2) {
        const char* variantPrefix = swrSound_sfxVariantPrefixes[variant];
        sprintf(name, "%s%s%.3i.wav", variantPrefix, categoryPrefix, id);
        found = swrSound_Find(name);
        if (found == NULL) {
            sprintf(name, "%s%s%.3ia.wav", variantPrefix, categoryPrefix, id);
            found = swrSound_Find(name);
        }
    } else {
        sprintf(name, "%s%.3i.wav", categoryPrefix, id);
        found = swrSound_Find(name);
        if (found == NULL) {
            sprintf(name, "%s%.3ia.wav", categoryPrefix, id);
            found = swrSound_Find(name);
        }
    }

    if (found != NULL)
        return *(int*) (found + 0x20);
    return -1;
}

// True while the per-category (or per-variant, for categories 0-1) sfx cooldown timer is still
// counting down. Throttles repeated one-shot sfx.
// 0x00427360
int swrSound_IsSfxOnCooldown(int category, int variant)
{
    if (category < 0 || 1 < category) {
        if (0.0f < swrSound_sfxCategoryCooldown[category])
            return 1;
    } else if (0.0f < swrSound_sfxVariantCooldown[variant]) {
        return 1;
    }
    return 0;
}

// Records a sound id in the 3-entry recent-sfx ring; returns nonzero when the write wraps.
// 0x004273b0
int swrSound_PushRecentSfx(short soundId)
{
    swrSound_recentSfxRing[swrSound_recentSfxWriteIndex] = soundId;
    int next = swrSound_recentSfxWriteIndex + 1;
    swrSound_recentSfxWriteIndex = (short) (next % 3);
    return next / 3;
}

// 0x004273e0
int swrSound_WasSfxRecentlyPlayed(int soundId)
{
    for (int i = 0; i < 3; i++) {
        if (swrSound_recentSfxRing[i] == soundId)
            return 1;
    }
    return 0;
}

// 0x00427670
unsigned int swrSound_TestSfxFlag(int index, unsigned int mask)
{
    return swrSound_sfxFlags[index] & mask;
}

// 0x00427690
void swrSound_SetSfxFlag(int index, unsigned int mask)
{
    swrSound_sfxFlags[index] |= mask;
}

// 0x004276a0
void swrSound_ClearSfxFlag(int index, unsigned int mask)
{
    swrSound_sfxFlags[index] &= ~mask;
}

// 0x00427ad0
unsigned int swrSound_SelectPlanetIntroMusic(unsigned int planet)
{
    HANG("TODO");
}
