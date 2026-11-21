#include "swr.h"

#include "macros.h"
#include "globals.h"
#include "engine_config.h"
#include "Swr/swrSound.h"

// 0x00426910
void swr_noop2(void)
{
    return;
}

// 0x00426A00
void swrSound_RequestVoice(int soundId, short priority, float pitch, float volume, short pan, int positional, int trackPosition, int* position)
{
    swrSound* voice;
    float fade;
    float gain;
    int slot;
    int lowest;
    int i;

    if (positional != 0) {
        fade = 1.0f - (float)(uint8_t)swrSprite_unk1_a * SWR_SOUND_VOLUME_SCALE;
    } else {
        fade = 1.0f;
    }
    // the music volume is a short; only its low byte is the slider value
    volume = (float)(swrSound_UsesMusicVolume(soundId) != 0 ? *(uint8_t*)&sound_music_volume : sound_sfx_volume) * SWR_SOUND_VOLUME_SCALE * volume;
    if (swrSound_UsesMusicVolume(soundId) != 0) {
        priority = SWR_SOUND_LOOPING_PRIORITY;
    }
    gain = fade * volume;
    if (gain == 0.0f) {
        return;
    }
    gain = gain * SWR_SOUND_GAIN_SCALE;
    if ((swrRace_saveData.unlockFlags & swrSaveData_OPTION_STEREO) == 0 && pan != SWR_SOUND_PAN_POSITIONAL) {
        pan = SWR_SOUND_PAN_CENTER;
    }
    if (soundId < 0) {
        return;
    }

    if (positional != 0) {
        for (i = 0; i < SWR_SOUND_NUM_VOICES; i++) {
            voice = &swrSound_voicesRequested[i];
            if (voice->unk08 != 0 && voice->id == soundId) {
                // a louder request of the same sound already started this frame wins
                if ((float)voice->volume > gain && voice->startFrame == frametotal) {
                    return;
                }
                voice->pitch = pitch + pitch;
                voice->volume = (int)gain;
                voice->pan = pan;
                voice->priority = priority;
                voice->startFrame = frametotal;
                voice->pos = *(rdVector3*)position;
                voice->maxDist = swrSound_spatialMaxDist;
                voice->minDist = swrSound_spatialMinDist;
                return;
            }
        }
    }

    slot = -1;
    for (i = 0; i < SWR_SOUND_NUM_VOICES; i++) {
        if (swrSound_voicesRequested[i].activeSoundId == -1 && slot == -1) {
            slot = i;
        }
    }
    if (slot == -1) {
        lowest = priority;
        for (i = 0; i < SWR_SOUND_NUM_VOICES; i++) {
            if (swrSound_voicesRequested[i].priority < lowest) {
                lowest = swrSound_voicesRequested[i].priority;
                slot = i;
            }
        }
        if (slot == -1) {
            return;
        }
    }
    voice = &swrSound_voicesRequested[slot];
    voice->id = soundId;
    voice->activeSoundId = -2;
    voice->unk08 = positional;
    voice->startFrame = frametotal;
    voice->priority = priority;
    voice->pitch = pitch + pitch;
    voice->volume = (int)gain;
    voice->pan = pan;
    // position is an rdVector3 passed as int*; the EXE copies the raw dwords
    voice->pos = *(rdVector3*)position;
    voice->trackedPos = trackPosition != 0 ? (rdVector3*)position : NULL;
    voice->maxDist = swrSound_spatialMaxDist;
    voice->minDist = swrSound_spatialMinDist;
}

// 0x00426C80
void swrSound_Play2D(int a0, short a1, float a2, float a3, int a4)
{
    if (0.0f < a3)
        swrSound_RequestVoice(a0, a1, a2, a3, 0x40, a4, 0, (int*)&rdVector_sound_pos);
}

// 0x00426CC0
void swrSound_Play2DMinVolume(int a1, short a2, float a3, float a4, int a5)
{
    if (a4 < 1.0f)
        a4 = 1.0f;
    swrSound_RequestVoice(a1, a2, a3, a4, 0x40, a5, 0, (int*)&rdVector_sound_pos);
}

// 0x004270c0
void swr_noop4(void)
{
    if (swrSound_unk_init != 0)
        swr_noop1();
}

// 0x00482E50
void swr_noop1(void)
{
    return;
}

// 0x00483ba0
void swr_noop3(void)
{
    swr_noop1();
}
