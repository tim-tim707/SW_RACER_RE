#pragma once

#include <cstdint>

// A small multi-voice mixer for looping custom sounds, streamed through winmm waveOut beside the
// game's own audio. Used for Sebulba's film engine loop and for giving AI pods the player-style
// geared engine loops (with Doppler).
//
// Game-thread code (re)asserts each voice every physics tick with the volume / playback rate /
// pan it wants; the mixer thread glides every voice toward those values smoothly (linear-
// interpolated resampling for the pitch) and sums them. A voice the game stops asserting
// (paused, menus, race over, pod gone) fades out by itself after a moment and is dropped.

// Load a 16-bit PCM WAV (mono or stereo, any rate) by path RELATIVE TO THE GAME EXE's folder,
// e.g. "data\\wavs\\22K\\sfx_pod_maw_slow_loop.wav". Cached; returns a sound id, or -1.
int custom_sound_load(const char* rel_path);

// Assert voice `key` this tick: play sound `sound` looping at gain 0..1, rate (1 = original
// pitch), pan -1..+1. The key identifies the voice across ticks (e.g. pod pointer + layer).
void custom_sound_voice(uint64_t key, int sound, float gain, float rate, float pan);

// Sebulba's film loop (sounds\sebulba_engine_loop.wav): the single voice used by audio_mix.
void custom_engine_sound_set(float gain, float rate, float pan);

// True once the output opened.
bool custom_engine_sound_available();

// Last load/open problem, for the settings panel ("" if none).
const char* custom_engine_sound_status();
