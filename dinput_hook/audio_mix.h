//
// Per-category volume mixer for gameplay sound.
//
// Every gameplay/menu sound funnels through playASoundImpl, which only knows two levels: the SFX
// byte and the music byte. We tag each request with a category (from the bank entry's name, or
// from whichever game function is emitting it) and scale its gain before the original runs.
// Category volumes sit on top of the existing "Sound effects volume"; music is untouched.
//
#pragma once

enum AudioMixCategory {
    AUDIO_MIX_NONE = -1,
    AUDIO_MIX_VOICES,
    AUDIO_MIX_ALERTS,
    AUDIO_MIX_COUNTDOWN,
    AUDIO_MIX_PLAYER_ENGINE,
    AUDIO_MIX_OPPONENT_ENGINES,
    AUDIO_MIX_AMBIENCE,
    AUDIO_MIX_CRASHES,
    AUDIO_MIX_MENU,
    AUDIO_MIX_COUNT,
};

// Registers the playASoundImpl gain hook and the context hooks. Call from init_renderer_hooks(),
// before init_hooks() applies the detours.
void audio_mix_RegisterHooks();

// Read/write the category volumes in SW_RACER_RE.ini [audio_mix].
void audio_mix_LoadSettings();
void audio_mix_SaveSettings();

// Draws one slider per category; returns true if any value changed.
bool audio_mix_DrawSliders();
