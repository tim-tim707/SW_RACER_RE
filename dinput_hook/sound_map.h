// Sound bank indices by name.
//
// The game's sound ids are 0-based positions in data/Sounds.map counting only active entries
// (comment lines, blanks and NUM* directives are skipped) -- podloop1.wav is 144, DroidLoop1.wav
// 152. A manifest names a sound rather than guessing the number.
#pragma once

#include <string>

// "podloop1" or "podloop1.wav", case-insensitive -> bank index; -1 if the map has no such entry.
int sound_map_IndexOf(const std::string &name);

// The name at a bank index, or "" -- for logging what a table entry means.
std::string sound_map_NameOf(int index);

// A wav from the content store, appended to the game's sound bank; returns its bank index, or -1.
// The game finds a sound by a name under data/wavs/, so the blob is hard-linked (copied if the
// volume refuses) as data/wavs/Music/cs_<24 hex of the hash>.wav -- the same blob is one entry
// however many tracks name it. Only valid once the sound system is up (menus onward); the bank
// gets its headroom from swrSound_AllocBank_delta.
int sound_map_RegisterCustom(const std::string &sha256, const std::string &label);
