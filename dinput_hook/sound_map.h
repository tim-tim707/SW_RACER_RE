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
