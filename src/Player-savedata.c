# Savedata format

## tgfd.dat file

What a mess.. this mirrors the current profile file, so they can desync too.
Also since this keeps track of the freeplay stuff, that can also desync with the current profile.

```C
// This data follows the 4 byte magic in data/player/tgfd.dat)
// They come from 0xE364A0 in memory
typedef struct {
  uint8_t race_unlocked[4]; // 0xC 1 bit per course starting at LSb: unlocks race for freeplay
  uint8_t podracer_unlocked[4]; // 0x10 1 bit per podracer ??? for freeplay
  Savedata profiles[4]; // 0x14 4 profiles, but the first profile seems to be the one used for most things

  // This keeps track of the best times.
  // Out of the 100 entries, there seem to be always group of times.
  //
  // Starting at index 0: 3 laps
  // Starting at index 50: 1 lap [best lap]
  //
  // The mapping from track select screen to times is not yet known
  // 
  // Element 0 is the boonta training course [3 laps].
  // Element 50 the boonta training course [best lap]
  // Element 88 is abyss [best lap]
  //
  float time_seconds[100]; // 0x154 default value seems to be 3599.9899902344 (0x4560FFD7) which is about an hour
  char time_names[100][32]; // 0x2E4 default value seems to be 0x41 ('A')
  uint8_t time_podracer[100]; // 0xF64 default value seems to be the track favorite

  uint8_t unk[12]; // 0xFC8

  // 4052 bytes
} TGFD;
```

## sav files

Note that this info is typically loaded from tgfd.dat
So if you modify something, you should delete that file first

```C
// This data follows the 4 byte magic in the savegames (from data/player/*.sav)
// They come from 0xE364B4 in memory
typedef struct {
  char profileName[32]; // 0x00, size correct?
  uint8_t unk[4]; // 0x20
  uint8_t last_podracer; // 0x24 value:
                         //   0x01 = Anakin Skywalker ??? Probably 0x00. Teemto somethingsomething seems to be 0x01
                         //   0x09 = Ebe Endocott
                         //   0x0A = Dud Bolt
                         //   0x0B = Gasgano

  uint8_t race_unlocked[5]; // 0x25 1 bit per course starting at LSb: unlocks race
  uint16_t race_status[5]; // 0x2A 2 bit per course starting at LSb: 0=4th (or not finished), 1=3rd, 2=2nd, 3=1st.

  uint8_t podracers_unlocked[4]; // 0x34 1 bit per podracer ???

  uint32_t truguts; // 0x38

  uint8_t unk[4]; // 0x3C

  uint8_t pit_droid_count; // 0x40

  // Parts, in same order as shown in menu (probably)
  uint8_t part_index[7]; // 0x41
  uint8_t part_health[7]; // 0x48

  uint8_t unk; // 0x4F seems to be zero; padding only?

  // 80 bytes
} Savedata;
```

# Write savedata

```C
//----- (004219D0) --------------------------------------------------------
// a1 = profile name (example: "anakin.sav")
// Returns TRUE on sucess
BOOL __cdecl sub_4219D0(int a1) {

  // Copy playerdata which will be written to the savegame
  uint8_t v6[0x50];
  qmemcpy(v6, byte_E364B4, 0x50u);

  //FIXME: Unknown?
  if ( dword_4B6C90 < 0 ) {
    return 0;
  }

  // Generate a string which holds the target path
  char v7[256];
  sprintf(v7, aSS_0, PathName, a1);
  sub_484600(v7, (int)&off_4B4F7C);

  // Open file for writing
  FILE* v3 = fopen(v7, aWb);
  if ( !v3 ) {
    return 0;
  }

  // Declare an error flag
  int32_t v1 = 0;

  // Write version (?) magic
  uint32_t v5 = 0x00010003;
  if ( !sub_4A0160(&v5, 1u, 4u, v3) ) {
    v1 = 1;
  }

  // Write actual data
  if ( !sub_4A0160(v6, 1u, 0x50u, v3) ) {
    v1 = 1;
  }

  // Close file again
  fclose(v3);

  // Return if we had success
  return v1 == 0;
}
```