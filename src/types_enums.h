#ifndef TYPES_ENUMS_H
#define TYPES_ENUMS_H

typedef enum rdCameraProjectType
{
    rdCameraProjectType_Ortho = 0,
    rdCameraProjectType_Perspective = 1,
    rdCameraProjectType_PerspMVP = 2
} rdCameraProjectType;

typedef enum swrLoader_TYPE
{
    swrLoader_TYPE_MODEL_BLOCK = 0,
    swrLoader_TYPE_SPRITE_BLOCK = 1,
    swrLoader_TYPE_SPLINE_BLOCK = 2,
    swrLoader_TYPE_TEXTURE_BLOCK = 3
} swrLoader_TYPE;

typedef enum swrRace_STATE
{
    swrRace_STATE_LEGAL = 0,
    swrRace_STATE_SPLASH = 1,
    swrRace_STATE_ENTER_NAME = 2,
    swrRace_STATE_MAIN_MENU = 3,
    swrRace_STATE_JUNKYARD = 4,
    swrRace_STATE_POST_RACE_INFO = 5,
    swrRace_STATE_UNKNOWN = 6,
    swrRace_STATE_WATTO = 7,
    swrRace_STATE_LOOK_AT_VEHICLE = 8,
    swrRace_STATE_SELECT_VEHICLE = 9,
    swrRace_STATE_SELECT_PLANET = 12,
    swrRace_STATE_SELECT_TRACK = 13,
} swrRace_STATE; // from FUN_00454d40

typedef enum swrRace_TRACK
{
    swrRace_TRACK_BOONTA_TRAINING_COURSE = 0,
    swrRace_TRACK_BOONTA_CLASSIC = 1,
    swrRace_TRACK_BEEDOS_WILD_RIDE = 2,
    swrRace_TRACK_HOWLER_GORGE = 3,
    swrRace_TRACK_ANDOBI_MOUNTAIN_RUN = 4,
    swrRace_TRACK_ANDOBI_PRIME_CENTRUM = 5,
    swrRace_TRACK_AQUILARIS_CLASSIC = 6,
    swrRace_TRACK_SUNKEN_CITY = 7,
    swrRace_TRACK_BUMBYS_BREAKERS = 8,
    swrRace_TRACK_SCRAPPERS_RUN = 9,
    swrRace_TRACK_DETHROS_REVENGE = 10,
    swrRace_TRACK_ABYSS = 11,
    swrRace_TRACK_BAROO_COAST = 12,
    swrRace_TRACK_GRABVINE_GATEWAY = 13,
    swrRace_TRACK_FIRE_MOUNTAIN_RALLY = 14,
    swrRace_TRACK_INFERNO = 15,
    swrRace_TRACK_MON_GAZZA_SPEEDWAY = 16,
    swrRace_TRACK_SPICE_MINE_RUN = 17,
    swrRace_TRACK_ZUGGA_CHALLENGE = 18,
    swrRace_TRACK_VENGEANCE = 19,
    swrRace_TRACK_EXECUTIONER = 20,
    swrRace_TRACK_THE_GAUNTLET = 21,
    swrRace_TRACK_MALASTARE_100 = 22,
    swrRace_TRACK_DUG_DERBY = 23,
    swrRace_TRACK_SEBULBAS_LEGACY = 24
} swrRace_TRACK;

#endif // TYPES_ENUMS_H
