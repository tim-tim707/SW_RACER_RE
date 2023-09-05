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

#endif // TYPES_ENUMS_H
