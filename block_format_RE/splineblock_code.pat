// Same as splineblock.pat but from the in-game parsing code perspective

#pragma endian big

#include "std/mem.pat"

// #pragma pattern_limit 0x100000

u32 splineCount @ 0x00;

struct SplinePoint {
    s16 next_count;
    s16 previous_count;
    s16 next1;
    s16 next2;
    s16 previous1;
    s16 previous2;
    s16 unkC;
    s16 unkE;
    float pX;
    float pY;
    float pZ;
    float rX;
    float rY;
    float rZ;
    float handle1X;
    float handle1Y;
    float handle1Z;
    float handle2X;
    float handle2Y;
    float handle2Z;
    s16 point_num0;
    s16 point_num1;
    s16 point_num2;
    s16 point_num3;
    s16 point_num4;
    s16 point_num5;
    s16 point_num6;
    s16 point_num7;
    s16 point_num8;
    s16 point_unk;
};

struct SplineHeader {
    u32 unk;
    s32 point_count;
    u32 segment_count;
    u32 unkC;
    u8 unk10[16];
    SplinePoint splinePoints[point_count];
};

struct SplineHeaderPtr {
    SplineHeader* ptr: u32 [[inline]];
};

SplineHeaderPtr splinesAddresses[splineCount] @ 0x04;
