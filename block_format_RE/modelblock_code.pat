// Same as modelblock.pat but from the in-game parsing code perspective

struct map {
    u32 begin;
    u32 headerBegin;
    u32 end;
};

struct Header {
    HEADER_STR identifier; // altN, Data, Anim
    u32 unk4;
    u32 unk8;
};

u32 requestedID = 8; // arbitrary, lets say we want #7

map currentMap @ (requestedID * 8 + 4);

u32 size1 = currentMap.headerBegin - currentMap.begin;
u32 size2 = currentMap.end - currentMap.headerBegin;

u8 data1[size1] @ currentMap.begin;
Header header @ currentMap.headerBegin;

if (header.identifier == HEADER_STR::Comp) {
    // TODO
} else {

}

u8 data2[size2] @ currentMap.headerBegin; // not comp

