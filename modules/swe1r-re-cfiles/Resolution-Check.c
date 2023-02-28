// EnumDisplayModes callback
// a1 is the display mode being enumerated
// a2 is the user pointer
signed int __stdcall sub_488F50(const DDSURFACEDESC2 *a1, void *a2)
{
    unsigned int v7; // ebx
    unsigned int v10; // ebx
    unsigned int v13; // ebx

    // We can't handle more than 64 display modes
    if (dword_52D44C >= 64)
    {
        return 0;
    }

    if (dword_52D45C == 1)
    {
        // Check TV resolutions?!
        bool isGood = false;
        isGood |= (a1->dwWidth == 512 && a1->dwHeight == 384);
        isGood |= (a1->dwWidth == 640 && a1->dwHeight == 480);
        isGood |= (a1->dwWidth == 800 && a1->dwHeight == 600);
        if (!isGood)
        {
            return 1;
        }
    }
}
else
{
    // Check PC resolutions?!
    bool isGood = false;
    isGood |= (a1->dwWidth == 512 && a1->dwHeight == 384);
    isGood |= (a1->dwWidth == 640 && a1->dwHeight == 480);
    isGood |= (a1->dwWidth == 800 && a1->dwHeight == 600);
    isGood |= (a1->dwWidth == 1024 && a1->dwHeight == 768);
    isGood |= (a1->dwWidth == 1152 && a1->dwHeight == 864);
    isGood |= (a1->dwWidth == 1280 && a1->dwHeight == 1024);
    isGood |= (a1->dwWidth == 1600 && a1->dwHeight == 1200);
    if (!isGood)
    {
        return 1;
    }
}

// Get entry in our displaymode array we want to modify
struct
{
    uint32_t aspectRatio; // 0
    uint32_t width; // 1
    uint32_t height; // 2
    uint32_t byteCount; // 3
    uint32_t pitch; // 4
    uint32_t pitchInPixels; // 5
    uint32_t isRGB; // 6 FIXME: turn this into enum class or something: Palette
                    // = 0, RGB = 1
    uint32_t bitPerPixel; // 7
    uint32_t unk8;
    uint32_t unk9;
    uint32_t unk10;
    uint32_t unk11;
    uint32_t unk12;
    uint32_t unk13;
    uint32_t unk14;
    uint32_t unk15;
    uint32_t unk16;
    uint32_t unk17;
    uint32_t unk18;
    uint32_t unk19;
} *v4 = &dword_5295F8[20 * dword_52D44C];

// Copy resolution
v4->width = a1->dwWidth;
v4->height = a1->dwHeight;

// What is this shit? Some weird aspect ratio stuff?
// The actual aspect ratio would be different..
if ((v4->width == 320 && v4->height == 200)
    || (v4->height == 640 && v4->height == 400))
{
    v4->aspectRatio = 0.75f; // [1 / (4:3)]
}
else
{
    v4->aspectRatio = 1.0f; // [1 / (1:1)]
}

v4->pitch = a1->lPitch;

if (a1->ddpfPixelFormat.dwFlags & DDPF_PALETTEINDEXED8)
{
    v4->isRGB = 0;
    v4->bitsPerPixel = 8;
    v4->unk8 = 0;
    v4->unk9 = 0;
    v4->unk10 = 0;
}
else if (a1->ddpfPixelFormat.dwFlags & DDPF_RGB)
{
    v4->isRGB = 1;
    v4->bitsPerPixel = a1->ddpfPixelFormat.dwRGBBitCount;

    // Red bits?
    v7 = a1->ddpfPixelFormat.dwRBitMask;
    for (int i = 0; !(v7 & 1); ++i)
    {
        v7 >>= 1;
    }
    v4->unk11 = i;
    v4->unk14 = sub_484880(0xFFu / (a1->ddpfPixelFormat.dwRBitMask >> i));
    for (int j = 0; v7 & 1; ++j)
    {
        v7 >>= 1;
    }
    v4->unk8 = j;

    // Green bits?
    v10 = a1->ddpfPixelFormat.dwGBitMask;
    for (int k = 0; !(v10 & 1); ++k)
    {
        v10 >>= 1;
    }
    v4->unk12 = k;
    v4->unk15 = sub_484880(0xFFu / (a1->ddpfPixelFormat.dwGBitMask >> k));
    for (int l = 0; v10 & 1; ++l)
    {
        v10 >>= 1;
    }
    v4->unk9 = l;

    // Blue bits?
    v13 = a1->ddpfPixelFormat.dwRBitMask;
    for (int m = 0; !(v13 & 1); ++m)
    {
        v13 >>= 1;
    }
    v4->unk13 = m;
    v4->unk16 = sub_484880(0xFFu / (ddpfPixelFormat.dwRBitMask >> m));
    for (int n = 0; v13 & 1; ++n)
    {
        v13 >>= 1;
    }
    v4->unk10 = n;
}

// Get bytes per pixel
switch (v4->bitPerPixel)
{
case 8:
    v4->pitchInPixels = v4->pitch;
    break;
case 16:
    v4->pitchInPixels = v4->pitch / 2;
    break;
case 24:
    v4->pitchInPixels = v4->pitch / 3;
    break;
case 32:
    v4->pitchInPixels = v4->pitch / 4;
    break;
default:
    break;
}
int pixelCount = v4->width * v4->height;
v4->byteCount = pixelCount * (v4->bitPerPixel / 8);
if (dword_EC8D80 >= (unsigned int)(2 * (v4->byteCount + pixelCount)))
{
    dword_52D44C++;
}
return 1;
}
