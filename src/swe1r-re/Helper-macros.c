#include <stdint.h>

// 0x4a646765 = MAGIC('J', 'd', 'g', 'e')
// 0x54657374 = MAGIC('T', 'e', 's', 't')
// 0x456c6d6f = MAGIC('E', 'l', 'm', 'o')
// 0x54726967 = MAGIC('T', 'r', 'i', 'g')
// 0x4c6f636c = MAGIC('L', 'o', 'c', 'l')
// 0x41414949 = MAGIC('A', 'A', 'I', 'I')
// 0x48697474 = MAGIC('H', 'i', 't', 't')
// 0x426f746d = MAGIC('B', 'o', 't', 'm')
// 0x416c6c21 = MAGIC('A', 'l', 'l', '!')
// 0x634d616e = MAGIC('c', 'M', 'a', 'n')
// 0x48616e67 = MAGIC('H', 'a', 'n', 'g')
// 0x546f7373 = MAGIC('T', 'o', 's', 's')
// 0x536d6f6b = MAGIC('S', 'm', 'o', 'k')
// 0x43687372 = MAGIC('C', 'h', 's', 'r')
// 0x46726565 = MAGIC('F', 'r', 'e', 'e')
// 0x416c6f63 = MAGIC('A', 'l', 'o', 'c')
// 0x46726565 = MAGIC('S', 'n', 'a', 'p')
// 0x734c4f44 = MAGIC('s', 'L', 'O', 'D')
// 0x56684c74 = MAGIC('V', 'h', 'L', 't')
// 0x5370726b = MAGIC('S', 'p', 'r', 'k')
// 0x6c6f7374 = MAGIC('l', 'o', 's', 't')
// 0x72656a6e = MAGIC('r', 'e', 'j', 'n')
// 0x70727879 = MAGIC('p', 'r', 'x', 'y')
// 0x6374726c = MAGIC('c', 't', 'r', 'l')
// 0x68656c6c = MAGIC('h', 'e', 'l', 'l') // lava
// 0x666c616d = MAGIC('f', 'l', 'a', 'm')
// 0x7461756e = MAGIC('t', 'a', 'u', 'n')
// 0x74726967 = MAGIC('t', 'r', 'i', 'g') // !! Not Trig with a capital T
// 0x71756974 = MAGIC('q', 'u', 'i', 't')
// 0x706c6170 = MAGIC('p', 'l', 'a', 'p')
// 0x52454d4f = MAGIC('R', 'E', 'M', 'O')
// 0x46696e69 = MAGIC('F', 'i', 'n', 'i')
// 0x66696e69 = MAGIC('f','i', 'n', 'i')
// 0x51657279 = MAGIC('Q', 'e', 'r', 'y')
// 0x4c6f6164 = MAGIC('L', 'o', 'a', 'd')
// 0x4c744674 = MAGIC('L', 't', 'F', 't')
// 0x52744674 = MAGIC('R', 't', 'F', 't')
// 0x4b506f77 = MAGIC('K', 'P', 'o', 'w')
// 0x4c745364 = MAGIC('L', 't', 'S', 'd')
// 0x52745364 = MAGIC('R', 't', 'S', 'd')
// 0x52536574 = MAGIC('R', 'S', 'e', 't')
// 0x41627274 = MAGIC('A', 'b', 'r', 't')
#define MAGIC(a1, a2, a3, a4) (((a1) << 24) | ((a2) << 16) | ((a3) << 8) | (a4))

#define ASSERT(condition, message, path, line)                                                                         \
    if (!(condition))                                                                                                  \
    {                                                                                                                  \
        dword_ECC420->unk6((message), (path), (line));                                                                 \
    }

static uint16_t swap16(uint16_t v)
{
    return (v >> 8) | (v << 8);
}

static uint16_t *swap16(uint16_t *v, uint32_t count)
{
    uint32_t i = 0;
    for (; i < count; i++)
    {
        v[i] = swap16(v[i]);
    }
    return &v[i]; // FIXME: Might be off by one
}

static uint32_t swap32(uint32_t v)
{
    return ((v & 0xFF0000 | (v >> 16)) >> 8) | (((v << 16) | v & 0xFF00) << 8);
}

// Ghidra version
static uint32_t swap32(uint32_t v)
{
    return (v & 0xff00 | v << 0x10) << 8 | (v >> 0x10 | v & 0xff0000) >> 8;
}

// Another Ghidra version also decompiled
static uint32_t swap32(uint32_t v)
{
    return (v & 0xff00 | v << 0x10) << 8 | (v & 0xff0000 | v >> 0x10) >> 8;
}

// // Ghidra version: char = 1 byte
// static uint16_t CONCAT11(char a, char b)
// {
//     return (a << 8 | b);
// }

// // Ghidra version: short = 2 bytes
// static uint32_t CONCAT22(short a, short b)
// {
//     return (a << 16 | b);
// }

static uint32_t *swap32(uint32_t *v, uint32_t count)
{
    uint32_t i = 0;
    for (; i < count; i++)
    {
        v[i] = swap32(v[i]);
    }
    return &v[i]; // FIXME: Might be off by one
}

// Ghidra: 4.656613e-10

// Returns a random float in range [0.0, 1.0]
// `(double)sub_4816B0() * 4.6566129e-10 * 64.0 - -64.0`
// would become `frand() * 64.0 + 64.0`
static float frand()
{
    // _frand_max()
    return (float)sub_4816B0() * (1.0f / (float)0x7FFFFFFF); // int_max
}

// Returns a random float in range [a, b]
// `(double)sub_4816B0() * 4.6566129e-10 * 64.0 - -64.0`
// would become `frand(64.0, 128.0)`
static float frand(float a, float b)
{
    return frand() * (b - a) + a;
}

// Clamps a value in range [a, b]
// `if ( v44 < 0 ) { v44 = 0; }   if ( v44 > 255 ) { v44 = 255; }`
// would become `v44 = clamp(v44, 0, 255);`
static clamp(x, a, b)
{
    if (x < a)
    {
        x = a;
    }
    if (b < x)
    {
        x = b;
    }
    return x;
}

#define CLAMP(x, _min, _max)                                                                                           \
    if (_max < x)                                                                                                      \
    {                                                                                                                  \
        x = _max;                                                                                                      \
    }                                                                                                                  \
    if (x < _min)                                                                                                      \
    {                                                                                                                  \
        x = _min;                                                                                                      \
    }

#define SET_CLAMP(x, _min, _max, value)                                                                                \
    if (value < _min)                                                                                                  \
    {                                                                                                                  \
        x = _min;                                                                                                      \
    }                                                                                                                  \
    else if (_max < value)                                                                                             \
    {                                                                                                                  \
        x = _max;                                                                                                      \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        x = value;                                                                                                     \
    }

#define MAX(x, _max)                                                                                                   \
    if (x < _max)                                                                                                      \
    {                                                                                                                  \
        x = _max;                                                                                                      \
    }

#define MIN(x, _min)                                                                                                   \
    if (_min < x)                                                                                                      \
    {                                                                                                                  \
        x = _min;                                                                                                      \
    }

// Thanks to MerryMage for identifiying this function.
// Also see http://bits.stephan-brumme.com/inverse.html
static float fast_inverse(float a)
{
    uint32_t x = 0x7F000000 - *(uint32_t *)&a;
    return *(float *)&x;
}

// Thanks to wwylele for identifiying this function.
// Also see
// https://en.wikipedia.org/wiki/Newton%27s_method#Multiplicative_inverses_of_numbers_and_power_series
static float inverse(float a)
{
    float x_0 = fast_inverse(a);
    return x_0 * (2.0f - a * x_0);
}

static float frndint(float x)
{
    // FIXME: This should instead use the x86 FPU `frndint` instruction.
    //        The current implementation is *wrong*.
    //        Consider this a stub
    return roundf(x);
}

static uintptr_t align_up(uintptr_t address, uintptr_t alignment)
{
    // Slightly modified to allow non-POT alignments
    // Originally implemented as `return (address + (alignment - 1)) &
    // ~(alignment - 1);`
    return address + (alignment - address) % alignment;
}

// counter is the variable since we cannot initialize it locally (pre c99)
// We should note that value may not be a byte nor n be a byte count (size of
// pointers)
// WARNING ! Mind the *buffer and not buffer !
#define MEMSET(counter, buffer, value, n)                                                                              \
    for (counter = n; counter != 0; counter = counter + -1)                                                            \
    {                                                                                                                  \
        *buffer = value;                                                                                               \
        buffer = buffer + 1;                                                                                           \
    }

// WARNING ! Mind the *destination = *source and not destination = source !
#define QMEMCPY(counter, source, destination, n)                                                                       \
    for (counter = n; counter != 0; counter = counter + -1)                                                            \
    {                                                                                                                  \
        *destination = *source;                                                                                        \
        source = source + 1;                                                                                           \
        destination = destination + 1;                                                                                 \
    }

// These are inlined
static int strcmp()
{} // TODO
static int strcpy()
{} // TODO
static int strlen()
{} // TODO
