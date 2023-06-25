#ifndef TYPES_H
#define TYPES_H

#ifdef WIN32
#include <io.h>
#include <winsock2.h>
#include <windows.h>

#endif

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef int8_t i8;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint32_t u32;
typedef int32_t i32;
typedef uintptr_t u32_ptr;
typedef intptr_t i32_ptr;

typedef float f32;
typedef double f64;

#endif // TYPES_H
