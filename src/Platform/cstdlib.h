#ifndef CSTDLIB_H
#define CSTDLIB_H

/*
 * The game statically links against a C standard library, and this is found
 * in the decompilation. Compiling against the dynamically linked msvcrt to get
 * the C standard library conflicts with this statically linked version, and
 * there is a crash.
 *
 * This header provides implementations of these c standard library functions
 * to be used within the decompilation. These will then hook into the provided
 * C standard library inside the compiled game.
 *
 * There is no intention to decompile these functions.
 */

#include <stdio.h>

// stdio.h
#define fclose_ADDR (0x0049f0f0)
#define fclose c_fclose
int fclose(FILE* stream);

#define fgets_ADDR (0x004a1530)
#define fgets c_fgets
char* fgets(char* str, int n, FILE* stream);

#define fopen_ADDR (0x0049f1e0)
#define fopen c_fopen
FILE* fopen(const char* filename, const char* mode);

#define fread_ADDR (0x0049ffe0)
#define fread c_fread
size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream);

#define fseek_ADDR (0x004a0950)
#define fseek c_fseek
int fseek(FILE *stream, long int offset, int origin);

#define ftell_ADDR (0x0049fbd0)
#define ftell c_ftell
long int ftell(FILE *stream);

#define fwrite_ADDR (0x004a0160)
#define fwrite c_fwrite
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream);

#define sprintf_ADDR (0x0049eb80)
#define sprintf c_sprintf
int sprintf(char* str, const char* format, ...);

#define vsnprintf_ADDR (0x004a10e0)
#define vsnprintf c_vsnprintf
int vsnprintf(char* s, size_t n, const char* format, va_list arg);

// wchar.h
#define fgetws_ADDR (0x004a15c0)
wchar_t* fgetws (wchar_t* ws, int num, FILE* stream);

#endif // CSTDLIB_H
