#include "cstdlib.h"

// These are all c standard library functions. No decompilation necessary

// stdio.h

// 0x0049f0f0 DO NOT DECOMPILE
int fclose(FILE* stream) {}

// 0x004a1530 DO NOT DECOMPILE
char* fgets(char* str, int n, FILE* stream) {}

// 0x0049f1e0 DO NOT DECOMPILE
FILE* fopen(const char* filename, const char* mode) {}

// 0x0049ffe0 DO NOT DECOMPILE
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {}

// 0x004a0950 DO NOT DECOMPILE
int fseek(FILE *stream, long int offset, int origin) {}

// 0x0049fbd0 DO NOT DECOMPILE
long int ftell(FILE *stream) {}

// 0x004a0160 DO NOT DECOMPILE
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream) {}

// 0x0049eb80 DO NOT DECOMPILE
int sprintf(char* str, const char* format, ...) {}

// 0x004a10e0 DO NOT DECOMPILE
int vsnprintf(char* s, size_t n, const char* format, va_list arg) {}

// wchar.h

// 0x004a15c0 DO NOT DECOMPILE
wchar_t* fgetws (wchar_t* ws, int num, FILE* stream) {}

