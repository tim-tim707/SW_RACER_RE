#include <macros.h>

#include "cstdlib.h"

// These are all c standard library functions. No decompilation necessary.
// The HANG bodies only make each function large enough for its reverse hook; an empty
// body compiles to a lone RET under -O2, which is too small to detour.

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"

// ctype.h
// 0x004a04e0
long c__filelength(int fd)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f440
int c__isctype(int c, int desc)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049fe50
int c_tolower(int c)
{
    HANG("game CRT, reverse-hooked to retail");
}

// math.h
// 0x0049ebf0
void c__fpmath(void)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049ed20
long c__ftol(double f)
{
    HANG("game CRT, reverse-hooked to retail");
}

// stdlib.h
// 0x0049ea60
void c_exit(int status)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049ef90
double c_atof(const char* str)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f040
long c_atol(const char* str)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f0e0
int c_atoi(const char* str)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049fd80
void* c_bsearch(const void* key, const void* base, size_t nmemb, size_t size, int (*compar)(const void*, const void*))
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a8cc0
void* c_calloc(size_t num_elements, size_t element_size)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f200
void c_free(void* ptr)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f270
void* c_malloc(size_t size)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a1380
void* c_realloc(void* ptr, size_t size)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f8c0
void c_qsort(void* base, size_t nmemb, size_t size, int (*compar)(const void*, const void*))
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f820
int c_rand(void)
{
    HANG("game CRT, reverse-hooked to retail");
}

// stdio.h
// 0x004a0c10
void c__amsg_exit(int status, const char* msg)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a0c70
intptr_t c__findfirst(const char* filespec, void* fileinfo)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a0ec0
int c__findclose(intptr_t handle)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a0da0
int c__findnext(intptr_t handle, void* fileinfo)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f850
int c__snprintf(char* buffer, size_t count, char* format, ...)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a05b0
int c__sopen(const char* filename, int oflag, int shflag, int pmode)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a0ef0
time_t c__timet_from_ft(const void* ft)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a10e0
int c__vsnprintf(char* s, size_t n, const char* format, va_list arg)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f0f0
int c_fclose(FILE* stream)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0048c6a0
int c_feof(FILE* stream)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a1530
char* c_fgets(char* str, int n, FILE* stream)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f1e0
FILE* c_fopen(const char* filename, const char* mode)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049ffe0
size_t c_fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a0950
int c_fseek(FILE* stream, long int offset, int origin)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049fbd0
long int c_ftell(FILE* stream)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a0160
size_t c_fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049eb80
int c_sprintf(char* str, const char* format, ...)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a99c0
int c_ungetc(int c, FILE* stream)
{
    HANG("game CRT, reverse-hooked to retail");
}

// string.h
// 0x004ab570
char* c__strdup(const char* strSource)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049ec50
int c__stricmp(const char* string1, const char* string2)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004ab170
size_t c__strncnt(const char* str, size_t count)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004aa280
int c__strnicmp(const char* str1, const char* str2, size_t n)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f4e0
void* c_memcpy(void* dest, const void* src, size_t n)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049fb10
char* c_strchr(const char* str, int c)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a8450
size_t c_strcspn(const char* str1, const char* str2)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049edd0
char* c_strlwr(char* str)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a0fb0
char* c_strncat(char* dest, const char* src, size_t n)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f000
int c_strncmp(const char* str1, const char* str2, size_t n)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049f340
char* c_strncpy(char* dest, const char* src, size_t n)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a1300
char* c_strpbrk(const char* str1, const char* str2)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a0f80
char* c_strrchr(const char* str, int c)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a1340
size_t c_strspn(const char* str1, const char* str2)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049ed50
char* c_strstr(const char* haystack, const char* needle)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a02f0
char* c_strtok(char* str, const char* delim)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004ab5d0
char* c_strupr(char* str)
{
    HANG("game CRT, reverse-hooked to retail");
}

// time.h
// 0x004a8e70
void c__tzset(void)
{
    HANG("game CRT, reverse-hooked to retail");
}

// wchar.h
// 0x004a1170
int c__snwprintf(wchar_t* str, size_t size, const wchar_t* format, ...)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004ab4a0
unsigned char* c__mbschr(unsigned char* str, unsigned int c)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004aa950
size_t c__wcsncnt(const wchar_t* str, size_t count)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a15c0
wchar_t* c_fgetws(wchar_t* ws, int num, FILE* stream)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a95d0
int c_mbtowc(wchar_t* pwc, const char* str, size_t n)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a1150
size_t c_wcslen(const wchar_t* str)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x0049ef50
wchar_t* c_wcsncpy(wchar_t* dest, const wchar_t* src, size_t n)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a1210
wchar_t* c_wcsrchr(const wchar_t* str, wchar_t ch)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a1250
wchar_t* c_wcstok(wchar_t* str, const wchar_t* delim)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004a6aa0
int c_wctomb(char* s, wchar_t wc)
{
    HANG("game CRT, reverse-hooked to retail");
}

// 0x004aa6e0
size_t c_wcstombs(char* dst, const wchar_t* src, size_t len)
{
    HANG("game CRT, reverse-hooked to retail");
}

#pragma GCC diagnostic pop
