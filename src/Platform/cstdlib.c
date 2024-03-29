#include "cstdlib.h"

// These are all c standard library functions. No decompilation necessary

// ctype.h
// 0x004a04e0
long _filelength(int fd) {}

// 0x0049f440
int _isctype(int c, int desc) {}

// 0x0049f350
int tolower(int c) {}

// math.h
// 0x0049ebf0
void _fpmath(void) {}

// 0x0049ed20
long _ftol(double f) {}

// stdlib.h
// 0x0049ea60
void _exit(int status) {}

// 0x0049ef90
double atof(const char* str) {}

// 0x0049f040
long atol(const char* str) {}

// 0x0049f0e0
int atoi(const char* str) {}

// 0x0049fd80
void* bsearch(const void* key, const void* base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {}

// 0x004a8cc0
void *calloc(size_t num_elements, size_t element_size) {}

// 0x0049ea40
void exit(int status) {}

// 0x0049f200
void free(void* ptr) {}

// 0x0049f270
void* malloc(size_t size) {}

// 0x004a1380
void *realloc(void *ptr, size_t size) {}

// 0x0049f8c0
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {}

// 0x0049f820
int rand(void) {}

// stdio.h
// 0x004a0c10
void _amsg_exit(int status, const char *msg) {}

// 0x994a0c70
intptr_t _findfirst(const char *filespec, void *fileinfo) {}

// 0x004a0ec0
int _findclose(intptr_t handle) {}

// 0x004a0da0
int _findnext(intptr_t handle, void *fileinfo) {}

// 0x0049f850
int _snprintf(char* buffer, size_t count, char* format, ...) {}

// 0x004a05b0
int _sopen(const char* filename, int oflag, int shflag, int pmode) {}

// 0x004a0ef0
time_t _timet_from_ft(const void *ft) {}

// 0x004a10e0
int _vsnprintf(char* s, size_t n, const char* format, va_list arg) {}

// 0x0049f0f0
int fclose(FILE* stream) {}

// 0x0048c6a0
int feof(FILE* stream) {}

// 0x004a1530
char* fgets(char* str, int n, FILE* stream) {}

// 0x0049f1e0
FILE* fopen(const char* filename, const char* mode) {}

// 0x0049ffe0
size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream) {}

// 0x004a0950
int fseek(FILE *stream, long int offset, int origin) {}

// 0x0049fbd0
long int ftell(FILE *stream) {}

// 0x004a0160
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream) {}

// 0x0049eb80
int sprintf(char* str, const char* format, ...) {}

// 0x004a99c0
int ungetc(int c, FILE *stream) {}

// string.h
// 0x004ab570
char* _strdup(const char *strSource) {}

// 0x0049ec50
int _stricmp(const char* string1, const char* string2) {}

// 0x004ab170
size_t _strncnt(const char *str, size_t count) {}

// 0x004aa280
int strnicmp(const char *str1, const char *str2, size_t n) {}

// 0x0049f4e0
void* memcpy(void* dest, const void* src, size_t n) {}

// 0x0049fb10
char* strchr(const char* str, int c) {}

// 0x004a8450
size_t strcspn(const char *str1, const char *str2) {}

// 0x0049edd0
char* strlwr(char* str) {}

// 0x004a0fb0
char* strncat(char* dest, const char* src, size_t n) {}

// 0x0049edd0
int strncmp(const char* str1, const char* str2, size_t n) {}

// 0x0049f340
char* strncpy(char* dest, const char* src, size_t n) {}

// 0x004a1300
char *strpbrk(const char *str1, const char *str2) {}

// 0x004a0f80
char* strrchr(const char *str, int c) {}

// 0x004a1340
size_t strspn(const char *str1, const char *str2) {}

// 0x0049ed50
char* strstr(const char* haystack, const char* needle) {}

// 0x004a02f0
char* strtok(char* str, const char* delim) {}

// 0x004ab5d0
char *strupr(char *str) {}

// time.h
// 0x004a8e70
void _tzset(void) {}

// wchar.h
// 0x004a1170
int _snwprintf(wchar_t *str, size_t size, const wchar_t *format, ...) {}

// 0x004ab4a0
unsigned char *_mbschr(unsigned char *str, unsigned int c) {}

// 0x004aa950
size_t _wcsncnt(const wchar_t *str, size_t count) {}

// 0x004a15c0
wchar_t* fgetws (wchar_t* ws, int num, FILE* stream) {}

// 0x004a95d0
int mbtowc(wchar_t *pwc, const char *str, size_t n) {}

// 0x004a1150
size_t wcslen(const wchar_t *str) {}

// 0x0049ef50
wchar_t* wcsncpy(wchar_t* dest, const wchar_t* src, size_t n) {}

// 0x004a1210
wchar_t* wcsrchr(const wchar_t *str, wchar_t ch) {}

// 0x004a1250
wchar_t* wcstok(wchar_t *str, const wchar_t *delim) {}

// 0x004a6aa0
int wctomb(char *s, wchar_t wc) {}

// 0x004aa6e0
size_t wcstombs(char *dst, const wchar_t *src, size_t len) {}

