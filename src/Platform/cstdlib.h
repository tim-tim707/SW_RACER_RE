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

// ctype.h
#define _filelength_ADDR (0x004a04e0)
#define _filelength c__filelength
long _filelength(int fd);

#define _isctype_ADDR (0x0049f440)
#define _isctype c__isctype
int _isctype(int c, int desc);

#define tolower_ADDR (0x0049f350)
#define tolower c_tolower
int tolower(int c);

// math.h
#define _fpmath_ADDR (0x0049ebf0)
#define _fpmath c__fpmath
void _fpmath(void);

#define _ftol_ADDR (0x0049ed20)
#define _ftol c__ftol
long _ftol(double f);

// stdlib.h
#define _exit_ADDR (0x0049ea60)
#define _exit c__exit
void _exit(int status);

#define atof_ADDR (0x0049ef90)
#define atof c_atof
double atof(const char* str);

#define atol_ADDR (0x0049f040)
#define atol c_atol
long atol(const char* str);

#define atoi_ADDR (0x0049f0e0)
#define atoi c_atoi
int atoi(const char* str);

#define bsearch_ADDR (0x0049fd80)
#define bsearch c_bsearch
void* bsearch(const void* key, const void* base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));

#define calloc_ADDR (0x004a8cc0)
#define calloc c_calloc
void *calloc(size_t num_elements, size_t element_size);

#define exit_ADDR (0x0049ea40)
#define exit c_exit
void exit(int status);

#define free_ADDR (0x0049f200)
#define free c_free
void free(void* ptr);

#define malloc_ADDR (0x0049f270)
#define malloc c_malloc
void* malloc(size_t size);

#define realloc_ADDR (0x004a1380)
#define realloc c_realloc
void *realloc(void *ptr, size_t size);

#define qsort_ADDR (0x0049f8c0)
#define qsort c_qsort
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));

#define rand_ADDR (0x0049f820)
#define rand c_rand
int rand(void);

// stdio.h
#define _amsg_exit_ADDR (0x004a0c10)
#define _amsg_exit c__amsg_exit
void _amsg_exit(int status, const char *msg);

#define _findfirst_ADDR (0x994a0c70)
#define _findfirst c__findfirst
intptr_t _findfirst(const char *filespec, void *fileinfo);

#define _findclose_ADDR (0x004a0ec0)
#define _findclose c__findclose
int _findclose(intptr_t handle);

#define _findnext_ADDR (0x004a0da0)
#define _findnext c__findnext
int _findnext(intptr_t handle, void *fileinfo);

#define _snprintf_ADDR (0x0049f850)
#define _snprintf c__snprintf
int _snprintf(char* buffer, size_t count, char* format, ...);

#define _sopen_ADDR (0x004a05b0)
#define _sopen c__sopen
int _sopen(const char* filename, int oflag, int shflag, int pmode);

#define _timet_from_ft_ADDR (0x004a0ef0)
#define _timet_from_ft c__timet_from_ft
time_t _timet_from_ft(const void *ft);

#define _vsnprintf_ADDR (0x004a10e0)
#define _vsnprintf c__vsnprintf
int _vsnprintf(char* s, size_t n, const char* format, va_list arg);

#define fclose_ADDR (0x0049f0f0)
#define fclose c_fclose
int fclose(FILE* stream);

#define feof_ADDR (0x0048c6a0)
#define feof c_feof
int feof(FILE* stream);

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

#define ungetc_ADDR (0x004a99c0)
#define ungetc c_ungetc
int ungetc(int c, FILE *stream);

// string.h
#define _strdup_ADDR (0x004ab570)
#define _strdup c__strdup
char* _strdup(const char *strSource);

#define _stricmp_ADDR (0x0049ec50)
#define _stricmp c__stricmp
int _stricmp(const char* string1, const char* string2);

#define _strncnt_ADDR (0x004ab170)
#define _strncnt c__strncnt
size_t _strncnt(const char *str, size_t count);

#define _strnicmp_ADDR (0x004aa280)
#define _strnicmp c__strnicmp
int _strnicmp(const char *str1, const char *str2, size_t n);

#define memcpy_ADDR (0x0049f4e0)
#define memcpy c_memcpy
void* memcpy(void* dest, const void* src, size_t n);

#define strchr_ADDR (0x0049fb10)
#define strchr c_strchr
char* strchr(const char* str, int c);

#define strcspn_ADDR (0x004a8450)
#define strcspn c_strcspn
size_t strcspn(const char *str1, const char *str2);

#define strlwr_ADDR (0x0049edd0)
#define strlwr c_strlwr
char* strlwr(char* str);

#define strncat_ADDR (0x004a0fb0)
#define strncat c_strncat
char* strncat(char* dest, const char* src, size_t n);

#define strncmp_ADDR (0x0049edd0)
#define strncmp c_strncmp
int strncmp(const char* str1, const char* str2, size_t n);

#define strncpy_ADDR (0x0049f340)
#define strncpy c_strncpy
char* strncpy(char* dest, const char* src, size_t n);

#define strpbrk_ADDR (0x004a1300)
#define strpbrk c_strpbrk
char *strpbrk(const char *str1, const char *str2);

#define strrchr_ADDR (0x004a0f80)
#define strrchr c_strrchr
char* strrchr(const char *str, int c);

#define strspn_ADDR (0x004a1340)
#define strspn c_strspn
size_t strspn(const char *str1, const char *str2);

#define strstr_ADDR (0x0049ed50)
#define strstr c_strstr
char* strstr(const char* haystack, const char* needle);

#define strtok_ADDR (0x004a02f0)
#define strtok c_strtok
char* strtok(char* str, const char* delim);

#define strupr_ADDR (0x004ab5d0)
#define strupr c_strupr
char *strupr(char *str);

// time.h
#define _tzset_ADDR (0x004a8e70)
#define _tzset c__tzset
void _tzset(void);

// wchar.h
#define _snwprintf_ADDR (0x004a1170)
#define _snwprintf c__snwprintf
int _snwprintf(wchar_t *str, size_t size, const wchar_t *format, ...);

#define _mbschr_ADDR (0x004ab4a0)
#define _mbschr c__mbschr
unsigned char *_mbschr(unsigned char *str, unsigned int c);

#define _wcsncnt_ADDR (0x004aa950)
#define _wcsncnt c__wcsncnt
size_t _wcsncnt(const wchar_t *str, size_t count);

#define fgetws_ADDR (0x004a15c0)
#define fgetws c_fgetws
wchar_t* fgetws (wchar_t* ws, int num, FILE* stream);

#define mbtowc_ADDR (0x004a95d0)
#define mbtowc c_mbtowc
int mbtowc(wchar_t *pwc, const char *str, size_t n);

#define wcslen_ADDR (0x004a1150)
#define wcslen c_wcslen
size_t wcslen(const wchar_t *str);

#define wcsncpy_ADDR (0x0049ef50)
#define wcsncpy c_wcsncpy
wchar_t* wcsncpy(wchar_t* dest, const wchar_t* src, size_t n);

#define wcsrchr_ADDR (0x004a1210)
#define wcsrchr c_wcsrchr
wchar_t* wcsrchr(const wchar_t *str, wchar_t ch);

// NOTE: this differs from the current C stdlib implementation that has
// a third parameter, wchar** ptr which is used to store internal state
#define wcstok_ADDR (0x004a1250)
#define wcstok c_wcstok
wchar_t* wcstok(wchar_t *str, const wchar_t *delim);

#define wctomb_ADDR (0x004a6aa0)
#define wctomb c_wctomb
int wctomb(char *s, wchar_t wc);

#define wcstombs_ADDR (0x004aa6e0)
#define wcstombs c_wcstombs
size_t wcstombs(char *dst, const wchar_t *src, size_t len);

#endif // CSTDLIB_H
