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

#define tolower_ADDR (0x0049fe50)
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
void* bsearch(const void* key, const void* base, size_t nmemb, size_t size, int (*compar)(const void*, const void*));

#define calloc_ADDR (0x004a8cc0)
#define calloc c_calloc
void* calloc(size_t num_elements, size_t element_size);

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
void* realloc(void* ptr, size_t size);

#define qsort_ADDR (0x0049f8c0)
#define qsort c_qsort
void qsort(void* base, size_t nmemb, size_t size, int (*compar)(const void*, const void*));

#define rand_ADDR (0x0049f820)
#define rand c_rand
int rand(void);

// stdio.h
#define _amsg_exit_ADDR (0x004a0c10)
#define _amsg_exit c__amsg_exit
void _amsg_exit(int status, const char* msg);

#define _findfirst_ADDR (0x994a0c70)
#define _findfirst c__findfirst
intptr_t _findfirst(const char* filespec, void* fileinfo);

#define _findclose_ADDR (0x004a0ec0)
#define _findclose c__findclose
int _findclose(intptr_t handle);

#define _findnext_ADDR (0x004a0da0)
#define _findnext c__findnext
int _findnext(intptr_t handle, void* fileinfo);

#define _snprintf_ADDR (0x0049f850)
#define _snprintf c__snprintf
int _snprintf(char* buffer, size_t count, char* format, ...);

#define _sopen_ADDR (0x004a05b0)
#define _sopen c__sopen
int _sopen(const char* filename, int oflag, int shflag, int pmode);

#define _timet_from_ft_ADDR (0x004a0ef0)
#define _timet_from_ft c__timet_from_ft
time_t _timet_from_ft(const void* ft);

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
int fseek(FILE* stream, long int offset, int origin);

#define ftell_ADDR (0x0049fbd0)
#define ftell c_ftell
long int ftell(FILE* stream);

#define fwrite_ADDR (0x004a0160)
#define fwrite c_fwrite
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream);

#define sprintf_ADDR (0x0049eb80)
#define sprintf c_sprintf
int sprintf(char* str, const char* format, ...);

#define ungetc_ADDR (0x004a99c0)
#define ungetc c_ungetc
int ungetc(int c, FILE* stream);

// string.h
#define _strdup_ADDR (0x004ab570)
#define _strdup c__strdup
char* _strdup(const char* strSource);

#define _stricmp_ADDR (0x0049ec50)
#define _stricmp c__stricmp
int _stricmp(const char* string1, const char* string2);

#define _strncnt_ADDR (0x004ab170)
#define _strncnt c__strncnt
size_t _strncnt(const char* str, size_t count);

#define _strnicmp_ADDR (0x004aa280)
#define _strnicmp c__strnicmp
int _strnicmp(const char* str1, const char* str2, size_t n);

#define memcpy_ADDR (0x0049f4e0)
#define memcpy c_memcpy
void* memcpy(void* dest, const void* src, size_t n);

#define strchr_ADDR (0x0049fb10)
#define strchr c_strchr
char* strchr(const char* str, int c);

#define strcspn_ADDR (0x004a8450)
#define strcspn c_strcspn
size_t strcspn(const char* str1, const char* str2);

#define strlwr_ADDR (0x0049edd0)
#define strlwr c_strlwr
char* strlwr(char* str);

#define strncat_ADDR (0x004a0fb0)
#define strncat c_strncat
char* strncat(char* dest, const char* src, size_t n);

#define strncmp_ADDR (0x0049f000)
#define strncmp c_strncmp
int strncmp(const char* str1, const char* str2, size_t n);

#define strncpy_ADDR (0x0049f340)
#define strncpy c_strncpy
char* strncpy(char* dest, const char* src, size_t n);

#define strpbrk_ADDR (0x004a1300)
#define strpbrk c_strpbrk
char* strpbrk(const char* str1, const char* str2);

#define strrchr_ADDR (0x004a0f80)
#define strrchr c_strrchr
char* strrchr(const char* str, int c);

#define strspn_ADDR (0x004a1340)
#define strspn c_strspn
size_t strspn(const char* str1, const char* str2);

#define strstr_ADDR (0x0049ed50)
#define strstr c_strstr
char* strstr(const char* haystack, const char* needle);

#define strtok_ADDR (0x004a02f0)
#define strtok c_strtok
char* strtok(char* str, const char* delim);

#define strupr_ADDR (0x004ab5d0)
#define strupr c_strupr
char* strupr(char* str);

// time.h
#define _tzset_ADDR (0x004a8e70)
#define _tzset c__tzset
void _tzset(void);

// wchar.h
#define _snwprintf_ADDR (0x004a1170)
#define _snwprintf c__snwprintf
int _snwprintf(wchar_t* str, size_t size, const wchar_t* format, ...);

#define _mbschr_ADDR (0x004ab4a0)
#define _mbschr c__mbschr
unsigned char* _mbschr(unsigned char* str, unsigned int c);

#define _wcsncnt_ADDR (0x004aa950)
#define _wcsncnt c__wcsncnt
size_t _wcsncnt(const wchar_t* str, size_t count);

#define fgetws_ADDR (0x004a15c0)
#define fgetws c_fgetws
wchar_t* fgetws(wchar_t* ws, int num, FILE* stream);

#define mbtowc_ADDR (0x004a95d0)
#define mbtowc c_mbtowc
int mbtowc(wchar_t* pwc, const char* str, size_t n);

#define wcslen_ADDR (0x004a1150)
#define wcslen c_wcslen
size_t wcslen(const wchar_t* str);

#define wcsncpy_ADDR (0x0049ef50)
#define wcsncpy c_wcsncpy
wchar_t* wcsncpy(wchar_t* dest, const wchar_t* src, size_t n);

#define wcsrchr_ADDR (0x004a1210)
#define wcsrchr c_wcsrchr
wchar_t* wcsrchr(const wchar_t* str, wchar_t ch);

// NOTE: this differs from the current C stdlib implementation that has
// a third parameter, wchar** ptr which is used to store internal state
#define wcstok_ADDR (0x004a1250)
#define wcstok c_wcstok
wchar_t* wcstok(wchar_t* str, const wchar_t* delim);

#define wctomb_ADDR (0x004a6aa0)
#define wctomb c_wctomb
int wctomb(char* s, wchar_t wc);

#define wcstombs_ADDR (0x004aa6e0)
#define wcstombs c_wcstombs
size_t wcstombs(char* dst, const wchar_t* src, size_t len);

// Added here without C file changes, all the functions beneath the stdlib, time, locale, crt functions
// They are not sorted by address like all the other functions but we should not have to touch them, only here for decompilation reference

#define crt_internal_ADDR (0x004a4e70)
#define crt_internal1_ADDR (0x004a3120)
#define crt_internal2_ADDR (0x004a3160)
#define crt_internal3_ADDR (0x004a3c40)
#define crt_internal4_ADDR (0x004a1640)
#define crt_internal5_ADDR (0x004a3ca0)
#define crt_internal6_ADDR (0x004a3de0)
#define crt_internal7_ADDR (0x004a58d0)
#define crt_internal8_ADDR (0x004a53d0)
#define crt_internal9_ADDR (0x004a1670)
#define crt_internal10_ADDR (0x004a16f0)
#define crt_internal11_ADDR (0x004a56b0)
#define crt_internal12_ADDR (0x004a56f0)
#define crt_internal13_ADDR (0x004a3b00)
#define crt_internal14_ADDR (0x004a29a0)
#define crt_internal15_ADDR (0x004a5650)
#define crt_internal16_ADDR (0x004a4e90)
#define crt_internal17_ADDR (0x004a4fc0)
#define crt_internal18_ADDR (0x004a4ed0)
#define crt_internal19_ADDR (0x004a5060)
#define crt_internal20_ADDR (0x004a5270)
#define crt_internal21_ADDR (0x004a24a0)
#define crt_internal22_ADDR (0x004a2900)
#define crt_internal23_ADDR (0x004a2530)
#define crt_internal24_ADDR (0x004a2440)
#define crt_internal25_ADDR (0x004a2510)
#define crt_internal26_ADDR (0x004a6cc0)
#define crt_internal27_ADDR (0x004a6c80)
#define crt_internal28_ADDR (0x004a6ce0)
#define crt_internal29_ADDR (0x004a6d80)
#define crt_internal30_ADDR (0x004a72f0)
#define crt_internal31_ADDR (0x004a72b0)
#define crt_internal32_ADDR (0x004a8490)
#define crt_internal33_ADDR (0x004a2710)
#define crt_internal33_ADDR (0x004a9c40)
#define crt_internal34_ADDR (0x004a2840)
#define crt_internal35_ADDR (0x004a2590)
#define crt_internal36_ADDR (0x004a73d0)
#define crt_internal37_ADDR (0x004a7330)
#define crt_internal38_ADDR (0x004a2610)
#define crt_internal39_ADDR (0x004a2780)
#define crt_internal40_ADDR (0x004a7460)
#define crt_internal41_ADDR (0x004a9d40)
#define crt_internal42_ADDR (0x004aa650)
#define crt_internal43_ADDR (0x004aa390)
#define crt_internal44_ADDR (0x004a9be0)
#define crt_internal45_ADDR (0x004a9b70)
#define crt_internal46_ADDR (0x004a7290)
#define crt_internal47_ADDR (0x004a7270)
#define crt_internal48_ADDR (0x004a70a0)
#define crt_internal49_ADDR (0x004a6fc0)
#define crt_internal50_ADDR (0x004a6f90)
#define crt_internal51_ADDR (0x004a6ef0)
#define crt_internal52_ADDR (0x004a6fe0)
#define crt_internal53_ADDR (0x004a2970)
#define crt_internal54_ADDR (0x004a3040)
#define crt_internal55_ADDR (0x004a1750)
#define crt_internal56_ADDR (0x004a17c0)
#define crt_internal57_ADDR (0x004a5a95)
#define crt_internal58_ADDR (0x004a6b10)
#define crt_internal59_ADDR (0x004a3dc0)
#define crt_internal60_ADDR (0x004a6e10)
#define crt_internal61_ADDR (0x004a6e80)
#define crt_internal62_ADDR (0x004a9b40)
#define crt_internal63_ADDR (0x004a3460)
#define crt_internal64_ADDR (0x004a3400)
#define crt_internal65_ADDR (0x004a3330)
#define crt_internal66_ADDR (0x004a32d0)
#define crt_internal67_ADDR (0x004a5600)
#define crt_internal68_ADDR (0x004a6fb0)

#define locale_internal1_ADDR (0x004a8190)
#define locale_internal2_ADDR (0x004a7ea0)
#define locale_internal3_ADDR (0x004a7ca0)
#define locale_internal4_ADDR (0x004a7530)
#define locale_internal5_ADDR (0x004a7960)
#define locale_internal6_ADDR (0x004a75e0)
#define locale_internal7_ADDR (0x004a7f90)
#define locale_internal8_ADDR (0x004a8120)
#define locale_internal9_ADDR (0x004a7ba0)
#define locale_internal10_ADDR (0x004aa0d0)
#define locale_internal11_ADDR (0x004aaca0)
#define locale_internal12_ADDR (0x004aab70)
#define locale_internal13_ADDR (0x004a80e0)

#define stdlib_internal1_ADDR (0x004a3cc0)
#define stdlib_internal2_ADDR (0x004a91c0)
#define stdlib_internal3_ADDR (0x004a9430)
#define stdlib_internal4_ADDR (0x004a34c0)
#define stdlib_internal5_ADDR (0x004a5af0)
#define stdlib_internal6_ADDR (0x004a8de0)
#define stdlib_internal7_ADDR (0x004a6810)
#define stdlib_internal8_ADDR (0x004a1710)
#define stdlib_internal9_ADDR (0x004a1780)
#define stdlib_internal10_ADDR (0x004a4890)
#define stdlib_internal11_ADDR (0x004a4ad0)
#define stdlib_internal12_ADDR (0x004a5dc0)
#define stdlib_internal13_ADDR (0x004a1920)
#define stdlib_internal14_ADDR (0x004a2340)
#define stdlib_internal15_ADDR (0x004a2300)
#define stdlib_internal16_ADDR (0x004a22b0)
#define stdlib_internal17_ADDR (0x004a6790)
#define stdlib_internal18_ADDR (0x004a6750)
#define stdlib_internal19_ADDR (0x004a6720)
#define stdlib_internal20_ADDR (0x004a67d0)
#define stdlib_internal21_ADDR (0x004a67f0)
#define stdlib_internal22_ADDR (0x004a2380)
#define stdlib_internal23_ADDR (0x004a9750)
#define stdlib_internal24_ADDR (0x004a17f0)
#define stdlib_internal25_ADDR (0x004a2d30)
#define stdlib_internal26_ADDR (0x004a2cb0)
#define stdlib_internal27_ADDR (0x004aaa20)
#define stdlib_internal28_ADDR (0x004a6a70)
#define stdlib_internal29_ADDR (0x004a98c0)
#define stdlib_internal30_ADDR (0x004a40f0)
#define stdlib_internal31_ADDR (0x004a5ab0)
#define stdlib_internal32_ADDR (0x004a2bd0)
#define stdlib_internal33_ADDR (0x004a4490)
#define stdlib_internal34_ADDR (0x004a3ff0)
#define stdlib_internal35_ADDR (0x004a41e0)
#define stdlib_internal36_ADDR (0x004a4720)
#define stdlib_internal37_ADDR (0x004aa760)
#define stdlib_internal38_ADDR (0x004a8d70)
#define stdlib_internal39_ADDR (0x004a4510)
#define stdlib_internal40_ADDR (0x004a4260)
#define stdlib_internal41_ADDR (0x004a4a30)
#define stdlib_internal42_ADDR (0x004a4aa0)
#define stdlib_internal43_ADDR (0x004a4070)
#define stdlib_internal43_ADDR (0x004a9650)
#define stdlib_internal44_ADDR (0x004a3d40)
#define stdlib_internal44_ADDR (0x004a49e0)
#define stdlib_internal45_ADDR (0x004a4940)

#define time_internal1_ADDR (0x004a8eb0)
#define time_internal2_ADDR (0x004aa990)
#define time_internal3_ADDR (0x004a5cd0)
#define time_internal4_ADDR (0x004aade0)
#define time_internal5_ADDR (0x004aaea0)
#define time_internal6_ADDR (0x004aae20)
#define time_internal7_ADDR (0x004ab1a0)
#define time_internal8_ADDR (0x004ab430)
#define time_internal9_ADDR (0x004ab3b0)

void* crt_internal(void* param_1);
void* crt_internal1();
void* crt_internal2();
void* crt_internal3();
void* crt_internal4();
void* crt_internal5(void* param_1);
void* crt_internal6();
void* crt_internal7();
void* crt_internal8(void* param_1);
void* crt_internal9(void* param_1);
void* crt_internal10(void* param_1);
void* crt_internal11();
void* crt_internal12();
void* crt_internal13(void* param_1, void* param_2, void* param_3, void* param_4, void* param_5, void* param_6, void* param_7);
void* crt_internal14(void* param_1, void* param_2, void* param_3, void* param_4, void* param_5, void* param_6, void* param_7, void* param_8);
void* crt_internal15(void* param_1);
void* crt_internal16(void* param_1, void* param_2, char param_3);
void* crt_internal17();
void* crt_internal18();
void* crt_internal19(void* param_1, void* param_2, void* param_3, void* param_4, void* param_5);
void* crt_internal20();
void* crt_internal21(void* param_1);
void* crt_internal22(void* param_1, void* param_2, void* param_3, void* param_4, void* param_5);
void* crt_internal23(void* param_1, void* param_2, void* param_3);
void* crt_internal24(void* param_1);
void* crt_internal25(void* param_1);
void* crt_internal26(void* param_1, void* param_2);
void* crt_internal27(void* param_1, void* param_2);
void* crt_internal28(void* param_1);
void* crt_internal29(void* param_1);
void* crt_internal30(void* param_1, void* param_2);
void* crt_internal31(void* param_1, void* param_2);
void* crt_internal32(void* param_1, void* param_2, void* param_3, void* param_4, void* param_5, void* param_6, void* param_7);
void* crt_internal33(void* param_1, void* param_2, void* param_3);
void* crt_internal33(void* param_1, void* param_2, void* param_3);
void* crt_internal34(void* param_1, void* param_2, void* param_3, void* param_4);
void* crt_internal35(void* param_1, void* param_2, void* param_3, void* param_4);
void* crt_internal36(char param_1, void* param_2, void* param_3, void* param_4);
void* crt_internal37(void* param_1, void* param_2, void* param_3);
void* crt_internal38(void* param_1, void* param_2, void* param_3, void* param_4, char param_5);
void* crt_internal39(void* param_1, void* param_2, void* param_3, char param_4);
void* crt_internal40(void* param_1, void* param_2);
void* crt_internal41(void* param_1, void* param_2, void* param_3, void* param_4, char param_5, void* param_6);
void* crt_internal42(void* param_1, void* param_2, void* param_3);
void* crt_internal43(void* param_1, void* param_2);
void* crt_internal44(void* param_1);
void* crt_internal45(void* param_1, void* param_2);
void* crt_internal46(void* param_1, void* param_2);
void* crt_internal47(void* param_1, void* param_2);
void* crt_internal48(void* param_1, void* param_2, void* param_3);
void* crt_internal49(void* param_1);
void* crt_internal50(void* param_1, void* param_2);
void* crt_internal51(void* param_1, void* param_2);
void* crt_internal52(void* param_1, void* param_2);
void* crt_internal53(void* param_1, void* param_2);
void* crt_internal54();
void* crt_internal55(void* param_1, void* param_2);
void* crt_internal56(void* param_1, void* param_2);
void* crt_internal57(void* param_1);
void* crt_internal58(void* param_1, short param_2);
void* crt_internal59();
void* crt_internal60(void* param_1, void* param_2);
void* crt_internal61(void* param_1, void* param_2);
void* crt_internal62(void* param_1, void* param_2, void* param_3);
void* crt_internal63(void* param_1, void* param_2, void* param_3);
void* crt_internal64(void* param_1, void* param_2, void* param_3);
void* crt_internal65(void* param_1);
void* crt_internal66(void* param_1);
void* crt_internal67(void* param_1);
void* crt_internal68(void* param_1);

void* locale_internal1();
void* locale_internal2();
void* locale_internal3();
void* locale_internal4();
void* locale_internal5(void* param_1);
void* locale_internal6(void* param_1);
void* locale_internal7(void* param_1);
void* locale_internal8(void* param_1);
void* locale_internal9(void* param_1, void* param_2);
void* locale_internal10(void* bUnk, void* param_2, void* param_3, void* param_4);
void* locale_internal11(void* param_1, void* param_2, void* param_3, void* param_4, void* param_5);
void* locale_internal12(void* param_1, void* param_2, void* param_3, void* param_4, void* param_5);
void* locale_internal13(void* param_1);

void* stdlib_internal1();
void* stdlib_internal2(void* param_1);
void* stdlib_internal3(void* param_1, void* param_2, void* param_3, void* param_4, void* param_5, void* param_6, void* param_7, void* param_8, void* param_9, void* param_10, void* param_11);
void* stdlib_internal4(void* param_1);
void* stdlib_internal5(void* param_1);
void* stdlib_internal6();
void* stdlib_internal7(void* param_1);
void* stdlib_internal8(void* param_1);
void stdlib_internal9(int param_1);
void* stdlib_internal10(void* param_1, void* param_2);
void* stdlib_internal11(char param_1);
void* stdlib_internal12(void* param_1, void* param_2, void* param_3);
void* stdlib_internal13(void* param_1, void* param_2, void* param_3);
void* stdlib_internal14(void* param_1, void* param_2, void* param_3, void* param_4);
void* stdlib_internal15(void* param_1, void* param_2, void* param_3, void* param_4);
void* stdlib_internal16(void* param_1, void* param_2, void* param_3);
void* stdlib_internal17(void* param_1, void* param_2, void* param_3, void* param_4);
void* stdlib_internal18(void* param_1, void* param_2, void* param_3, void* param_4);
void* stdlib_internal19(void* param_1, void* param_2, void* param_3);
void* stdlib_internal20(void* param_1);
void* stdlib_internal21(void* param_1);
void* stdlib_internal22(void* param_1);
void* stdlib_internal23(void* param_1, void* param_2);
void* stdlib_internal24(void* param_1, void* param_2);
void* stdlib_internal25(void* param_1);
void* stdlib_internal26(void* param_1);
void* stdlib_internal27(void* param_1, void* param_2);
void* stdlib_internal28(void* param_1);
void* stdlib_internal29(void* param_1);
void* stdlib_internal30(void* param_1);
void* stdlib_internal31();
void* stdlib_internal32(void* param_1, void* param_2);
void* stdlib_internal33(void* param_1, void* param_2, void* param_3);
void* stdlib_internal34(void* param_1, void* param_2, void* param_3);
void* stdlib_internal35(void* param_1, void* param_2, void* param_3);
void* stdlib_internal36();
void* stdlib_internal37(void* param_1, void* param_2, void* param_3);
void* stdlib_internal38(void* param_1, void* param_2);
void* stdlib_internal39(void* param_1, void* param_2, void* param_3);
void* stdlib_internal40(void* param_1, void* param_2, void* param_3);
void* stdlib_internal41(void* param_1);
void* stdlib_internal42(void* param_1);
void* stdlib_internal43(void* param_1, void* param_2, void* param_3);
void* stdlib_internal43(void* param_1, void* param_2, void* param_3);
void* stdlib_internal44(void* param_1);
void* stdlib_internal44(void* param_1);
void* stdlib_internal45(void* param_1);

void* time_internal1();
void* time_internal2(void* param_1);
void* time_internal3(void* param_1, void* param_2, void* param_3, void* param_4, void* param_5, void* param_6, void* param_7);
void* time_internal4(void* param_1, void* param_2, void* param_3);
void* time_internal5(void* locale, void* param_2, char* str, void* count, void* param_5, void* param_6, void* param_7);
void* time_internal6();
void* time_internal7(void* param_1, void* param_2);
void* time_internal8(void* param_1);
void* time_internal9(void* param_1, void* param_2);

#endif // CSTDLIB_H
