#ifndef SWR_STDLIB_H
#define SWR_STDLIB_H

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

// Used only for Ghidra analysis, use the real functions instead

struct _finddata32_t;

#define stdlib____setargv_ADDR (0x0042D500)
#define stdlib_timeGetTime_ADDR (0x0048C490)
#define stdlib__feof_ADDR (0x0048C6A0)
#define stdlib_CoUninitialize_ADDR (0x0049E960)
#define stdlib___cinit_ADDR (0x0049EA10)
#define stdlib__exit_0_ADDR (0x0049EA40)
#define stdlib___exit_ADDR (0x0049EA60)
#define stdlib__doexit_ADDR (0x0049EA80)
#define stdlib___lockexit_ADDR (0x0049EB40)
#define stdlib___unlockexit_ADDR (0x0049EB50)
#define stdlib___initterm_ADDR (0x0049EB60)
#define stdlib__sprintf_ADDR (0x0049EB80)
#define stdlib___fpmath_ADDR (0x0049EBF0)
#define stdlib___cfltcvt_init_7_ADDR (0x0049EC10)
#define stdlib___strcmpi_ADDR (0x0049EC50)
#define stdlib___ftol_ADDR (0x0049ED20)
#define stdlib__strstr_ADDR (0x0049ED50)
#define stdlib__strlwr_ADDR (0x0049EDD0)
#define stdlib__wcsncpy_ADDR (0x0049EF50)
#define stdlib__atof_ADDR (0x0049EF90)
#define stdlib__strncmp_ADDR (0x0049F000)
#define stdlib__atol_ADDR (0x0049F040)
#define stdlib__atoi_ADDR (0x0049F0E0)
#define stdlib__fclose_ADDR (0x0049F0F0)
#define stdlib___fclose_lk_ADDR (0x0049F130)
#define stdlib___fsopen_ADDR (0x0049F1A0)
#define stdlib__fopen_ADDR (0x0049F1E0)
#define stdlib__free_ADDR (0x0049F200)
#define stdlib__malloc_ADDR (0x0049F270)
#define stdlib___nh_malloc_ADDR (0x0049F290)
#define stdlib___heap_alloc_ADDR (0x0049F2E0)
#define stdlib__strncpy_ADDR (0x0049F340)
#define stdlib___isctype_ADDR (0x0049F440)
#define stdlib__memcpy_ADDR (0x0049F4E0)
#define stdlib__rand_ADDR (0x0049F820)
#define stdlib___snprintf_ADDR (0x0049F850)
#define stdlib__qsort_ADDR (0x0049F8C0)
#define stdlib__shortsort_ADDR (0x0049FA70)
#define stdlib__swap_ADDR (0x0049FAD0)
#define stdlib__strchr_ADDR (0x0049FB10)
#define stdlib__ftell_ADDR (0x0049FBD0)
#define stdlib___ftell_lk_ADDR (0x0049FC00)
#define stdlib__bsearch_ADDR (0x0049FDB0)
#define stdlib__tolower_ADDR (0x0049FE50) // 4ab5d0
#define stdlib__fread_ADDR (0x0049ffe0)
#define stdlib__fread_nolock_ADDR (0x004A0020)
#define stdlib__fwrite_ADDR (0x004A0160)
#define stdlib__fwrite_nolock_ADDR (0x004A01A0)
#define stdlib__strtok_ADDR (0x004A02F0)
#define stdlib___close_ADDR (0x004A03E0)
#define stdlib___close_lk_ADDR (0x004A0450)
#define stdlib___filelength_ADDR (0x004A04E0)
#define stdlib___sopen_ADDR (0x004A05B0)
#define stdlib__fseek_ADDR (0x004A0950)
#define stdlib___fseek_lk_ADDR (0x004A0990)
#define stdlib___alloca_probe_ADDR (0x004A0A30)
#define stdlib_start_ADDR (0x004A0A60)
#define stdlib___amsg_exit_ADDR (0x004A0C10)
#define stdlib___amsg_exit_0_ADDR (0x004A0C40)
#define stdlib_nullsub_4_ADDR (0x004A0C66)
#define stdlib___findfirst_ADDR (0x004A0C70)
#define stdlib___findnext_ADDR (0x004A0DA0)
#define stdlib___findclose_ADDR (0x004A0EC0)
#define stdlib____timet_from_ft_ADDR (0x004A0EF0)
#define stdlib__strrchr_ADDR (0x004A0F80)
#define stdlib__strncat_ADDR (0x004A0FB0)
#define stdlib___vsnprintf_ADDR (0x004A10E0)
#define stdlib__wcslen_ADDR (0x004A1150)
#define stdlib___snwprintf_ADDR (0x004A1170)
#define stdlib__wcsrchr_ADDR (0x004A1210)
#define stdlib__wcstok_ADDR (0x004A1250)
#define stdlib__strpbrk_ADDR (0x004A1300)
#define stdlib__strspn_ADDR (0x004A1340)
#define stdlib__realloc_ADDR (0x004A1380)
#define stdlib__fgets_ADDR (0x004A1530)
#define stdlib__fgetws_ADDR (0x004A15C0)
#define stdlib___mtinitlocks_ADDR (0x004A1640)
#define stdlib___lock_ADDR (0x004A1670)
#define stdlib___unlock_ADDR (0x004A16F0)
#define stdlib___lock_file_ADDR (0x004A1710)
#define stdlib___lock_file2_ADDR (0x004A1750)
#define stdlib___unlock_file_ADDR (0x004A1780)
#define stdlib___unlock_file2_ADDR (0x004A17C0)
#define stdlib___flsbuf_ADDR (0x004A17F0)
#define stdlib___output_ADDR (0x004A1920)
#define stdlib__write_char_ADDR (0x004A22B0)
#define stdlib__write_multi_char_ADDR (0x004A2300)
#define stdlib__write_string_ADDR (0x004A2340)
#define stdlib__get_short_arg_ADDR (0x004A2380)
#define stdlib___setdefaultprecision_ADDR (0x004A23A0)
#define stdlib___ms_p5_test_fdiv_ADDR (0x004A23C0)
#define stdlib___ms_p5_mp_test_fdiv_ADDR (0x004A2410)
#define stdlib___forcdecpt_ADDR (0x004A2440)
#define stdlib___positive_ADDR (0x004A2510)
#define stdlib___fassign_ADDR (0x004A2530)
#define stdlib___cftoe_ADDR (0x004A2590)
#define stdlib___cftoe2_ADDR (0x004A2610)
#define stdlib___cftof_ADDR (0x004A2710)
#define stdlib___cftof2_ADDR (0x004A2780)
#define stdlib___cftog_ADDR (0x004A2840)
#define stdlib___cfltcvt_ADDR (0x004A2900)
#define stdlib___shift_ADDR (0x004A2970)
#define stdlib___fltin2_ADDR (0x004A2BD0)
#define stdlib___allmul_ADDR (0x004A2C70)
#define stdlib___freebuf_ADDR (0x004A2CB0)
#define stdlib___fflush_lk_ADDR (0x004A2CF0)
#define stdlib___flush_ADDR (0x004A2D30)
#define stdlib___flushall_ADDR (0x004A2DA0)
#define stdlib__flsall_ADDR (0x004A2DB0)
#define stdlib___openfile_ADDR (0x004A2E70)
#define stdlib___getstream_ADDR (0x004A3040)
#define stdlib___heap_init_ADDR (0x004A3120)
#define stdlib____sbh_new_region_ADDR (0x004A3160)
#define stdlib____sbh_release_region_ADDR (0x004A32D0)
#define stdlib____sbh_decommit_pages_ADDR (0x004A3330)
#define stdlib____sbh_find_block_ADDR (0x004A3400)
#define stdlib____sbh_free_block_ADDR (0x004A3460)
#define stdlib____sbh_alloc_block_ADDR (0x004A34C0)
#define stdlib____sbh_alloc_block_from_page_ADDR (0x004A3700)
#define stdlib____sbh_resize_block_ADDR (0x004A3880)
#define stdlib___callnewh_ADDR (0x004A3950)
#define stdlib____crtGetStringTypeW_ADDR (0x004A3970)
#define stdlib___mtinit_ADDR (0x004A3C40)
#define stdlib___initptd_ADDR (0x004A3CA0)
#define stdlib___getptd_ADDR (0x004A3CC0)
#define stdlib___dosmaperr_ADDR (0x004A3D40)
#define stdlib___errno_ADDR (0x004A3DC0)
#define stdlib____doserrno_ADDR (0x004A3DD0)
#define stdlib___ioinit_ADDR (0x004A3DE0)
#define stdlib___lseek_ADDR (0x004A3FF0)
#define stdlib___lseek_lk_ADDR (0x004A4070)
#define stdlib___filbuf_ADDR (0x004A40F0)
#define stdlib___read_ADDR (0x004A41E0)
#define stdlib___read_lk_ADDR (0x004A4260)
#define stdlib___write_ADDR (0x004A4490)
#define stdlib___write_lk_ADDR (0x004A4510)
#define stdlib___alloc_osfhnd_ADDR (0x004A4720)
#define stdlib___set_osfhnd_ADDR (0x004A4890)
#define stdlib___free_osfhnd_ADDR (0x004A4940)
#define stdlib___get_osfhandle_ADDR (0x004A49E0)
#define stdlib___lock_fhandle_ADDR (0x004A4A30)
#define stdlib___unlock_fhandle_ADDR (0x004A4AA0)
#define stdlib___chsize_lk_ADDR (0x004A4AD0)
#define stdlib___XcptFilter_ADDR (0x004A4C20)
#define stdlib__xcptlookup_ADDR (0x004A4E30)
#define stdlib___ismbblead_ADDR (0x004A4E70)
#define stdlib__x_ismbbtype_ADDR (0x004A4E90)
#define stdlib___setenvp_ADDR (0x004A4ED0)
#define stdlib___setargv_ADDR (0x004A4FC0)
#define stdlib__parse_cmdline_ADDR (0x004A5060)
#define stdlib____crtGetEnvironmentStringsA_ADDR (0x004A5270)
#define stdlib__getSystemCP_ADDR (0x004A5600)
#define stdlib__CPtoLCID_ADDR (0x004A5650)
#define stdlib__setSBCS_ADDR (0x004A56B0)
#define stdlib____initmbctable_ADDR (0x004A58D0)
#define stdlib___global_unwind2_ADDR (0x004A58E0)
#define stdlib___unwind_handler_ADDR (0x004A5900)
#define stdlib___local_unwind2_ADDR (0x004A5922)
#define stdlib___abnormal_termination_ADDR (0x004A598A)
#define stdlib__at_done_ADDR (0x004A59AC)
#define stdlib___NLG_Notify1_ADDR (0x004A59AD)
#define stdlib___NLG_Notify_ADDR (0x004A59B6)
#define stdlib___except_handler3_ADDR (0x004A59D8)
#define stdlib__seh_longjmp_unwind_ADDR (0x004A5A95)
#define stdlib___FF_MSGBANNER_ADDR (0x004A5AB0)
#define stdlib___NMSG_WRITE_ADDR (0x004A5AF0)
#define stdlib____loctotime_t_ADDR (0x004A5CD0)
#define stdlib___woutput_ADDR (0x004A5DC0)
#define stdlib__write_char_0_ADDR (0x004A6720)
#define stdlib__write_multi_char_0_ADDR (0x004A6750)
#define stdlib__write_string_0_ADDR (0x004A6790)
#define stdlib__get_int_arg_ADDR (0x004A67D0)
#define stdlib__get_int64_arg_ADDR (0x004A67F0)
#define stdlib___getwc_lk_ADDR (0x004A6810)
#define stdlib___getbuf_ADDR (0x004A6A10)
#define stdlib___isatty_ADDR (0x004A6A70)
#define stdlib__wctomb_ADDR (0x004A6AA0)
#define stdlib___wctomb_lk_ADDR (0x004A6B10)
#define stdlib___aulldiv_ADDR (0x004A6B90)
#define stdlib___aullrem_ADDR (0x004A6C00)
#define stdlib___control87_ADDR (0x004A6C80)
#define stdlib___controlfp_ADDR (0x004A6CC0)
#define stdlib___abstract_cw_ADDR (0x004A6CE0)
#define stdlib___hw_cw_ADDR (0x004A6D80)
#define stdlib___ZeroTail_ADDR (0x004A6E10)
#define stdlib___IncMan_ADDR (0x004A6E80)
#define stdlib___RoundMan_ADDR (0x004A6EF0)
#define stdlib___CopyMan_ADDR (0x004A6F90)
#define stdlib___FillZeroMan_ADDR (0x004A6FB0)
#define stdlib___IsZeroMan_ADDR (0x004A6FC0)
#define stdlib___ShrMan_ADDR (0x004A6FE0)
#define stdlib___ld12cvt_ADDR (0x004A70A0)
#define stdlib___fptostr_ADDR (0x004A7330)
#define stdlib___fltout2_ADDR (0x004A73D0)
#define stdlib____dtold_ADDR (0x004A7460)
#define stdlib___fptrap_ADDR (0x004A7520)
#define stdlib____init_time_ADDR (0x004A7530)
#define stdlib___get_lc_time_ADDR (0x004A75E0)
#define stdlib___free_lc_time_ADDR (0x004A7960)
#define stdlib__storeTimeFmt_ADDR (0x004A7BA0)
#define stdlib____init_numeric_ADDR (0x004A7CA0)
#define stdlib____init_monetary_ADDR (0x004A7EA0)
#define stdlib___get_lc_lconv_ADDR (0x004A7F90)
#define stdlib__fix_grouping_ADDR (0x004A80E0)
#define stdlib___free_lc_lconv_ADDR (0x004A8120)
#define stdlib__strcspn_ADDR (0x004A8450)
#define stdlib____strgtold12_ADDR (0x004A8490)
#define stdlib___commit_ADDR (0x004A8C20)
#define stdlib__calloc_ADDR (0x004A8CC0)
#define stdlib___setmode_lk_ADDR (0x004A8D70)
#define stdlib____crtMessageBoxA_ADDR (0x004A8DE0)
#define stdlib____tzset_ADDR (0x004A8E70)
#define stdlib___tzset_lk_ADDR (0x004A8EB0)
#define stdlib___isindst_ADDR (0x004A9190)
#define stdlib__cvtdate_ADDR (0x004A9430)
#define stdlib__mbtowc_ADDR (0x004A95D0)
#define stdlib___mbtowc_lk_ADDR (0x004A9650)
#define stdlib___putwc_lk_ADDR (0x004A9750)
#define stdlib___filwbuf_ADDR (0x004A98C0)
#define stdlib__ungetc_ADDR (0x004A99C0)
#define stdlib__ungetc_0_ADDR (0x004A99F0)
#define stdlib___allshl_ADDR (0x004A9A80)
#define stdlib___fcloseall_ADDR (0x004A9AA0)
#define stdlib____addl_ADDR (0x004A9B40)
#define stdlib____add_12_ADDR (0x004A9B70)
#define stdlib____shl_12_ADDR (0x004A9BE0)
#define stdlib____shr_12_ADDR (0x004A9C10)
#define stdlib____mtold12_ADDR (0x004A9C40)
#define stdlib__$I10_OUTPUT_ADDR (0x004A9D40)
#define stdlib____getlocaleinfo_ADDR (0x004AA0D0)
#define stdlib___strnicmp_ADDR (0x004AA280)
#define stdlib____ld12mul_ADDR (0x004AA390)
#define stdlib____multtenpow12_ADDR (0x004AA650)
#define stdlib__wcstombs_ADDR (0x004AA6E0)
#define stdlib___wcstombs_lk_ADDR (0x004AA760)
#define stdlib__wcsncnt_ADDR (0x004AA950)
#define stdlib___getenv_lk_ADDR (0x004AA990)
#define stdlib___flswbuf_ADDR (0x004AAA20)
#define stdlib____crtGetLocaleInfoW_ADDR (0x004AAB70)
#define stdlib___mbsnbicoll_ADDR (0x004AADE0)
#define stdlib____wtomb_environ_ADDR (0x004AAE20)
#define stdlib____crtCompareStringA_ADDR (0x004AAEA0)
#define stdlib__strncnt_ADDR (0x004AB170)
#define stdlib____crtsetenv_ADDR (0x004AB1A0)
#define stdlib__findenv_ADDR (0x004AB3B0)
#define stdlib__copy_environ_ADDR (0x004AB430)
#define stdlib___mbschr_ADDR (0x004AB4A0)
#define stdlib___strdup_ADDR (0x004AB570)
#define stdlib_RtlUnwind_ADDR (0x004AB5C0)
#define stdlib_strupr_ADDR (0x004AB5D0)

void stdlib____setargv(void);
DWORD stdlib_timeGetTime();
int stdlib__feof(FILE* stream);
void stdlib_CoUninitialize();
void stdlib___cinit();
void stdlib__exit_0(int status);
void stdlib___exit();
void stdlib__doexit();
void stdlib___lockexit();
void stdlib___unlockexit();
void stdlib___initterm();
int stdlib__sprintf(char* buffer, const char* format, ...);
void stdlib___fpmath();
void stdlib___cfltcvt_init_7();
int stdlib___strcmpi(const char* string1, const char* string2);
void stdlib___ftol();
char* stdlib__strstr(const char* str, const char* strSearch);
char* stdlib__strlwr(char* str);
wchar_t* stdlib__wcsncpy(wchar_t* strDest, const wchar_t* strSource, size_t count);
double stdlib__atof(const char* str);
int stdlib__strncmp(const char* string1, const char* string2, size_t count);
long stdlib__atol(const char* str);
int stdlib__atoi(const char* str);
int stdlib__fclose(FILE* stream);
int stdlib___fclose_lk(FILE* stream);
FILE* stdlib___fsopen(const char* filename, const char* mode, int shflag);
FILE* stdlib__fopen(const char* filename, const char* mode);
void stdlib__free(void* ptr);
void* stdlib__malloc(size_t size);
void stdlib___nh_malloc();
void stdlib___heap_alloc();
char* stdlib__strncpy(char* strDest, const char* strSource, size_t count);
int stdlib___isctype(int c, int desc);
void* stdlib__memcpy(void* dest, const void* src, size_t count);
int stdlib__rand(void);
int stdlib___snprintf(char* buffer, size_t count, const char* format, ...);
// void stdlib__qsort(void* base, size_t number, size_t width, int(__cdecl* compare)(const void*, const void*));
void stdlib__qsort(void* base, size_t number, size_t width, void* f);
void stdlib__shortsort();
void stdlib__swap();
char* stdlib__strchr(const char* str, int c);
long stdlib__ftell(FILE* stream);
long stdlib___ftell_lk(FILE* stream);
// void* stdlib__bsearch(const void* key, const void* base, size_t num, size_t width, int(__cdecl* compare)(const void* key, const void* datum));
void* stdlib__bsearch(const void* key, const void* base, size_t num, size_t width, void* f);
int stdlib__tolower(int c);
size_t stdlib__fread(void* buffer, size_t size, size_t count, FILE* stream);
size_t stdlib__fread_nolock(void* buffer, size_t size, size_t count, FILE* stream);
size_t stdlib__fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
size_t stdlib__fwrite_nolock(const void* buffer, size_t size, size_t count, FILE* stream);
char* stdlib__strtok(char* strToken, const char* strDelimit);
int stdlib___close(int fd);
int stdlib___close_lk(int fd);
long stdlib___filelength(int fd);
int stdlib___sopen(const char* filename, int oflag, int shflag, int pmode);
int stdlib__fseek(FILE* stream, long offset, int origin);
int stdlib___fseek_lk(FILE* stream, long offset, int origin);
void stdlib___alloca_probe();
void stdlib_start();
void stdlib___amsg_exit(int rterrnum);
void stdlib___amsg_exit_0();
void stdlib_nullsub_4();
intptr_t stdlib___findfirst(const char* filespec, struct _finddata32_t* fileinfo);
int stdlib___findnext(intptr_t handle, struct _finddata32_t* fileinfo);
int stdlib___findclose(intptr_t handle);
void stdlib____timet_from_ft();
char* stdlib__strrchr(const char* str, int c);
char* stdlib__strncat(char* strDest, const char* strSource, size_t count);
int stdlib___vsnprintf(char* buffer, size_t count, const char* format, va_list argptr);
size_t stdlib__wcslen(const wchar_t* str);
int stdlib___snwprintf(wchar_t* buffer, size_t count, const wchar_t* format, ...);
const wchar_t* stdlib__wcsrchr(const wchar_t* str, wchar_t c);
wchar_t* stdlib__wcstok(wchar_t* strToken, const wchar_t* strDelimit);
char* stdlib__strpbrk(const char* str, const char* strCharSet);
size_t stdlib__strspn(const char* str, const char* strCharSet);
void* stdlib__realloc(void* memblock, size_t size);
char* stdlib__fgets(char* str, int numChars, FILE* stream);
wchar_t* stdlib__fgetws(wchar_t* str, int numChars, FILE* stream);
void stdlib___mtinitlocks();
void stdlib___lock(int locknum);
void stdlib___unlock(int locknum);
void stdlib___lock_file(FILE* file);
void stdlib___lock_file2();
void stdlib___unlock_file(FILE* file);
void stdlib___unlock_file2();
void stdlib___flsbuf();
void stdlib___output();
void stdlib__write_char();
void stdlib__write_multi_char();
void stdlib__write_string();
void stdlib__get_short_arg();
void stdlib___setdefaultprecision();
void stdlib___ms_p5_test_fdiv();
void stdlib___ms_p5_mp_test_fdiv();
void stdlib___forcdecpt();
void stdlib___positive();
void stdlib___fassign();
void stdlib___cftoe();
void stdlib___cftoe2();
void stdlib___cftof();
void stdlib___cftof2();
void stdlib___cftog();
void stdlib___cfltcvt();
void stdlib___shift();
void stdlib___fltin2();
void stdlib___allmul();
void stdlib___freebuf();
int stdlib___fflush_lk(FILE* stream);
int stdlib___flush(FILE* stream);
int stdlib___flushall(void);
void stdlib__flsall();
void stdlib___openfile();
void stdlib___getstream();
void stdlib___heap_init();
void stdlib____sbh_new_region();
void stdlib____sbh_release_region();
void stdlib____sbh_decommit_pages();
void stdlib____sbh_find_block();
void stdlib____sbh_free_block();
void stdlib____sbh_alloc_block();
void stdlib____sbh_alloc_block_from_page();
void stdlib____sbh_resize_block();
int stdlib___callnewh(size_t size);
void stdlib____crtGetStringTypeW();
void stdlib___mtinit();
void stdlib___initptd();
void stdlib___getptd();
void stdlib___dosmaperr();
void stdlib___errno();
void stdlib____doserrno();
void stdlib___ioinit();
long stdlib___lseek(int fd, long offset, int origin);
long stdlib___lseek_lk(int fd, long offset, int origin);
void stdlib___filbuf();
int stdlib___read(int const fd, void* const buffer, unsigned const buffer_size);
int stdlib___read_lk(int const fd, void* const buffer, unsigned const buffer_size);
int stdlib___write(int fd, const void* buffer, unsigned int count);
int stdlib___write_lk(int fd, const void* buffer, unsigned int count);
void stdlib___alloc_osfhnd();
void stdlib___set_osfhnd();
void stdlib___free_osfhnd();
intptr_t stdlib___get_osfhandle(int fd);
void stdlib___lock_fhandle();
void stdlib___unlock_fhandle();
int stdlib___chsize_lk(int fd, long size);
void stdlib___XcptFilter();
void stdlib__xcptlookup();
int stdlib___ismbblead(unsigned int c);
void stdlib__x_ismbbtype();
void stdlib___setenvp();
void stdlib___setargv();
void stdlib__parse_cmdline();
void stdlib____crtGetEnvironmentStringsA();
void stdlib__getSystemCP();
void stdlib__CPtoLCID();
void stdlib__setSBCS();
void stdlib____initmbctable();
void stdlib___global_unwind2();
void stdlib___unwind_handler();
void stdlib___local_unwind2();
void stdlib___abnormal_termination();
void stdlib__at_done();
void stdlib___NLG_Notify1();
void stdlib___NLG_Notify();
void stdlib___except_handler3();
void stdlib__seh_longjmp_unwind();
void stdlib___FF_MSGBANNER();
void stdlib___NMSG_WRITE();
void stdlib____loctotime_t();
void stdlib___woutput();
void stdlib__write_char_0();
void stdlib__write_multi_char_0();
void stdlib__write_string_0();
void stdlib__get_int_arg();
void stdlib__get_int64_arg();
wint_t stdlib___getwc_lk(FILE* stream);
void stdlib___getbuf();
int stdlib___isatty(int fd);
int stdlib__wctomb(char* mbchar, wchar_t wchar);
int stdlib___wctomb_lk(char* mbchar, wchar_t wchar);
void stdlib___aulldiv();
void stdlib___aullrem();
void stdlib___control87();
void stdlib___controlfp();
void stdlib___abstract_cw();
void stdlib___hw_cw();
void stdlib___ZeroTail();
void stdlib___IncMan();
void stdlib___RoundMan();
void stdlib___CopyMan();
void stdlib___FillZeroMan();
void stdlib___IsZeroMan();
void stdlib___ShrMan();
void stdlib___ld12cvt();
void stdlib___fptostr();
void stdlib___fltout2();
void stdlib____dtold();
void stdlib___fptrap();
void stdlib____init_time();
void stdlib___get_lc_time();
void stdlib___free_lc_time();
void stdlib__storeTimeFmt();
void stdlib____init_numeric();
void stdlib____init_monetary();
void stdlib___get_lc_lconv();
void stdlib__fix_grouping();
void stdlib___free_lc_lconv();
size_t stdlib__strcspn(const char* str, const char* strCharSet);
void stdlib____strgtold12();
void stdlib___commit();
void* stdlib__calloc(size_t number, size_t size);
int stdlib___setmode_lk(int fd, int mode);
void stdlib____crtMessageBoxA();
void stdlib____tzset();
void stdlib___tzset_lk();
void stdlib___isindst();
void stdlib__cvtdate();
int stdlib__mbtowc(wchar_t* wchar, const char* mbchar, size_t count);
int stdlib___mbtowc_lk(wchar_t* wchar, const char* mbchar, size_t count);
wint_t stdlib___putwc_lk(wchar_t c, FILE* stream);
void stdlib___filwbuf();
int stdlib__ungetc(int c, FILE* stream);
void stdlib__ungetc_0();
void stdlib___allshl();
int stdlib___fcloseall(void);
void stdlib____addl();
void stdlib____add_12();
void stdlib____shl_12();
void stdlib____shr_12();
void stdlib____mtold12();
void stdlib__$I10_OUTPUT();
void stdlib____getlocaleinfo();
int stdlib___strnicmp(const char* string1, const char* string2, size_t count);
void stdlib____ld12mul();
void stdlib____multtenpow12();
size_t stdlib__wcstombs(char* mbstr, const wchar_t* wcstr, size_t count);
size_t stdlib___wcstombs_lk(char* mbstr, const wchar_t* wcstr, size_t count);
size_t stdlib__wcsncnt(const wchar_t* str, size_t count);
char* stdlib___getenv_lk(const char* varname);
void stdlib___flswbuf();
void stdlib____crtGetLocaleInfoW();
void stdlib___mbsnbicoll();
void stdlib____wtomb_environ();
void stdlib____crtCompareStringA();
size_t stdlib__strncnt(const char* str, size_t count);
void stdlib____crtsetenv();
void stdlib__findenv();
void stdlib__copy_environ();
unsigned char* stdlib___mbschr(const unsigned char* str, unsigned int c);
char* stdlib___strdup(const char* strSource);
void stdlib_RtlUnwind();
char* stdlib_strupr(char* str);

#endif // SWR_STDLIB_H
