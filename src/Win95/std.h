#ifndef STD_H
#define STD_H

#include <stdio.h>

#define stdFileOpen_ADDR (0x0048c5f0)
#define stdFileClose_ADDR (0x0048c610)
#define stdFileRead_ADDR (0x0048c620)
#define stdFileGets_ADDR (0x0048c660)
#define stdFileWrite_ADDR (0x0048c640)
#define stdFtell_ADDR (0x0048c6b0)
#define stdFseek_ADDR (0x0048c6c0)
#define stdFileSize_ADDR (0x0048c6e0)
#define stdFilePrintf_ADDR (0x0048c730)
#define stdFileGetws_ADDR (0x0048c680)

FILE* stdFileOpen(const char* _Filename, const char* _Mode);
int stdFileClose(FILE* _File);
size_t stdFileRead(FILE* _File, void* _DstBuf, size_t _Count);
char* stdFileGets(FILE* _File, char* _Buf, int _MaxCount);
size_t stdFileWrite(FILE* _File, const void* _Str, size_t _Count);
long stdFtell(FILE* _File);
int stdFseek(FILE* _File, long _Offset, int _Origin);
int stdFileSize(const char* _Filename);
int stdFilePrintf(FILE* f, const char* format, ...);
wchar_t* stdFileGetws(FILE* _File, wchar_t* _Dst, int _SizeInWords);

#endif // STD_H
