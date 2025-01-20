#include "std.h"

#include <stdio.h>
#include "globals.h"

#include <Platform/cstdlib.h>

// 0x00484880
int stdCalcBitPos(signed int val)
{
    int result;

    for (result = 0; val > 1; ++result)
        val >>= 1;
    return result;
}

// 0x0048c5f0
FILE* stdFileOpen(const char* _Filename, const char* _Mode)
{
    return fopen(_Filename, _Mode);
}

// 0x0048c610
int stdFileClose(FILE* _File)
{
    return fclose(_File);
}

// 0x0048c620
size_t stdFileRead(FILE* _File, void* _DstBuf, size_t _Count)
{
    return fread(_DstBuf, 1, _Count, _File);
}

// 0x0048c660
char* stdFileGets(FILE* _File, char* _Buf, size_t _MaxCount)
{
    return fgets(_Buf, _MaxCount, _File);
}

// 0x0048c640
size_t stdFileWrite(FILE* _File, const void* _Str, size_t _Count)
{
    return fwrite(_Str, 1, _Count, _File);
}

// 0x0048c6b0
int stdFtell(FILE* _File)
{
    return ftell(_File);
}

// 0x0048c6c0
int stdFseek(FILE* _File, int _Offset, int _Origin)
{
    return fseek(_File, _Offset, _Origin);
}

// 0x0048c6e0
int stdFileSize(const char* _Filename)
{
    FILE* f = stdFileOpen(_Filename, "rb");
    if (f == NULL)
        return 0;
    stdFseek(f, 0, SEEK_END);
    int size = stdFtell(f);
    stdFileClose(f);
    return size;
}

// 0x0048c730
int stdFilePrintf(FILE* f, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    int len = vsnprintf(stdFilePrintf_buffer, sizeof(stdFilePrintf_buffer), format, args);
    va_end(args);
    stdFileWrite(f, stdFilePrintf_buffer, len);
    return 0;
}

// 0x0048c680
wchar_t* stdFileGetws(FILE* _File, wchar_t* _Dst, size_t _SizeInWords)
{
    return fgetws(_Dst, _SizeInWords, _File);
}
