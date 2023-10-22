#ifndef STDSTRING_H
#define STDSTRING_H

#include "types.h"

#define stdString_RemoveTEXTTag_ADDR (0x00421470)

#define stdString_CopyBetweenDelimiter_ADDR (0x0048c2d0)
#define stdString_CharToWchar_ADDR (0x0048c340)
#define stdString_WcharToChar_ADDR (0x0048c380)

char* stdString_removeTEXTTag(char* str);

char* stdString_CopyBetweenDelimiter(char* instr, char* outstr, int out_size, char* find_str);
int stdString_CharToWchar(wchar_t* wstr, char* str, int param_3);
int stdString_WcharToChar(char* str, wchar_t* wstr, int param_3);

#endif // STDSTRING_H
