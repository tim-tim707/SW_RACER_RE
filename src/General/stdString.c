#include "stdString.h"

#include <string.h>

// 0x0048c2d0
char* stdString_CopyBetweenDelimiter(char* instr, char* outstr, int out_size, char* find_str)
{
    char cVar1;
    size_t sVar2;
    char* str_find;
    char* str;
    unsigned int idk_len;
    char* retval;

    if (outstr != NULL)
    {
        *outstr = '\0';
    }
    sVar2 = _strspn(instr, find_str);
    str = instr + sVar2;
    str_find = _strpbrk(str, find_str);
    if (str_find == NULL)
    {
        idk_len = _strlen(str);
    }
    else
    {
        idk_len = (int)str_find - (int)str;
    }
    if (out_size - 1U <= idk_len)
    {
        idk_len = out_size - 1U;
    }
    if (outstr != NULL)
    {
        _strncpy(outstr, str, idk_len);
        outstr[idk_len] = '\0';
    }
    return str_find;
}

// 0x0048c340
int stdString_CharToWchar(wchar_t* wstr, char* str, int param_3)
{
    int res;

    res = 0;
    if (0 < param_3)
    {
        do
        {
            if (*str == 0)
                break;
            *wstr = (unsigned short)(char)*str;
            wstr = wstr + 1;
            str = str + 1;
            res = res + 1;
        } while (res < param_3);
    }
    if (res < param_3)
    {
        *wstr = L'\0';
    }
    return;
}

// 0x0048c380
int stdString_WcharToChar(char* str, wchar_t* wstr, int param_3)
{
    int res;

    res = 0;
    if (0 < param_3)
    {
        do
        {
            if (*wstr == L'\0')
                break;
            if ((unsigned short)*wstr < 0x100)
            {
                *str = *(char*)wstr;
            }
            else
            {
                *str = '?';
            }
            wstr = wstr + 1;
            str = str + 1;
            res = res + 1;
        } while (res < param_3);
    }
    if (res < param_3)
    {
        *str = '\0';
    }
    return res;
}
