#include "stdString.h"

#include <string.h>

// 0x00421470
char* stdString_RemoveTEXTTag(char* str) // /?*/thing -> thing
{
    char cVar1;
    char* actual_text;
    int iVar2;

    if (str == NULL)
    {
        return NULL;
    }
    if (*str == '\0')
    {
        return str;
    }
    if (*str != '/')
    {
        return str;
    }
    iVar2 = -1;
    actual_text = str;
    do
    {
        if (iVar2 == 0) // redondant check
            break;
        iVar2 = iVar2 + -1;
        cVar1 = *actual_text;
        actual_text = actual_text + 1;
    } while (cVar1 != '\0');
    if (iVar2 == -3) // single slash string "/"
    {
        return str;
    }
    actual_text = strchr(str + 1, 0x2f);
    return actual_text + 1;
}

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
    sVar2 = strspn(instr, find_str);
    str = instr + sVar2;
    str_find = strpbrk(str, find_str);
    if (str_find == NULL)
    {
        idk_len = strlen(str);
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
        strncpy(outstr, str, idk_len);
        outstr[idk_len] = '\0';
    }
    return str_find;
}

// 0x0048c340
int stdString_CharToWchar(wchar_t* wstr, char* str, int length)
{
    int res;

    res = 0;
    if (0 < length)
    {
        do
        {
            if (*str == 0)
                break;
            *wstr = (unsigned short)(char)*str;
            wstr = wstr + 1;
            str = str + 1;
            res = res + 1;
        } while (res < length);
    }
    if (res < length)
    {
        *wstr = L'\0';
    }
    return res;
}

// 0x0048c380
int stdString_WcharToChar(char* str, wchar_t* wstr, int length)
{
    int res;

    res = 0;
    if (0 < length)
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
        } while (res < length);
    }
    if (res < length)
    {
        *str = '\0';
    }
    return res;
}
