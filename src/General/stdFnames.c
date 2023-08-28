#include "stdFnames.h"

// 0x00484690
char* stdFnames_Concat(char* left, char* right, int bufferLen)
{
    int len_;

    int lenPlusOne = _strlen(left) + 1;
    len_ = lenPlusOne - 1;

    if (left[lenPlusOne - 2] != '\\' && len_ < bufferLen - 1 && left[0] != '\0')
    {
        left[len_] = '\\';
        left[lenPlusOne] = '\0';
        len_ = lenPlusOne;
    }

    _strncat(left, right, bufferLen - len_ - 1);
    return left;
}

// 0x004846e0
void stdFnames_MakePath(char* str, int bufferLen, char* str2, char* extension)
{
    _strncpy(str, str2, bufferLen - 1);
    str[bufferLen - 1] = '\0';
    stdFnames_Concat(str, extension, bufferLen);
}
