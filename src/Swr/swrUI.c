#include "swrUI.h"

// 0x004174e0
char* swrUI_replaceAllocatedStr(char* str, char* mondo_text)
{
    size_t len;
    char* res;

    res = NULL;
    if (str != NULL)
    {
        stdlib__free(str);
    }
    if (mondo_text != NULL)
    {
        len = _strlen(mondo_text);
        res = (char*)stdlib__malloc(len);
        _strncpy(res, mondo_text, len - 1);
        res[len - 1] = '\0';
    }
    return res;
}
