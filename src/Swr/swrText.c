#include "swrText.h"

#include "types.h"
#include "globals.h"

// 0x00407b00
char* swrText_GetKeyNameText(uint32_t id, char* str)
{
    HANG("TODO");
    return NULL;
}

// 0x00421120
int swrText_ParseRacerTab(char* filepath)
{
    HANG("TODO: missing stdlib function");
    return 0;
}

// 0x004212f0
int swrText_CmpRacerTab(char** a, char** b)
{
    char* a_;
    char* b_;
    int cmp;
    char a_0;

    b_ = (char*)*b;
    a_ = (char*)*a;
    while (1)
    {
        a_0 = *a_;
        cmp = a_0 < *b_;
        if (a_0 != *b_)
            break;
        if (a_0 == 0)
        {
            return 0;
        }
        a_0 = a_[1];
        cmp = a_0 < b_[1];
        if (a_0 != b_[1])
            break;
        a_ = a_ + 2;
        b_ = b_ + 2;
        if (a_0 == 0)
        {
            return 0;
        }
    }
    return (1 - (uint32_t)cmp) - (uint32_t)(cmp != 0);
}

// 0x00421330
void swrText_Shutdown(void)
{
    if (swrText_racerTab_buffer != NULL)
    {
        (*stdPlatform_hostServices_ptr->free)(swrText_racerTab_buffer);
    }
    if (swrText_racerTab_array != NULL)
    {
        (*stdPlatform_hostServices_ptr->free)(swrText_racerTab_array);
    }
}

// 0x00421360
char* swrText_Translate(char* text)
{
    HANG("TODO");
    return NULL;
}

// 0x004503e0
void swrText_CreateEntry(short x, short y, char r, char g, char b, char a, char* screenText, int formatInt, int isEntry2)
{
    HANG("TODO, easy");
}

// 0x00450530
void swrText_CreateTextEntry1(int x, int y, int r, int g, int b, int a, char* screenText)
{
    swrText_CreateEntry(x, y, r, g, b, a, screenText, -1, 0);
}

// 0x00450560
void swrText_CreateColorlessEntry1(short x, short y, char* screenText)
{
    swrText_CreateEntry(x, y, -1, -1, -1, -1, screenText, -1, 0);
}

// 0x00450590
void swrText_CreateColorlessFormattedEntry1(int formatInt, short x, short y, char* screenText)
{
    swrText_CreateEntry(x, y, -1, -1, -1, -1, screenText, formatInt, 0);
}

// 0x004505c0
void swrText_CreateEntry2(short x, short y, char r, char g, char b, char a, char* screenText)
{
    swrText_CreateEntry(x, y, r, g, b, a, screenText, -1, 1);
}
