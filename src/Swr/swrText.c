#include "swrText.h"

#include "types.h"
#include "globals.h"

#include <macros.h>

#include <stdio.h>

// 0x00407b00
char* swrText_GetKeyNameText(int id, char* str)
{
    HANG("TODO");
    return NULL;
}

// 0x004208e0 HOOK
void swrText_FormatPodName(int podIndex, char* out_buffer, size_t count)
{
    char* lastname;
    char* name;

    lastname = swrText_Translate(swrRacer_PodData[podIndex].lastname);
    name = swrText_Translate(swrRacer_PodData[podIndex].name);
    snprintf(out_buffer, count, "%s %s", name, lastname);
}

// 0x00421120
int swrText_ParseRacerTab(char* filepath)
{
    HANG("TODO: missing stdlib function");
    return 0;
}

// 0x004212f0 HOOK
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

// 0x00421330 HOOK
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

// 0x00450280
void DrawTextEntries()
{
    HANG("TODO");
}

// 0x004502B0
void DrawTextEntries2()
{
    HANG("TODO");
}

// 0x004503e0 HOOK
void swrText_CreateEntry(short x, short y, char r, char g, char b, char a, char* screenText, int formatInt, int isEntry2)
{
    if (isEntry2 == 0)
    {
        if (swrTextEntries1Count < 128)
        {
            if (formatInt < 0)
            {
                // DAT_004b2304 = "%s"
                sprintf((char*)&swrTextEntries1Text[swrTextEntries1Count],swrTextFmtString1,screenText);
            }
            else
            {
                // DAT_004c3e48 = "~f%d%s"
                sprintf((char*)&swrTextEntries1Text[swrTextEntries1Count],swrTextFmtString2,formatInt, screenText);
            }
            swrTextEntries1Pos[swrTextEntries1Count][0] = x;
            swrTextEntries1Pos[swrTextEntries1Count][1] = y;
            swrTextEntries1Colors[swrTextEntries1Count][0] = r;
            swrTextEntries1Colors[swrTextEntries1Count][1] = g;
            swrTextEntries1Colors[swrTextEntries1Count][2] = b;
            swrTextEntries1Colors[swrTextEntries1Count][3] = a;
            swrTextEntries1Count = swrTextEntries1Count + 1;
            return;
        }
    }
    else if (swrTextEntries2Count < 32)
    {
        if (formatInt < 0)
        {
            // DAT_004b2304 = "%s"
            sprintf((char*)&swrTextEntries2Text[swrTextEntries2Count],swrTextFmtString1,screenText);
        }
        else
        {
            // DAT_004c3e48 = "~f%d%s"
            sprintf((char*)&swrTextEntries2Text[swrTextEntries2Count],swrTextFmtString2, formatInt, screenText);
        }
        swrTextEntries2Pos[swrTextEntries2Count][0] = x;
        swrTextEntries2Pos[swrTextEntries2Count][1] = y;
        swrTextEntries2Colors[swrTextEntries2Count][0] = r;
        swrTextEntries2Colors[swrTextEntries2Count][1] = g;
        swrTextEntries2Colors[swrTextEntries2Count][2] = b;
        swrTextEntries2Colors[swrTextEntries2Count][3] = a;
        swrTextEntries2Count = swrTextEntries2Count + 1;
    }
}

// 0x00450530 HOOK
void swrText_CreateTextEntry1(int x, int y, int r, int g, int b, int a, char* screenText)
{
    swrText_CreateEntry(x, y, r, g, b, a, screenText, -1, 0);
}

// 0x00450560 TODO: crashes on release, works fine on debug
void swrText_CreateColorlessEntry1(short x, short y, char* screenText)
{
    swrText_CreateEntry(x, y, -1, -1, -1, -1, screenText, -1, 0);
}

// 0x00450590 TODO: crashes on release, works fine on debug
void swrText_CreateColorlessFormattedEntry1(int formatInt, short x, short y, char* screenText)
{
    swrText_CreateEntry(x, y, -1, -1, -1, -1, screenText, formatInt, 0);
}

// 0x004505c0 TODO: crashes on release, works fine on debug
void swrText_CreateEntry2(short x, short y, char r, char g, char b, char a, char* screenText)
{
    swrText_CreateEntry(x, y, r, g, b, a, screenText, -1, 1);
}

// 0x004505f0 HOOK
void swrText_CreateTimeEntryFormat(int x, int y, int unused, int r, int g, int b, int a, int bFormat)
{
    char* screen_text;

    if (bFormat != 0)
    {
        screen_text = swrText_Translate("~r~s");
        swrText_CreateTimeEntryPrecise(x, y, unused, r, g, b, a, screen_text);
        return;
    }
    screen_text = swrText_Translate("~s");
    swrText_CreateTimeEntryPrecise(x, y, unused, r, g, b, a, screen_text);
}

// 0x00450670
void swrText_CreateTimeEntry(int x, int y, int unused, int r, int g, int b, int a, char* screenText)
{
    // Notice the %.2d instead of the %.3d from Precise version
    HANG("TODO");
    int todo = 0;
    char buffer[256];
    int mins = 0;
    int secs = 0;
    int mills = 0;

    if (todo)
    {
        sprintf(buffer, "%s%.2d.%.2d", screenText, mins, secs);
    }
    else
    {
        sprintf(buffer, "%s%d:%.2d.%.2d", screenText, mins, secs, mills);
    }
    swrText_CreateTextEntry1(x, y, r, g, b, a, buffer);
}

// 0x00450760
void swrText_CreateTimeEntryPrecise(int x, int y, int unused, int r, int g, int b, int a, char* screenText)
{
    HANG("TODO");
    int todo = 0;
    char buffer[256];
    int mins = 0;
    int secs = 0;
    int mills = 0;

    if (todo)
    {
        sprintf(buffer, "%s%.2d.%.3d", screenText, mins, secs);
    }
    else
    {
        sprintf(buffer, "%s%d:%.2d.%.3d", screenText, mins, secs, mills);
    }
    swrText_CreateTextEntry1(x, y, r, g, b, a, buffer);
}
