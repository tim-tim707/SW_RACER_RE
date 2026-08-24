#include "swrText.h"

#include "types.h"
#include "globals.h"

#include <macros.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 0x004208e0
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
    stdFile_t stream;
    unsigned int size;
    int magic;
    char* p;
    char* end;
    char* line;
    char** entry;

    swrText_nbLinesRacerTab = 0;
    stream = (*stdPlatform_hostServices_ptr->fileOpen)(filepath, "rb");
    if (stream == NULL)
        return 1;

    (*stdPlatform_hostServices_ptr->fileRead)(stream, &magic, 4);
    (*stdPlatform_hostServices_ptr->fseek)(stream, 0, SEEK_END);
    size = ftell(stream);
    (*stdPlatform_hostServices_ptr->fseek)(stream, 0, SEEK_SET);
    swrText_racerTab_buffer = (*stdPlatform_hostServices_ptr->alloc)(size);
    (*stdPlatform_hostServices_ptr->fileRead)(stream, swrText_racerTab_buffer, size);
    (*stdPlatform_hostServices_ptr->fileClose)(stream);

    // "RCNE" magic => obfuscated file: real data starts after the 4-byte magic and is XOR 0xdd
    if (magic == 0x454e4352)
    {
        size -= 4;
        for (int i = 0; i < (int) size; i++)
            swrText_racerTab_buffer[i] = swrText_racerTab_buffer[i + 4] ^ 0xdd;
    }

    // count newline-delimited lines
    end = swrText_racerTab_buffer + size;
    p = swrText_racerTab_buffer;
    do
    {
        if (p < end)
        {
            while (p < end && *p != '\r' && *p != '\n')
                p++;
            while (p < end && (*p == '\r' || *p == '\n'))
                p++;
        }
        swrText_nbLinesRacerTab++;
    } while (p < end - 1);

    swrText_racerTab_array = (*stdPlatform_hostServices_ptr->alloc)(swrText_nbLinesRacerTab * 4);

    // split each line: unescape, cut at the first tab, uppercase, record the pointer
    entry = swrText_racerTab_array;
    line = swrText_racerTab_buffer;
    do
    {
        for (p = line; p < swrText_racerTab_buffer + size && *p != '\r' && *p != '\n'; p++)
            ;
        if (p < swrText_racerTab_buffer + size)
        {
            while (p < swrText_racerTab_buffer + size && (*p == '\r' || *p == '\n'))
            {
                *p = '\0';
                p++;
            }
        }
        swrText_UnescapeString(line, line);
        char* tab = strchr(line, '\t');
        if (tab != NULL)
            *tab = '\0';
        strupr(line);
        *entry++ = line;
        line = p;
    } while (p < swrText_racerTab_buffer + (size - 1));

    qsort(swrText_racerTab_array, swrText_nbLinesRacerTab, 4, (int (*)(const void*, const void*)) swrText_CmpRacerTab);
    return 1;
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
    char buffer[256];

    if (text == NULL)
        return NULL;

    if (*text == '/' && strlen(text) >= 2)
    {
        char* afterSecondSlash = strchr(text + 1, '/');
        if (swrText_racerTab_buffer == NULL)
            return afterSecondSlash + 1;

        strncpy(buffer, text + 1, 0xfe);
        char* sep = strchr(buffer, '/');
        if (sep != NULL)
            *sep = '\0';
        strupr(buffer);

        char* key = buffer;
        char** found = bsearch(&key, swrText_racerTab_array, swrText_nbLinesRacerTab, 4,
                               (int (*)(const void*, const void*)) swrText_CmpRacerTab);
        if (found == NULL)
            return afterSecondSlash + 1;

        // the stored entry is "KEY\0VALUE"; return VALUE if it is non-empty
        char* value = *found;
        size_t keyLen = strlen(value);
        if (value[keyLen + 1] != '\0')
            return value + keyLen + 1;
    }
    return text;
}

// Decode C-string escape sequences from src into dest; returns the decoded length.
// 0x004214c0
int swrText_UnescapeString(char* dest, char* src)
{
    char* out = dest;

    while (*src != '\0')
    {
        if (*src != '\\')
        {
            *out++ = *src++;
            continue;
        }

        // octal escape: backslash followed by a digit (\NNN, three octal digits)
        if (src[1] >= '0' && src[1] <= '9')
        {
            unsigned char value = 0;
            for (int i = 1; i < 4; i++)
                value = (unsigned char) (value << 3 | (src[i] - '0'));
            *out++ = (char) value;
            src += 4;
            continue;
        }

        switch (src[1])
        {
        case '"': *out++ = '"'; src += 2; break;
        case '\'': *out++ = '\''; src += 2; break;
        case '?': *out++ = '?'; src += 2; break;
        case '\\': *out++ = '\\'; src += 2; break;
        case 'a': *out++ = '\a'; src += 2; break;
        case 'b': *out++ = '\b'; src += 2; break;
        case 'f': *out++ = '\f'; src += 2; break;
        case 'n': *out++ = '\n'; src += 2; break;
        case 'r': *out++ = '\r'; src += 2; break;
        case 't': *out++ = '\t'; src += 2; break;
        case 'v': *out++ = '\v'; src += 2; break;
        case 'x':
        case 'X':
        {
            char c2 = src[2];
            char c3 = src[3];
            int hi = (c2 >= '0' && c2 <= '9') ? c2 - '0'
                : (c2 >= 'a' && c2 <= 'f')    ? c2 - 'a' + 10
                : (c2 >= 'A' && c2 <= 'F')    ? c2 - 'A' + 10
                                              : -1;
            int lo = (c3 >= '0' && c3 <= '9') ? c3 - '0'
                : (c3 >= 'a' && c3 <= 'f')    ? c3 - 'a' + 10
                : (c3 >= 'A' && c3 <= 'F')    ? c3 - 'A' + 10
                                              : -1;
            if (hi >= 0 && lo >= 0)
            {
                *out++ = (char) (hi << 4 | lo);
                src += 4;
            }
            else if (c2 >= '0' && c2 <= '9')
            {
                *out++ = (char) (c2 - '0');
                src += 3;
            }
            else
            {
                src += 1;
            }
            break;
        }
        default:
            src += 1;
            break;
        }
    }

    *out = '\0';
    return (int) (out - dest);
}

// 0x0044fce0
void swrText_ShowTimedMessage(char* text, float duration)
{
    if (text != NULL && swrText_minTimedMessageDuration < duration) {
        // A leading "~_" marks the message as centered.
        if (text[0] == '~' && text[1] == '_') {
            swrText_timedMessageCentered = 1;
            text += 2;
        } else {
            swrText_timedMessageCentered = 0;
        }
        sprintf(swrText_timedMessageBuffer, swrTextFmtString1, text);
        swrText_timedMessageTimer = duration;
        swrText_timedMessageAlpha = 1.0f;
    }
}

// 0x0042de10
int swrText_GetStringWidthByFont(char* text, int fontIndex)
{
    return swrText_GetStringWidth(text, swrText_fontsByIndex[fontIndex]);
}

// Width of the first line of text (stops at a "~n" newline marker); honors "~" format codes.
// 0x0042de30
int swrText_GetStringWidth(char* text, swrFont* font)
{
    int width = 0;
    int done = 0;
    int i = 0;

    do {
        uint8_t c = text[i];
        if (c == 0)
            done = 1;
        if (c == '~') {
            i++;
            if (text[i] == 'n')
                done = 1;
            else
                c = ((text[i] != '~') - 1) & 0x7e; // "~~" -> literal '~'; any other "~x" code -> skipped
        }
        if (c != 0 && !done) {
            swrTextGlyph* glyph = NULL;
            if (c == '_')
                c = ' ';
            // fold lowercase to uppercase when the font has no lowercase glyphs
            if (c > 0x60 && c < 0x7b && font->lastChar < 0x61)
                c -= 0x20;
            // extended (accented) characters are composed via the lookup tables
            if (c > 0x96 && font->extGlyphs != NULL && swrText_extCharComposeIndex[c - 0x97] != 0xff) {
                int row = swrText_extCharComposeIndex[c - 0x97] * 2;
                int slot = swrText_extCharComposePairs[row];
                c = swrText_extCharComposePairs[row + 1];
                if (c == 0xff) {
                    glyph = &font->extGlyphs[slot];
                    c = 0;
                }
            }
            if (font->glyphs != NULL && font->firstChar <= c && c <= font->lastChar)
                glyph = &font->glyphs[c - font->firstChar];
            if (glyph != NULL)
                width += glyph->advance;
        }
        i++;
    } while (!done);

    return width;
}

// Average glyph height across the glyphs in the string.
// 0x0042df70
int swrText_GetStringHeight(char* text, swrFont* font)
{
    int totalHeight = 0;
    int count = 0;
    int done = 0;
    int i = 0;

    do {
        uint8_t c = text[i];
        if (c == 0)
            done = 1;
        if (c == '~') {
            i++;
            if (text[i] == 'n')
                done = 1;
            else
                c = ((text[i] != '~') - 1) & 0x7e;
        }
        if (c != 0 && !done) {
            swrTextGlyph* glyph = NULL;
            if (c == '_')
                c = ' ';
            if (c > 0x60 && c < 0x7b && font->lastChar < 0x61)
                c -= 0x20;
            if (c > 0x96 && font->extGlyphs != NULL && swrText_extCharComposeIndex[c - 0x97] != 0xff) {
                int row = swrText_extCharComposeIndex[c - 0x97] * 2;
                int slot = swrText_extCharComposePairs[row];
                c = swrText_extCharComposePairs[row + 1];
                if (c == 0xff) {
                    glyph = &font->extGlyphs[slot];
                    c = 0;
                }
            }
            if (font->glyphs != NULL && font->firstChar <= c && c <= font->lastChar)
                glyph = &font->glyphs[c - font->firstChar];
            if (glyph != NULL) {
                totalHeight += glyph->height;
                count++;
            }
        }
        i++;
    } while (!done);

    if (count != 0)
        return totalHeight / count;
    return 0;
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

// 0x004503e0
void swrText_CreateEntry(short x, short y, char r, char g, char b, char a, char* screenText, int formatInt, int isEntry2)
{
    if (isEntry2 == 0)
    {
        if (swrTextEntries1Count < 128)
        {
            if (formatInt < 0)
            {
                // DAT_004b2304 = "%s"
                sprintf((char*)&swrTextEntries1Text[swrTextEntries1Count], swrTextFmtString1, screenText);
            }
            else
            {
                // DAT_004c3e48 = "~f%d%s"
                sprintf((char*)&swrTextEntries1Text[swrTextEntries1Count], swrTextFmtString2, formatInt, screenText);
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
            sprintf((char*)&swrTextEntries2Text[swrTextEntries2Count], swrTextFmtString1, screenText);
        }
        else
        {
            // DAT_004c3e48 = "~f%d%s"
            sprintf((char*)&swrTextEntries2Text[swrTextEntries2Count], swrTextFmtString2, formatInt, screenText);
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

// 0x00450530
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

// 0x004505f0
void swrText_CreateTimeEntryFormat(int x, int y, float time, int r, int g, int b, int a, int bFormat)
{
    char* screen_text;

    if (bFormat != 0)
    {
        screen_text = swrText_Translate("~r~s");
        swrText_CreateTimeEntryPrecise(x, y, time, r, g, b, a, screen_text);
        return;
    }
    screen_text = swrText_Translate("~s");
    swrText_CreateTimeEntryPrecise(x, y, time, r, g, b, a, screen_text);
}

// Format a race time (`time`, in seconds) as [minutes:]seconds.centiseconds and enqueue it as a
// text entry. The centisecond version; swrText_CreateTimeEntryPrecise is identical but resolves
// to milliseconds (%.3d).
// 0x00450670
void swrText_CreateTimeEntry(int x, int y, float time, int r, int g, int b, int a, char* screenText)
{
    char buffer[256];
    float minutesf = time * (1.0f / 60.0f);
    int minutes = (int)minutesf;
    float secondsf = (minutesf - (float)minutes) * 60.0f;
    int seconds = (int)secondsf;
    int centis = (int)((secondsf - (float)seconds + 0.005f) * 100.0f);
    if (centis == 100) {
        centis = 0;
        seconds++;
        if (seconds == 60)
            minutes++;
    }
    if (minutes == 0)
        sprintf(buffer, "%s%.2d.%.2d", screenText, seconds, centis);
    else
        sprintf(buffer, "%s%d:%.2d.%.2d", screenText, minutes, seconds, centis);
    swrText_CreateTextEntry1(x, y, r, g, b, a, buffer);
}

// Format a race time (`time`, in seconds) as [minutes:]seconds.milliseconds and enqueue it as a
// text entry. Millisecond-precision variant of swrText_CreateTimeEntry (%.3d vs %.2d, and a finer
// rounding bias).
// 0x00450760
void swrText_CreateTimeEntryPrecise(int x, int y, float time, int r, int g, int b, int a, char* screenText)
{
    char buffer[256];
    float minutesf = time * (1.0f / 60.0f);
    int minutes = (int)minutesf;
    float secondsf = (minutesf - (float)minutes) * 60.0f;
    int seconds = (int)secondsf;
    int millis = (int)((secondsf - (float)seconds + 0.0005f) * 1000.0f);
    if (millis == 1000) {
        millis = 0;
        seconds++;
        if (seconds == 60)
            minutes++;
    }
    if (minutes == 0)
        sprintf(buffer, "%s%.2d.%.3d", screenText, seconds, millis);
    else
        sprintf(buffer, "%s%d:%.2d.%.3d", screenText, minutes, seconds, millis);
    swrText_CreateTextEntry1(x, y, r, g, b, a, buffer);
}
