#include "swrText.h"

#include "types.h"
#include "globals.h"
#include "engine_config.h"
#include "swrSprite.h"
#include "swr.h"
#include "swrRender.h"

#include <macros.h>
#include <General/utils.h>
#include <Engine/rdMaterial.h>

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

// 0x0044fcc0
void swrText_ResetOverlayDrawQueues(void)
{
    numMiniMapPositions = 0;
    swrTextEntries1Count = 0;
    swrTextEntries2Count = 0;
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

// 0x0042d720
void swrText_InitFonts(void)
{
    // conversion order is retail's: fonts 3, 0, 1, 2, 4
    static const int order[] = { 3, 0, 1, 2, 4 };
    uint8_t* palette = NULL;
    int f;
    int i;

    for (f = 0; f < (int)(sizeof(order) / sizeof(order[0])); f++) {
        swrFont* font = &swrText_fonts[order[f]];
        for (i = 0; i < font->pageCount; i++)
            swrModel_ConvertTextureDataToRdMaterial(swrTexelFormat_IA, swrTexelSize_4BIT, SWR_FONT_PAGE_WIDTH, SWR_FONT_PAGE_HEIGHT, SWR_FONT_PAGE_WIDTH, SWR_FONT_PAGE_HEIGHT, &font->pages[i], &palette, 1, 0);
    }
    swrText_fontCount = SWR_FONT_SLOT_COUNT;
    swrText_fontsByIndex[0] = &swrText_fonts[3];
    swrText_fontsByIndex[1] = &swrText_fonts[2];
    swrText_fontsByIndex[2] = &swrText_fonts[1];
    swrText_fontsByIndex[3] = &swrText_fonts[2];
    swrText_fontsByIndex[4] = &swrText_fonts[4];
    swrText_fontsByIndex[5] = &swrText_fonts[3];
    swrText_fontsByIndex[6] = &swrText_fonts[0];
    swrText_currentFont = &swrText_fonts[3];
}

// 0x0042d8d0
void swrText_SetCurrentFont(int fontIndex)
{
    short index = (short)fontIndex;
    if (index >= swrText_fontCount)
        index = (short)(swrText_fontCount - 1);
    if (index < 0)
        index = 0;
    swrText_currentFont = swrText_fontsByIndex[index];
}

// 0x0042d900
void swrText_SetFont(int fontIndex)
{
    swrText_SetCurrentFont(fontIndex);
}

// 0x0042ddf0
void swrText_BindFontPage(void* font, int page)
{
    swrFont* f = (swrFont*)font;
    if (page < f->pageCount)
        rdModel_SetCurrentMaterial((RdMaterial*)f->pages[page]); // faithful: the call pushes two extra ignored 1s
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

// 0x0044fd50
void swrText_UpdateTimedMessage(void)
{
    double slide;
    float drop;
    int16_t x;
    int16_t y;

    if (swrText_timedMessageTimer <= 0.0f)
        return;
    if (swrText_timedMessageBuffer[0] != 0) {
        // drops away during its last quarter second
        slide = swrText_timedMessageTimer * 4.0;
        if (slide > 1.0)
            slide = 1.0f;
        drop = (float)(1.0 - slide);
        if (swrText_timedMessageAlpha > 0.0f) {
            uint8_t fade = (uint8_t)(int)(swrText_timedMessageAlpha * 255.0f);
            swrSprite_setCurrentSpriteColor(fade, 0xff, fade, 0xff);
        } else {
            swrSprite_setCurrentSpriteColor(0, (uint8_t)(int)((long double)swrUtils_Rand() * SWR_CTL_RAND_NORM * 55.0f - -200.0f), 0, 0xff);
        }
        swrSprite_setCurrentTextPos(0x1a, (int16_t)(int)(drop * 20.0f - -215.0f));
        swrText_RenderString(swrText_timedMessageBuffer);
        if (swrText_timedMessageCentered != 0) {
            swrSprite_setCurrentSpriteColor(0, (uint8_t)(int)(swrText_timedMessageBlink * 255.0), 0, 0xff);
            swrSprite_getCurrentTextPos(&x, &y);
            swrSprite_setCurrentTextPos(x, y + 5);
            swrText_RenderString("-");
        }
        swrText_timedMessageBlink = (float)(swrText_timedMessageBlink - (swrRace_deltaTimeSecs + swrRace_deltaTimeSecs));
        swrText_timedMessageAlpha = (float)(swrText_timedMessageAlpha - (swrRace_deltaTimeSecs + swrRace_deltaTimeSecs));
        if (swrText_timedMessageBlink < 0.0f)
            swrText_timedMessageBlink = 1.0f;
    }
    swrText_timedMessageTimer = (float)(swrText_timedMessageTimer - swrRace_deltaTimeSecs);
}

// 0x00450100
void swrText_RenderEntries1(void)
{
    for (int i = 0; i < swrTextEntries1Count; i++) {
        swrSprite_setCurrentSpriteColor(swrTextEntries1Colors[i][0], swrTextEntries1Colors[i][1], swrTextEntries1Colors[i][2], swrTextEntries1Colors[i][3]);
        swrSprite_setCurrentTextPos(swrTextEntries1Pos[i][0], swrTextEntries1Pos[i][1]);
        // swrText_SetEntryClipRect stores entry i's clip one slot up, at [i + 1]; the enable flag is never cleared
        if (swrTextEntries1ClipEnabled[i + 1] != 0) {
            swrText_clipEnabled = 1;
            swrText_clipLeft = swrTextEntries1ClipRect[i + 1][0];
            swrText_clipTop = swrTextEntries1ClipRect[i + 1][1];
            swrText_clipRight = swrTextEntries1ClipRect[i + 1][2];
            swrText_clipBottom = swrTextEntries1ClipRect[i + 1][3];
        }
        swrText_RenderString(swrTextEntries1Text[i]);
        swrText_clipEnabled = 0;
    }
    swrTextEntries1Count = 0;
}

// 0x004501f0
void swrText_RenderEntries2(void)
{
    for (int i = 0; i < swrTextEntries2Count; i++) {
        swrSprite_setCurrentSpriteColor(swrTextEntries2Colors[i][0], swrTextEntries2Colors[i][1], swrTextEntries2Colors[i][2], swrTextEntries2Colors[i][3]);
        swrSprite_setCurrentTextPos(swrTextEntries2Pos[i][0], swrTextEntries2Pos[i][1]);
        swrText_RenderString(swrTextEntries2Text[i]);
    }
    swrTextEntries2Count = 0;
}

// 0x00450280
void swrText_DrawEntries1()
{
    if (numMiniMapPositions < 1 && swrTextEntries1Count < 1)
        return;
    swrSprite_ResetCurrentMaterial();
    swrText_RenderEntries1();
    swrSprite_RenderMiniMapDotsAndCrosses();
    swr_noop2();
}

// 0x004502B0
void swrText_DrawEntries2()
{
    if (swrText_timedMessageTimer <= 0.0f && swrTextEntries2Count < 1)
        return;
    swrSprite_ResetCurrentMaterial();
    swrText_UpdateTimedMessage();
    swrText_RenderEntries2();
    swr_noop2();
}

// 0x004502f0
void swrText_ClearEntryClipRects(void)
{
    // slot 0 is never used: clips are stored one slot up
    for (int i = 1; i <= SWR_TEXT_MAX_ENTRIES; i++)
        swrTextEntries1ClipEnabled[i] = 0;
}

// 0x00450310
void swrText_SetEntryClipRect(int* rect)
{
    int count = swrTextEntries1Count;

    // design-space rect (640x480) -> screen; stored at the current count, i.e. for the next entry
    if (count >= SWR_TEXT_MAX_ENTRIES || count == 0 || rect == NULL)
        return;
    swrTextEntries1ClipEnabled[count] = 1;
    swrTextEntries1ClipRect[count][0] = rect[0] * swrDisplay_screenWidth / SWR_UI_DESIGN_WIDTH;
    swrTextEntries1ClipRect[count][1] = rect[1] * swrDisplay_screenHeight / SWR_UI_DESIGN_HEIGHT;
    swrTextEntries1ClipRect[count][2] = rect[2] * swrDisplay_screenWidth / SWR_UI_DESIGN_WIDTH;
    swrTextEntries1ClipRect[count][3] = rect[3] * swrDisplay_screenHeight / SWR_UI_DESIGN_HEIGHT;
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

typedef struct swrTextQuad
{
    short originX;
    short originY;
    short width;
    short height;
    short u;
    short v;
} swrTextQuad;

static void swrText_LoadQuad(swrTextQuad* quad, const swrTextGlyph* glyph)
{
    quad->originX = glyph->originX;
    quad->originY = glyph->originY;
    quad->width = glyph->width;
    quad->height = glyph->height;
    quad->u = glyph->u;
    quad->v = glyph->v;
}

static void swrText_EmitQuad(short x, short y, const swrTextQuad* quad)
{
    // faithful: retail also pushes the glyph's unk01 (0 when font->unk00 is set) as an ignored 9th argument
    rdProcEntry_Add2DQuad2(x, y, quad->originX, quad->originY, quad->width, quad->height, quad->u, quad->v);
}

// black "~o" outline / "~s" shadow / "~k" thick quads drawn under a glyph
static void swrText_EmitStyleQuads(short x, short y, int outline, int shadow, int thick, const swrTextQuad* quad)
{
    if (outline) {
        rdProcEntry_SetCurrentColor(0, 0, 0, 0, 0, currentSpriteColor[3]);
        swrText_EmitQuad(x - 1, y - 1, quad);
        swrText_EmitQuad(x + 1, y + 1, quad);
        swrText_EmitQuad(x + 1, y - 1, quad);
        swrText_EmitQuad(x - 1, y + 1, quad);
        swrText_EmitQuad(x - 1, y, quad);
        swrText_EmitQuad(x + 1, y, quad);
        swrText_EmitQuad(x, y - 1, quad);
        swrText_EmitQuad(x, y + 1, quad);
    } else if (shadow) {
        rdProcEntry_SetCurrentColor(0, 0, 0, 0, 0, currentSpriteColor[3]);
        swrText_EmitQuad(x + 1, y + 1, quad);
    } else if (thick) {
        rdProcEntry_SetCurrentColor(0, 0, 0, 0, 0, currentSpriteColor[3]);
        swrText_EmitQuad(x - 1, y, quad);
        swrText_EmitQuad(x + 1, y, quad);
        swrText_EmitQuad(x, y - 1, quad);
        swrText_EmitQuad(x, y + 1, quad);
    } else {
        return;
    }
    rdProcEntry_SetCurrentColor(0, 0, currentSpriteColor[0], currentSpriteColor[1], currentSpriteColor[2], currentSpriteColor[3]);
}

// 0x0042e150
void swrText_DrawString(char* text, void* font, short pass)
{
    swrFont* f = (swrFont*)font;
    short startX = currentTextPosX;
    short x = currentTextPosX;
    short y = currentTextPosY;
    int outline = 0;
    int shadow = 0;
    int thick = 0;
    int boldSegment = 0;
    int i = 0;
    // retail leaves these uninitialized; a glyph with u == -1 reuses the previous glyph's quad
    swrTextQuad quad = { 0 };
    swrTextQuad extQuad = { 0 };
    short extX = 0;
    short extY = 0;

    swrText_BindFontPage(font, pass);
    while (text[i] != '\0' && boldSegment <= swrText_boldSegment) {
        uint8_t c = text[i];
        uint16_t advance = 0;
        short page;
        short extPage = SWR_TEXT_PAGE_NO_ACCENT;

        swrText_orientation = c;
        if (c == '~') {
            char code;
            i++;
            code = text[i];
            switch (code) {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                c = 0;
                swrSprite_setCurrentSpriteColor(swrText_paletteColors[code - '0'][0], swrText_paletteColors[code - '0'][1], swrText_paletteColors[code - '0'][2], currentSpriteColor[3]);
                rdProcEntry_SetCurrentColor(0, 0, currentSpriteColor[0], currentSpriteColor[1], currentSpriteColor[2], currentSpriteColor[3]);
                break;
            case 'b':
                boldSegment++;
                c = 0;
                break;
            case 'c':
                c = 0;
                x = startX - swrText_GetStringWidth(text + i + 1, swrText_currentFont) / 2;
                currentTextPosX = x;
                break;
            case 'k':
                thick = !thick;
                c = 0;
                break;
            case 'n':
                c = 0;
                currentTextPosX = startX;
                x = startX;
                y += f->lineHeight;
                break;
            case 'o':
                outline = !outline;
                c = 0;
                break;
            case 'p':
                shadow = 0;
                outline = 0;
                thick = 0;
                c = 0;
                break;
            case 'r':
                c = 0;
                x = startX - swrText_GetStringWidth(text + i + 1, swrText_currentFont);
                currentTextPosX = x;
                break;
            case 's':
                shadow = !shadow;
                c = 0;
                break;
            case 't':
                c = '~';
                break;
            case '~':
                c = 0; // faithful: "~~" draws nothing (GetStringWidth counts it as a '~'); "~t" is the literal
                break;
            default:
                c = code;
                break;
            }
        }

        if (swrText_hasBoldCode == 0 || boldSegment == swrText_boldSegment) {
            // extended (accented) characters: draw the accent glyph, then fall through to the base char
            if (c > 0x96 && f->extGlyphs != NULL && swrText_extCharComposeIndex[c - 0x97] != 0xff) {
                int row = swrText_extCharComposeIndex[c - 0x97] * 2;
                uint8_t slot = swrText_extCharComposePairs[row];
                if (slot != 0xff) {
                    swrTextGlyph* glyph = &f->extGlyphs[slot];
                    if (glyph->u == -1) {
                        extPage = SWR_TEXT_PAGE_NONE;
                    } else {
                        extPage = glyph->page;
                        swrText_LoadQuad(&quad, glyph);
                    }
                    extQuad = quad;
                    extX = x;
                    extY = y;
                    if (extPage == pass)
                        swrText_EmitStyleQuads(x, y, outline, shadow, thick, &quad);
                    c = swrText_extCharComposePairs[row + 1];
                    if (c == 0xff) {
                        advance = glyph->advance;
                        c = 0;
                    }
                } else {
                    c = swrText_extCharComposePairs[row + 1];
                    if (c == 0xff)
                        c = 0;
                }
            }

            if (c == 0) {
                page = SWR_TEXT_PAGE_NONE;
            } else {
                if (c == '_')
                    c = ' ';
                if (c >= 'a' && c <= 'z' && f->lastChar < 'a')
                    c -= 'a' - 'A';
                if (f->glyphs != NULL && c >= f->firstChar && c <= f->lastChar) {
                    swrTextGlyph* glyph = &f->glyphs[c - f->firstChar];
                    advance = glyph->advance;
                    if (glyph->u == -1) {
                        page = SWR_TEXT_PAGE_NONE;
                    } else {
                        page = glyph->page;
                        swrText_LoadQuad(&quad, glyph);
                    }
                } else {
                    page = SWR_TEXT_PAGE_NONE;
                    advance = 0;
                }
            }

            if (c != 0 && page == pass) {
                swrText_EmitStyleQuads(x, y, outline, shadow, thick, &quad);
                swrText_EmitQuad(x, y, &quad);
            }
            if (extPage == pass)
                swrText_EmitQuad(extX, extY, &extQuad);
            x += advance;
        }
        i++;
    }
    previousTextPosX = x;
    previousTextPosY = y;
}

// 0x0042ec50
void swrText_RenderString(char* text)
{
    int16_t savedX;
    int16_t savedY;
    int start;
    int pass;
    int i;

    swrText_SetCurrentFont(0);
    swrText_bboxMinX = SWR_TEXT_BBOX_RESET;
    swrText_bboxMaxX = -SWR_TEXT_BBOX_RESET;
    swrText_hasBoldCode = 0;
    for (i = 0; text[i] != '\0' && swrText_hasBoldCode == 0; i++) {
        if (text[i] == '~' && text[i + 1] == 'b') {
            swrText_hasBoldCode = 1;
        }
    }
    start = 0;
    if (text[0] == '~' && text[1] == 'f') {
        swrText_SetCurrentFont((short)text[2] - '0');
        start = 3;
    }
    swrText_halfScale = 0;
    if (text[0] == '~' && text[1] == 'F') {
        swrText_halfScale = 1;
        swrText_SetCurrentFont((short)text[2] - '0');
        start = 3;
    }
    savedX = currentTextPosX;
    savedY = currentTextPosY;
    rdProcEntry_SetCurrentColor(0, 0, currentSpriteColor[0], currentSpriteColor[1], currentSpriteColor[2], currentSpriteColor[3]);
    // each font page is a separate pass over the same string from the same origin
    for (pass = 0; pass < swrText_currentFont->pageCount; pass++) {
        currentTextPosX = savedX;
        currentTextPosY = savedY;
        swrText_DrawString(text + start, swrText_currentFont, (short)pass);
    }
    if (swrText_bboxMinX < swrText_bboxMaxX && swrText_bboxMinY < swrText_bboxMaxY) {
        swrSprite_AddDirtyRect(swrText_bboxMinX, swrText_bboxMinY, swrText_bboxMaxX, swrText_bboxMaxY);
    }
    currentTextPosX = previousTextPosX;
    currentTextPosY = previousTextPosY;
}

// 0x0042edc0
void swrText_SetupGlyph(char c)
{
    swrFont* font;
    swrTextGlyph* glyph;
    int page;

    rdProcEntry_SetCurrentColor(0, 0, currentSpriteColor[0], currentSpriteColor[1], currentSpriteColor[2], currentSpriteColor[3]);
    swrSprite_colorApplied = 1;
    if (c == '_')
        c = ' ';
    font = swrText_currentFont;
    // fonts without lowercase glyphs draw lowercase as uppercase
    if (c >= 'a' && c <= 'z' && font->lastChar < 'a')
        c = c + ('A' - 'a');
    page = SWR_TEXT_PAGE_NONE;
    if (font->glyphs != NULL && c >= font->firstChar && c <= font->lastChar) {
        glyph = &font->glyphs[c - font->firstChar];
        if (glyph->u != -1) {
            swrText_glyphOriginX = glyph->originX;
            page = glyph->page;
            swrText_glyphOriginY = glyph->originY;
            swrText_glyphWidth = glyph->width;
            swrText_glyphHeight = glyph->height;
            swrText_glyphU = glyph->u;
            swrText_glyphV = glyph->v;
            if (font->unk00 == 0)
                swrText_glyphUnk01 = glyph->unk01;
            else
                swrText_glyphUnk01 = 0;
        }
    }
    if (page >= 0)
        swrText_BindFontPage(font, page);
}

static void swrText_EmitGlyphQuad(short x, short y)
{
    // faithful: retail also pushes swrText_glyphUnk01 as a 9th argument, which rdProcEntry_Add2DQuad2 ignores
    rdProcEntry_Add2DQuad2(x, y, swrText_glyphOriginX, swrText_glyphOriginY, swrText_glyphWidth, swrText_glyphHeight, swrText_glyphU, swrText_glyphV);
}

// 0x0042eeb0
void swrText_DrawGlyph(short x, short y, char style)
{
    short left = x - (short)(swrText_glyphWidth / 2);
    short top = (short)(swrText_glyphHeight / 2) + y;

    if (style == 'o') {
        rdProcEntry_SetCurrentColor(0, 0, 0, 0, 0, currentSpriteColor[3]);
        swrText_EmitGlyphQuad(left - 1, top - 1);
        swrText_EmitGlyphQuad(left + 1, top + 1);
        swrText_EmitGlyphQuad(left + 1, top - 1);
        swrText_EmitGlyphQuad(left - 1, top + 1);
        swrText_EmitGlyphQuad(left - 1, top);
        swrText_EmitGlyphQuad(left + 1, top);
        swrText_EmitGlyphQuad(left, top - 1);
        swrText_EmitGlyphQuad(left, top + 1);
    } else if (style == 's') {
        rdProcEntry_SetCurrentColor(0, 0, 0, 0, 0, currentSpriteColor[3]);
        swrText_EmitGlyphQuad(left + 1, top + 1);
    } else if (style == 'f') {
        rdProcEntry_SetCurrentColor(0, 0, 0, 0, 0, currentSpriteColor[3]);
        swrText_EmitGlyphQuad(left - 1, top);
        swrText_EmitGlyphQuad(left + 1, top);
        swrText_EmitGlyphQuad(left, top - 1);
        swrText_EmitGlyphQuad(left, top + 1);
    }
    if (style == 'o' || style == 's' || style == 'f') {
        rdProcEntry_SetCurrentColor(0, 0, currentSpriteColor[0], currentSpriteColor[1], currentSpriteColor[2], currentSpriteColor[3]);
        swrSprite_colorApplied = 1;
    }
    if (swrSprite_colorApplied == 0) {
        rdProcEntry_SetCurrentColor(0, 0, currentSpriteColor[0], currentSpriteColor[1], currentSpriteColor[2], currentSpriteColor[3]);
        swrSprite_colorApplied = 1;
    }
    swrText_EmitGlyphQuad(left, top);
}

// 0x0042e0e0
void swrText_GetCharSize(char c, void* font, int* outWidth, int* outHeight)
{
    swrFont* f;
    swrTextGlyph* glyph;
    int width;
    int height;

    f = (swrFont*)font;
    if (outWidth != NULL) {
        *outWidth = -1;
    }
    if (outHeight != NULL) {
        *outHeight = -1;
    }

    // Faithful: a missing glyph reports the char argument itself as both width and height.
    width = c;
    height = c;
    if (f->glyphs != NULL && c >= f->firstChar && c <= f->lastChar) {
        glyph = &f->glyphs[c - f->firstChar];
        width = glyph->advance;
        height = glyph->height;
    }
    if (outWidth != NULL) {
        *outWidth = width;
    }
    if (outHeight != NULL) {
        *outHeight = height;
    }
}
