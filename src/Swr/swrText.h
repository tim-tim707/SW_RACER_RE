#ifndef SWRTEXT_H
#define SWRTEXT_H

#include <stddef.h>

#define swrText_GetKeyNameText_ADDR (0x00407b00)

#define swrText_FormatPodName_ADDR (0x004208e0)

#define swrText_ParseRacerTab_ADDR (0x00421120)
#define swrText_CmpRacerTab_ADDR (0x004212f0)
#define swrText_Shutdown_ADDR (0x00421330)
#define swrText_Translate_ADDR (0x00421360)

#define DrawTextEntries_ADDR (0x00450280)
#define DrawTextEntries2_ADDR (0x004502B0)

#define swrText_CreateEntry_ADDR (0x004503e0)

#define swrText_CreateTextEntry1_ADDR (0x00450530)

#define swrText_CreateColorlessEntry1_ADDR (0x00450560)

#define swrText_CreateColorlessFormattedEntry1_ADDR (0x00450590)

#define swrText_CreateEntry2_ADDR (0x004505c0)

#define swrText_CreateTimeEntryFormat_ADDR (0x004505f0)

#define swrText_CreateTimeEntry_ADDR (0x00450670)

#define swrText_CreateTimeEntryPrecise_ADDR (0x00450760)

char* swrText_GetKeyNameText(int id, char* str);

void swrText_FormatPodName(int podIndex, char* out_buffer, size_t count);

int swrText_ParseRacerTab(char* filepath);
int swrText_CmpRacerTab(char** a, char** b);
void swrText_Shutdown(void);
char* swrText_Translate(char* text);

void DrawTextEntries();
void DrawTextEntries2();

void swrText_CreateEntry(short x, short y, char r, char g, char b, char a, char* screenText, int formatInt, int isEntry2);

void swrText_CreateTextEntry1(int x, int y, int r, int g, int b, int a, char* screenText);

void swrText_CreateColorlessEntry1(short x, short y, char* screenText);

void swrText_CreateColorlessFormattedEntry1(int formatInt, short x, short y, char* screenText);

void swrText_CreateEntry2(short x, short y, char r, char g, char b, char a, char* screenText);

void swrText_CreateTimeEntryFormat(int x, int y, int unused, int r, int g, int b, int a, int bFormat);

void swrText_CreateTimeEntry(int x, int y, int unused, int r, int g, int b, int a, char* screenText);

void swrText_CreateTimeEntryPrecise(int x, int y, int unused, int r, int g, int b, int a, char* screenText);

#endif // SWRTEXT_H
