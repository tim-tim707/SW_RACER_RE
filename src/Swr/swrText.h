#ifndef SWRTEXT_H
#define SWRTEXT_H

#define swrText_ParseRacerTab_ADDR (0x00421120)
#define swrText_CmpRacerTab_ADDR (0x004212f0)
#define swrText_Shutdown_ADDR (0x00421330)
#define swrText_Translate_ADDR (0x00421360)

int swrText_ParseRacerTab(char* filepath);
int swrText_CmpRacerTab(char** a, char** b);
void swrText_Shutdown(void);
char* swrText_Translate(char* text);

#endif // SWRTEXT_H
