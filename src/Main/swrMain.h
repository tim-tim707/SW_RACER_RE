#ifndef SWR_MAIN_H
#define SWR_MAIN_H

#define Main_Startup_ADDR (0x00423cc0)
#define Main_Shutdown_ADDR (0x004240d0)

#define Main_ShutdownError_ADDR (0x00424150)

#define Main_ParseCmdLine_ADDR (0x00424430)

int Main_Startup(char* cmdline);
void Main_Shutdown(void);

void Main_ShutdownError(void);
int Main_ParseCmdLine(char* cmdline);

#endif // SWR_MAIN_H
