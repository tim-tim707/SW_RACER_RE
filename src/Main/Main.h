#ifndef MAIN_MAIN_H
#define MAIN_MAIN_H

#define Main_Startup_ADDR (0x00423cc0)
#define Main_Shutdown_ADDR (0x004240d0)

int Main_Startup(char* cmdline);
void Main_Shutdown(void);

#endif // MAIN_MAIN_H
