#ifndef STDCONFFILE_H
#define STDCONFFILE_H

#include "types.h"

#define stdConffile_Open_ADDR (0x004877b0)

#define stdConffile_OpenWrite_ADDR (0x004877d0)

#define stdConffile_OpenMode_ADDR (0x00487830)

#define stdConffile_Close_ADDR (0x00487900)

#define stdConffile_CloseWrite_ADDR (0x00487960)

#define stdConffile_ReadArgsFromStr_ADDR (0x00487a50)

#define stdConffile_ReadArgs_ADDR (0x00487ae0)

#define stdConffile_ReadLine_ADDR (0x00487b20)

#define stdConffile_PushStack_ADDR (0x00487c00)

#define stdConffile_PopStack_ADDR (0x00487c90)

int stdConffile_Open(const char* pFilename);

int stdConffile_OpenWrite(char* pFilename);

int stdConffile_OpenMode(const char* pFilename, const char* openMode);

void stdConffile_Close(void);

void stdConffile_CloseWrite(void);

int stdConffile_ReadArgsFromStr(char* pStr);

int stdConffile_ReadArgs();

int stdConffile_ReadLine(void);

void stdConffile_PushStack(void);

void stdConffile_PopStack(void);

#endif // STDCONFFILE_H
