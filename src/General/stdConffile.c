#include "stdConffile.h"

// 0x004877b0
int stdConffile_Open(const char* pFilename)
{
    stdConffile_OpenMode(pFilename, "r");
}

// 0x004877d0
int stdConffile_OpenWrite(char* pFilename)
{
    HANG("TODO");
}

// 0x00487830
int stdConffile_OpenMode(const char* pFilename, const char* openMode)
{
    HANG("TODO");
}

// 0x00487900
void stdConffile_Close(void)
{
    HANG("TODO");
}

// 0x00487960
void stdConffile_CloseWrite(void)
{
    HANG("TODO");
}

// 0x00487a50
int stdConffile_ReadArgsFromStr(char* pStr)
{
    HANG("TODO");
}

// 0x00487ae0
int stdConffile_ReadArgs()
{
    HANG("TODO");
}

// 0x00487b20
int stdConffile_ReadLine(void)
{
    HANG("TODO");
}

// 0x00487c00
void stdConffile_PushStack(void)
{
    HANG("TODO");
}

// 0x00487c90
void stdConffile_PopStack(void)
{
    HANG("TODO");
}
