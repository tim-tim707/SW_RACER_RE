#include "stdConffile.h"

#include "globals.h"
#include <macros.h>

#include <string.h>

// 0x004877b0 TODO: Crashes on release build, works on debug
int stdConffile_Open(const char* pFilename)
{
    return stdConffile_OpenMode(pFilename, "r");
}

// 0x004877d0
int stdConffile_OpenWrite(char* pFilename)
{
    if (stdConffile_writeFile != NULL)
        return 0;

    stdConffile_writeFile = (*stdPlatform_hostServices_ptr->fileOpen)(pFilename, "wb");
    if (stdConffile_writeFile == NULL)
    {
        stdConffile_writeFile = NULL;
        return 0;
    }
    strncpy(stdConffile_aWriteFilename, pFilename, 0x7f);
    stdConffile_aWriteFilename[0x7f] = '\0';
    return 1;
}

// 0x00487830
int stdConffile_OpenMode(const char* pFilename, const char* openMode)
{
    if (stdConffile_bOpen != 0)
        stdConffile_PushStack();

    // "none" opens a conffile context with no backing file (in-memory only)
    if (strcmp(pFilename, "none") == 0)
    {
        stdConffile_openFile = NULL;
    }
    else
    {
        stdConffile_openFile = (*stdPlatform_hostServices_ptr->fileOpen)(pFilename, openMode);
        if (stdConffile_openFile == NULL)
        {
            stdConffile_openFile = NULL;
            if (stdConffile_bOpen != 0)
                stdConffile_PopStack();
            return 0;
        }
    }

    stdConffile_g_aLine = (*stdPlatform_hostServices_ptr->alloc)(0x1000);
    strncpy(stdConffile_pFilename, pFilename, 0x7f);
    stdConffile_pFilename[0x7f] = '\0';
    stdConffile_linenum = 0;
    stdConffile_bOpen = 1;
    return 1;
}

// 0x00487900
void stdConffile_Close(void)
{
    if (stdConffile_bOpen != 0)
    {
        if (stdConffile_openFile != NULL)
            (*stdPlatform_hostServices_ptr->fileClose)(stdConffile_openFile);
        stdConffile_openFile = NULL;
        (*stdPlatform_hostServices_ptr->free)(stdConffile_g_aLine);
        if (stdConffile_stackLevel != 0)
        {
            stdConffile_PopStack();
            return;
        }
        stdConffile_bOpen = 0;
    }
}

// 0x00487960
void stdConffile_CloseWrite(void)
{
    if (stdConffile_writeFile != NULL)
    {
        (*stdPlatform_hostServices_ptr->fileClose)(stdConffile_writeFile);
        stdConffile_writeFile = NULL;
        strncpy(stdConffile_aWriteFilename, "NOT_OPEN", 0x7f);
        stdConffile_aWriteFilename[0x7f] = '\0';
    }
}

// 0x00487a50
int stdConffile_ReadArgsFromStr(char* pStr)
{
    int n = 0;
    stdConffile_g_entry.numArgs = 0;

    char* tok = strtok(pStr, ", \t\n\r");
    if (tok == NULL)
    {
        stdConffile_g_entry.numArgs = 0;
        return 0;
    }

    do
    {
        if (n >= 512)
            return 1;

        char* eq = strchr(tok, '=');
        if (eq == NULL)
        {
            stdConffile_g_entry.aArgs[n].argName = tok;
            stdConffile_g_entry.aArgs[n].argValue = tok;
        }
        else
        {
            *eq = '\0';
            stdConffile_g_entry.aArgs[n].argName = tok;
            stdConffile_g_entry.aArgs[n].argValue = eq + 1;
        }
        n++;
        tok = strtok(NULL, ", \t\n\r");
    } while (tok != NULL);

    stdConffile_g_entry.numArgs = n;
    return 0;
}

// 0x00487ae0
int stdConffile_ReadArgs(void)
{
    if (stdConffile_ReadLine() == 0)
        return 0;

    while (stdConffile_ReadArgsFromStr(stdConffile_g_aLine) == 0)
    {
        if (stdConffile_g_entry.numArgs != 0)
            return 1;
        if (stdConffile_ReadLine() == 0)
            return 0;
    }
    return 0;
}

// 0x00487b20
int stdConffile_ReadLine(void)
{
    bool done = false;
    size_t remaining = 0xfff;
    char* str = stdConffile_g_aLine;

    do
    {
        if (remaining == 0)
            return 1;

        if ((*stdPlatform_hostServices_ptr->fileGets)(stdConffile_openFile, str, remaining) == NULL)
            return 0;

        stdConffile_linenum++;

        char first = *str;
        if (first != ';' && first != '#' && first != '\n' && first != '\r')
        {
            char* comment = strchr(str, '#');
            if (comment != NULL)
                *comment = '\0';
            strlwr(str);

            size_t len = strlen(stdConffile_g_aLine);
            if (stdConffile_g_aLine[len - 2] == '\\')
            {
                // trailing backslash: continuation, keep reading over the backslash
                remaining = 0x1000 - len;
                str = stdConffile_g_aLine + (len - 2);
            }
            else
            {
                done = true;
                if (stdConffile_g_aLine[len - 1] == '\r' || stdConffile_g_aLine[len - 1] == '\n')
                    stdConffile_g_aLine[len - 1] = '\0';
            }
        }

        if (done)
            return 1;
    } while (true);
}

// 0x00487c00
void stdConffile_PushStack(void)
{
    strcpy(stdConffile_aFilenameStack[stdConffile_stackLevel], stdConffile_pFilename);
    stdConffile_linenumStack[stdConffile_stackLevel] = stdConffile_linenum;
    stdConffile_linenum = 0;
    stdConffile_apBufferStack[stdConffile_stackLevel] = stdConffile_g_aLine;
    stdConffile_openFileStack[stdConffile_stackLevel] = stdConffile_openFile;
    stdConffile_openFile = NULL;
    stdConffile_aEntryStack[stdConffile_stackLevel] = stdConffile_g_entry;
    stdConffile_stackLevel++;
}

// 0x00487c90
void stdConffile_PopStack(void)
{
    if (stdConffile_stackLevel != 0)
    {
        int level = stdConffile_stackLevel - 1;
        strcpy(stdConffile_pFilename, stdConffile_aFilenameStack[level]);
        stdConffile_stackLevel = level;
        stdConffile_openFile = stdConffile_openFileStack[level];
        stdConffile_linenum = stdConffile_linenumStack[level];
        stdConffile_g_aLine = stdConffile_apBufferStack[level];
        stdConffile_g_entry = stdConffile_aEntryStack[level];
    }
}
