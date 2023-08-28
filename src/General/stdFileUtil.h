#ifndef STDFILEUTIL_H
#define STDFILEUTIL_H

#include "types.h"

#define stdFileUtil_NewFind_ADDR (0x00484140)
#define stdFileUtil_DisposeFind_ADDR (0x004841e0)
#define stdFileUtil_FindNext_ADDR (0x00484220)
#define stdFileUtil_MkDir_ADDR (0x00484310)
#define stdFileUtil_DelTree_ADDR (0x00484330)

stdFileSearch* stdFileUtil_NewFind(char* path, int searchMode, char* extension);
void stdFileUtil_DisposeFind(stdFileSearch* search);
int stdFileUtil_FindNext(stdFileSearch* search, stdFileSearchResult* result);
BOOL stdFileUtil_MkDir(LPCSTR lpPathName);
int stdFileUtil_DelTree(LPCSTR lpPathName);

#endif // STDFILEUTIL_H
