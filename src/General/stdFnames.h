#ifndef STDFNAMES_H
#define STDFNAMES_H

#include "types.h"

#define stdFnames_FindMedName_ADDR (0x004845b0)
#define stdFnames_FindExt_ADDR (0x004845e0)
#define stdFnames_ChangeExt_ADDR (0x00484600)
#define stdFnames_StripExtAndDot_ADDR (0x00484670)
#define stdFnames_Concat_ADDR (0x00484690)
#define stdFnames_MakePath_ADDR (0x004846e0)

char* stdFnames_FindMedName(char* path);
char* stdFnames_FindExt(char* path);
int stdFnames_ChangeExt(char* str, char* ext);
char* stdFnames_StripExtAndDot(char* str);
char* stdFnames_Concat(char* left, char* right, int bufferLen);
void stdFnames_MakePath(char* str, int bufferLen, char* str2, char* extension);

#endif // STDFNAMES_H
