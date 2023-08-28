#ifndef STDFNAMES_H
#define STDFNAMES_H

#include "types.h"

#define stdFnames_Concat_ADDR (0x00484690)

#define stdFnames_MakePath_ADDR (0x004846e0)

char* stdFnames_Concat(char* left, char* right, int bufferLen);

void stdFnames_MakePath(char* str, int bufferLen, char* str2, char* extension);

#endif // STDFNAMES_H
