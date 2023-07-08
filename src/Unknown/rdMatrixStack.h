#ifndef UNKNOWN_H
#define UNKNOWN_H

#include "rdMatrix.h"

#define RDMATRIX_STACK_SIZE_MAX (0x21)
int rdMatrixStack44_size; // 0x0050c5e8
rdMatrix44 rdMatrixStack44[RDMATRIX_STACK_SIZE_MAX]; // 0x00e985c0

int rdMatrixStack34_size; // 0x0050c6f4
rdMatrix34 rdMatrixStack34[RDMATRIX_STACK_SIZE_MAX]; // 0x00e375c0
int rdMatrixStack34_modified; // 0x004c3c0c

#define rdMatrixStack44_Init_ADDR (0x00445150)
#define rdMatrixStack44_Push_ADDR (0x00445200)
#define rdMatrixStack44_Peek_ADDR (0x00445500)
#define rdMatrixStack44_Pop_ADDR (0x00445630)

void rdMatrixStack44_Init(void);
void rdMatrixStack44_Push(rdMatrix44* in);
void rdMatrixStack44_Peek(rdMatrix44* out);
void rdMatrixStack44_Pop(void);

#endif // UNKNOWN_H
