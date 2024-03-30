#ifndef UNKNOWN_H
#define UNKNOWN_H

#include "Primitives/rdMatrix.h"

#if 0
#define RDMATRIX_STACK_SIZE_MAX (0x21)
int rdMatrixStack44_size; // 0x0050c5e8
rdMatrix44 rdMatrixStack44[RDMATRIX_STACK_SIZE_MAX]; // 0x00e985c0

int rdMatrixStack34_size; // 0x0050c6f4
rdMatrix34 rdMatrixStack34[RDMATRIX_STACK_SIZE_MAX]; // 0x00e375c0
int rdMatrixStack34_modified; // 0x004c3c0c
#endif

#define rdMatrixStack44_Init_ADDR (0x00445150)
#define rdMatrixStack44_Push_ADDR (0x00445200)
#define rdMatrixStack44_Peek_ADDR (0x00445500)
#define rdMatrixStack44_Pop_ADDR (0x00445630)
#define rdMatrix44_ringBuffer_Get_ADDR (0x0044b660)
#define SetModelMVPAndTranslation_ADDR (0x0044b690)
#define rdMatrixStack34_Push_ADDR (0x0044b750)
#define rdMatrixStack34_PushMultiply_ADDR (0x0044b7e0)
#define rdMatrixStack34_Peek_ADDR (0x0044b9b0)
#define rdMatrixStack34_Pop_ADDR (0x0044bab0)

#define rdMatrixStack34_Init_ADDR (0x0044bb40)
#define rdMatrixStack34_PrecomputeMVPMatrices_ADDR (0x0044bc20)

void rdMatrixStack44_Init(void);
void rdMatrixStack44_Push(rdMatrix44* in);
void rdMatrixStack44_Peek(rdMatrix44* out);
void rdMatrixStack44_Pop(void);
rdMatrix44* rdMatrix44_ringBuffer_Get(void);
void SetModelMVPAndTranslation(const rdMatrix44 *mvp, const rdVector3* translation);
void rdMatrixStack34_Push(const rdMatrix34* mat);
void rdMatrixStack34_PushMultiply(const rdMatrix34 *a1);
void rdMatrixStack34_Peek(rdMatrix34 *a1);
void rdMatrixStack34_Pop();

void rdMatrixStack34_Init();
void rdMatrixStack34_PrecomputeMVPMatrices();

#endif // UNKNOWN_H
