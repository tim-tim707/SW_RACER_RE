#ifndef RD_MATRIX_H
#define RD_MATRIX_H

#include "rdVector.h"
#include "types.h"

#define rdMatrix_Multiply44_ADDR (0x0042fb70)
#define rdMatrix_Multiply44Acc_ADDR (0x0042ff80)
// address gap
#define rdMatrix_TranformPoint44_ADDR (0x00480690)

void rdMatrix_Multiply44(rdMatrix44* out, rdMatrix44* mat1, rdMatrix44* mat2);
void rdMatrix_Multiply44Acc(rdMatrix44* out, rdMatrix44* mat2);
void rdMatrix_TransformPoint44(rdVector4* a1, const rdVector4* a2, const rdMatrix44* a3);

#endif // RD_MATRIX_H
