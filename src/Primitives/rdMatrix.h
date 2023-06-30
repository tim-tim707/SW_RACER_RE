#ifndef RD_MATRIX_H
#define RD_MATRIX_H

#include "rdVector.h"
#include "types.h"

#define rdMatrix_Multiply44_ADDR (0x0042fb70)
#define rdMatrix_Multiply44Acc_ADDR (0x0042ff80)

void rdMatrix_Multiply44(rdMatrix44 *out, rdMatrix44 *mat1, rdMatrix44 *mat2);
void rdMatrix_Multiply44Acc(rdMatrix44 *out, rdMatrix44 *mat2);

#endif // RD_MATRIX_H
