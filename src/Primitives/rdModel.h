#ifndef RDMODEL_H
#define RDMODEL_H

#include "types.h"

#define rdModel_DrawFace_ADDR (0x0048f700)

// Looks like OpenJKDF2 but still very different
int rdModel_DrawFace(rdFace* param_1, int param_2, int param_3, unsigned int param_4, unsigned int param_5);

#endif // RDMODEL_H
