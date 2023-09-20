#ifndef A3D_H
#define A3D_H

#include "types.h"

#define a3d_RegisterAll_ADDR (0x0049e50)
#define a3d_RegisterCLSID_ADDR (0x0049e8e0)
#define a3d_CoInitialize_ADDR (0x0049e940)
#define a3d_CoCreateInstance_ADDR (0x0049e970)

int a3d_RegisterAll(void);
void a3d_RegisterCLSID(LPCSTR str1, LPCSTR str2, char* str3);
HRESULT a3d_CoInitialize(void);
HRESULT a3d_CoCreateInstance(GUID* null, IA3d4** ia3d, LPUNKNOWN null2, DWORD features);

#endif // A3D_H
