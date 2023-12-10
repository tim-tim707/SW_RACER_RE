#ifndef RDROID_H
#define RDROID_H

#include "types.h"

#define rdStartup_ADDR (0x00490950)
#define rdShutdown_ADDR (0x00490990)
#define rdOpen_ADDR (0x004909b0)
#define rdClose_ADDR (0x00490a00)
#define rdSetRenderOptions_ADDR (0x00490a20)
#define rdSetGeometryMode_ADDR (0x00490a30)
#define rdSetLightingMode_ADDR (0x00490a40)

int rdStartup(HostServices* p_hs);
void rdShutdown(void);
int rdOpen(void);
void rdClose(void);
void rdSetRenderOptions(RdDroidFlags options);
void rdSetGeometryMode(RdGeometryMode mode);
void rdSetLightingMode(RdLightMode mode);

#endif // RDROID_H
