#ifndef STDDISPLAY_H
#define STDDISPLAY_H

#include "types.h"

#define stdDisplay_VBufferNew_ADDR (0x004881c0)

#define stdDisplay_VBufferFree_ADDR (0x00488310)
#define stdDisplay_VBufferLock_ADDR (0x00488370)
#define stdDisplay_VBufferUnlock_ADDR (0x004883c0)

#define stdDisplay_VBufferLock__ADDR (0x00489a00)
#define stdDisplay_VBufferUnlock__ADDR (0x00489a60)

stdVBuffer* stdDisplay_VBufferNew(stdVBufferTexFmt* texFormat, int create_ddraw_surface, int param_3);

void stdDisplay_VBufferFree(stdVBuffer* vbuffer);
int stdDisplay_VBufferLock(stdVBuffer* vbuffer);
int stdDisplay_VBufferUnlock(stdVBuffer* vbuffer);

char* stdDisplay_VBufferLock_(rdDDrawSurface** rdsurface);
int stdDisplay_VBufferUnlock_(rdDDrawSurface** rdsurface);

#endif // STDDISPLAY_H
