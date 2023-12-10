#ifndef RDFONT_H
#define RDFONT_H

#include "types.h"

#define rdFont_Shutdown_ADDR (0x00493e10)

#define rdFont_Open_ADDR (0x00493e40)
#define rdFont_Close_ADDR (0x00493e60)

void rdFont_Shutdown(void);

int rdFont_Open(void);
void rdFont_Close(void);

#endif // RDFONT_H
