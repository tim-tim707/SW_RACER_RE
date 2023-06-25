#ifndef HOOK_H
#define HOOK_H

#include "types.h"

void hook_function(u32 hook_addr, u8 *hook_dst);
void hook_abort(u8 *hook_addr);

#endif // HOOK_H
