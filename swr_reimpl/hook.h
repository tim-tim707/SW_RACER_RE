#ifndef HOOK_H
#define HOOK_H

#include "types.h"

void hook_function(intptr_t hook_addr, void* hook_dst);
void hook_abort(intptr_t hook_addr);


#endif // HOOK_H
