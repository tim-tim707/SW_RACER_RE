#ifndef TRIAGE_H
#define TRIAGE_H

// All the "analysed" but still unknown functions

#include "types.h"

// 0x00427670
unsigned int test_unk_statuses(int id, unsigned int flag);

// 0x00427690
void set_unk_statuses(int id, unsigned int flag);

// 0x004276aa
void unset_unk_statuses(int id, unsigned int flag);

#endif //  TRIAGE_H
