#include "hook.h"
#include "hook_addresses.h"

#include <stdio.h>
#include <windows.h>

#include "types.h"
#include "main.h"
#include "macros.h"
#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "General/stdMath.h"
#include "Win95/Window.h"
#include "Main/swrMain2.h"

uint8_t* g_SWR_BASE_ADDR = NULL;
uint8_t* g_SWR_TEXT_ADDR = NULL;
uint8_t* g_SWR_DATA_ADDR = NULL;

void hook_function(const char* function_name, uint32_t hook_addr_, uint8_t* hook_dst)
{
    // ASLR rebase
    uint8_t* hook_addr = g_SWR_BASE_ADDR + (hook_addr_ - SWR_BASE_ADDR_);

    if ((uint32_t)hook_addr_ < (uint32_t)SWR_TEXT_ADDR_)
    {
        printf("Trying to hook %d below .text section %d!\n", hook_addr_, SWR_TEXT_ADDR_);
    }
    if ((uint32_t)hook_addr_ >= (uint32_t)SWR_DATA_ADDR_)
    {
        printf("Trying to hook %d above .text section! %d\n", hook_addr_, SWR_DATA_ADDR_);
    }

    if (hook_addr == hook_dst)
    {
        printf("Attempted to hook addr %p to itself!\n", hook_addr);
        return;
    }

    DWORD oldProtect;
    VirtualProtect(hook_addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    uint8_t* rel_addr = hook_dst - (uint32_t)hook_addr - 5;
    hook_addr[0] = 0xe9; // jmp rel32
    hook_addr += 1;
    ((uint32_t*)hook_addr)[0] = (uint32_t)rel_addr;

    VirtualProtect(hook_addr, 5, oldProtect, &oldProtect);
}

void hook_abort(uint8_t* hook_addr)
{
    hook_addr[0] = 0x0f; // und
    hook_addr[1] = 0x0b;
}

void hook_init(FILE* hook_log)
{
    g_SWR_BASE_ADDR = (uint8_t*)GetModuleHandleA(NULL);
    g_SWR_TEXT_ADDR = g_SWR_BASE_ADDR + (uint32_t)SWR_TEXT_OFFSET;
    g_SWR_DATA_ADDR = g_SWR_BASE_ADDR + (uint32_t)SWR_DATA_OFFSET;

    // hook everything listed
    fprintf(hook_log, "[Hooking]\n");
    fflush(hook_log);
    hook_generated(hook_log);
}
