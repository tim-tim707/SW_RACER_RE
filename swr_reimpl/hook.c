#include "hook.h"

#include <stdio.h>
#include <windows.h>

#include "addresses.h"

// void InstallHook(void *func2hook, void *payloadFunction)
// {
//     DWORD oldProtect;
//     VirtualProtect(AddColors, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

//     // 32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
//     uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

//     // to fill out the last 4 bytes of jmpInstruction, we need the offset between
//     // the payload function and the instruction immediately AFTER the jmp instruction
//     const uint32_t relAddr = (uint32_t)payloadFunction - ((uint32_t)func2hook + sizeof(jmpInstruction));
//     memcpy(jmpInstruction + 1, &relAddr, 4);

//     // install the hook
//     memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));
// }

void hook_function(u32 hook_addr_, u8 *hook_dst)
{
    // ASLR rebase
    u8 *hook_addr = g_SWR_BASE_ADDR + (hook_addr_ - SWR_BASE_ADDR_);

    // if ((u32_ptr)hook_addr < (u32_ptr)g_SWR_TEXT_ADDR)
    // {
    //     printf("Trying to hook below .text section!\n");
    //     return;
    // }
    // if ((u32_ptr)hook_addr > (u32_ptr)(g_SWR_TEXT_ADDR + (u32_ptr)SWR_TEXT_LEN))
    // {
    //     printf("Trying to hook above .text section!\n");
    //     return;
    // }

    if (hook_addr == hook_dst)
    {
        printf("Attempted to hook addr %x to itself!\n", hook_addr);
        return;
    }

    DWORD oldProtect;
    VirtualProtect(hook_addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    // hook_addr = hook_addr - (u32_ptr)SWR_BASE_ADDR_ + (u32_ptr)g_SWR_BASE_ADDR;
    u8 *rel_addr = hook_dst - (u32_ptr)hook_addr - 5;
    hook_addr[0] = 0xe9; // jmp rel32
    hook_addr += 1;
    ((u32 *)hook_addr)[0] = (u32)rel_addr;

    VirtualProtect(hook_addr, 5, oldProtect, &oldProtect);
}

void hook_abort(u8 *hook_addr)
{
    hook_addr[0] = 0x0f; // und
    hook_addr[1] = 0x0b;
}
