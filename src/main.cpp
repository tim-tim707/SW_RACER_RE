#include "main.h"

#include <windows.h>
#include "macros.h"
#include <stdint.h>

int Window_Main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR lpCmdLine, int32_t nShowCmd)
{
    printf("%p %p %S %d\n", (void *)hInstance, (void *)hPrevInstance, lpCmdLine, nShowCmd);

    // main(hInstance, hPrevInstance, lpCmdLine, nShowCmd, "Episode I Racer");
    swr_main(hInstance, hPrevInstance, lpCmdLine, nShowCmd, "Episode I Racer: Community Edition");

    return 0;
}

WPARAM swr_main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int32_t nCmdShow, LPCSTR window_name)
{
    printf("Window name is %s\n", window_name);
    printf("Entering reimpl main which should be the same as the original\nHanging now...\n");
    hang();
    return 0;
}
