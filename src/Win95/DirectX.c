#include "DirectX.h"

// 0x00487370
BOOL DirectPlay_EnumConnectionsCallback(GUID* lpguidSP, LPVOID lpConnection, DWORD dwConnectionSize, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext)
{
    HANG("TODO. Argument count doesnt match documentation");
    return 1;
}
