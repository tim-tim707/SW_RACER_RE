
// commctrl.h
// winuser.h

//----- (004238D0) --------------------------------------------------------
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                      LPSTR lpCmdLine, int nShowCmd)
{
    main(hInstance, (int)hPrevInstance, lpCmdLine, nShowCmd, WindowName);
    return 0;
}

int g_nShowCmd;

//----- (0049CD40) --------------------------------------------------------
WPARAM __cdecl main(HINSTANCE hInstance, int a2, char *a3, int a4,
                    LPCSTR lpWindowName)
{
    int width; // edi
    BOOL v6; // eax

    g_nShowCmd = a4;

    // Create the window
    create_window(hInstance, a4, lpWindowName);

    // Copy HWND
    set_hwnd((int)child_window);

    // Copy HINSTANCE
    set_hinstance((int)hInstance);

    // Copy ?????
    sub_48C7B0((int *)&unk_4AF9B0);

    // ?
    InitCommonControls();

    dword_DFAA34 = 2 * GetSystemMetrics(32);
    dword_DFAA38 = GetSystemMetrics(15) + 2 * GetSystemMetrics(32);

    // Initialize game (not an actual call probably?)
    if (!load_registry_options((int)GetSystemMetrics, a3))
    {
        return 0;
    }

    // FIXME: I rewrote this in a weird way. It should still be correct tho
    while (true)
    {
        // Handle all messages
        struct tagMSG Msg; // [esp+10h] [ebp-1Ch]
        while (PeekMessageA(&Msg, 0, 0, 0, 0))
        {
            v6 = GetMessageA(&Msg, 0, 0, 0);
            if (v6 == -1)
            { // There was an error
                return -1;
            }
            if (v6 == 0)
            { // Received a WM_QUIT
                return Msg.wParam;
            }
            TranslateMessage(&Msg);
            DispatchMessageA(&Msg);
        }

        game_loop();
    }
}

//----- (0049CEA0) --------------------------------------------------------
// hInstance = instance
// a2 = unused?
// lpWindowName = window name
int __cdecl create_window(HINSTANCE hInstance, int a2, LPCSTR lpWindowName)
{
    int height; // ST1C_4
    int width; // eax
    HWND v6; // eax
    WNDCLASSEXA class_exa; // [esp+Ch] [ebp-30h]

    class_exa.cbSize = 48;
    class_exa.hInstance = hInstance;
    class_exa.lpszClassName = ClassName;
    class_exa.lpszMenuName = 0;
    class_exa.lpfnWndProc = sub_49CFD0;
    class_exa.style = 0;

    class_exa.hIcon = LoadIconA(hInstance, IconName);
    if (class_exa.hIcon == 0)
    {
        class_exa.hIcon = LoadIconA(0, (LPCSTR)0x7F00);
    }

    class_exa.hIconSm = LoadIconA(hInstance, IconName);
    if (class_exa.hIconSm == 0)
    {
        class_exa.hIconSm = LoadIconA(0, (LPCSTR)0x7F00);
    }

    class_exa.hCursor = LoadCursorA(0, (LPCSTR)0x7F00);
    class_exa.cbClsExtra = 0;
    class_exa.cbWndExtra = 0;
    class_exa.hbrBackground = (HBRUSH)GetStockObject(4);

    if (!RegisterClassExA(&class_exa))
    {
        return 0;
    }

    // Quit if the game already runs
    if (FindWindowA(ClassName, lpWindowName))
    {
        exit_0(-1);
    }

    height = GetSystemMetrics(SM_CYSCREEN);
    width = GetSystemMetrics(SM_CXSCREEN);

    child_window = CreateWindowExA(WS_EX_TOPMOST, ClassName, lpWindowName,
                                   WS_VISIBLE | WS_POPUP, 0, 0, width, height,
                                   0, 0, hInstance, 0);
    if (child_window == 0)
    {
        return 0;
    }

    ShowWindow(child_window, 1);
    UpdateWindow(child_window);
    return 1;
}

//----- (0048C770) --------------------------------------------------------
// a1 = HWND
HWND __cdecl set_hwnd(HWND a1)
{
    dword_52EE70 = a1;
    return a1;
}

//----- (0048C790) --------------------------------------------------------
HINSTANCE __cdecl set_hinstance(HINSTANCE a1)
{
    dword_52EE74 = a1;
    return a1;
}

//----- (0048C7B0) --------------------------------------------------------
int *__cdecl sub_48C7B0(int *a1)
{
    dword_52EE60 = a1[0];
    dword_52EE64 = a1[1];
    dword_52EE68 = a1[2];
    dword_52EE6C = a1[3];
    return a1;
}

//----- (0048C780) --------------------------------------------------------
HWND get_hwnd()
{
    return dword_52EE70;
}

//----- (0048C7A0) --------------------------------------------------------
HINSTANCE get_hinstance()
{
    return dword_52EE74;
}

//----- (0048C7E0) --------------------------------------------------------
int *sub_48C7E0()
{
    return &dword_52EE60;
}
