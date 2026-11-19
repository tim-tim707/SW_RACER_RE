#include "Window.h"

#include <Windows.h>
#include <commctrl.h>

#include "globals.h"
#include "stdDisplay.h"

#include "stdPlatform.h"

#include <macros.h>
#include <Gui/swrGui.h>
#include <Main/swrControl.h>
#include <Platform/std3D.h>
#include <Platform/stdControl.h>
#include <Swr/swrDisplay.h>
#include <Win95/Window.h>
#include <Main/swrMain.h>
#include <Main/swrMain2.h>
#include <Swr/swrUI.h>
#include <Swr/swrText.h>
#include <Platform/smush.h>
#include <engine_config.h>
#include <swr.h>
#include <Platform/wuRegistry.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 0x004080C0
void Window_AddKeyEvent(WPARAM virtual_key_code, USHORT flags, uint8_t pressed)
{
    if (!enableWindowInput)
        return;

    EnterCriticalSection(&WindowsInputCritSection);
    if (WindowsInputStackSize < 64u)
    {
        WindowsInputStack[WindowsInputStackSize++] = (WindowsInputItem){
            .virtualKeyCode = virtual_key_code,
            .keystrokeMessageFlags = flags,
            .keydown = pressed,
        };
    }
    LeaveCriticalSection(&WindowsInputCritSection);
}

// 0x00423900
LRESULT Window_msg_default_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT* uMsg_ptr)
{
    // TODO
    return 0;
}

// 0x00423aa0
void Window_ActivateApp(HWND hwnd, WPARAM activated, LPARAM unused)
{
    Window_SetActivated(hwnd, activated);
}

// 0x00423ac0
void Window_Activate(HWND hwnd, int active, LPARAM unused, WPARAM unused2)
{
    Window_SetActivated(hwnd, (unsigned int)(active != 0));
}

// 0x00423ae0
void Window_SetActivated(HWND hwnd, WPARAM activated)
{
    if (activated != 0)
    {
        if (Window_Active == 0)
        {
            swrDisplay_SetWindowSize();
            stdDisplay_Refresh(1);
            std3D_ClearCacheList();
            swrDisplay_SetWindowSize();
        }
        swrMain_GuiAdvanceFunction = (void*)swrMain2_GuiAdvance;
        Window_Active = 1;
        swrGui_Stop(0);
        stdControl_SetActivation(activated);
        return;
    }
    swrMain_GuiAdvanceFunction = stdPlatform_noop;
    stdDisplay_Refresh(0);
    Window_Active = 0;
    swrGui_Stop(1);
    stdControl_SetActivation(0);
}

// 0x00423b90
void Window_Resize(HWND hwnd, WPARAM edgeOfWindow, struct tagRECT* dragRectangle)
{
    int height;
    int width;
    struct tagRECT windowRect;
    struct tagRECT clientRect;

    GetWindowRect(hwnd, &windowRect);
    GetClientRect(hwnd, &clientRect);
    clientRect.right = (windowRect.right - windowRect.left) - clientRect.right;
    clientRect.bottom = (windowRect.bottom - windowRect.top) - clientRect.bottom;
    switch (edgeOfWindow)
    {
    case 1:
    case 2:
        width = (dragRectangle->right - clientRect.right) - dragRectangle->left;
        hwnd = (HWND)((int)(width + (width >> 0x1f & 3U)) >> 2);
        break;
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
        hwnd = (HWND)(((dragRectangle->bottom - dragRectangle->top) - clientRect.bottom) / 3);
    }
    Windows_windowWidth = (int)hwnd * 3;
    Windows_windowHeight = (int)hwnd * 4;
    width = Windows_windowWidth;
    if (Windows_windowWidth < 0x50)
    {
        width = 0x50;
    }
    height = Windows_windowHeight;
    if (Windows_windowHeight < 0x3c)
    {
        height = 0x3c;
    }
    dragRectangle->bottom = dragRectangle->top + width + clientRect.bottom;
    dragRectangle->right = dragRectangle->left + height + clientRect.right;
    Windows_WinProc_res = 1;
}

// 0x00423c80
void Window_ResizeExit(HWND unused)
{
    int set;

    set = swrDisplay_SetWindowSize();
    if (set == 0)
    {
        swrDisplay_Resize(&swrMainDisplaySettings_g, Windows_windowWidth, Windows_windowHeight);
    }
}

// 0x004246c0
void Window_SetWindowed(int windowed)
{
    swrMainDisplay_windowed = windowed;
}

// 0x004246d0
void Window_DisplaySettingsBox(HWND hwnd, swrMainDisplaySettings* displaySettings)
{
    HINSTANCE hInstance;

    hInstance = (HINSTANCE)GetWindowLongA(hwnd, GWL_HINSTANCE);
    DialogBoxParamA(hInstance, MAKEINTRESOURCEA(WINDOW_DISPLAY_SETTINGS_DIALOG), hwnd, Window_DisplaySettingsCallback, (LPARAM)displaySettings);
}

// 0x00424700
INT_PTR __stdcall Window_DisplaySettingsCallback(HWND dialogBoxHwnd, UINT message, WPARAM infos, LPARAM displaySettings)
{
    if (message == WM_INITDIALOG)
        return Window_DisplaySettingsInitDialog(dialogBoxHwnd, infos, (swrMainDisplaySettings*)displaySettings);
    if (message != WM_COMMAND)
        return 0;
    Window_DisplaySettingsCommand(dialogBoxHwnd, LOWORD(infos), displaySettings, HIWORD(infos));
    return 1;
}

static void Window_ComboAddItem(HWND combo, const char* text, LPARAM data)
{
    WPARAM index;

    index = SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)text);
    SendMessageA(combo, CB_SETITEMDATA, index, data);
}

static LRESULT Window_ComboGetSelectedData(HWND combo)
{
    WPARAM index;

    index = SendMessageA(combo, CB_GETCURSEL, 0, 0);
    return SendMessageA(combo, CB_GETITEMDATA, index, 0);
}

// 0x00424760
BOOL Window_DisplaySettingsInitDialog(HWND hDlg, WPARAM wParam, swrMainDisplaySettings* displaySettings)
{
    HWND combo;
    WPARAM index;
    unsigned int device;
    StdDisplayInfo* info;

    Window_DisplaySettingsMoveWindow(hDlg);
    combo = GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_DISPLAY_DEVICE);
    for (device = 0; device < (unsigned int)Main_drawDevices->numInfos; device++) {
        info = &Main_drawDevices->aDisplayInfos[device];
        if (info->displayDevice.b3DAccel == 1) {
            sprintf(std_output_buffer, "%s", info->displayDevice.aDriverName);
            index = SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)std_output_buffer);
            SendMessageA(combo, CB_SETITEMDATA, index, device);
            if (device == (unsigned int)displaySettings->currentDevice)
                SendMessageA(combo, CB_SETCURSEL, index, 0);
        }
    }

    combo = GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_GEOMETRY_MODE);
    Window_ComboAddItem(combo, "Vertex Only", RD_GEOMETRY_VERTEX);
    Window_ComboAddItem(combo, "Wire Frame", RD_GEOMETRY_WIREFRAME);
    Window_ComboAddItem(combo, "Solid", RD_GEOMETRY_SOLID);
    index = SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM) "Texture");
    SendMessageA(combo, CB_SETITEMDATA, index, RD_GEOMETRY_FULL);
    SendMessageA(combo, CB_SETCURSEL, index, 0);

    combo = GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_LIGHT_MODE);
    // faithful: "None" and "Lit" carry each other's values
    Window_ComboAddItem(combo, "None", RD_LIGHTING_LIT);
    Window_ComboAddItem(combo, "Lit", RD_LIGHTING_NONE);
    Window_ComboAddItem(combo, "Diffuse", RD_LIGHTING_DIFFUSE);
    index = SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM) "Gouraud");
    SendMessageA(combo, CB_SETITEMDATA, index, RD_LIGHTING_GOURAUD);
    SendMessageA(combo, CB_SETCURSEL, index, 0);

    combo = GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_TEXTURE_FILTER);
    Window_ComboAddItem(combo, "None", 0);
    // faithful: the EXE selects "Bilinear" before attaching its item data
    index = SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM) "Bilinear");
    SendMessageA(combo, CB_SETCURSEL, index, 0);
    SendMessageA(combo, CB_SETITEMDATA, index, 1);
    Window_ComboAddItem(combo, "Trilinear", 2);

    Window_DisplaySettingsPopulateModes(hDlg, displaySettings);
    SetWindowLongA(hDlg, DWL_USER, (LONG)displaySettings);
    CheckDlgButton(hDlg, WINDOW_DISPLAY_SETTINGS_FULLSCREEN, displaySettings->RegFullScreen);
    CheckDlgButton(hDlg, WINDOW_DISPLAY_SETTINGS_FIX_FLICKER, displaySettings->RegFixFlicker);
    CheckDlgButton(hDlg, WINDOW_DISPLAY_SETTINGS_DEV_MODE, displaySettings->RegDevMode);
    CheckDlgButton(hDlg, WINDOW_DISPLAY_SETTINGS_USE_FETT, displaySettings->RegUseFett);
    SetDlgItemTextA(hDlg, WINDOW_DISPLAY_SETTINGS_DIALOG, swrText_Translate("/MONDOTEXT_H_0525/Racer Display Settings"));
    SetDlgItemTextA(hDlg, WINDOW_DISPLAY_SETTINGS_HARDWARE_LABEL, swrText_Translate("/MONDOTEXT_H_0526/Graphics Hardware"));
    SetDlgItemTextA(hDlg, WINDOW_DISPLAY_SETTINGS_3D_DEVICE_LABEL, swrText_Translate("/MONDOTEXT_H_0527/3D Device"));
    SetDlgItemTextA(hDlg, WINDOW_DISPLAY_SETTINGS_DISPLAY_MODE_LABEL, swrText_Translate("/MONDOTEXT_H_0528/Display Mode"));
    SetDlgItemTextA(hDlg, IDOK, swrText_Translate("/MONDOTEXT_H_0529/&Accept"));
    SetDlgItemTextA(hDlg, IDCANCEL, swrText_Translate("/MONDOTEXT_H_0530/&Cancel"));
    return 1;
}

// 0x00424a90
void Window_DisplaySettingsCommand(HWND hDlg, int controlId, WPARAM wParam, int notifyCode)
{
    swrMainDisplaySettings* settings;
    StdDisplayInfo* info;
    OLECHAR guidWide[130];
    CHAR guidString[260];

    settings = (swrMainDisplaySettings*)GetWindowLongA(hDlg, DWL_USER);
    if (controlId > WINDOW_DISPLAY_SETTINGS_ACCEPT_ON_DBLCLK) {
        if (controlId == WINDOW_DISPLAY_SETTINGS_VIDEO_MODE) {
            if (notifyCode == CBN_SELCHANGE)
                settings->videoModeIndex = Window_ComboGetSelectedData(GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_VIDEO_MODE));
        } else if (controlId == WINDOW_DISPLAY_SETTINGS_DISPLAY_DEVICE) {
            if (notifyCode == CBN_SELCHANGE) {
                settings->currentDevice = Window_ComboGetSelectedData(GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_DISPLAY_DEVICE));
                Window_DisplaySettingsPopulateModes(hDlg, settings);
            }
        } else if (controlId == WINDOW_DISPLAY_SETTINGS_3D_DEVICE && notifyCode == CBN_SELCHANGE) {
            settings->device3DIndex = Window_ComboGetSelectedData(GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_3D_DEVICE));
        }
        return;
    }

    if (controlId == WINDOW_DISPLAY_SETTINGS_ACCEPT_ON_DBLCLK) {
        if (notifyCode != CBN_DBLCLK)
            return;
        controlId = IDOK;
    } else if (controlId != IDOK) {
        if (controlId != IDCANCEL)
            return;
        EndDialog(hDlg, IDCANCEL);
        exit(0);
    }

    settings->device3DIndex = Window_ComboGetSelectedData(GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_3D_DEVICE));
    settings->videoModeIndex = Window_ComboGetSelectedData(GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_VIDEO_MODE));
    settings->geometryMode = Window_ComboGetSelectedData(GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_GEOMETRY_MODE));
    if (settings->geometryMode == RD_GEOMETRY_WIREFRAME)
        settings->backbufferFill = 1;
    settings->lightMode = Window_ComboGetSelectedData(GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_LIGHT_MODE));
    settings->textureFilter = Window_ComboGetSelectedData(GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_TEXTURE_FILTER));

    info = &Main_drawDevices->aDisplayInfos[settings->currentDevice];
    wuRegistry_SetString("Display", info->displayDevice.aDriverName);
    wuRegistry_SetString("3D Device", info->aDevices[settings->device3DIndex].deviceDescription);
    wuRegistry_SaveInt("Display Width", info->aModes[settings->videoModeIndex].rasterInfo.width);
    wuRegistry_SaveInt("Display Height", info->aModes[settings->videoModeIndex].rasterInfo.height);
    StringFromGUID2(&info->displayDevice.guid, guidWide, 0x104);
    WideCharToMultiByte(CP_ACP, 0, guidWide, -1, guidString, sizeof(guidString), NULL, NULL);
    wuRegistry_SetString("GUID", guidString);
    settings->RegFullScreen = IsDlgButtonChecked(hDlg, WINDOW_DISPLAY_SETTINGS_FULLSCREEN) == BST_CHECKED;
    settings->RegFixFlicker = IsDlgButtonChecked(hDlg, WINDOW_DISPLAY_SETTINGS_FIX_FLICKER) == BST_CHECKED;
    settings->RegDevMode = IsDlgButtonChecked(hDlg, WINDOW_DISPLAY_SETTINGS_DEV_MODE) == BST_CHECKED;
    settings->RegUseFett = IsDlgButtonChecked(hDlg, WINDOW_DISPLAY_SETTINGS_USE_FETT) == BST_CHECKED;
    EndDialog(hDlg, controlId);
    exit(0);
}

// 0x00424e50
void Window_DisplaySettingsPopulateModes(HWND hDlg, swrMainDisplaySettings* displaySettings)
{
    HWND modeCombo;
    HWND deviceCombo;
    StdDisplayInfo* info;
    StdVideoMode* mode;
    WPARAM index;
    unsigned int i;
    int found;

    modeCombo = GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_VIDEO_MODE);
    deviceCombo = GetDlgItem(hDlg, WINDOW_DISPLAY_SETTINGS_3D_DEVICE);
    SendMessageA(modeCombo, CB_RESETCONTENT, 0, 0);
    SendMessageA(deviceCombo, CB_RESETCONTENT, 0, 0);
    found = 0;
    info = &Main_drawDevices->aDisplayInfos[displaySettings->currentDevice];
    for (i = 0; i < (unsigned int)info->numDevices; i++) {
        sprintf(std_output_buffer, "%s", info->aDevices[i].deviceDescription);
        index = SendMessageA(deviceCombo, CB_ADDSTRING, 0, (LPARAM)std_output_buffer);
        SendMessageA(deviceCombo, CB_SETITEMDATA, index, i);
        if ((unsigned int)displaySettings->device3DIndex == i) {
            SendMessageA(deviceCombo, CB_SETCURSEL, index, 0);
            found = 1;
        }
    }
    if (!found)
        SendMessageA(deviceCombo, CB_SETCURSEL, 0, 0);

    swrMainDisplayMode.rasterInfo.colorInfo.bpp = SWR_DISPLAY_BPP;
    for (i = 0; i < (unsigned int)info->numModes; i++) {
        mode = &info->aModes[i];
        sprintf(std_output_buffer, "%dx%d %dbpp", mode->rasterInfo.width, mode->rasterInfo.height, mode->rasterInfo.colorInfo.bpp);
        if (mode->rasterInfo.colorInfo.bpp == SWR_DISPLAY_BPP) {
            index = SendMessageA(modeCombo, CB_ADDSTRING, 0, (LPARAM)std_output_buffer);
            SendMessageA(modeCombo, CB_SETITEMDATA, index, i);
            if (mode->rasterInfo.width == swrMainDisplayMode.rasterInfo.width && mode->rasterInfo.height == swrMainDisplayMode.rasterInfo.height)
                SendMessageA(modeCombo, CB_SETCURSEL, index, 0);
        }
    }
}

// 0x00425070
int Window_SmushPlayCallback(const SmushImage* image)
{
    LPDIRECTDRAWSURFACE4* surface;
    DDSURFACEDESC2 desc;
    unsigned int width;
    unsigned int height;
    unsigned int pairs;
    unsigned int pair;
    uint8_t* src;
    uint8_t* dst;
    const uint32_t* srcPixels;
    uint32_t* dstPixels;

    swrControl_ProcessInputs();
    surface = &stdDisplay_g_backBuffer.pVSurface.pDDSurf;
    if (swrDisplay_directlyBlitVideoToScreen != 1)
        surface = &ddSurfaceForVideo;
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    if (IDirectDrawSurface4_Lock(*surface, NULL, &desc, DDLOCK_WAIT, NULL) != DD_OK) {
        // faithful: a failed Lock only latches the skip flag; the zeroed desc is still used below
        if (swrControl_cancelPressedEdge != 0) {
            Window_smushSkipRequested = 1;
        } else {
            Window_smushSkipRequested = 0;
            if (swrControl_acceptPressedEdge != 0)
                Window_smushSkipRequested = 1;
        }
    }

    width = image->width;
    if (width > desc.dwWidth)
        width = desc.dwWidth;
    height = image->height;
    if (height > desc.dwHeight)
        height = desc.dwHeight;
    // the horizontal offset is (surface width - frame width) bytes, i.e. centered in 16-bit pixels
    dst = (uint8_t*)desc.lpSurface + ((desc.dwHeight - height) >> 1) * desc.lPitch - width + desc.dwWidth;
    src = image->data;
    if (Window_smushColorTable != NULL) {
        pairs = width >> 1;
        for (; height != 0; height--) {
            srcPixels = (const uint32_t*)src;
            dstPixels = (uint32_t*)dst;
            for (pair = 0; pair < pairs; pair++)
                dstPixels[pair] = Window_smushColorTable[srcPixels[pair] & 0xffff] | ((uint32_t)Window_smushColorTable[srcPixels[pair] >> 16] << 16);
            dst += desc.lPitch;
            src += image->rowSize;
        }
    } else {
        for (; height != 0; height--) {
            memcpy(dst, src, width * 2);
            dst += desc.lPitch;
            src += image->rowSize;
        }
    }
    IDirectDrawSurface4_Unlock(*surface, NULL);
    if (swrDisplay_directlyBlitVideoToScreen != 1)
        IDirectDrawSurface4_Blt(stdDisplay_g_backBuffer.pVSurface.pDDSurf, &Window_smushDstRect, ddSurfaceForVideo, &Window_smushSrcRect, DDBLT_WAIT, NULL);
    swr_noop2();
    stdDisplay_Update();
    swrMain_ProcessDebugKeys();
    Window_smushSkipRequested = swrControl_cancelPressedEdge != 0 || swrControl_acceptPressedEdge != 0;
    if (Window_smushSkipRequested != 0) {
        swrControl_menuAcceptPressedEdge = 0;
        swrControl_acceptPressedEdge = 0;
        swrControl_cancelPressedEdge = 0;
        inRaceLocalPlayerInputBitset1[0] = 0;
        swrControl_ClearDeviceState(-1);
    }
    return Window_smushSkipRequested;
}

// 0x00425500
int Window_CDCheck(void)
{
    DWORD versionHandle;
    DWORD versionSize;
    void* versionData;
    WORD* translation;
    UINT valueLength;
    char subBlock[256];
    char path[256];
    char volumeLabel[128];
    char expectedLabel[128];
    char wheelMap[128];
    FILE* wheelMapFile;
    int fd;
    int answer;

    // faithful: the EXE zeroes this buffer from byte 17 on only
    memset(path + 17, 0, sizeof(path) - 17);
    if (!Window_bCDCheckEnabled) {
        sprintf(rootPathName, wuRegistry_lpClass);
        return 0;
    }

    versionSize = GetFileVersionInfoSizeA("swep1rcr.exe", &versionHandle);
    if (versionSize != 0) {
        versionData = malloc(versionSize);
        if (GetFileVersionInfoA("swep1rcr.exe", 0, versionSize, versionData) && VerQueryValueA(versionData, "\\VarFileInfo\\Translation", (LPVOID*)&translation, &valueLength)) {
            wsprintfA(subBlock, "\\StringFileInfo\\%04X%04X\\FileVersion", translation[0], translation[1]);
            if (VerQueryValueA(versionData, subBlock, (LPVOID*)&translation, &valueLength))
                memcpy(path, translation, strlen((const char*)translation) + 1);
        }
        free(versionData);
    }

    if (wuRegistry_GetString("CD Path", rootPathName, sizeof(rootPathName), wuRegistry_lpClass) != 0) {
        MessageBoxA(Main_hWnd, "Error:  Please reinstall program.", "BAD INSTALL", MB_ICONHAND);
        Main_Shutdown();
        exit(0);
    }

    // faithful: the EXE NOPs out the branches on GetDriveTypeA, fopen, GetVolumeInformationA and
    // strncmp, so only the PlanetG.znm size decides
    GetDriveTypeA(rootPathName);
    sprintf(wheelMap, "%s\\%swheel.map", rootPathName, ".\\data\\config\\default\\");
    // the EXE never closes this handle; closed here (the file is still created/truncated)
    wheelMapFile = fopen(wheelMap, "w");
    if (wheelMapFile != NULL)
        fclose(wheelMapFile);
    sprintf(expectedLabel, "racer%s", "100_0");
    do {
        GetVolumeInformationA(rootPathName, volumeLabel, sizeof(volumeLabel), NULL, NULL, NULL, NULL, 0);
        strncmp(volumeLabel, expectedLabel, strlen(expectedLabel) - 1);
        sprintf(wheelMap, "%s\\%swheel.map", rootPathName, ".\\data\\config\\default\\");
        sprintf(path, "%s%s", rootPathName, "\\Data\\Anims\\PlanetG.znm");
        fd = _open(path, 0);
        if (fd != -1) {
            if (_filelength(fd) == WINDOW_CD_PLANETG_ZNM_SIZE) {
                _close(fd);
                memcpy(rootPathName + strlen(rootPathName), "\\", 2);
                return 0;
            }
            _close(fd);
        }
        sprintf(subBlock, "Error:  Please insert CD-ROM '%s' into drive.\n\nPress OK to continue or CANCEL to exit to desktop", expectedLabel);
        answer = MessageBoxA(Main_hWnd, subBlock, "CD ERROR", MB_OKCANCEL | MB_ICONEXCLAMATION);
    } while (answer != IDCANCEL);
    Main_Shutdown();
    exit(0);
}

// 0x004252a0
int Window_PlayCinematic(char* znmFile)
{
    int savedUiInputActive;
    unsigned int width;
    unsigned int height;
    unsigned int x;
    unsigned int y;
    int scaled;
    int volume;
    char path[256];

    savedUiInputActive = swrControl_uiInputActive;
    swrGui_Stop(1);
    width = stdDisplay_g_backBuffer.rasterInfo.width;
    height = stdDisplay_g_backBuffer.rasterInfo.height;
    if (width >= SWR_SMUSH_VIDEO_WIDTH && height >= SWR_SMUSH_VIDEO_HEIGHT) {
        swrDisplay_directlyBlitVideoToScreen = 1;
    } else if (IDirectDraw4_CreateSurface(std3D_pDirectDraw, &ddSurfaceDescForVideo, &ddSurfaceForVideo, NULL) != DD_OK) {
        swrDisplay_directlyBlitVideoToScreen = 1;
    }
    // faithful: nothing here resets swrDisplay_directlyBlitVideoToScreen to 0

    if (swrDisplay_directlyBlitVideoToScreen == 0) {
        Window_smushSrcRect.left = 0;
        Window_smushSrcRect.top = 0;
        Window_smushSrcRect.right = SWR_SMUSH_VIDEO_WIDTH;
        Window_smushSrcRect.bottom = SWR_SMUSH_VIDEO_HEIGHT;
        x = 0;
        y = 0;
        if ((float)height / (float)width < SWR_SMUSH_VIDEO_ASPECT) {
            scaled = (int)(SWR_SMUSH_VIDEO_ASPECT_INV * (float)height);
            x = (width - scaled) >> 1;
            Window_smushDstRect.right = scaled + x;
            Window_smushDstRect.bottom = height;
        } else {
            scaled = (int)((float)width * SWR_SMUSH_VIDEO_ASPECT);
            y = (height - scaled) >> 1;
            Window_smushDstRect.right = width;
            Window_smushDstRect.bottom = scaled + y;
        }
        Window_smushDstRect.left = x;
        Window_smushDstRect.top = y;
    }

    SmushStartup(Main_hWnd, 0);
    if (swrMain_introMoviesPending != 0)
        volume = SWR_SMUSH_MAX_VOLUME;
    else if (Main_sound == 0)
        volume = 0;
    else
        volume = (uint8_t)sound_music_volume * SWR_SMUSH_MAX_VOLUME / 255;
    SmushSetVolume(volume);
    stdDisplay_VBufferFill(&stdDisplay_g_backBuffer, 0, NULL);
    stdDisplay_Update();
    if (swrMainDisplaySettings_g.RegFullScreen == 0)
        stdDisplay_VBufferFill(&stdDisplay_g_backBuffer, 0, NULL);
    swrControl_uiInputActive = 0;
    Window_CDCheck();
    sprintf(path, "%s%s%s", rootPathName, ".\\data\\anims\\", znmFile);
    SmushPlay(path, SWR_SMUSH_PLAY_FLAGS, 0, 0, 0, SWR_SMUSH_VIDEO_WIDTH, SWR_SMUSH_VIDEO_HEIGHT, -1, 0, Window_SmushPlayCallback, 1, SWR_SMUSH_FRAME_RATE_SCALE, SWR_SMUSH_FRAME_RATE_SCALE);
    swrControl_uiInputActive = savedUiInputActive;
    SmushShutdown();
    if (swrDisplay_directlyBlitVideoToScreen == 0)
        IDirectDrawSurface4_Release(ddSurfaceForVideo);
    swrGui_Stop(0);
    return 1;
}

// 0x00425820
int Window_DisplaySettingsMoveWindow(HWND dialogBoxHwnd)
{
    HWND hWnd;
    int iVar1;
    int iVar2;
    struct tagRECT window_rect;
    struct tagRECT desktop_window;
    struct tagRECT client_rect;
    struct tagRECT* desktop_window_ref;

    GetWindowRect(dialogBoxHwnd, &window_rect);
    GetClientRect(dialogBoxHwnd, &client_rect);
    iVar1 = window_rect.right - window_rect.left;
    desktop_window_ref = &desktop_window;
    iVar2 = window_rect.bottom - window_rect.top;
    hWnd = GetDesktopWindow();
    GetWindowRect(hWnd, desktop_window_ref);
    window_rect.top = (((desktop_window.bottom - window_rect.bottom) - window_rect.top) - desktop_window.top) / 2;
    window_rect.left = (((desktop_window.right - window_rect.right) - window_rect.left) - desktop_window.left) / 2;
    window_rect.bottom = iVar2 + window_rect.top;
    window_rect.right = iVar1 + window_rect.left;
    MoveWindow(dialogBoxHwnd, window_rect.left, window_rect.top, window_rect.right - window_rect.left, window_rect.bottom - window_rect.top, 1);
    return 1;
}

// 0x0048c770
void Window_SetHWND(HWND hwnd)
{
    Window_hWnd = hwnd;
}

// 0x0048c780
HWND Window_GetHWND(void)
{
    return Window_hWnd;
}

// 0x0048c790
void Window_SetHINSTANCE(HINSTANCE hInstance)
{
    Window_hinstance = hInstance;
}

// 0x0048c7a0
HINSTANCE Window_GetHINSTANCE(void)
{
    return Window_hinstance;
}

// 0x0048c7b0
void Window_SetGUID(GUID* guid)
{
    // copy guid
    ((uint32_t*)&Window_GUID)[0] = ((uint32_t*)guid)[0];
    ((uint32_t*)&Window_GUID)[1] = ((uint32_t*)guid)[1];
    ((uint32_t*)&Window_GUID)[2] = ((uint32_t*)guid)[2];
    ((uint32_t*)&Window_GUID)[3] = ((uint32_t*)guid)[3];
}

// 0x0048c7e0
GUID* Window_GetGUID(void)
{
    return &Window_GUID;
}

// 0x0049cd40
int Window_Main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow, const char* window_name)
{
    int iVar1;
    int iVar2;
    BOOL msg_res;
    LPCSTR unaff_ESI;
    int unaff_EDI;
    struct tagMSG msg;

    g_nCmdShow = nCmdShow;
    Window_CreateMainWindow(hInstance, nCmdShow, window_name, 0, NULL);
    Window_SetHWND(g_hWnd);
    Window_SetHINSTANCE(hInstance);
    Window_SetGUID((GUID*)Window_UUID);
    InitCommonControls();
    iVar1 = GetSystemMetrics(0x20);
    Window_border_width = iVar1 << 1;
    iVar1 = GetSystemMetrics(0x20);
    iVar2 = GetSystemMetrics(0xf);
    Window_border_height = iVar2 + iVar1 * 2;
    iVar1 = Main_Startup((char*)pCmdLine);
    if (iVar1 == 0)
    {
        return 0;
    }
    do
    {
        while (msg_res = PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE), msg_res == 0)
        {
            swrMain2_GuiAdvance();
        }
        do
        {
            msg_res = GetMessageA(&msg, NULL, 0, 0);
            if (msg_res == -1)
            {
                return -1;
            }
            if (msg_res == 0)
            {
                return msg.wParam;
            }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
            msg_res = PeekMessageA(&msg, NULL, 0, 0, 0);
        } while (msg_res != 0);
    } while (true);
}

// 0x0049ce60
BOOL Window_SetWindowSize(int width, int height)
{
    return SetWindowPos(g_hWnd, NULL, 0, 0, width + Window_border_width, height + Window_border_height, SWP_NOMOVE | SWP_NOZORDER);
}

// 0x0049ce90
void Window_set_msg_handler(Window_MSGHANDLER handler)
{
    g_WndProc = handler;
}

// 0x0049cea0
int Window_CreateMainWindow(HINSTANCE hInstance, int unused, const char* window_name, int unused2, LPCSTR unused3)
{
    ATOM register_class_res;
    HWND hWnd;
    int nHeight;
    int nWidth;
    HMENU hMenu;
    LPVOID lpParam;
    WNDCLASSEXA wndClass;

    wndClass.cbSize = 0x30;
    wndClass.hInstance = hInstance;
    wndClass.lpszClassName = "wKernelJones3D";
    wndClass.lpszMenuName = NULL;
    wndClass.lpfnWndProc = Window_msg_main_handler;
    // FROM LRESULT (*)(HWND, UINT, WPARAM, LPARAM)
    // TO WNDPROC
    // aka
    // long int (*)(HWND__*, unsigned int, unsigned int, long int)
    // long int (__attribute__((stdcall)) *)(HWND__*, unsigned int, unsigned int, long int)
    wndClass.style = 0;
    wndClass.hIcon = LoadIconA(hInstance, "APPICON");
    if (wndClass.hIcon == NULL)
    {
        wndClass.hIcon = LoadIconA(NULL, IDI_APPLICATION);
    }
    wndClass.hIconSm = LoadIconA(hInstance, "APPICON");
    if (wndClass.hIconSm == NULL)
    {
        wndClass.hIconSm = LoadIconA(NULL, IDI_APPLICATION);
    }
    wndClass.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wndClass.cbClsExtra = 0;
    wndClass.cbWndExtra = 0;
    wndClass.hbrBackground = (HBRUSH)GetStockObject(4);
    register_class_res = RegisterClassExA(&wndClass);
    if (register_class_res == 0)
    {
        return 0;
    }
    hWnd = FindWindowA("wKernelJones3D", window_name);
    if (hWnd != NULL)
    {
        exit(-1);
    }
    lpParam = NULL;
    hMenu = NULL;
    hWnd = NULL;
    nHeight = GetSystemMetrics(SM_CYSCREEN);
    nWidth = GetSystemMetrics(SM_CXSCREEN);
    g_hWnd = CreateWindowExA(8, "wKernelJones3D", window_name, WS_VISIBLE | WS_POPUP, 0, 0, nWidth, nHeight, hWnd, hMenu, hInstance, lpParam);
    if (g_hWnd == NULL)
    {
        return 0;
    }
    ShowWindow(g_hWnd, 1);
    UpdateWindow(g_hWnd);
    return 1;
}

// 0x0049cfd0
LRESULT __stdcall Window_msg_main_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    LPARAM lParam_;
    WPARAM wParam_;
    UINT uMsg_;
    int window_proc_res;

    lParam_ = lParam;
    wParam_ = wParam;
    uMsg_ = uMsg;
    if (uMsg == 2)
    {
        Main_Shutdown();
        PostQuitMessage(0);
    }
    else if (g_WndProc != NULL)
    {
        window_proc_res = (*g_WndProc)(hWnd, uMsg, wParam, lParam, &uMsg);
        if (window_proc_res != 0)
        {
            return uMsg;
        }
        goto end;
    }
    lParam_ = lParam;
    wParam_ = wParam;
    if (false) // original compilation artifact
    {
        return 1;
    }
end:
    return DefWindowProcA(hWnd, uMsg_, wParam_, lParam_);
}
