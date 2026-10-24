#if ENABLE_XINPUT_RUMBLE

#include "sony_pad_rumble.h"

#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" {
extern FILE *hook_log;
// game_deltas/stdControl_delta.c: USB product id of the active joystick if it's a Sony pad.
int stdControl_GetActiveSonyPid(void);
}

#define SONY_USB_VID 0x054C
#define DS4_PID_V1 0x05C4
#define DS4_PID_V2 0x09CC
#define DS4_PID_ADAPTER 0x0BA0

// Output report sizes over USB; anything else on the same product is the Bluetooth interface.
#define DS4_USB_OUTPUT_REPORT_LEN 32
#define DS5_USB_OUTPUT_REPORT_LEN_MIN 48

#define DS4_USB_REPORT_ID 0x05
#define DS4_FLAG_RUMBLE 0x01 // byte 1: apply the motor bytes, leave lightbar/flash alone
#define DS4_OFS_MOTOR_RIGHT 4// high-frequency motor
#define DS4_OFS_MOTOR_LEFT 5 // low-frequency motor

#define DS5_USB_REPORT_ID 0x02
#define DS5_FLAG0_RUMBLE 0x03// byte 1: compatible-vibration emulation + haptics-as-rumble
#define DS5_OFS_MOTOR_RIGHT 3
#define DS5_OFS_MOTOR_LEFT 4

#define REOPEN_INTERVAL_MS 2000

typedef BOOLEAN(__stdcall *HidD_GetAttributes_t)(HANDLE, PHIDD_ATTRIBUTES);
typedef void(__stdcall *HidD_GetHidGuid_t)(LPGUID);
typedef BOOLEAN(__stdcall *HidD_GetPreparsedData_t)(HANDLE, PHIDP_PREPARSED_DATA *);
typedef BOOLEAN(__stdcall *HidD_FreePreparsedData_t)(PHIDP_PREPARSED_DATA);
typedef NTSTATUS(__stdcall *HidP_GetCaps_t)(PHIDP_PREPARSED_DATA, PHIDP_CAPS);
typedef HDEVINFO(WINAPI *SetupDiGetClassDevsW_t)(const GUID *, PCWSTR, HWND, DWORD);
typedef BOOL(WINAPI *SetupDiEnumDeviceInterfaces_t)(HDEVINFO, PSP_DEVINFO_DATA, const GUID *,
                                                    DWORD, PSP_DEVICE_INTERFACE_DATA);
typedef BOOL(WINAPI *SetupDiGetDeviceInterfaceDetailW_t)(HDEVINFO, PSP_DEVICE_INTERFACE_DATA,
                                                         PSP_DEVICE_INTERFACE_DETAIL_DATA_W, DWORD,
                                                         PDWORD, PSP_DEVINFO_DATA);
typedef BOOL(WINAPI *SetupDiDestroyDeviceInfoList_t)(HDEVINFO);

// hid.dll / setupapi.dll are loaded on first use, like the XInput DLLs, so the hook DLL gains no
// new link dependencies.
static struct {
    bool tried;
    bool ok;
    HidD_GetAttributes_t GetAttributes;
    HidD_GetHidGuid_t GetHidGuid;
    HidD_GetPreparsedData_t GetPreparsedData;
    HidD_FreePreparsedData_t FreePreparsedData;
    HidP_GetCaps_t GetCaps;
    SetupDiGetClassDevsW_t GetClassDevs;
    SetupDiEnumDeviceInterfaces_t EnumDeviceInterfaces;
    SetupDiGetDeviceInterfaceDetailW_t GetDeviceInterfaceDetail;
    SetupDiDestroyDeviceInfoList_t DestroyDeviceInfoList;
} g_api;

static HANDLE g_pad = INVALID_HANDLE_VALUE;
static int g_padPid = 0;
static DWORD g_reportLen = 0;
static uint32_t g_lastOpenAttemptMs = 0;

static OVERLAPPED g_writeOv;
static BYTE g_report[128];
static bool g_writePending = false;
static int g_sentLeft = -1, g_sentRight = -1;

static void sony_load_api() {
    g_api.tried = true;
    HMODULE hid = LoadLibraryA("hid.dll");
    HMODULE setup = LoadLibraryA("setupapi.dll");
    if (!hid || !setup)
        return;
    g_api.GetAttributes = (HidD_GetAttributes_t) GetProcAddress(hid, "HidD_GetAttributes");
    g_api.GetHidGuid = (HidD_GetHidGuid_t) GetProcAddress(hid, "HidD_GetHidGuid");
    g_api.GetPreparsedData = (HidD_GetPreparsedData_t) GetProcAddress(hid, "HidD_GetPreparsedData");
    g_api.FreePreparsedData =
        (HidD_FreePreparsedData_t) GetProcAddress(hid, "HidD_FreePreparsedData");
    g_api.GetCaps = (HidP_GetCaps_t) GetProcAddress(hid, "HidP_GetCaps");
    g_api.GetClassDevs = (SetupDiGetClassDevsW_t) GetProcAddress(setup, "SetupDiGetClassDevsW");
    g_api.EnumDeviceInterfaces =
        (SetupDiEnumDeviceInterfaces_t) GetProcAddress(setup, "SetupDiEnumDeviceInterfaces");
    g_api.GetDeviceInterfaceDetail = (SetupDiGetDeviceInterfaceDetailW_t) GetProcAddress(
        setup, "SetupDiGetDeviceInterfaceDetailW");
    g_api.DestroyDeviceInfoList =
        (SetupDiDestroyDeviceInfoList_t) GetProcAddress(setup, "SetupDiDestroyDeviceInfoList");
    g_api.ok = g_api.GetAttributes && g_api.GetHidGuid && g_api.GetPreparsedData &&
               g_api.FreePreparsedData && g_api.GetCaps && g_api.GetClassDevs &&
               g_api.EnumDeviceInterfaces && g_api.GetDeviceInterfaceDetail &&
               g_api.DestroyDeviceInfoList;
}

static bool sony_is_ds4(int pid) {
    return pid == DS4_PID_V1 || pid == DS4_PID_V2 || pid == DS4_PID_ADAPTER;
}

static void sony_close() {
    if (g_pad != INVALID_HANDLE_VALUE) {
        CancelIo(g_pad);
        CloseHandle(g_pad);
    }
    if (g_writeOv.hEvent)
        CloseHandle(g_writeOv.hEvent);
    memset(&g_writeOv, 0, sizeof(g_writeOv));
    g_pad = INVALID_HANDLE_VALUE;
    g_padPid = 0;
    g_writePending = false;
    g_sentLeft = g_sentRight = -1;
}

// Open the USB HID interface of the pad with this product id. Matched by VID/PID: DirectInput
// doesn't hand out the device path at the interface version the game creates.
static bool sony_open(int pid) {
    GUID hidGuid;
    g_api.GetHidGuid(&hidGuid);
    HDEVINFO set = g_api.GetClassDevs(&hidGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (set == INVALID_HANDLE_VALUE)
        return false;

    bool found = false;
    SP_DEVICE_INTERFACE_DATA ifData;
    ifData.cbSize = sizeof(ifData);
    for (DWORD i = 0; !found && g_api.EnumDeviceInterfaces(set, NULL, &hidGuid, i, &ifData); i++) {
        BYTE detailBuf[1024];
        PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W) detailBuf;
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        if (!g_api.GetDeviceInterfaceDetail(set, &ifData, detail, sizeof(detailBuf), NULL, NULL))
            continue;
        HANDLE h = CreateFileW(detail->DevicePath, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED, NULL);
        if (h == INVALID_HANDLE_VALUE)
            continue;

        HIDD_ATTRIBUTES attr;
        attr.Size = sizeof(attr);
        HIDP_CAPS caps = {};
        PHIDP_PREPARSED_DATA pp = NULL;
        const bool match = g_api.GetAttributes(h, &attr) && attr.VendorID == SONY_USB_VID &&
                           attr.ProductID == pid && g_api.GetPreparsedData(h, &pp);
        if (match) {
            g_api.GetCaps(pp, &caps);
            g_api.FreePreparsedData(pp);
        }
        const bool usb = sony_is_ds4(pid) ? caps.OutputReportByteLength == DS4_USB_OUTPUT_REPORT_LEN
                                          : caps.OutputReportByteLength >= DS5_USB_OUTPUT_REPORT_LEN_MIN &&
                                                caps.OutputReportByteLength <= sizeof(g_report);
        if (match && usb) {
            g_pad = h;
            g_padPid = pid;
            g_reportLen = caps.OutputReportByteLength;
            g_writeOv.hEvent = CreateEventA(NULL, TRUE, TRUE, NULL);
            found = true;
        } else {
            if (match)
                fprintf(hook_log, "[sony-rumble] pid 0x%04x output report %u bytes: not USB, skipped\n",
                        pid, (unsigned) caps.OutputReportByteLength);
            CloseHandle(h);
        }
    }
    g_api.DestroyDeviceInfoList(set);
    fprintf(hook_log, "[sony-rumble] pid 0x%04x: %s\n", pid, found ? "USB HID opened" : "no USB interface");
    fflush(hook_log);
    return found;
}

static BYTE motor_byte(float v) {
    if (v <= 0.0f)
        return 0;
    if (v >= 1.0f)
        return 255;
    return (BYTE) (v * 255.0f);
}

void sony_pad_rumble_set(float left, float right) {
#if ENABLE_GLFW_INPUT_HANDLING
    const int pid = 0;// no DirectInput joystick list to find the pad in
#else
    const int pid = stdControl_GetActiveSonyPid();
#endif
    if (pid == 0) {
        if (g_pad != INVALID_HANDLE_VALUE)
            sony_close();
        return;
    }
    if (!g_api.tried)
        sony_load_api();
    if (!g_api.ok)
        return;
    if (g_pad != INVALID_HANDLE_VALUE && g_padPid != pid)
        sony_close();
    if (g_pad == INVALID_HANDLE_VALUE) {
        const uint32_t now = GetTickCount();
        if (g_lastOpenAttemptMs != 0 && now - g_lastOpenAttemptMs < REOPEN_INTERVAL_MS)
            return;
        g_lastOpenAttemptMs = now;
        if (!sony_open(pid))
            return;
    }

    // One write in flight at a time; the levels are re-sent every frame, so a change made while
    // a write is pending (including the final 0,0) goes out on a later frame.
    if (g_writePending) {
        DWORD written;
        if (!GetOverlappedResult(g_pad, &g_writeOv, &written, FALSE)) {
            if (GetLastError() == ERROR_IO_INCOMPLETE)
                return;
            sony_close();// unplugged; reopen on a later frame
            return;
        }
        g_writePending = false;
    }

    const BYTE l = motor_byte(left);
    const BYTE r = motor_byte(right);
    if (l == g_sentLeft && r == g_sentRight)
        return;

    memset(g_report, 0, sizeof(g_report));
    if (sony_is_ds4(g_padPid)) {
        g_report[0] = DS4_USB_REPORT_ID;
        g_report[1] = DS4_FLAG_RUMBLE;
        g_report[DS4_OFS_MOTOR_RIGHT] = r;
        g_report[DS4_OFS_MOTOR_LEFT] = l;
    } else {
        g_report[0] = DS5_USB_REPORT_ID;
        g_report[1] = DS5_FLAG0_RUMBLE;
        g_report[DS5_OFS_MOTOR_RIGHT] = r;
        g_report[DS5_OFS_MOTOR_LEFT] = l;
    }
    ResetEvent(g_writeOv.hEvent);
    if (!WriteFile(g_pad, g_report, g_reportLen, NULL, &g_writeOv)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            sony_close();
            return;
        }
        g_writePending = true;
    }
    g_sentLeft = l;
    g_sentRight = r;
}

#endif // ENABLE_XINPUT_RUMBLE
