#include "stdControl.h"

#include "globals.h"
#include <Win95/DirectX.h>
#include <Win95/Window.h>

#include <macros.h>
#include "engine_config.h"

#include <math.h>
#include <string.h>

static LPDIRECTINPUTDEVICEA* stdControl_DeviceSlot(LPDIRECTINPUTDEVICEA* first, unsigned int index)
{
    return (LPDIRECTINPUTDEVICEA*)((char*)first + index * STDCONTROL_JOYSTICK_RECORD_SIZE);
}

static DIDEVICEINSTANCEA* stdControl_DeviceInstance(void* records, unsigned int index)
{
    return (DIDEVICEINSTANCEA*)((char*)records + index * STDCONTROL_JOYSTICK_RECORD_SIZE);
}

// 0x00485360
int stdControl_Startup(void)
{
    if (stdControl_g_bStartup != 0)
        return 1;
    memset(stdControl_aKeyIdleTimes, 0, sizeof(stdControl_aKeyIdleTimes));
    memset(stdControl_aKeyInfos, 0, sizeof(stdControl_aKeyInfos));
    memset(stdControl_aAxes, 0, sizeof(stdControl_aAxes));
    memset(stdControl_aAxisPos, 0, sizeof(stdControl_aAxisPos));
    // faithful: only the first three mice's previous positions are cleared
    stdControl_mousePrevX[0] = 0;
    stdControl_mousePrevY[0] = 0;
    stdControl_mousePrevX[1] = 0;
    stdControl_mousePrevY[1] = 0;
    stdControl_mousePrevX[2] = 0;
    stdControl_mousePrevY[2] = 0;
    DirectInputNbKeyboard = 0;
    memset(&DirectInputKeyboards, 0, STDCONTROL_MAX_KEYBOARD_DEVICES * STDCONTROL_JOYSTICK_RECORD_SIZE);
    memset(&DirectInputJoysticks, 0, STDCONTROL_MAX_JOYSTICK_DEVICES * STDCONTROL_JOYSTICK_RECORD_SIZE);
    memset(&DirectInputMouses, 0, STDCONTROL_MAX_MOUSE_DEVICES * STDCONTROL_JOYSTICK_RECORD_SIZE);
    stdControl_numJoystickDevices = 0;
    DirectInputNbMouses = 0;
    if (DirectX_DirectInputCreateA(Window_GetHINSTANCE(), STDCONTROL_DIRECTINPUT_VERSION, &iDirectInputA_ptr, NULL) != DI_OK)
        return 1;
    if (iDirectInputA_ptr->lpVtbl->EnumDevices(iDirectInputA_ptr, 0, DirectInput_EnumDevice_Callback, NULL, DIEDFL_ATTACHEDONLY) != DI_OK)
        return 1;
    stdControl_InitKeyboard();
    stdControl_InitJoysticks();
    stdControl_InitMouse();
    stdControl_Reset();
    stdControl_g_bStartup = 1;
    return 0;
}

// 0x00485460
void stdControl_Shutdown(void)
{
    unsigned int i;
    LPDIRECTINPUTDEVICEA* device;

    if (stdControl_g_bStartup == 0) {
        return;
    }
    stdControl_g_bStartup = 0;
    for (i = 0; i < (unsigned int)DirectInputNbMouses; i++) {
        device = stdControl_DeviceSlot(&pDIMouseDevice, i);
        if (*device != NULL) {
            (*device)->lpVtbl->Unacquire(*device);
            (*device)->lpVtbl->Release(*device);
        }
    }
    DirectInputNbMouses = 0;
    memset(&DirectInputMouses, 0, STDCONTROL_MAX_MOUSE_DEVICES * STDCONTROL_JOYSTICK_RECORD_SIZE);
    for (i = 0; i < (unsigned int)DirectInputNbKeyboard; i++) {
        device = stdControl_DeviceSlot(&stdControlKeyboardDevice, i);
        if (*device != NULL) {
            (*device)->lpVtbl->Unacquire(*device);
            (*device)->lpVtbl->Release(*device);
        }
    }
    DirectInputNbKeyboard = 0;
    memset(&DirectInputKeyboards, 0, STDCONTROL_MAX_KEYBOARD_DEVICES * STDCONTROL_JOYSTICK_RECORD_SIZE);
    for (i = 0; i < (unsigned int)stdControl_numJoystickDevices; i++) {
        device = stdControl_DeviceSlot(&stdControlJoystickDevice, i);
        if (*device != NULL) {
            (*device)->lpVtbl->Unacquire(*device);
            (*device)->lpVtbl->Release(*device);
        }
    }
    stdControl_numJoystickDevices = 0;
    memset(&DirectInputJoysticks, 0, STDCONTROL_MAX_JOYSTICK_DEVICES * STDCONTROL_JOYSTICK_RECORD_SIZE);
    if (iDirectInputA_ptr != NULL) {
        iDirectInputA_ptr->lpVtbl->Release(iDirectInputA_ptr);
        iDirectInputA_ptr = NULL;
    }
}

// 0x00485570
int stdControl_Open(void)
{
    if (stdControl_g_bStartup == 0)
    {
        return 1;
    }
    stdControl_g_bOpen = 1;
    stdControl_SetActivation(1);
    return 0;
}

// 0x004855a0
void stdControl_Close(void)
{
    if (stdControl_g_bOpen != 0)
    {
        stdControl_SetActivation(0);
        stdControl_g_bOpen = 0;
    }
}

// 0x004855c0
void stdControl_Reset(void)
{
    int i;

    stdControl_bReadMouse = 0;
    stdControl_bReadJoysticks = 0;
    for (i = 0; i < STDCONTROL_MAX_AXES; i++) {
        stdControl_aAxes[i].flags &= ~STDCONTROL_AXIS_ENABLED;
    }
}

// 0x004855f0
int stdControl_EnableAxis(int axisID)
{
    if ((unsigned int)axisID >= STDCONTROL_MAX_AXES) {
        return 0;
    }
    if ((stdControl_aAxes[axisID].flags & STDCONTROL_AXIS_REGISTERED) == 0) {
        return 0;
    }
    stdControl_aAxes[axisID].flags |= STDCONTROL_AXIS_ENABLED;
    stdControl_EnableAxisRead(axisID);
    return 1;
}

// 0x00485630
void stdControl_ReadControls(void)
{
    if (!stdControl_bControlsActive)
        return;

    memset(stdControl_aKeyIdleTimes, 0, sizeof(stdControl_aKeyIdleTimes));
    memset(stdControl_g_aKeyPressCounter, 0, sizeof(stdControl_g_aKeyPressCounter));
    stdControl_bControlsIdle = 1;
    stdControl_curReadTime = timeGetTime();
    stdControl_readDeltaTime = stdControl_curReadTime - stdControl_lastReadTime;
    memset(stdControl_aAxisPos, 0, 0xF0u);
    sithControl_secFPS = 1.0 / (double)(stdControl_curReadTime - stdControl_lastReadTime);
    sithControl_msecFPS = 1.0 / (double)(stdControl_curReadTime - stdControl_lastReadTime) * 1000.0;
    stdControl_ReadKeyboard();
    if (stdControl_bReadJoysticks)
        stdControl_ReadJoysticks();
    stdControl_ReadMouse();
    stdControl_lastReadTime = stdControl_curReadTime;
}

// 0x004856e0
RETAIL_FP long double stdControl_ReadAxis(int controlId)
{
    int delta;
    int magnitude;
    long double value; // retail returns the product unrounded

    if (stdControl_bControlsActive == 0) {
        return 0.0f;
    }
    if ((stdControl_aAxes[controlId].flags & STDCONTROL_AXIS_ENABLED) == 0) {
        return 0.0f;
    }
    delta = stdControl_aAxisPos[controlId] - stdControl_aAxes[controlId].xOffset;
    if (delta == 0) {
        return 0.0f;
    }
    if ((stdControl_aAxes[controlId].flags & STDCONTROL_AXIS_UNKNOWN_8) == 0 && stdControl_aAxes[controlId].yOffset != 0) {
        magnitude = delta < 0 ? -delta : delta;
        if (magnitude < stdControl_aAxes[controlId].yOffset) {
            return 0.0f;
        }
    }
    value = stdControl_aAxes[controlId].fltMedian * delta;
    if ((value < 0.0f ? -value : value) <= (float)STDCONTROL_AXIS_MIN_VALUE) {
        value = 0.0f;
    }
    if (stdControl_bControlsIdle != 0 && value != 0.0f) {
        stdControl_bControlsIdle = 0;
    }
    return value;
}

// 0x004857b0
RETAIL_FP long double stdControl_ReadKeyAsAxis(unsigned int keyId)
{
    unsigned int heldMs;
    long double value; // retail returns the product unrounded

    if (stdControl_bControlsActive == 0) {
        return 0.0f;
    }
    heldMs = stdControl_aKeyIdleTimes[keyId];
    if (heldMs == 0) {
        if (stdControl_aKeyInfos[keyId] == 0) {
            return 0.0f;
        }
        heldMs = stdControl_readDeltaTime;
    }
    if (heldMs >= (unsigned int)stdControl_readDeltaTime) {
        heldMs = stdControl_readDeltaTime;
    }
    value = (long double)heldMs * sithControl_secFPS;
    if (stdControl_bControlsIdle != 0 && value != 0.0f) {
        stdControl_bControlsIdle = 0;
    }
    return value;
}

// 0x00485840
RETAIL_FP int stdControl_ReadAxisAsKeyEx(int controlId)
{
    long double value;

    value = stdControl_ReadAxis(controlId);
    if (value < 0.0f) {
        value = -value;
    }
    return value > STDCONTROL_AXIS_AS_KEY_THRESHOLD ? 1 : 0;
}

// 0x00485880
int stdControl_ReadKey(unsigned int keyNum, int* pNumPressed)
{
    if (keyNum < 0)
        return 0;
    if (!stdControl_bControlsActive)
    {
        if (pNumPressed)
            *pNumPressed = 0;
        return 0;
    }

    if (pNumPressed)
        *pNumPressed += stdControl_g_aKeyPressCounter[keyNum];

    if (stdControl_bControlsIdle && stdControl_aKeyInfos[keyNum])
        stdControl_bControlsIdle = 0;

    return stdControl_aKeyInfos[keyNum];
}

// 0x004858e0
void stdControl_SetAxisDeadzone(float deadzone, int joystick, int axis)
{
    DIPROPRANGE range;
    LPDIRECTINPUTDEVICEA device;

    range.diph.dwSize = sizeof(DIPROPRANGE);
    range.diph.dwHeaderSize = sizeof(DIPROPHEADER);
    // the original leaves dwObj unset for axis > 5
    range.diph.dwObj = 0;
    if (axis == 0) {
        range.diph.dwObj = DIJOFS_X;
    } else if (axis == 1) {
        range.diph.dwObj = DIJOFS_Y;
    } else if (axis == 2) {
        range.diph.dwObj = DIJOFS_Z;
    } else if (axis == 3) {
        range.diph.dwObj = DIJOFS_RX;
    } else if (axis == 4) {
        range.diph.dwObj = DIJOFS_RY;
    } else if (axis == 5) {
        range.diph.dwObj = DIJOFS_RZ;
    }
    range.diph.dwHow = DIPH_BYOFFSET;
    device = *(LPDIRECTINPUTDEVICEA*)((char*)&stdControlJoystickDevice + joystick * STDCONTROL_JOYSTICK_RECORD_SIZE);
    if (device->lpVtbl->GetProperty(device, DIPROP_RANGE, &range.diph) >= 0) {
        stdControl_RegisterAxis(joystick * STDCONTROL_AXES_PER_JOYSTICK + axis, range.lMin, range.lMax, deadzone);
    }
}

// 0x004859a0
void stdControl_SetMouseRange(float xRange, float yRange)
{
    int extent;

    stdControl_mouseRangeX = xRange;
    stdControl_mouseRangeY = yRange;
    if ((stdControl_aAxes[STDCONTROL_MOUSE_AXIS_BASE].flags & STDCONTROL_AXIS_REGISTERED) != 0) {
        extent = (int)lrintf(xRange * STDCONTROL_MOUSE_X_EXTENT);
        stdControl_RegisterAxis(STDCONTROL_MOUSE_AXIS_BASE, -extent, extent, 0.0f);
    }
    if ((stdControl_aAxes[STDCONTROL_MOUSE_AXIS_BASE + 1].flags & STDCONTROL_AXIS_REGISTERED) != 0) {
        extent = (int)lrintf(stdControl_mouseRangeY * STDCONTROL_MOUSE_Y_EXTENT);
        stdControl_RegisterAxis(STDCONTROL_MOUSE_AXIS_BASE + 1, -extent, extent, 0.0f);
    }
}

// 0x00485a30
int stdControl_SetActivation(int bActive)
{
    unsigned int i;
    int key;
    LPDIRECTINPUTDEVICEA device;

    if (stdControl_g_bOpen == 0) {
        return 0;
    }
    for (key = 0; key < STDCONTROL_NUM_KEYBOARD_KEYS; key++) {
        if (stdControl_aKeyInfos[key] != 0) {
            stdControl_aKeyInfos[key] = 0;
            if (stdControl_aKeyIdleTimes[key] == 0) {
                stdControl_aKeyIdleTimes[key] = stdControl_readDeltaTime;
            }
        }
    }
    if (stdControl_bReadMouse != 0) {
        for (i = 0; i < (unsigned int)DirectInputNbMouses; i++) {
            if (*stdControl_DeviceSlot(&pDIMouseDevice, i) == NULL) {
                continue;
            }
            for (key = STDCONTROL_MOUSE_KEY_BASE + i * STDCONTROL_MOUSE_NUM_KEYS; key < STDCONTROL_MOUSE_KEY_BASE + (i + 1) * STDCONTROL_MOUSE_NUM_KEYS; key++) {
                if (stdControl_aKeyInfos[key] != 0) {
                    stdControl_aKeyInfos[key] = 0;
                    if (stdControl_aKeyIdleTimes[key] == 0) {
                        stdControl_aKeyIdleTimes[key] = stdControl_readDeltaTime;
                    }
                }
            }
        }
    }
    if (bActive != 0) {
        if (stdControl_bReadMouse != 0) {
            for (i = 0; i < (unsigned int)DirectInputNbMouses; i++) {
                device = *stdControl_DeviceSlot(&pDIMouseDevice, i);
                if (device != NULL && device->lpVtbl->Acquire(device) == DI_OK) {
                    ShowCursor(FALSE);
                }
            }
        }
        for (i = 0; i < (unsigned int)DirectInputNbKeyboard; i++) {
            device = *stdControl_DeviceSlot(&stdControlKeyboardDevice, i);
            if (device != NULL) {
                device->lpVtbl->Acquire(device);
            }
        }
        for (i = 0; i < (unsigned int)stdControl_numJoystickDevices; i++) {
            device = *stdControl_DeviceSlot(&stdControlJoystickDevice, i);
            if (device != NULL) {
                device->lpVtbl->Acquire(device);
            }
        }
        stdControl_bControlsActive = 1;
        return stdControl_numJoystickDevices;
    }
    for (i = 0; i < (unsigned int)DirectInputNbMouses; i++) {
        device = *stdControl_DeviceSlot(&pDIMouseDevice, i);
        if (device != NULL && device->lpVtbl->Unacquire(device) == DI_OK) {
            ShowCursor(TRUE);
        }
    }
    for (i = 0; i < (unsigned int)DirectInputNbKeyboard; i++) {
        device = *stdControl_DeviceSlot(&stdControlKeyboardDevice, i);
        if (device != NULL) {
            device->lpVtbl->Unacquire(device);
        }
    }
    for (i = 0; i < (unsigned int)stdControl_numJoystickDevices; i++) {
        device = *stdControl_DeviceSlot(&stdControlJoystickDevice, i);
        if (device != NULL) {
            device->lpVtbl->Unacquire(device);
        }
    }
    stdControl_bControlsActive = 0;
    return stdControl_numJoystickDevices;
}

// Creates one keyboard/mouse device from its enumerated record; on any failure the slot is released and cleared.
static void stdControl_InitBufferedDevice(DIDEVICEINSTANCEA* instance, LPDIRECTINPUTDEVICEA* device, LPCDIDATAFORMAT format)
{
    LPDIDEVCAPS caps = (LPDIDEVCAPS)(device + 1);
    DIPROPDWORD bufferSize;

    if (iDirectInputA_ptr->lpVtbl->CreateDevice(iDirectInputA_ptr, &instance->guidInstance, device, NULL) >= 0) {
        caps->dwSize = sizeof(DIDEVCAPS);
        if ((*device)->lpVtbl->GetCapabilities(*device, caps) >= 0 && (*device)->lpVtbl->SetDataFormat(*device, format) >= 0 && (*device)->lpVtbl->SetCooperativeLevel(*device, Window_GetHWND(), DISCL_NONEXCLUSIVE | DISCL_FOREGROUND) >= 0) {
            bufferSize.diph.dwSize = sizeof(DIPROPDWORD);
            bufferSize.diph.dwHeaderSize = sizeof(DIPROPHEADER);
            bufferSize.diph.dwObj = 0;
            bufferSize.diph.dwHow = DIPH_DEVICE;
            bufferSize.dwData = STDCONTROL_DEVICE_DATA_BUFFER_SIZE;
            if ((*device)->lpVtbl->SetProperty(*device, DIPROP_BUFFERSIZE, &bufferSize.diph) >= 0)
                return;
        }
    }
    if (*device != NULL)
        (*device)->lpVtbl->Release(*device);
    *device = NULL;
}

// 0x00485c40
void stdControl_InitJoysticks(void)
{
    static const DWORD axisOffsets[STDCONTROL_AXES_PER_JOYSTICK] = { DIJOFS_X, DIJOFS_Y, DIJOFS_Z, DIJOFS_RX, DIJOFS_RY, DIJOFS_RZ };
    LPDIRECTINPUTDEVICEA created = NULL;
    LPDIRECTINPUTDEVICEA* device;
    LPDIDEVCAPS caps;
    DIPROPRANGE range;
    DIPROPDWORD autoCenter;
    unsigned int j;
    int a;
    HRESULT hr;

    for (j = 0; j < (unsigned int)stdControl_numJoystickDevices; j++) {
        DIDEVICEINSTANCEA* instance = stdControl_DeviceInstance(&DirectInputJoysticks, j);
        int axisBase = j * STDCONTROL_AXES_PER_JOYSTICK;

        device = stdControl_DeviceSlot(&stdControlJoystickDevice, j);
        caps = (LPDIDEVCAPS)(device + 1);
        // faithful: the CreateDevice result is not checked
        iDirectInputA_ptr->lpVtbl->CreateDevice(iDirectInputA_ptr, &instance->guidInstance, &created, NULL);
        hr = created->lpVtbl->QueryInterface(created, &directInputDevice2A_GUID, (void**)device);
        created->lpVtbl->Release(created);
        created = NULL;
        if (hr >= 0) {
            caps->dwSize = sizeof(DIDEVCAPS);
            if ((*device)->lpVtbl->GetCapabilities(*device, caps) >= 0 && (*device)->lpVtbl->SetDataFormat(*device, &stdControl_dfJoystick) >= 0 && (*device)->lpVtbl->SetCooperativeLevel(*device, Window_GetHWND(), DISCL_EXCLUSIVE | DISCL_BACKGROUND) >= 0) {
                range.diph.dwSize = sizeof(DIPROPRANGE);
                range.diph.dwHeaderSize = sizeof(DIPROPHEADER);
                range.diph.dwHow = DIPH_BYOFFSET;
                for (a = 0; a < STDCONTROL_AXES_PER_JOYSTICK; a++) {
                    range.diph.dwObj = axisOffsets[a];
                    if ((*device)->lpVtbl->GetProperty(*device, DIPROP_RANGE, &range.diph) >= 0)
                        stdControl_RegisterAxis(axisBase + a, range.lMin, range.lMax, STDCONTROL_JOYSTICK_DEADZONE);
                }
                hr = DI_OK;
                if (caps->dwFlags & DIDC_FORCEFEEDBACK) {
                    autoCenter.diph.dwSize = sizeof(DIPROPDWORD);
                    autoCenter.diph.dwHeaderSize = sizeof(DIPROPHEADER);
                    autoCenter.diph.dwObj = 0;
                    autoCenter.diph.dwHow = DIPH_DEVICE;
                    autoCenter.dwData = DIPROPAUTOCENTER_OFF;
                    hr = (*device)->lpVtbl->SetProperty(*device, DIPROP_AUTOCENTER, &autoCenter.diph);
                }
                if (hr >= 0 && (*device)->lpVtbl->Acquire(*device) >= 0)
                    continue;
            }
        }
        if (*device != NULL)
            (*device)->lpVtbl->Release(*device);
        *device = NULL;
        for (a = 0; a < STDCONTROL_AXES_PER_JOYSTICK; a++)
            stdControl_aAxes[axisBase + a].flags &= ~STDCONTROL_AXIS_REGISTERED;
    }
}

// 0x00485f20
void stdControl_InitKeyboard(void)
{
    unsigned int i;

    if (iDirectInputA_ptr == NULL)
        return;
    for (i = 0; i < (unsigned int)DirectInputNbKeyboard; i++)
        stdControl_InitBufferedDevice(stdControl_DeviceInstance(&DirectInputKeyboards, i), stdControl_DeviceSlot(&stdControlKeyboardDevice, i), &stdControl_dfKeyboard);
}

// 0x00486010
void stdControl_InitMouse(void)
{
    unsigned int i;

    if (iDirectInputA_ptr == NULL)
        return;
    for (i = 0; i < (unsigned int)DirectInputNbMouses; i++)
        stdControl_InitBufferedDevice(stdControl_DeviceInstance(&DirectInputMouses, i), stdControl_DeviceSlot(&pDIMouseDevice, i), &stdControl_dfMouse);
    if (DirectInputNbMouses != 0) {
        stdControl_RegisterAxis(STDCONTROL_MOUSE_AXIS_BASE, -(int)STDCONTROL_MOUSE_X_EXTENT, (int)STDCONTROL_MOUSE_X_EXTENT, 0.0f);
        stdControl_RegisterAxis(STDCONTROL_MOUSE_AXIS_BASE + 1, -(int)STDCONTROL_MOUSE_Y_EXTENT, (int)STDCONTROL_MOUSE_Y_EXTENT, 0.0f);
        // only the first mouse's caps decide whether the wheel axis exists
        if (((LPDIDEVCAPS)(&pDIMouseDevice + 1))->dwAxes > 2)
            stdControl_RegisterAxis(STDCONTROL_MOUSE_AXIS_BASE + 2, -STDCONTROL_MOUSE_WHEEL_EXTENT, STDCONTROL_MOUSE_WHEEL_EXTENT, 0.0f);
    }
}

// 0x00486140
void stdControl_EnableAxisRead(unsigned int axisID)
{
    if (axisID >= STDCONTROL_MOUSE_AXIS_BASE && axisID < STDCONTROL_MOUSE_AXIS_BASE + STDCONTROL_MOUSE_NUM_AXES) {
        stdControl_bReadMouse = 1;
        return;
    }
    if (axisID < STDCONTROL_NUM_JOYSTICK_AXES) {
        stdControl_bReadJoysticks = 1;
    }
}

static void stdControl_PressKey(int key, int idleTime)
{
    if (stdControl_aKeyInfos[key] == 0) {
        stdControl_aKeyInfos[key] = 1;
        stdControl_aKeyIdleTimes[key] = idleTime;
        stdControl_g_aKeyPressCounter[key]++;
    }
}

static void stdControl_ReleaseKey(int key, int idleDelta)
{
    if (stdControl_aKeyInfos[key] != 0) {
        stdControl_aKeyInfos[key] = 0;
        if (stdControl_aKeyIdleTimes[key] == 0)
            stdControl_aKeyIdleTimes[key] = stdControl_readDeltaTime;
        stdControl_aKeyIdleTimes[key] += idleDelta;
    }
}

static void stdControl_SetKey(int key, int pressed)
{
    if (pressed)
        stdControl_PressKey(key, 0);
    else
        stdControl_ReleaseKey(key, 0);
}

// 0x00486170
void stdControl_ReadKeyboard(void)
{
    DIDEVICEOBJECTDATA data[STDCONTROL_DEVICE_DATA_BUFFER_SIZE];
    char state[STDCONTROL_NUM_KEYBOARD_KEYS];
    DWORD count = STDCONTROL_DEVICE_DATA_BUFFER_SIZE; // faithful: not refilled between devices
    unsigned int i;
    unsigned int k;
    LPDIRECTINPUTDEVICEA device;
    HRESULT hr;

    for (i = 0; i < (unsigned int)DirectInputNbKeyboard; i++) {
        device = *stdControl_DeviceSlot(&stdControlKeyboardDevice, i);
        hr = device->lpVtbl->GetDeviceData(device, sizeof(DIDEVICEOBJECTDATA), data, &count, 0);
        if (hr == DI_OK) {
            for (k = 0; k < count; k++) {
                if (data[k].dwData != 0)
                    stdControl_PressKey(data[k].dwOfs, stdControl_curReadTime - data[k].dwTimeStamp);
                else
                    stdControl_ReleaseKey(data[k].dwOfs, data[k].dwTimeStamp - stdControl_curReadTime);
            }
            // faithful: retail reuses the device index register as the event counter
            i = count;
        } else if (hr == DI_BUFFEROVERFLOW) {
            if (device->lpVtbl->GetDeviceState(device, sizeof(state), state) >= 0) {
                for (k = 0; k < STDCONTROL_NUM_KEYBOARD_KEYS; k++)
                    stdControl_SetKey(k, state[k] != 0);
            }
        } else {
            device->lpVtbl->Acquire(device);
        }
    }
}

// 0x00486340
void stdControl_ReadJoysticks(void)
{
    DIJOYSTATE state;
    unsigned int j;
    unsigned int b;
    unsigned int p;
    unsigned int numPOVs;
    LPDIRECTINPUTDEVICE2A device;

    for (j = 0; j < (unsigned int)stdControl_numJoystickDevices; j++) {
        int* axisPos = &stdControl_aAxisPos[j * STDCONTROL_AXES_PER_JOYSTICK];
        int keyBase = STDCONTROL_JOYSTICK_KEY_BASE + j * STDCONTROL_KEYS_PER_JOYSTICK;

        device = (LPDIRECTINPUTDEVICE2A)*stdControl_DeviceSlot(&stdControlJoystickDevice, j);
        if (device->lpVtbl->Poll(device) < 0 || device->lpVtbl->GetDeviceState(device, sizeof(state), &state) < 0) {
            // faithful: one failing joystick stops the read for the rest
            device->lpVtbl->Acquire(device);
            return;
        }
        axisPos[0] = state.lX;
        axisPos[1] = state.lY;
        axisPos[2] = state.lZ;
        axisPos[3] = state.lRx;
        axisPos[4] = state.lRy;
        axisPos[5] = state.lRz;
        for (b = 0; b < STDCONTROL_JOYSTICK_NUM_BUTTONS; b++)
            stdControl_SetKey(keyBase + b, state.rgbButtons[b] != 0);

        numPOVs = *(DWORD*)((char*)&stdControlJoystickCapsPOVs + j * STDCONTROL_JOYSTICK_RECORD_SIZE);
        for (p = 0; p < numPOVs && p < STDCONTROL_JOYSTICK_MAX_POVS; p++) {
            DWORD pov = state.rgdwPOV[p];
            int centered = LOWORD(pov) == 0xffff;
            int key = keyBase + STDCONTROL_JOYSTICK_POV_KEY_BASE + p * STDCONTROL_KEYS_PER_POV;

            // POV hundredths of a degree; each direction covers a 90 degree arc, neighbours overlap at the diagonals
            stdControl_SetKey(key + 0, pov >= STDCONTROL_POV_225 && pov <= STDCONTROL_POV_315);
            stdControl_SetKey(key + 1, (pov >= STDCONTROL_POV_315 || pov <= STDCONTROL_POV_45) && !centered);
            stdControl_SetKey(key + 2, pov >= STDCONTROL_POV_45 && pov <= STDCONTROL_POV_135);
            stdControl_SetKey(key + 3, pov >= STDCONTROL_POV_135 && pov <= STDCONTROL_POV_225);
        }
    }
}

// 0x00486710
void stdControl_ReadMouse(void)
{
    DIDEVICEOBJECTDATA data[STDCONTROL_DEVICE_DATA_BUFFER_SIZE];
    DIMOUSESTATE state;
    DWORD count = STDCONTROL_DEVICE_DATA_BUFFER_SIZE; // faithful: not refilled between devices
    unsigned int i;
    unsigned int k;
    LPDIRECTINPUTDEVICEA device;
    HRESULT hr;

    if (stdControl_bReadMouse == 0)
        return;

    for (i = 0; i < (unsigned int)DirectInputNbMouses; i++) {
        int* axisPos = &stdControl_aAxisPos[STDCONTROL_MOUSE_AXIS_BASE + i * STDCONTROL_MOUSE_NUM_AXES];
        int keyBase = STDCONTROL_MOUSE_KEY_BASE + i * STDCONTROL_MOUSE_NUM_KEYS;

        device = *stdControl_DeviceSlot(&pDIMouseDevice, i);
        if (device == NULL)
            continue;

        hr = device->lpVtbl->GetDeviceState(device, sizeof(state), &state);
        if (hr != DI_OK) {
            device->lpVtbl->Acquire(device);
        } else {
            axisPos[0] = state.lX;
            axisPos[1] = state.lY;
            axisPos[2] = state.lZ;
            // smooth X/Y over two reads at high frame rates
            if ((unsigned int)stdControl_readDeltaTime < STDCONTROL_MOUSE_SMOOTH_MAX_MS) {
                axisPos[0] = (stdControl_mousePrevX[i] + state.lX) >> 1;
                axisPos[1] = (stdControl_mousePrevY[i] + state.lY) >> 1;
            }
            stdControl_mousePrevX[i] = state.lX;
            stdControl_mousePrevY[i] = state.lY;
        }

        hr = device->lpVtbl->GetDeviceData(device, sizeof(DIDEVICEOBJECTDATA), data, &count, 0);
        if (hr == DI_OK) {
            for (k = 0; k < count; k++) {
                DWORD ofs = data[k].dwOfs;
                if (ofs < DIMOFS_BUTTON0 || ofs > DIMOFS_BUTTON3)
                    continue;
                if (data[k].dwData != 0)
                    stdControl_PressKey(keyBase + ofs - DIMOFS_BUTTON0, stdControl_curReadTime - data[k].dwTimeStamp);
                else
                    stdControl_ReleaseKey(keyBase + ofs - DIMOFS_BUTTON0, data[k].dwTimeStamp - stdControl_curReadTime);
            }
        } else if (hr == DI_BUFFEROVERFLOW) {
            for (k = 0; k < STDCONTROL_MOUSE_NUM_KEYS; k++)
                stdControl_SetKey(keyBase + k, state.rgbButtons[k] != 0);
        } else {
            device->lpVtbl->Acquire(device);
        }
    }
}

// 0x00486970
void stdControl_RegisterAxis(int axisID, int min, int max, float scale)
{
    int center;
    float halfRange;

    stdControl_aAxes[axisID].flags |= STDCONTROL_AXIS_REGISTERED;
    center = ((max - min) + 1) / 2 + min;
    stdControl_aAxes[axisID].min = min;
    stdControl_aAxes[axisID].max = max;
    stdControl_aAxes[axisID].xOffset = center;
    halfRange = (float)(max - center);
    stdControl_aAxes[axisID].fltMedian = 1.0f / halfRange;
    if (scale != 0.0f) {
        stdControl_aAxes[axisID].yOffset = (int)(scale * halfRange);
        return;
    }
    stdControl_aAxes[axisID].yOffset = 0;
}
