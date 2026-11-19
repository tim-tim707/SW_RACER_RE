#include "stdControl.h"

#include "globals.h"

#include <macros.h>
#include "engine_config.h"

#include <math.h>
#include <string.h>

static LPDIRECTINPUTDEVICEA* stdControl_DeviceSlot(LPDIRECTINPUTDEVICEA* first, unsigned int index)
{
    return (LPDIRECTINPUTDEVICEA*)((char*)first + index * STDCONTROL_JOYSTICK_RECORD_SIZE);
}

// 0x00485360
int stdControl_Startup(void)
{
    HANG("TODO");
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

// 0x00485570 TODO: crashes on release build, works fine on debug
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

// 0x004855a0 TODO: crashes on release build, works fine on debug
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
float stdControl_ReadAxis(int controlId)
{
    int delta;
    int magnitude;
    float value;

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
    value = (float)delta * stdControl_aAxes[controlId].fltMedian;
    if (fabsf(value) <= STDCONTROL_AXIS_MIN_VALUE) {
        value = 0.0f;
    }
    if (stdControl_bControlsIdle != 0 && value != 0.0f) {
        stdControl_bControlsIdle = 0;
    }
    return value;
}

// 0x004857b0
float stdControl_ReadKeyAsAxis(unsigned int keyId)
{
    unsigned int heldMs;
    float value;

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
    value = (float)heldMs * sithControl_secFPS;
    if (stdControl_bControlsIdle != 0 && value != 0.0f) {
        stdControl_bControlsIdle = 0;
    }
    return value;
}

// 0x00485840
int stdControl_ReadAxisAsKeyEx(int controlId)
{
    float value;

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

// 0x00485c40
void stdControl_InitJoysticks(void)
{
    HANG("TODO");
}

// 0x00485f20
void stdControl_InitKeyboard(void)
{
    HANG("TODO");
}

// 0x00486010
void stdControl_InitMouse(void)
{
    HANG("TODO");
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

// 0x00486170
void stdControl_ReadKeyboard(void)
{
    HANG("TODO");
}

// 0x00486340
void stdControl_ReadJoysticks(void)
{
    HANG("TODO");
}

// 0x00486710
void stdControl_ReadMouse(void)
{
    HANG("TODO");
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
