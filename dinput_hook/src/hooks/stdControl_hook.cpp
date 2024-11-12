#include "stdControl_hook.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <globals.h>

int stdControl_Startup_hook(void) {
    stdControl_g_bStartup = 1;
    return 0;
}

void stdControl_ReadControls_hook(void) {
    if (!stdControl_bControlsActive)
        return;

    memset(stdControl_aKeyIdleTimes, 0, sizeof(stdControl_aKeyIdleTimes));
    memset(stdControl_g_aKeyPressCounter, 0, sizeof(stdControl_g_aKeyPressCounter));
    stdControl_bControlsIdle = 1;
    stdControl_curReadTime = timeGetTime();
    stdControl_readDeltaTime = stdControl_curReadTime - stdControl_lastReadTime;
    memset(stdControl_aAxisPos, 0, 0xF0u);
    sithControl_secFPS = 1.0 / (double) (stdControl_curReadTime - stdControl_lastReadTime);
    sithControl_msecFPS =
        1.0 / (double) (stdControl_curReadTime - stdControl_lastReadTime) * 1000.0;
    glfwPollEvents();
    stdControl_lastReadTime = stdControl_curReadTime;
}

int stdControl_SetActivation_hook(int bActive) {
    stdControl_bControlsActive = bActive;

    return 0;
}
