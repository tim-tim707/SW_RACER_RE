#include "rdLight.h"

// 0x00490510
int rdLight_NewEntry(rdLight* light)
{
    light->type = 2;
    light->active = 1;
    (light->direction).x = 0.0;
    (light->direction).y = 0.0;
    (light->direction).z = 0.0;
    light->intensity = 1.0;
    light->color = 1.0;
    light->dword20 = 1.0;
    light->dword24 = 0;
    light->falloffMin = 0.0;
    light->falloffMax = 0.0;
    return 1;
}
