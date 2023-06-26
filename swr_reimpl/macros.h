#ifndef MACROS_H
#define MACROS_H

#include <stdio.h>
#include <windows.h>

#define hang()                                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("Hanging at %s, line %d, %s\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);                               \
        while (1)                                                                                                      \
        {                                                                                                              \
            Sleep(1000); /* Without sleep, CPU go brr */                                                               \
        }                                                                                                              \
    } while (0)

#endif // MACROS_H
