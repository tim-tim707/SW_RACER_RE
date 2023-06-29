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

#ifdef DEBUG
#undef DEBUG
#define DEBUG(format, ...)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("DBG in %s %s:%d ", __FILE__, __PRETTY_FUNCTION__, __LINE__);                                           \
        printf(format, __VA_ARGS__);                                                                                   \
    } while (0);
#else
#define DEBUG(format, ...)
#endif // DEBUG

#ifdef LOG
#undef LOG
#define LOG(format, ...)                                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("LOG in %s %s:%d ", __FILE__, __PRETTY_FUNCTION__, __LINE__);                                           \
        printf(format, __VA_ARGS__);                                                                                   \
    } while (0);
#else
#define LOG(format, ...)
#endif // LOG

#endif // MACROS_H
