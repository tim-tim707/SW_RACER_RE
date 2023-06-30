#ifndef TYPES_H
#define TYPES_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

    typedef struct rdVector2
    {
        float x;
        float y;
    } rdVector2;

    typedef struct rdVector3
    {
        float x;
        float y;
        float z;
    } rdVector3;

    typedef struct rdVector4
    {
        float x;
        float y;
        float z;
        float w;
    } rdVector4;

    typedef struct rdMatrix44
    {
        rdVector4 vA;
        rdVector4 vB;
        rdVector4 vC;
        rdVector4 vD;
    } rdMatrix44;

#ifdef __cplusplus
}
#endif
#endif // TYPES_H
