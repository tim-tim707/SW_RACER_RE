#include "swrEvent.h"

#include "types.h"
#include "globals.h"

#include "swrAssetBuffer.h"
#include "swr.h"

#include <macros.h>

// 0x00447300
void swrEvent_AllocateAndLoadObjs(int event, int count)
{
    char* objs = swrAssetBuffer_GetBuffer();
    void* used = swrEvent_SetObjs(event, count, objs);
    swrEvent_Initialize(event);
    swrAssetBuffer_SetBuffer(objs + (int) used);
    int subEvent = 0x4c6f6164; // 'Load'
    swrEvent_CallF4(event, &subEvent);
}

// 0x00447350
void swrEvent_ClearObjs(int event)
{
    swrEvent_SetObjs(event, 0, NULL);
}

// 0x00450850
void swrEvent_Initialize(int event)
{
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++)
    {
        swrEventManager* manager = *it;
        if (manager->event == event)
        {
            swrObj* obj = manager->head;
            for (short i = 0; i < manager->count; i++)
            {
                obj->id = i;
                obj->event = manager->event;
                obj->flags = (short) manager->flags;
                obj = (swrObj*) ((char*) obj + manager->size);
            }
        }
    }
}

// 0x004508b0
void swrEvent_CallAllF0(void)
{
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++)
    {
        swrEventManager* manager = *it;
        if (manager->f0 != NULL && (manager->flags & swrEvent_f0SkipMask) == 0)
        {
            swrObj* obj = manager->head;
            for (short i = 0; i < manager->count; i++)
            {
                if ((obj->flags & 0x1100) == 0)
                    manager->f0(obj);
                obj = (swrObj*) ((char*) obj + manager->size);
                swr_noop4();
            }
        }
    }
}

// 0x00450930
void swrEvent_CallAllF1(void)
{
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++)
    {
        swrEventManager* manager = *it;
        if (manager->f1 != NULL && (manager->flags & swrEvent_f0SkipMask) == 0)
        {
            swrObj* obj = manager->head;
            for (short i = 0; i < manager->count; i++)
            {
                if ((obj->flags & 0x1100) == 0)
                    manager->f1(obj);
                obj = (swrObj*) ((char*) obj + manager->size);
                swr_noop4();
            }
        }
    }
}

// 0x004509b0
void swrEvent_CallAllF2(void)
{
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++)
    {
        swrEventManager* manager = *it;
        if (manager->f2 != NULL && (manager->flags & swrEvent_f0SkipMask) == 0)
        {
            swrObj* obj = manager->head;
            for (short i = 0; i < manager->count; i++)
            {
                if ((obj->flags & 0x1100) == 0)
                    manager->f2(obj);
                obj = (swrObj*) ((char*) obj + manager->size);
                swr_noop4();
            }
        }
    }
}

// 0x00450a30
void swrEvent_CallAllF3(void)
{
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++)
    {
        swrEventManager* manager = *it;
        if (manager->f3 != NULL)
        {
            swrObj* obj = manager->head;
            for (short i = 0; i < manager->count; i++)
            {
                if ((obj->flags & 0x1100) == 0)
                    manager->f3(obj);
                obj = (swrObj*) ((char*) obj + manager->size);
            }
            swr_noop4();
        }
    }
}

// 0x00450aa0
void* swrEvent_FindObjectById(int event, int id)
{
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++)
    {
        swrEventManager* manager = *it;
        if (manager->event == event)
        {
            swrObj* obj = manager->head;
            for (short i = 0; i < manager->count; i++)
            {
                if ((obj->flags & 0x100) == 0 && obj->id == id)
                    return obj;
                obj = (swrObj*) ((char*) obj + manager->size);
            }
        }
    }
    return NULL;
}

// 0x00450b00
int swrEvent_GetEventCount(int event)
{
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++)
    {
        swrEventManager* manager = *it;
        if (manager->event == event)
            return manager->count;
    }
    return 0;
}

// 0x00450b30
void* swrEvent_GetItem(int event, int index)
{
    swrEvent_lastManager = NULL;
    swrEventManager** it = eventManagerMain;
    swrEventManager* manager = *it;
    if (manager == NULL)
        return NULL;

    while (manager->event != event)
    {
        manager = *++it;
        if (manager == NULL)
            return NULL;
    }

    if (index < manager->count)
    {
        swrEvent_lastManager = manager;
        swrEvent_lastIndex = index;
        return (char*) manager->head + manager->size * index;
    }
    return NULL;
}

// Retail pushes the message twice: F4 handlers that take a third argument see the message again.
typedef int (*swrEvent_F4Call)(void* obj, void* msg, void* msgAgain);

// 0x00450c00
void swrEvent_DispatchSubEvents(void* obj, int* subEvents)
{
    if (obj == NULL)
        return;

    swrEventManager** it = eventManagerMain;
    swrEventManager* manager = *it;
    if (manager == NULL)
        return;

    while (manager->event != ((swrObj*) obj)->event)
    {
        manager = *++it;
        if (manager == NULL)
            return;
    }

    if (manager->f4 != NULL && (((swrObj*) obj)->flags & 0x100) == 0)
        ((swrEvent_F4Call) manager->f4)(obj, subEvents, subEvents);
}

// 0x00450c50
void swrEvent_CallF4(int event, void* forward_param)
{
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++)
    {
        swrEventManager* manager = *it;
        if (manager->event != event && event != 0x416c6c21 /* 'All!' */)
            continue;

        if (manager->f4 != NULL)
        {
            swrObj* obj = manager->head;
            for (int i = 0; i < manager->count; i++)
            {
                if ((obj->flags & 0x100) == 0 && ((swrEvent_F4Call) manager->f4)(obj, forward_param, forward_param) == 2)
                    return;
                obj = (swrObj*) ((char*) obj + manager->size);
            }
        }

        if (event != 0x416c6c21)
            return;
    }
}

// 0x00450ce0
void* swrEvent_SetObjs(int event, int count, void* objs)
{
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++)
    {
        swrEventManager* manager = *it;
        if (manager->event == event)
        {
            manager->head = objs;
            manager->count = count;
            return (void*) (manager->size * count);
        }
    }
    return NULL;
}

// 0x00450d20
void* swrEvent_AllocObj(int event)
{
    swrEventManager** it = eventManagerMain;
    swrEventManager* manager = *it;
    if (manager == NULL)
        return NULL;

    while (manager->event != event)
    {
        manager = *++it;
        if (manager == NULL)
            return NULL;
    }

    if (manager->f4 == NULL)
        return NULL;

    swrObj* obj = manager->head;
    for (int i = 0; i < manager->count; i++)
    {
        if ((obj->flags & 0x100) != 0)
        {
            *((unsigned char*) obj + 7) &= 0xfe;
            int subEvent = 0x416c6f63; // 'Aloc'
            swrEvent_DispatchSubEvents(obj, &subEvent);
            return obj;
        }
        obj = (swrObj*) ((char*) obj + manager->size);
    }
    return NULL;
}

// 0x00450db0
void swrEvent_FreeObjs(int event)
{
    int subEvent = 0x46726565; // 'Free'
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++)
    {
        swrEventManager* manager = *it;
        if (manager->event == event)
        {
            swrObj* obj = manager->head;
            for (short i = 0; i < manager->count; i++)
            {
                if ((obj->flags & 0x100) == 0)
                {
                    swrEvent_DispatchSubEvents(obj, &subEvent);
                    *((unsigned char*) obj + 7) |= 1;
                }
                obj = (swrObj*) ((char*) obj + manager->size);
            }
        }
    }
}

// 0x00450b90
void swrEvent_BroadcastFiltered(int event, int filter, int* data)
{
    int msg[16];

    msg[0] = event;
    msg[1] = filter;
    for (int i = 2; i < 16; i++)
        msg[i] = data[i - 2];
    swr_noop2(); // EXE passes (0xee06, msg)
}

// 0x00450be0
void swrEvent_Broadcast(int event, int* subEvents)
{
    swrEvent_BroadcastFiltered(event, 'All!', subEvents);
}

// Collects up to maxResults objects of the given event type (0x416c6c21 'All!' = any type)
// within sqrt(maxDistSq) of pos, sorted nearest-first. Skips disabled objects (flags 0x100)
// and excludeObj. Fills squared distances, pos->object delta vectors and object pointers;
// returns the number found. Positions are read from the object's transform.vD (+0x50), which
// every caller relies on by passing 'Test' (swrRace) objects.
// 0x00450e70
RETAIL_FP int swrEvent_FindNearestObjects(int event, rdVector3* pos, float maxDistSq, void* excludeObj, int maxResults, float* outDistances, rdVector3* outDeltas, void** outObjects)
{
    int found = 0;
    for (swrEventManager** it = eventManagerMain; *it != NULL; it++) {
        swrEventManager* manager = *it;
        if ((manager->event != event && event != 0x416c6c21) || (manager->flags & 1) == 0)
            continue;

        char* obj = (char*)manager->head;
        for (int i = 0; i < manager->count; i++, obj += manager->size) {
            if ((((swrObj*)obj)->flags & 0x100) != 0 || obj == (char*)excludeObj)
                continue;

            rdVector4* objPos = &((swrRace*)obj)->transform.vD;
            // retail: dx and the sum stay in ST0, dy is squared raw x its float spill, dz from its spill
            long double dx = objPos->x - pos->x;
            long double dyRaw = objPos->y - pos->y;
            float dy = (float) dyRaw;
            float dz = objPos->z - pos->z;
            long double distSq = dx * dx + dyRaw * dy + dz * dz;
            if (maxDistSq <= distSq)
                continue;

            // Sorted insertion: find the first slot this distance does not beat.
            int insertIdx = 0;
            while (insertIdx < found && outDistances[insertIdx] < distSq)
                insertIdx++;
            if (insertIdx >= maxResults)
                continue;

            int lastIdx;
            if (found < maxResults)
                lastIdx = found++;
            else
                lastIdx = maxResults - 1;
            for (int j = lastIdx; j > insertIdx; j--) {
                outObjects[j] = outObjects[j - 1];
                outDistances[j] = outDistances[j - 1];
                outDeltas[j] = outDeltas[j - 1];
            }
            outDistances[insertIdx] = (float) distSq;
            outObjects[insertIdx] = obj;
            outDeltas[insertIdx].x = (float) dx;
            outDeltas[insertIdx].y = dy;
            outDeltas[insertIdx].z = dz;
        }
    }
    return found;
}
