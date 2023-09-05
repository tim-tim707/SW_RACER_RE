#include "swrText.h"

#include "types.h"
#include "globals.h"

// 0x00407b0
char* swrText_GetKeyNameText(uint32_t id, char* str)
{
    HANG("TODO");
    return NULL;
}

// 0x00421120
int swrText_ParseRacerTab(char* filepath)
{
    HANG("TODO: missing stdlib function");
    return 0;
}

// 0x004212f0
int swrText_CmpRacerTab(char** a, char** b)
{
    char* a_;
    char* b_;
    int cmp;
    char a_0;

    b_ = (char*)*b;
    a_ = (char*)*a;
    while (1)
    {
        a_0 = *a_;
        cmp = a_0 < *b_;
        if (a_0 != *b_)
            break;
        if (a_0 == 0)
        {
            return 0;
        }
        a_0 = a_[1];
        cmp = a_0 < b_[1];
        if (a_0 != b_[1])
            break;
        a_ = a_ + 2;
        b_ = b_ + 2;
        if (a_0 == 0)
        {
            return 0;
        }
    }
    return (1 - (uint32_t)cmp) - (uint32_t)(cmp != 0);
}

// 0x00421330
void swrText_Shutdown(void)
{
    if (swrText_racerTab_buffer != NULL)
    {
        (*stdPlatform_hostServices_ptr->free)(swrText_racerTab_buffer);
    }
    if (swrText_racerTab_array != NULL)
    {
        (*stdPlatform_hostServices_ptr->free)(swrText_racerTab_array);
    }
}

// 0x00421360
char* swrText_Translate(char* text)
{
    HANG("TODO");
    return NULL;
}
