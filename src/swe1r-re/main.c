#include <stdio.h>

#include "hello.h"
#include "other.h"

int main(void)
{
    printf("hello to you and to %s and  %s\n", hello(), other());
    return 0;
}
