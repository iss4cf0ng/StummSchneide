// payload.c

#include <stdio.h>

__attribute__((visibility("default")))
void payload_run(void)
{
    const char msg[] = "StummSchneide\n";

    __asm__ volatile (
        "int %0x80"
        :: "a"(4), "b"(1), "c"(msg), "d"(sizeof(msg) - 1)
    );
}