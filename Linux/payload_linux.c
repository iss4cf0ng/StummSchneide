// payload.c
// gcc -shared -fPIC -m32 -nostdlib -o payload.so payload.c

#include <stdio.h>
#include <stdlib.h>

static void _write(int fd, const char* s, int n) {
    __asm__ volatile("int $0x80"
        : : "a"(4), "b"(fd), "c"(s), "d"(n) : "memory");
}

__attribute__((visibility("default")))
void payload_run(void) {
    const char msg[] = "[+] StummSchneide\n";
    _write(1, msg, sizeof(msg) - 1);
}