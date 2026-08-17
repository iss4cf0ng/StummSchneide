// payload_linux.c
// gcc -shared -fPIC -nostdlib -o payload_linux.so payload_linux.c

static void _write(int fd, const char* s, long n)
{
    __asm__ volatile("syscall"
        : : "a"(1L), "D"((long)fd), "S"(s), "d"(n)
        : "rcx","r11","memory");
}

__attribute__((visibility("default")))
void payload_run(void)
{
    const char msg[] = "[+] StummSchneide\n";
    _write(1, msg, sizeof(msg) - 1);
}