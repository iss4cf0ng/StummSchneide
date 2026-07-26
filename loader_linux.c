// loader.c

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = {

};

int main()
{
    size_t len = sizeof(shellcode);
    void *mem = mmap(NULL, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED)
    {
        perror("[-] mmap failed");
        return 1;
    }

    memcpy(mem, shellcode, len);

    printf("[*] %zu bytes at %p, executing\n", len, mem);
    fflush(stdout);

    ((void(*)())mem)();

    printf("[*] returned\n");
    munmap(mem, len);

    return 0;
}