// loader_linux.c

#include <stdio.h>
#include <sys/mman.h>

#define MAP_ANONYMOUS  0x20

int main() {
    FILE* f = fopen("shellcode.bin", "rb");
    if (!f) { perror("shellcode.bin"); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);

    void* mem = mmap(NULL, sz,
                     PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    fread(mem, 1, sz, f); fclose(f);

    printf("[*] %ld bytes at %p — executing\n", sz, mem);
    fflush(stdout);
    ((void(*)())mem)();
    printf("[*] returned\n");
    munmap(mem, sz);
}