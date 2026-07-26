// helpers.cpp

#include <windows.h>
#include <winternl.h>

extern "C" ULONG_PTR GetKernel32Base()
{
    ULONG_PTR r = 0;
    __asm__ (
        ".intel_syntax noprefix\n"
        "mov eax, fs:[0x30]\n"
        "mov eax, [eax + 0x0C]\n"
        "mov eax, [eax + 0x14]\n"
        "mov eax, [eax]\n"
        "mov eax, [eax]\n"
        "mov %0, [eax + 0x10]\n"
        ".att_syntax\n"
        : "=r"(r)
    );

    return r;
}

extern "C" ULONG_PTR CustomGetProcAddress(ULONG_PTR moduleBase, const char *funcName)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(moduleBase + dos->e_lfanew);

    DWORD erva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!erva)
        return 0;

    PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + erva);
    DWORD *names = (DWORD *)(moduleBase + ed->AddressOfNames);
    WORD *ords = (WORD *)(moduleBase + ed->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(moduleBase + ed->AddressOfFunctions);

    for (DWORD i = 0; i < ed->NumberOfNames; i++)
    {
        const char *f1 = funcName;
        char *f2 = (char *)(moduleBase + names[i]);
        while (*f1 && *f2)
        {
            f1++;
            f2++;
        }

        if (!*f1 && !*f2)
            return moduleBase + funcs[ords[i]];
    }

    return 0;
}