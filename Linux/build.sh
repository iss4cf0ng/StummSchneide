gcc -O1 -nostdlib -fPIC -fno-plt -ffreestanding -fno-stack-protector -fno-exceptions -m32 -c shellcode_linux.c -o shellcode_linux.o
objcopy --only-section=.text -O binary shellcode_linux.o shellcode_linux.bin
gcc -shared -fPIC -m32 -nostdlib -o payload_linux.so payload_linux.c
gcc -o loader_linux loader_linux.c -z execstack -m32