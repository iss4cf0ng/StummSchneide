#!/bin/bash
set -e

FLAGS="-O1 -nostdlib -fno-pic -fno-plt -ffreestanding \
       -fno-stack-protector -fno-exceptions"

cat > link.ld << 'LDEOF'
OUTPUT_FORMAT(binary)
SECTIONS {
    . = 0;
    .text : {
        entry_linux.o(.text)
        helpers_linux.o(.text)
        *(.text*)
        *(.rodata*)
    }
}
LDEOF

echo "[*] compiling..."
gcc $FLAGS -c entry_linux.c   -o entry_linux.o
gcc $FLAGS -c helpers_linux.c -o helpers_linux.o

echo "[*] linking..."
ld -T link.ld entry_linux.o helpers_linux.o -o shellcode_linux.bin
echo "    $(wc -c < shellcode_linux.bin) bytes"

echo "[*] verifying..."
nm -n entry_linux.o | grep " T shellcode_entry"

echo "[*] building payload..."
gcc -shared -fPIC -nostdlib -o payload_linux.so payload_linux.c

echo "[*] building loader..."
gcc -o loader_linux loader_linux.c

echo "[+] done"