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
