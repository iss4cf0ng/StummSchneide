OUTPUT_FORMAT(binary)
SECTIONS {
    . = 0;
    .text : {
        entry_linux.o(.text.entry)
        *(.text*)
        *(.rodata*)
        *(.data*)
        *(.bss*)
    }
}
