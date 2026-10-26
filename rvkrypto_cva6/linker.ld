ENTRY(_start)

MEMORY
{
    DRAM (rwx) : ORIGIN = 0x80000000, LENGTH = 64K
}

SECTIONS
{
    . = ORIGIN(DRAM);

    .text : {
        KEEP(*(.text.init))
        *(.text*)
    } > DRAM

    .rodata : {
        *(.rodata*)
    } > DRAM

    .data : {
        *(.data*)
    } > DRAM

    .bss (NOLOAD) : {
        . = ALIGN(8);
        __bss_start = .;

        *(.bss*)
        *(.sbss*)
        *(COMMON)

        . = ALIGN(8);
        __bss_end = .;
    } > DRAM

    . = ALIGN(16);
    _stack_top = ORIGIN(DRAM) + LENGTH(DRAM);
}
