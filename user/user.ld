/*
 * Linker script for Kalkan user programs.
 *
 * Programs are position independent: the kernel picks a random load base (ASLR)
 * and applies R_X86_64_RELATIVE relocations itself before mapping the segments
 * with their final W^X permissions. Each segment starts on its own page.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    text    PT_LOAD    FLAGS(5);
    rodata  PT_LOAD    FLAGS(4);
    data    PT_LOAD    FLAGS(6);
    dynamic PT_DYNAMIC FLAGS(6);
    stack   PT_GNU_STACK FLAGS(6);
}

SECTIONS
{
    . = 0x1000;
    .text : { *(.text .text.*) } :text
    . = ALIGN(4096);

    .rodata : {
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
    } :rodata
    .dynsym   : { *(.dynsym) }   :rodata
    .gnu.hash : { *(.gnu.hash) } :rodata
    .hash     : { *(.hash) }     :rodata
    .dynstr   : { *(.dynstr) }   :rodata
    .rela.dyn : { *(.rela.dyn) } :rodata
    . = ALIGN(4096);

    .data : { *(.data .data.*) } :data
    .dynamic : { *(.dynamic) } :data :dynamic
    .bss : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.comment)
        *(.interp)
    }
}
