/*
 * Kalkan kernel linker script.
 *
 * The kernel is a position independent executable linked at the top 2 GiB of the
 * address space. Limine relocates it to a random address (KASLR).
 *
 * Every section group lives in its own page-aligned PT_LOAD segment so that the
 * kernel can map them with strict W^X permissions:
 *     .text    R-X
 *     .rodata  R--   (includes relocated read-only data: .data.rel.ro, .got)
 *     .data    RW-   (no execute)
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kalkan_entry)

PHDRS
{
    text    PT_LOAD    FLAGS(5); /* R + X */
    rodata  PT_LOAD    FLAGS(4); /* R     */
    data    PT_LOAD    FLAGS(6); /* R + W */
    dynamic PT_DYNAMIC FLAGS(6);
}

SECTIONS
{
    . = 0xffffffff80000000;
    __kernel_start = .;

    __text_start = .;
    .text : {
        *(.text .text.*)
    } :text
    . = ALIGN(4096);
    __text_end = .;

    __rodata_start = .;
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
    __rodata_end = .;

    __data_start = .;
    .data : {
        *(.data .data.*)
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :data
    .dynamic : { *(.dynamic) } :data :dynamic
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data
    . = ALIGN(4096);
    __data_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.comment)
        *(.interp)
    }
}
