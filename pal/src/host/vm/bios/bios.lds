OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

/* BIOS entrypoint must be located at the last 16 bytes of the code section (according to x86 boot
 * conventions). BIOS starts in 16-bit mode at `_reset`, and in `_reset` code performs a short jump
 * which can only take -127..+128 offset to the jump target. */
ENTRY(_reset);

/* Define segments (program headers) explicitly. Typically, linkers map sections to segments
 * themselves, and there is no need in PHDRS in the linker script. But in the BIOS case, we need a
 * special layout of segments: code segment must be last and end at 4GB. Note that only `PT_LOAD`
 * kinds of segments are loadable into VM memory and must not overlap; the other segments are
 * contained inside the `PT_LOAD` ones. Also note that our minimal BIOS doesn't have RW data. */
PHDRS
{
  phdr PT_PHDR PHDRS;
  ro PT_LOAD FILEHDR PHDRS FLAGS(4);
  rx PT_LOAD FLAGS(5);
  note PT_NOTE;
}

SECTIONS
{
  /* BIOS starts at address (4G - 64K): 64K is definitely enough for our tiny BIOS */
  . = 0xffff0000;

  /* Read-only (ro) segment */
  . += SIZEOF_HEADERS;
  .note.gnu.build-id : { *(.note.gnu.build-id) } :ro :note
  .note              : { *(.note .note.*) } :ro :note
  .rodata            : { *(.rodata .rodata.* .gnu.linkonce.r.*) } :ro

  /* Executable (rx) segment */
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  PROVIDE_HIDDEN (__text_start = .);
  .init          : { *(.init) } :rx
  .fini          : { *(.fini) } :rx
  .plt           : { *(.plt) *(.iplt) } :rx
  .text          : { *(.text .stub .text.*) } :rx

  /* Align .resetvec on 64K (QEMU convention); note that the .resetvec section is defined in
   * BIOS asm file and it is forced to be 0x80 bytes in size */
  . = ALIGN(. + 0x80, 0x10000) - 0x80;
  .text.reset    : { *(.resetvec) } :rx

  /* BIOS ends exactly at address 4G (because of .resetvec section aligned to 64K) */
}
