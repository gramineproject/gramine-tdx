#define FW_CFG_KERNEL_ENTRY 0x10
#define FW_CFG_PORT_SEL     0x510
#define QEMU_DEBUG_IO_PORT  0xe9

    .globl _reset
    .hidden _reset

    .section .rodata
_MSG_NO_KERNEL:
    .ascii  "Kernel not found! Please specify \"-kernel <ELF file>\" on QEMU command line!\r\n"
_MSG_NO_KERNEL_SIZE = . - _MSG_NO_KERNEL

    .macro  rdfwcfg entry
    mov     $FW_CFG_PORT_SEL, %dx
    mov     \entry, %ax
    out     %ax, %dx
    mov     $4, %ecx
    inc     %dx
1:  in      %dx, %al
    ror     $8, %eax
    loop    1b
    .endm

    .text
    .code32
_start32:
    xor     %edx, %edx
    mov     $(1 << 11) + (1 << 8) + (1 << 0), %eax
    mov     $0xc0000080, %ecx           // EFER MSR
    wrmsr                               // SCE, LME, NXE

    rdfwcfg $FW_CFG_KERNEL_ENTRY
    test    %eax, %eax
    jz      1f

    lea     0x10(%eax), %ebp            // end of kernel
    jmp     *%eax

    // to see this error message, qemu must be run with `-debugcon /dev/stdout`
1:  mov     $_MSG_NO_KERNEL_SIZE, %ecx
    mov     $QEMU_DEBUG_IO_PORT, %dx
    rep     outsb
    hlt
    jmp     .

    .section .resetvec, "ax"
    .align  0x80, 0xcc
    .code16

// GDT
1:  .quad   0, 0
_cs_sel = . - 1b
    .long   0xffff, 0xcf9b00            // 0x10 -- 32-bit code
_ds_sel = . - 1b
    .long   0xffff, 0xcf9300            // 0x18 -- 32-bit data
// GDTR
2:  .word   . - 1b - 1
    .long   1b - _end
    .align  0x40, 0xcc

3:  lgdtl   %cs:(2b - _end)

    mov     $1, %eax                    // PE
    mov     %eax, %cr0

    mov     $_ds_sel, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %fs
    mov     %ax, %gs
    mov     %ax, %ss

    mov     $(_MSG_NO_KERNEL - _end), %esi
    ljmpl   $_cs_sel, $(_start32 - _end)

    .align  0x10, 0xcc
_reset:
    cli
    cld
    jmp     3b
    .align  0x80, 0xcc
_end:
