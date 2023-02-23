#define FW_CFG_KERNEL_ENTRY 0x10
#define FW_CFG_PORT_SEL 0x510
#define QEMU_DEBUG_IO_PORT 0xe9

    .globl _reset
    .hidden _reset

    .sect   .rodata
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
    // Per TDX FAS, the GPRs, CR0, CR4 and EFER should contain the following:
    //
    // - RCX/R8 <- parameter (set by SEAMCALL[TDADDVPS])
    // - EDX    <- CPUID[1].EAX
    // - EBX    <- GPAW (GPA Width)
    // - ESI    <- Index of VP (0 for the 1st VP)
    // - All other GPRs zeroed
    //
    // - CR0    <- PE (Protected-mode Enabled)
    // - CR4    <- MCR (Machine Check Enabled)
    // - EFER   <- SCE (SysCall Enabled), LME (Long Mode Enabled), NXE (NoExec Enabled)
    //
    mov     $0x40, %eax
    mov     %eax, %cr4                  // MCE
    mov     $0x901, %eax
    xor     %edx, %edx
    mov     $0xc0000080, %ecx
    wrmsr                               // SCE, LME, NXE
    mov     $1, %eax
    cpuid
    mov     %eax, %edi                  // copy CPUID[1].EAX to %edx for later use
    mov     $0x80000008, %eax
    cpuid
    movzbl  %al, %ebx                   // GPA Width
    rdfwcfg $FW_CFG_KERNEL_ENTRY
    test    %eax, %eax
    jz      1f
    lea     0x10(%eax), %ebp            // end of kernel, 0 in real TD
    mov     %edi, %edx                  // CPUID[1].EAX
    xor     %esi, %esi                  // VP index
    mov     %esi, %edi
    mov     %esi, %esp
    mov     %esi, %ecx
    jmp     *%eax
1:  mov     $_MSG_NO_KERNEL_SIZE, %ecx
    mov     $QEMU_DEBUG_IO_PORT, %dx
    rep     outsb
    hlt
    jmp     .

    .sect   .resetvec, "ax"
    .align  0x80, 0xcc
    .code16
1:  .quad   0, 0
_cs_sel = . - 1b
    .long   0xffff, 0xcf9b00            // 0x10 -- 32-bit code
_ds_sel = . - 1b
    .long   0xffff, 0xcf9300            // 0x18 -- 32-bit data
2:  .word   . - 1b - 1                  // GDTR
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
    .fill   _end - . - 0x10, 1, 0xcc
_reset:
    cli
    cld
    jmp     3b
    .align  0x80, 0xcc
_end:
