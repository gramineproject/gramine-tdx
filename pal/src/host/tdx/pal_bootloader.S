/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

.macro globl sym
.globl \sym
.hidden \sym
.endm

    globl   pal_start

    .code64
    .align  0x1000

//
// TD-Shim loads this TDX PAL binary as the payload with arguments:
//   - RDI: holds the payload HOB address
//   - RSI: holds the address where the payload is loaded
//
// This entry code must be careful to not modify RDI and RSI, to forward them as-is to the C-level
// pal_start_c() function.
//
// This code setups GDT, IDT, CR4, XCR0, all data segment regs and CS segment reg.
//
pal_start:
    // set up our own GDT and IDT; this is important because e.g. TD-Shim installs its IDT that has
    // a #VE exception handler (that simply forwards requests to host VMM without sanitization)
    // TODO: this is probably not needed because our vm-common code resets these anyway
    lea     _gdtr(%rip), %rax
    lgdt    (%rax)
    lea     _idtr(%rip), %rax
    lidt    (%rax)

    // set data segment registers to our GDT "64-bit kernel data" segment descriptor
    mov     $(_gdt_entry_kernel_cs - _gdt_start + 8), %rax
    mov     %rax, %ds
    mov     %rax, %es
    mov     %rax, %fs
    mov     %rax, %gs
    mov     %rax, %ss

    // update CR4 to include OSXSAVE, OSXMMEXCPT, OSFXSR
    mov     %cr4, %rax
    or      $(1 << 18) + (1 << 10) + (1 << 9), %rax
    mov     %rax, %cr4

    // set XCR0 to enable SSE and X87 (RCX: which XCR reg to update, RDX: upper bits of features);
    // PAL will enable more features if available on VM
    mov     $3, %rax
    mov     $0, %rcx
    mov     $0, %rdx
    xsetbv

    // use our own initial stack and clear frame pointer (RBP) for sanity; note that we need to
    // conform to System V AMD64 ABI, thus we set an 8-byte-odd RSP on func entry
    xor     %rbp, %rbp
    lea     _sys_initial_stack(%rip), %rsp
    sub     $8, %rsp

    // jump to pal_start_c() entrypoint, together with setting the CS segment register
    lea     pal_start_c(%rip), %rax
    pushq   $(_gdt_entry_kernel_cs - _gdt_start)
    push    %rax
    lretq


    .data
    .align  0x1000

// IDT
_idt_start:
    .rept   256
    .word   0                                   // VA[15..0] of ISR
    .word   _gdt_entry_kernel_cs - _gdt_start   // code segment selector
    .byte   0                                   // Interrupt Task Table offset
    .byte   0b10001110                          // attributes (P=1, DPL=0, RSV=0, type=1110)
    .word   0                                   // VA[31..16] of ISR
    .long   0                                   // VA[64..32] of ISR
    .long   0                                   // Reserved
    .endr
_idtr:
    .word . - _idt_start - 1
    .quad _idt_start

// GDT
    .align  0x10
_gdt_start:
    .quad   0
_gdt_entry_kernel_cs:
    .long   0xffff, 0xaf9b00                    // 64-bit kernel code
    .long   0xffff, 0xaf9300                    // 64-bit kernel data
_gdt_entry_user_cs:
    .long   0xffff, 0xcffb00                    // 32-bit user code
    .long   0xffff, 0xcff300                    // 32-bit user data
    .long   0xffff, 0xaffb00                    // 64-bit user code
_tss_64bitmode_desc:
    .rept   1                   // currently only one CPU core supported
    .word   0                   // segment limit in bytes, bits 0-15 (will be filled in C)
    .word   0                   // segment base address, bits 0-15   (will be filled in C)
    .byte   0                   // segment base address, bits 16-23  (will be filled in C)
    .byte   0b10001001          // flags, bits 24-31 (P=1, DPL=00, RVD=0, Type=1001 (inactive task))
    .byte   0                   // segment limit, bits 16-19         (set to zero)
                                // and flags, bits 20-23 (G=0, RVD=00, AVL=0)
    .byte   0                   // segment base address, bits 24-31  (will be filled in C)
    .long   0                   // segment base address, bits 32-63  (will be filled in C)
    .long   0                   // reserved space
    .endr
_gdtr:
    .word   . - _gdt_start - 1
    .quad   _gdt_start

    .bss
    .align  0x10
    .space  0x4000
_sys_initial_stack:
