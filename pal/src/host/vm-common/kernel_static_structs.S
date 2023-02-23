/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

.macro globl sym
.globl \sym
.hidden \sym
.endm

    globl   idt_start
    globl   gdt_start
    globl   idtr
    globl   gdtr
    globl   gdt_entry_kernel_cs
    globl   gdt_entry_user_cs
    globl   tss_64bitmode
    globl   tss_64bitmode_desc

    .data
    .align  0x1000

// ------------------------------------- Task State Segment (TSS) ----------------------------------
//
// Barebones 64-bit-mode TSS: the only TSS used in our kernel so that the CPU can set up a known
// kernel stack pointer (RSP0) when jumping from user mode (ring 3) to kernel mode (ring 0) during a
// hardware interrupt. This TSS is pointed to be the TSS descriptor in the GDT (last descriptor,
// loaded via ltr instruction in 64-bit mode). We don't use RSP1 and RSP2 TSS fields because we don't
// use rings 2-3. We also don't use IST1..IST7 fields because we don't use Interrupt Stack Table.
tss_64bitmode:
    .rept   1                           // currently only one CPU core supported

    .long   0                           // reserved space
    .quad   _sys_interrupt_stack        // RSP0, kernel stack pointer (for interrupt handling)
    .quad   0                           // RSP1, unused
    .quad   0                           // RSP2, unused
    .quad   0                           // reserved space
    .quad   0                           // IST1, interrupt stack pointer 1, unused
    .quad   0                           // IST2, interrupt stack pointer 2, unused
    .quad   0                           // IST3, interrupt stack pointer 3, unused
    .quad   0                           // IST4, interrupt stack pointer 4, unused
    .quad   0                           // IST5, interrupt stack pointer 5, unused
    .quad   0                           // IST6, interrupt stack pointer 6, unused
    .quad   0                           // IST7, interrupt stack pointer 7, unused
    .quad   0                           // reserved space
    .word   0                           // reserved space
    .word   104                         // I/O map base address (offset from TSS base); since we don't use I/O
                                        // map, we specify the size of this TSS which is 104 bytes
    .endr

// IDT
idt_start:
    .rept   256
    .word   0                                   // VA[15..0] of ISR
    .word   gdt_entry_kernel_cs - gdt_start     // code segment selector
    .byte   0                                   // Interrupt Task Table offset
    .byte   0b10001110                          // attributes (P=1, DPL=0, RSV=0, type=1110)
    .word   0                                   // VA[31..16] of ISR
    .long   0                                   // VA[64..32] of ISR
    .long   0                                   // Reserved
    .endr
idtr:
    .word . - idt_start - 1
    .quad idt_start

// GDT
    .align  0x10
gdt_start:
    .quad   0
gdt_entry_kernel_cs:
    .long   0xffff, 0xaf9b00                    // 64-bit kernel code
    .long   0xffff, 0xaf9300                    // 64-bit kernel data
gdt_entry_user_cs:
    .long   0xffff, 0xcffb00                    // 32-bit user code
    .long   0xffff, 0xcff300                    // 32-bit user data
    .long   0xffff, 0xaffb00                    // 64-bit user code
tss_64bitmode_desc:
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
gdtr:
    .word   . - gdt_start - 1
    .quad   gdt_start

    .bss
    .align  0x10
    .space  0x4000
_sys_interrupt_stack:
