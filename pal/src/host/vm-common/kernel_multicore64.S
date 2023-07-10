#include "asm-offsets.h"

.macro globl sym
.globl \sym
.hidden \sym
.endm

    globl   ap_startup_page_start
    globl   ap_startup_page_end
    globl   initial_ap_pml4_table_base

// AP (Application Processor) startup code, specific for the MP Wakeup Mailbox technique (used in
// Intel TDX). APs are put by the firmware (e.g. TD-Shim) in a wait-for-mailbox-wakeup-command
// state, and the BSP (BootStrap Processor) first relocates this startup code (simply by memcpy) to
// a well-defined address and then sends a wakeup command in the MP Wakeup mailbox to each AP. Each
// AP starts at `ap_startup_page_start()` (it will be located at a well-defined address
// AP_STARTUP_PAGE_ADDRESS) in 64-bit long mode, with GDT, IDT and initial page tables already set
// up by the firmware. This code is assumed to fit into one 4KB page.
//
// This code largely resembles the one in tdx/pal_bootloader.S (for BSP).
// See also kernel_multicore.{h,c}.

    .sect   .ap_startup_page, "ax"
    .align  0x1000
    .code64
ap_startup_page_start:
    lgdt   AP_STARTUP_PAGE_ADDRESS + _gdtr - ap_startup_page_start

    // set data segment registers to our GDT "64-bit kernel data" segment descriptor
    mov     $(_gdt_entry_kernel_cs - _gdt_start + 8), %rax
    mov     %rax, %ds
    mov     %rax, %es
    mov     %rax, %fs
    mov     %rax, %gs
    mov     %rax, %ss

    mov     %cr4, %rax
    or      $(1 << 18) + (1 << 10) + (1 << 9), %rax
    mov     %rax, %cr4          // OSXSAVE, OSXMMEXCPT, OSFXSR

    xor     %rdx, %rdx
    mov     $3, %rax            // SSE and X87
    xor     %rcx, %rcx
    xsetbv

    mov     $1, %rdx
    mov     AP_STARTUP_PAGE_COUNTER, %rax
    lock xaddl %edx, (%rax)

    mov     %rdx, %rdi          // first arg (current CPU index) to pal_start_ap_c

1:  pause                       // wait for g_lock_single_ap_cpu to be released
    mov     $0, %rax
    mov     $1, %rcx
    mov     AP_STARTUP_PAGE_AP_LOCK, %rbx
    lock cmpxchgl %ecx, (%rbx)
    jnz     1b

    // each AP CPU re-uses the same stack; assumes there's nothing below AP_STARTUP_PAGE_ADDRESS
    xor     %rbp, %rbp
    mov     $AP_STARTUP_PAGE_ADDRESS, %rsp
    sub     $8, %rsp

    // jump to pal_start_ap_c() entrypoint, together with setting the CS segment register
    mov     AP_STARTUP_PAGE_C_FUNC, %rax
    push    $(_gdt_entry_kernel_cs - _gdt_start)
    push    %rax
    lretq

    hlt
ap_startup_page_end:

    .align  0x200, 0xcc
// GDT
_gdt_start:
    .quad   0
_gdt_entry_kernel_cs:
    .long   0xffff, 0xaf9b00                    // 64-bit kernel code
    .long   0xffff, 0xaf9300                    // 64-bit kernel data
_gdt_entry_user_cs:
    .long   0xffff, 0xcffb00                    // 32-bit user code
    .long   0xffff, 0xcff300                    // 32-bit user data
    .long   0xffff, 0xaffb00                    // 64-bit user code
_gdtr:
    .word   . - _gdt_start - 1
    .quad  AP_STARTUP_PAGE_ADDRESS + _gdt_start - ap_startup_page_start

    .data
    .align  0x1000
// dummy unused variable, required for uniformity with kernel_multicore.S
initial_ap_pml4_table_base:
    .quad   0
    .align  0x1000, 0
