#include "asm-offsets.h"

.macro globl sym
.globl \sym
.hidden \sym
.endm

    globl   ap_startup_page_start
    globl   ap_startup_page_end
    globl   initial_ap_pml4_table_base

// AP (Application Processor) startup code. APs are put by the VMM in wait-for-SIPI state, and the
// BSP (BootStrap Processor) first relocates this startup code (simply by memcpy) to a well-defined
// address and then sends SIPIs to each AP. Each AP starts at `ap_startup_page_start()` (it will be
// located at well-defined address AP_STARTUP_PAGE_ADDRESS) in 16-bit real mode, then through 32-bit
// protected mode goes into 64-bit mode, sets up its own stack and then jumps to the kernel AP code
// (written in C). This code is assumed to fit into one 4KB page. See also kernel_multicore.{h,c}.

    .sect   .ap_startup_page, "ax"
    .align  0x1000
    .code16
ap_startup_page_start:
    cli
    cld

    lgdtl   AP_STARTUP_PAGE_ADDRESS + _gdtr - ap_startup_page_start

    movl    $1, %eax            // PE
    movl    %eax, %cr0

    // long jump into 32-bit mode using code descriptor
    ljmp    $0x8, $(AP_STARTUP_PAGE_ADDRESS + _start32 - ap_startup_page_start)

    .align  0x100, 0xcc
_gdt:
    .long   0, 0                  // 0x0  -- first descriptor must be zero
    .long   0xffff, 0xcf9b00      // 0x8  -- 32-bit kernel code
    .long   0xffff, 0xcf9300      // 0x10 -- 32-bit kernel data
    .long   0, 0                  // 0x18 -- dummy descriptor for alignment
_gdtr:
    .word  . - _gdt - 1
    .long  AP_STARTUP_PAGE_ADDRESS + _gdt - ap_startup_page_start

    .align  0x80, 0xcc
_gdt64:
    .long   0, 0                  // first descriptor must be zero
    .long   0xffff, 0xaf9b00      // 0x8  -- 64-bit kernel code
    .long   0xffff, 0xcf9300      // 0x10 -- 32-bit kernel data
    .long   0x0068, 0xcf8900      // 0x18 -- tss
_gdtr64:
    .word  . - _gdt64 - 1
    .quad  AP_STARTUP_PAGE_ADDRESS + _gdt64 - ap_startup_page_start

    .align 0x200, 0xcc
    .code32
_start32:
    lgdtl   AP_STARTUP_PAGE_ADDRESS + _gdtr64 - ap_startup_page_start

    mov     $0x10, %eax         // 32-bit code data descriptor
    mov     %eax, %ds
    mov     %eax, %es
    mov     %eax, %fs
    mov     %eax, %gs
    mov     %eax, %ss

    xor     %edx, %edx
    mov     $(1 << 11) + (1 << 8) + (1 << 0), %eax
    mov     $0xc0000080, %ecx   // EFER MSR
    wrmsr                       // SCE, LME, NXE

    mov     AP_STARTUP_PAGE_PML4, %eax
    mov     %eax, %cr3

    mov     %cr4, %eax
    or      $(1 << 18) + (1 << 10) + (1 << 9) + (1 << 6) + (1 << 5), %eax
    mov     %eax, %cr4          // OSXSAVE, OSXMMEXCPT, OSFXSR, MCE, PAE

    xor     %edx, %edx
    mov     $3, %eax            // SSE and X87
    xor     %ecx, %ecx
    xsetbv

    mov     %cr0, %eax
    or      $(1 << 31), %eax    // PG
    mov     %eax, %cr0

    mov     $1, %edx
    mov     AP_STARTUP_PAGE_COUNTER, %eax
    lock xadd %edx, (%eax)

    mov     %edx, %edi          // first arg (current CPU index) to pal_start_ap_c

1:  pause                       // wait for g_lock_single_ap_cpu to be released
    movl $0, %eax
    movl $1, %ecx
    mov  AP_STARTUP_PAGE_AP_LOCK, %ebx
    lock cmpxchg %ecx, (%ebx)
    jnz 1b

    // each AP CPU re-uses the same stack; assumes there's nothing below AP_STARTUP_PAGE_ADDRESS
    mov     $AP_STARTUP_PAGE_ADDRESS, %esp

    // far return to _start64 using 64-bit code descriptor
    push    $0x8
    push    $(AP_STARTUP_PAGE_ADDRESS + _start64 - ap_startup_page_start)
    lret

    .align 0x400, 0xcc
    .code64
_start64:
    mov     AP_STARTUP_PAGE_C_FUNC, %rax
    call    *%rax
    hlt
ap_startup_page_end:

// below is a static page table hierarchy, enough to cover 4MB (cover the VM PAL binary)
    .data
    .align  0x1000
// 4KB leaf entries (PTE): 2 pages, each with 512 entries
1:  .rept   2 * 512
    .quad   (. - 1b) / 8 * (1 << 12) + 0x7    // 7 = User, Writable, Present
    .endr
    .align  0x1000, 0
// 2MB (PDE) entries: one page with 2 entries
2:  .rept   2
    .quad   1b + (. - 2b) / 8 * 0x1000 + 0x7  // 7 = User, Writable, Present
    .endr
    .align  0x1000, 0
// 1GB (PDPTE) entries: one page with single entry
3:  .quad   2b + 0x7                          // 7 = User, Writable, Present
    .align  0x1000, 0
// 512GB entries (PML4E): one page with single entry
initial_ap_pml4_table_base:
    .quad   3b + 0x7                          // 7 = User, Writable, Present
    .align  0x1000, 0
