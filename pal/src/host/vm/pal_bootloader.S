.macro globl sym
.globl \sym
.hidden \sym
.endm

    globl   pal_start
    globl   _end

_start64:
    mov     %edi, %edx          // restore %edx to CPUID[1].EAX
    mov     %ebx, %edi          // %ebx contains GPAW upon reset
    call    pal_start_c
    hlt
    jmp     .

_start32:
    .code32
    lgdt    (_gdtr - _start32)(%ebp)
    lidt    (_idtr - _start32)(%ebp)
    mov     $(_gdt_entry_kernel_cs - _gdt_start + 8), %eax  // 32-bit kernel data at this offset
    mov     %eax, %ds
    mov     %eax, %es
    mov     %eax, %fs
    mov     %eax, %gs
    mov     %eax, %ss
    lea     (_sys_initial_stack - _start32)(%ebp), %esp
    lea     (_start64 - _start32)(%ebp), %eax
    push    $(_gdt_entry_kernel_cs - _gdt_start)
    push    %eax
    lea     (_pml4_table_base - _start32)(%ebp), %eax
    mov     %eax, %cr3
    mov     %cr4, %eax
    or      $(1 << 18) + (1 << 10) + (1 << 9) + (1 << 5), %eax
    mov     %eax, %cr4                  // OSXSAVE, OSXMMEXCPT, OSFXSR, PAE
    xchg    %edx, %edi                  // %edi supposed to be init'ed to 0
    mov     $7, %eax                    // AVX, SSE, X87
    mov     %edx, %ecx                  // XCR0
    xsetbv
    mov     %cr0, %eax
    or      $(1 << 31), %eax            // PG
    mov     %eax, %cr0
    lret                                // far return to _start64 in 64-bit mode

    .data
    .align  0x1000

// We use 1:1 virtual-to-physical address translation. For this, we use the classic 4-level paging
// scheme. In this bootloader, we define a static page table hierarchy spanning 256MB of RAM:
//   1. CR3 register points to a PML4 table, which contains a single PML4E 64-bit entry
//   2. PML4E entry points to a PDPT table, which contains a single PDPTE 64-bit entries
//   3. PDPTE entry points to a PD table, which contains 128 PDE 64-bit entries
//   4. PDE entry points to one of 128 PTs (page tables), each containing 512 PTE entries
//
// Note that each PT has 512 entries, each entry pointing to a 4KB page. There are 128 PTs, thus,
// our page table hierarchy describes 256MB of memory. After this bootloader completes and jumps to
// the 64-bit C kernel, the kernel immediately allocates memory for the final page table hierarchy
// spanning up to 512GB of memory and rewires the CR3 register to this final hierarchy.
//
// The below static PT hierarchy constitutes (128 + 1 + 1 + 1) 4KB pages, or 524KB of data segment
// of the final kernel executable in total.
//
// For visual represenation of this address translation, see Figure 4-8 in Intel SDM.

// 4KB leaf entries (PTE): 128 pages, each with 512 entries
1:  .rept   128 * 512
    .quad   (. - 1b) / 8 * (1 << 12) + 0x7    // 7 = User, Writable, Present
    .endr
    .align  0x1000, 0

// 2MB (PDE) entries: one page with 128 entries
2:  .rept   128
    .quad   1b + (. - 2b) / 8 * 0x1000 + 0x7  // 7 = User, Writable, Present
    .endr
    .align  0x1000, 0

// 1GB (PDPTE) entries: one page with single entry
3:  .quad   2b + 0x7                          // 7 = User, Writable, Present
    .align  0x1000, 0

// 512GB entries (PML4E): one page with single entry
_pml4_table_base:
    .quad   3b + 0x7                          // 7 = User, Writable, Present
    .align  0x1000, 0


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
    .long   0xffff, 0xcf9300                    // 32-bit kernel data
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


    .sect   .note, "a"
    .align  4
    .long   2f - 1f
    .long   4f - 3f
    .long   18
1:  .string "Xen"
2:  .align  4
3:  .quad   pal_start
4:

    .bss
    .align  0x10
    .space  0x4000
_sys_initial_stack:

    .sect   .resetvec, "ax"
    .align  0x80
    .fill   _end - . - 0x10, 1, 0xcc
pal_start:
    cli
    cld
    add     $(_start32 - _end), %ebp    // %ebp init'ed to 0 (same as _end)
    jmp     _start32
    .align  0x80, 0xcc
_end:
