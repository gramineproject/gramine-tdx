/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* System calls via SYSCALL/SYSRET in 64-bit mode. See also the *.S code. */

#include <stdint.h>

#include "api.h"

#include "kernel_syscalls.h"

extern void syscall_asm(void);

int syscalls_init(void) {
    extern char gdt_start[], gdt_entry_kernel_cs[], gdt_entry_user_cs[];

    /*
     * IA32_STAR MSR has weird semantics (for 64-bit mode with SYSCALL/SYSRET):
     *   - bits 32-47 must contain a kernel code selector offset, and kernel data selector is
     *     computed as +8 to this kernel-code-selector value (so kernel data segment descriptor
     *     must immediatelly follow the kernel code segment descriptor in our bootloader)
     *   - bits 48-63 must contain a "user code selector offset minus 16", and user data selector
     *     is computed as "user code selector offset minus 8" (so user data segment descriptor must
     *     immediatelly preceed the user code segment descriptor)
     *
     * Note that the code selector is 64-bit-mode but the corresponding data selector is 32-bit-mode
     * in our GDT entries. However, we rely on the weird fact that syscall/sysret instructions do
     * not really load selectors from GDT but instead load fixed values (including switching to
     * 64-bit-mode), so our layout of GDT entries still works.
     */
    wrmsr(MSR_STAR,
        ((gdt_entry_user_cs - gdt_start) << 48) | ((gdt_entry_kernel_cs - gdt_start) << 32));

    /* IA32_LSTAR MSR simply contains the 64-bit address of the syscall entry */
    wrmsr(MSR_LSTAR, (uint64_t)&syscall_asm);

    /* IA32_SYSCALL_MASK MSR contains RFLAGS that are cleared on `syscall` (taken from Linux);
     * we don't clear the Interrupt Flag because our kernel is ok to be interrupted */
    wrmsr(MSR_SYSCALL_MASK, (uint64_t)(/*trap flag*/          1 << 8  |
                                       /*direction flag*/     1 << 10 |
                                       /*IO privilege level*/ 3 << 12 |
                                       /*nested task*/        1 << 14 |
                                       /*alignment check*/    1 << 18));

    return 0;
}
