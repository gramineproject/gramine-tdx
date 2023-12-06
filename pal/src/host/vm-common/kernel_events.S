/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include "asm-offsets.h"

.macro globl sym
.globl \sym
.hidden \sym
.endm

    globl   isr_spurious
    globl   isr_iret_to_userland
    globl   jump_into_user_mode
    globl   syscall_asm
    globl   save_context_and_restore_next
    globl   do_xsave
    globl   do_xrstor

.macro  isrstub num, has_errorcode
    globl   isr_\num
isr_\num:
    .ifb    \has_errorcode
    push    $0
    .endif
    push    $\num
    jmp     _isr_common
.endm

    isrstub 0
    isrstub 1
    isrstub 2
    isrstub 3
    isrstub 4
    isrstub 5
    isrstub 6
    isrstub 7
    isrstub 8, 1
    isrstub 9
    isrstub 10, 1
    isrstub 11, 1
    isrstub 12, 1
    isrstub 13, 1
    isrstub 14, 1
    isrstub 15
    isrstub 16
    isrstub 17, 1
    isrstub 18
    isrstub 19
    isrstub 20
    isrstub 32   // Local APIC timer interrupt (in TSC-deadline mode)
    isrstub 33   // "Invalidate TLB" IPI interrupt (used when updating page table entries)
    isrstub 64   // virtio devices interrupt (console, fs, vsock)

isr_spurious:
    iretq

isr_iret_to_userland:
    iretq

_isr_common:
    push    %rcx
    push    %rax
    push    %rdx
    push    %rbx
    push    %rbp
    push    %rsi
    push    %rdi
    push    %r15
    push    %r14
    push    %r13
    push    %r12
    push    %r11
    push    %r10
    push    %r9
    push    %r8

    mov     $MSR_IA32_GS_KERNEL_BASE, %rcx
    rdmsr
    shl     $32, %rdx
    or      %rdx, %rax

    mov     PER_CPU_DATA_XSAVE_AREA(%rax), %rdi
    push    %rdi
    callq   do_xsave

    mov     %rsp, %rdi

    // preserve stack ptr in RBX (callee-saved) and 16B-align it (required by System V AMD64 ABI)
    mov     %rsp, %rbx
    and     $~0xF, %rsp
    call    isr_c
    mov     %rbx, %rsp

    pop     %rdi
    callq   do_xrstor

    pop     %r8
    pop     %r9
    pop     %r10
    pop     %r11
    pop     %r12
    pop     %r13
    pop     %r14
    pop     %r15
    pop     %rdi
    pop     %rsi
    pop     %rbp
    pop     %rbx
    pop     %rdx
    pop     %rax
    pop     %rcx
    add     $16, %rsp   // jump over int_number and error_code on the stack
    iretq


jump_into_user_mode:
    pushfq
    pop     %r11                // sysretq expects user-land RFLAGS in R11, move it via pushf/pop
    mov     %rdi, %rcx          // sysretq expects user-land RIP (first arg) in RCX
    xor     %r15, %r15
    xor     %r14, %r14
    xor     %r13, %r13
    xor     %r12, %r12
    xor     %r10, %r10
    xor     %r9, %r9
    xor     %r8, %r8
    xor     %rbp, %rbp
    xor     %rbx, %rbx
    xor     %rax, %rax
    xor     %rdx, %rdx
    xor     %rsi, %rsi
    xor     %rdi, %rdi
    and     $~0xF, %rsp         // align stack by 16B
    sysretq


// FIXME: ideally must add swapgs in the very beginning, but GS is not used by ring-3 anyway
syscall_asm:
    mov     %rcx, %gs:PAL_TCB_VM_USER_RIP
    lea     sysret_asm(%rip), %rcx
    jmp     *%gs:(PAL_TCB_LIBOS + 0x8)      // `libos_syscall_entry` addr is at offset 0x8

// FIXME: ideally must add swapgs right-before sysretq, but GS is not used by ring-3 anyway
sysret_asm:
    mov     %gs:PAL_TCB_VM_USER_RIP, %rcx
    or      $0x200, %r11                    // userland RFLAGS will contain IF
    sysretq


    // void save_context_and_restore_next(uint64_t curr_gs_base, uint64_t next_gs_base,
    //                                    uint32_t* lock_to_unlock, int* clear_child_tid,
    //                                    uint32_t* critical_section_lock_to_unlock,
    //                                    void* scheduling_stack)
    //
    //   RDI (1st arg):  current context (= GS register base), may be 0x0
    //   RSI (2nd arg):  next context (= next GS register base), always exists
    //   RDX (3rd arg):  lock that was taken and needs to be released
    //   RCX (4th arg):  memory that should be zeroed (signal to parent that child exited)
    //   R8  (5th arg):  lock of the critical section that ends here, needs to be released
    //   R9  (6th arg):  temporary stack on which to put this func's local variables and pop rflags
save_context_and_restore_next:
    // note that r10 and r11 are caller-saved regs, so we can overwrite them freely

    // Store the original RFLAGS of the context as the very first operation, because later
    // operations (e.g. `test` instruction below) modify RFLAGS; this may be not needed if there is
    // no current context, but in that case we'll only clobber RAX which is benign.
    // We are possibly modifying the prev-thread stack, but we are under the
    // critical_section_lock_to_unlock() lock so this stack can't be raced on by another CPU.
    pushf
    pop     %rax

    test    %rdi, %rdi             // no curr_gs_base -- no context to save
    jz      .Lrestore_next_context

.Lsave_current_context:
    mov     %r8,  %gs:PAL_TCB_VM_CONTEXT_R8
    mov     %r9,  %gs:PAL_TCB_VM_CONTEXT_R9
    mov     %r10, %gs:PAL_TCB_VM_CONTEXT_R10
    mov     %r11, %gs:PAL_TCB_VM_CONTEXT_R11
    mov     %r12, %gs:PAL_TCB_VM_CONTEXT_R12
    mov     %r13, %gs:PAL_TCB_VM_CONTEXT_R13
    mov     %r14, %gs:PAL_TCB_VM_CONTEXT_R14
    mov     %r15, %gs:PAL_TCB_VM_CONTEXT_R15
    mov     %rdi, %gs:PAL_TCB_VM_CONTEXT_RDI
    mov     %rsi, %gs:PAL_TCB_VM_CONTEXT_RSI
    mov     %rbp, %gs:PAL_TCB_VM_CONTEXT_RBP
    mov     %rbx, %gs:PAL_TCB_VM_CONTEXT_RBX
    mov     %rdx, %gs:PAL_TCB_VM_CONTEXT_RDX
    movq    $0,   %gs:PAL_TCB_VM_CONTEXT_RAX
    mov     %rcx, %gs:PAL_TCB_VM_CONTEXT_RCX
    mov     %rsp, %gs:PAL_TCB_VM_CONTEXT_RSP

    // RAX contains current-context original RFLAGS; mark interrupts as enabled in the restored
    // context, this is because current context may be executed under `spinlock_lock_disable_irq()`
    or      $(1 << 9), %rax
    mov     %rax, %gs:PAL_TCB_VM_CONTEXT_RFLAGS

    lea     .Lrestore_saved_context(%rip), %rax
    mov     %rax, %gs:PAL_TCB_VM_CONTEXT_RIP

    // RDX (function arg `lock_to_unlock`) may be clobbered by do_xsave, so save on stack
    push    %rdx
    mov     %gs:PAL_TCB_VM_CONTEXT_FPREGS, %rdi
    callq   do_xsave
    pop     %rdx

.Lrestore_next_context:
    push    %rdx
    push    %rcx
    mov     %rsi, %rax              // low-order 32 bits of `next_gs_base`
    mov     %rsi, %rdx              // high-order 32 bits of `next_gs_base` (shifted-right below)
    shr     $32, %rdx
    mov     $MSR_IA32_GS_BASE, %rcx
    wrmsr
    pop     %rcx
    pop     %rdx

    cmp     $0, %rdx                // check if lock_to_unlock != NULL
    je      .Lskip_spinlock_unlock
    movl    $0, (%rdx)              // spinlock_unlock(lock_to_unlock)
.Lskip_spinlock_unlock:

    cmp     $0, %rcx                // check if clear_child_tid != NULL
    je      .Lskip_clear_child_tid
    movl    $0, (%rcx)              // set *clear_child_tid = 0
.Lskip_clear_child_tid:

    // Before we leave the critical section, need to shift to a temporary "scheduling" stack,
    // otherwise the operations below could modify the prev-thread stack and have a data race with
    // some CPU that simultaneously scheduled this thread and also modifies the stack.
    // The above is irrelevant if we currently execute in the interrupt handling context because
    // then we're operating on the interrupt stack which is per-CPU and cannot be preempted, thus no
    // data race on the interrupt stack is possible. (In this case, scheduling_stack = NULL.)
    cmp     $0, %r9                 // check if scheduling_stack != NULL
    je      .Lskip_setting_scheduling_stack
    mov     %r9, %rsp             // set this temporary scheduling stack
.Lskip_setting_scheduling_stack:

    // Now we are completely done with both previously running thread and next thread, can unlock
    // the critical section (typically `g_thread_list_lock`). Note that interrupts are re-enabled
    // (if that was the state of the restoring thread) during popfq below.
    movl    $0, (%r8)              // spinlock_unlock(critical_section_lock_to_unlock)

    mov     %gs:PAL_TCB_VM_CONTEXT_FPREGS, %rdi
    callq   do_xrstor

    mov     %gs:PAL_TCB_VM_CONTEXT_RFLAGS, %rax
    push    %rax
    popfq

    mov     %gs:PAL_TCB_VM_CONTEXT_R8,  %r8
    mov     %gs:PAL_TCB_VM_CONTEXT_R9,  %r9
    mov     %gs:PAL_TCB_VM_CONTEXT_R10, %r10
    mov     %gs:PAL_TCB_VM_CONTEXT_R11, %r11
    mov     %gs:PAL_TCB_VM_CONTEXT_R12, %r12
    mov     %gs:PAL_TCB_VM_CONTEXT_R13, %r13
    mov     %gs:PAL_TCB_VM_CONTEXT_R14, %r14
    mov     %gs:PAL_TCB_VM_CONTEXT_R15, %r15
    mov     %gs:PAL_TCB_VM_CONTEXT_RDI, %rdi
    mov     %gs:PAL_TCB_VM_CONTEXT_RSI, %rsi
    mov     %gs:PAL_TCB_VM_CONTEXT_RBP, %rbp
    mov     %gs:PAL_TCB_VM_CONTEXT_RBX, %rbx
    mov     %gs:PAL_TCB_VM_CONTEXT_RDX, %rdx
    mov     %gs:PAL_TCB_VM_CONTEXT_RCX, %rcx
    mov     %gs:PAL_TCB_VM_CONTEXT_RSP, %rsp
    mov     %gs:PAL_TCB_VM_CONTEXT_RAX, %rax

    jmp     *%gs:PAL_TCB_VM_CONTEXT_RIP

.Lrestore_saved_context:
    ret


    // void __do_xsave(PAL_XREGS_STATE* xsave_area)
    //   RDI (argument):        pointer to xsave_area
    //   R11 (return address):  in order to not touch stack
    //   RAX, RDX:              clobbered
__do_xsave:
    movq    $0, XSAVE_HEADER_OFFSET + 0 * 8(%rdi)    // clear xsave header
    movq    $0, XSAVE_HEADER_OFFSET + 1 * 8(%rdi)
    movq    $0, XSAVE_HEADER_OFFSET + 2 * 8(%rdi)
    movq    $0, XSAVE_HEADER_OFFSET + 3 * 8(%rdi)
    movq    $0, XSAVE_HEADER_OFFSET + 4 * 8(%rdi)
    movq    $0, XSAVE_HEADER_OFFSET + 5 * 8(%rdi)
    movq    $0, XSAVE_HEADER_OFFSET + 6 * 8(%rdi)
    movq    $0, XSAVE_HEADER_OFFSET + 7 * 8(%rdi)

    movl    $0xffffffff, %eax
    movl    $0xffffffff, %edx
    xsave64 (%rdi)
    jmp     *%r11

    // void do_xsave(PAL_XREGS_STATE* xsave_area)
do_xsave:
    popq    %r11
    jmp     __do_xsave

    // void __do_xrstor(const PAL_XREGS_STATE* xsave_area)
    //   RDI (argument):        pointer to xsave_area
    //   R11 (return address):  in order to not touch stack
    //   RAX, RDX:              clobbered
__do_xrstor:
    movl     $0xffffffff, %eax
    movl     $0xffffffff, %edx
    xrstor64 (%rdi)
    jmp      *%r11

    // void do_xrstor(const PAL_XREGS_STATE* xsave_area)
do_xrstor:
    popq %r11
    jmp __do_xrstor
