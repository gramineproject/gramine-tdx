/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

.macro globl sym
.globl \sym
.hidden \sym
.endm

// struct tdx_tdcall_regs {
//     uint64_t rax, rbx, rcx, rdx, r8, r9, r10, r11, r12, r13, r14, r15;
// } __attribute__((packed));
//
//  long tdx_tdcall(struct tdx_tdcall_regs* regs);

    globl   tdx_tdcall

    .code64
    .align  0x1000

tdx_tdcall:
    push    %rbp
    mov     %rsp, %rbp
    push    %r15
    push    %r14
    push    %r13
    push    %r12
    push    %rbx
    push    %rdi
    push    %rsi

    mov     (%rdi), %rax
    mov     8(%rdi), %rbx
    mov     16(%rdi), %rcx
    mov     24(%rdi), %rdx
    mov     32(%rdi), %r8
    mov     40(%rdi), %r9
    mov     48(%rdi), %r10
    mov     56(%rdi), %r11
    mov     64(%rdi), %r12
    mov     72(%rdi), %r13
    mov     80(%rdi), %r14
    mov     88(%rdi), %r15

    // TDCALL instruction -- note that we rely on the GPR/XMM mask in RCX to prevent data leaks
    // and malicious inputs in unused-by-TDCALL registers
    .byte   0x66, 0x0f, 0x01, 0xcc

    // RSP is always restored by TD to the value before TDCALL instruction, so we can trust it
    pop     %rsi
    pop     %rdi

    mov     %rax, (%rdi)
    mov     %rbx, 8(%rdi)
    mov     %rcx, 16(%rdi)
    mov     %rdx, 24(%rdi)
    mov     %r8,  32(%rdi)
    mov     %r9,  40(%rdi)
    mov     %r10, 48(%rdi)
    mov     %r11, 56(%rdi)
    mov     %r12, 64(%rdi)
    mov     %r13, 72(%rdi)
    mov     %r14, 80(%rdi)
    mov     %r15, 88(%rdi)

    pop     %rbx
    pop     %r12
    pop     %r13
    pop     %r14
    pop     %r15
    pop     %rbp

    mov     $0, %rax  // just for sanity
    ret
