/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

/*
 * This file contains handling of hardware exceptions (forwarding them to LibOS).
 */

#include "api.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_internal.h"

#include "kernel_interrupts.h"

/* fpregs is shallow copied by only setting a pointer */
static void isr_regs_to_pal_context(PAL_CONTEXT* context, struct isr_regs* regs,
                                    uint64_t faulted_addr) {
    context->r8  = regs->r8;
    context->r9  = regs->r9;
    context->r10 = regs->r10;
    context->r11 = regs->r11;
    context->r12 = regs->r12;
    context->r13 = regs->r13;
    context->r14 = regs->r14;
    context->r15 = regs->r15;
    context->rdi = regs->rdi;
    context->rsi = regs->rsi;
    context->rbp = regs->rbp;
    context->rbx = regs->rbx;
    context->rdx = regs->rdx;
    context->rax = regs->rax;
    context->rcx = regs->rcx;
    context->rsp = regs->rsp;
    context->rip = regs->rip;
    context->efl = regs->rflags;

    context->csgsfsss = 0; /* dummy */
    context->err      = 0; /* dummy */
    context->trapno   = 0; /* dummy */
    context->oldmask  = 0; /* dummy */
    context->cr2      = faulted_addr;

    context->mxcsr    = 0; /* dummy */
    context->fpcw     = 0; /* dummy */

    context->fpregs = regs->fpregs;
    context->is_fpregs_used = 1;
}

/* fpregs is shallow copied by only setting a pointer */
static void pal_context_to_isr_regs(struct isr_regs* regs, PAL_CONTEXT* context) {
    regs->r8  = context->r8;
    regs->r9  = context->r9;
    regs->r10 = context->r10;
    regs->r11 = context->r11;
    regs->r12 = context->r12;
    regs->r13 = context->r13;
    regs->r14 = context->r14;
    regs->r15 = context->r15;
    regs->rdi = context->rdi;
    regs->rsi = context->rsi;
    regs->rbp = context->rbp;
    regs->rbx = context->rbx;
    regs->rdx = context->rdx;
    regs->rax = context->rax;
    regs->rcx = context->rcx;
    regs->rsp = context->rsp;
    regs->rip = context->rip;
    regs->rflags = context->efl;

    regs->fpregs = context->fpregs;
}

int pal_common_perform_memfault_handling(uint64_t faulted_addr, struct isr_regs* regs) {
    pal_event_handler_t upcall = _PalGetExceptionHandler(PAL_EVENT_MEMFAULT);
    if (!upcall)
        return -PAL_ERROR_DENIED;

    struct pal_tcb_vm* curr_tcb = (struct pal_tcb_vm*)pal_get_tcb();
    if (!curr_tcb)
        return -PAL_ERROR_DENIED;

    /* RIP in the isr_regs is the actual user RIP */
    curr_tcb->kernel_thread.context.user_rip = regs->rip;

    PAL_CONTEXT context;
    isr_regs_to_pal_context(&context, regs, faulted_addr);
    (*upcall)(/*is_in_pal=*/false, faulted_addr, &context);
    pal_context_to_isr_regs(regs, &context);

    return 0;
}
