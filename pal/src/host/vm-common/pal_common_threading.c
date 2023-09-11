/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains APIs to create, exit and yield a thread.
 */

#include "api.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_internal.h"

#include "kernel_sched.h"
#include "kernel_thread.h"
#include "kernel_xsave.h"

static int assign_new_tid(void) {
    static int tid = 0;
    return __atomic_add_fetch(&tid, 1, __ATOMIC_SEQ_CST);
}

int pal_common_thread_create(struct pal_handle** handle, int (*callback)(void*),
                             const void* param) {
    /*
     * Stack layout for the new thread looks like this:
     *
     *                   +-------------------+
     *                   |  PAL TCB          | sizeof(struct pal_tcb_vm)
     *          tcb +--> +-------------------+
     *                   |  alternate stack  | ALT_STACK_SIZE - sizeof(struct pal_tcb_vm)
     *                   +-------------------+
     *                   |  normal stack     | THREAD_STACK_SIZE
     *       stack  +--> +-------------------+
     */

    struct pal_handle* thread_handle = calloc(1, sizeof(*thread_handle));
    if (!thread_handle)
        return -PAL_ERROR_NOMEM;

    /* fpregs may be allocated not at VM_XSAVE_ALIGN boundary, so need to add a margin for that */
    assert(g_xsave_size);
    void* fpregs = malloc(g_xsave_size + VM_XSAVE_ALIGN);
    if (!fpregs) {
        free(thread_handle);
        return -PAL_ERROR_NOMEM;
    }

    void* stack = thread_get_stack();
    if (!stack) {
        free(fpregs);
        free(thread_handle);
        return -PAL_ERROR_NOMEM;
    }

    /* fpregs may have been allocated not at VM_XSAVE_ALIGN boundary, so need to adjust */
    memset(fpregs, 0, g_xsave_size + VM_XSAVE_ALIGN);
    memcpy(ALIGN_UP_PTR(fpregs, VM_XSAVE_ALIGN), &g_xsave_reset_state, VM_XSAVE_RESET_STATE_SIZE);

    /* We zero out only the first page of the main stack (to comply with the requirement of gcc ABI,
     * in particular that the initial stack frame's return address must be NULL). We zero out the
     * whole altstack (since it is small anyway) and also the PAL TCB. */
    memset(stack + THREAD_STACK_SIZE - PRESET_PAGESIZE, 0, PRESET_PAGESIZE);
    memset(stack + THREAD_STACK_SIZE, 0, ALT_STACK_SIZE);

    thread_handle->hdr.type  = PAL_TYPE_THREAD;

    thread_handle->thread.tid    = assign_new_tid();
    thread_handle->thread.stack  = stack;
    thread_handle->thread.fpregs = fpregs;

    /* init TCB in the highest part of the allocated stack region */
    struct pal_tcb_vm* tcb = stack + THREAD_STACK_SIZE + ALT_STACK_SIZE - sizeof(*tcb);
    tcb->common.self   = &tcb->common;
    tcb->thread_handle = thread_handle;

    tcb->kernel_thread.state = THREAD_RUNNABLE;
    tcb->kernel_thread.blocked_on = NULL;
    memset(&tcb->kernel_thread.context, 0, sizeof(tcb->kernel_thread.context));
    memset(&tcb->kernel_thread.irq_pseudo_stack, 0, sizeof(tcb->kernel_thread.irq_pseudo_stack));

    /* thread_handle may be created via libos_syscall_clone(); in this case the newly created thread_handle jumps
     * to `sysret_asm` PAL VM trampoline, which expects user_rip to point to actual ring-3 rip */
    struct pal_tcb_vm* curr_tcb = (struct pal_tcb_vm*)pal_get_tcb();
    if (curr_tcb)
        tcb->kernel_thread.context.user_rip = curr_tcb->kernel_thread.context.user_rip;

    /* the context (GPRs, XSAVE pointer, etc.) is initialized with zeros; set only required regs */
    tcb->kernel_thread.context.rflags = 0x202;                            /* default RFLAGS */
    tcb->kernel_thread.context.rip = (uint64_t)callback;                  /* func to start */
    tcb->kernel_thread.context.rdi = (uint64_t)param;                     /* argument to func */
    tcb->kernel_thread.context.rsp = (uint64_t)stack + THREAD_STACK_SIZE; /* stack top */
    tcb->kernel_thread.context.fpregs = (PAL_XREGS_STATE*)ALIGN_UP_PTR(fpregs, VM_XSAVE_ALIGN);

    tcb->kernel_thread.context.rsp -= 8; /* x86-64 calling convention: must be 8-odd at entry */

    if (callback == thread_idle_run) {
        g_idle_thread = &tcb->kernel_thread;
    } else if (callback == thread_bottomhalves_run) {
        g_bottomhalves_thread = &tcb->kernel_thread;
    }

	sched_thread_add(&tcb->kernel_thread);

    *handle = thread_handle;
    return 0;
}

noreturn void pal_common_thread_exit(int* clear_child_tid) {
    struct pal_tcb_vm* curr_tcb = (struct pal_tcb_vm*)pal_get_tcb();
    struct pal_handle* thread_handle = curr_tcb->thread_handle;
    assert(thread_handle);

    /* at this point, we are guaranteed to not use this thread_handle's fpregs aka XSAVE area */
    free(thread_handle->thread.fpregs);

    /* get this thread_handle off the schedulable list; set GS=0x0 to skip saving its context */
	sched_thread_remove(&curr_tcb->kernel_thread);
    curr_tcb->kernel_thread.state = THREAD_STOPPED;
    curr_tcb->kernel_thread.blocked_on = NULL;
    wrmsr(MSR_IA32_GS_BASE, 0x0);

	thread_free_stack_and_die(thread_handle->thread.stack, clear_child_tid);
    __builtin_unreachable();
}

struct thread* get_thread_ptr(uintptr_t curr_gs_base) {
    struct pal_tcb_vm* curr_tcb = (struct pal_tcb_vm*)curr_gs_base;
    return &curr_tcb->kernel_thread;
}

uintptr_t get_gs_base(struct thread* next_thread) {
    return (uintptr_t)next_thread - offsetof(struct pal_tcb_vm, kernel_thread);
}
