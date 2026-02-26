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

#include "kernel_multicore.h"
#include "kernel_sched.h"
#include "kernel_thread.h"
#include "kernel_xsave.h"

static struct pal_tcb_vm g_dummy_tcb = {
    .common.stack_protector_canary = STACK_PROTECTOR_CANARY_DEFAULT
};

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

    void* stack;
    void* fpregs;
    int ret = thread_get_stack_and_fpregs(&stack, &fpregs);
    if (ret < 0) {
        free(thread_handle);
        return ret;
    }

    /* init TCB in the highest part of the allocated stack region */
    struct pal_tcb_vm* tcb = stack + THREAD_STACK_SIZE + ALT_STACK_SIZE - sizeof(*tcb);
    thread_setup(&tcb->kernel_thread, fpregs, stack, callback, param);

    thread_handle->hdr.type = PAL_TYPE_THREAD;
    thread_handle->thread.tid = assign_new_tid();
    thread_handle->thread.stack = stack;
    thread_handle->thread.kernel_thread = &tcb->kernel_thread;

    tcb->common.self   = &tcb->common;
    tcb->thread_handle = thread_handle;

    /* thread_handle may be created via libos_syscall_clone(); in this case the newly created
     * thread_handle jumps to `sysret_asm` PAL VM trampoline, which expects user_rip to point to
     * actual ring-3 rip */
    struct pal_tcb_vm* curr_tcb = (struct pal_tcb_vm*)pal_get_tcb();
    if (curr_tcb)
        tcb->kernel_thread.context.user_rip = curr_tcb->kernel_thread.context.user_rip;

    sched_thread_add(&tcb->kernel_thread);

    *handle = thread_handle;
    return 0;
}

noreturn void pal_common_thread_exit(int* clear_child_tid) {
    struct pal_tcb_vm* curr_tcb = (struct pal_tcb_vm*)pal_get_tcb();
    struct pal_handle* thread_handle = curr_tcb->thread_handle;
    assert(thread_handle);

    /* get this thread_handle off the schedulable list */
    sched_thread_remove(&curr_tcb->kernel_thread);

	thread_free_stack_and_die(thread_handle->thread.stack, clear_child_tid);
    __builtin_unreachable();
}

int pal_common_thread_set_cpu_affinity(struct pal_handle* thread, unsigned long* cpu_mask,
                                       size_t cpu_mask_len) {
    sched_thread_set_cpu_affinity(thread->thread.kernel_thread, cpu_mask, cpu_mask_len);
    return 0;
}

int pal_common_thread_get_cpu_affinity(struct pal_handle* thread, unsigned long* cpu_mask,
                                       size_t cpu_mask_len) {
    __UNUSED(thread);
    assert(g_num_cpus >= 1 && g_num_cpus <= MAX_NUM_CPUS);

    static bool called = false;
    if (__atomic_exchange_n(&called, true, __ATOMIC_ACQUIRE)) {
        /* LibOS must call this API only once (at init) */
        log_error("Get CPU affinity called twice?! Bug in LibOS.");
        BUG();
    }

    if (cpu_mask_len * BITS_IN_TYPE(*cpu_mask) > MAX_NUM_CPUS) {
        log_error("Get CPU affinity: too many CPUs requested in CPU mask.");
        return -PAL_ERROR_INVAL;
    }

    if (cpu_mask_len * BITS_IN_TYPE(*cpu_mask) < g_num_cpus) {
        log_error("Get CPU affinity: CPU mask cannot fit all CPUs.");
        return -PAL_ERROR_INVAL;
    }

    for (size_t i = 0; i < g_num_cpus; i++) {
        cpu_mask[i / BITS_IN_TYPE(*cpu_mask)] |= 1UL << (i % BITS_IN_TYPE(*cpu_mask));
    }
    return 0;
}

struct thread* get_thread_ptr(uintptr_t curr_gs_base) {
    struct pal_tcb_vm* curr_tcb = (struct pal_tcb_vm*)curr_gs_base;
    return &curr_tcb->kernel_thread;
}

uintptr_t get_gs_base(struct thread* next_thread) {
    return (uintptr_t)next_thread - offsetof(struct pal_tcb_vm, kernel_thread);
}

/* In cases of (1) bootstrapping the VM and (2) receiving interrupts while current thread is
 * terminating, a TCB in the GS register is meaningless, but GCC's stack protector will look for a
 * canary at gs:[0x8], so let's install a dummy TCB inside GS with a default canary */
__attribute_no_stack_protector
void set_dummy_gs_base(void) {
    wrmsr(MSR_IA32_GS_BASE, (uintptr_t)&g_dummy_tcb);
}

__attribute_no_stack_protector
uintptr_t replace_with_null_if_dummy_gs_base(uintptr_t gs_base) {
    return gs_base == (uintptr_t)&g_dummy_tcb ? 0 : gs_base;
}
