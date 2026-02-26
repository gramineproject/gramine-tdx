/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Trivial round-robin scheduler implementation. Currently assumes single-core VM.
 */

#include <stdint.h>

#include "api.h"
#include "cpu.h"
#include "pal_error.h"

#include "kernel_interrupts.h"
#include "kernel_sched.h"
#include "kernel_thread.h"
#include "kernel_xsave.h"

/* below functions are located in kernel_events.S */
noreturn void isr_iret_to_userland(void);
int save_context_and_restore_next(uint64_t curr_gs_base, uint64_t next_gs_base,
                                  uint32_t* lock_to_unlock, int* clear_child_tid);

static LISTP_TYPE(thread) g_thread_list = LISTP_INIT;

/*
 * Guards operations on g_thread_list. This lock should be acquired in two ways:
 *   - if used in interrupt-handler context, must call spinlock_lock()
 *   - if used in normal (interruptible) context, must call spinlock_lock_disable_irq()
 */
static spinlock_t g_thread_list_lock = INIT_SPINLOCK_UNLOCKED;

static uint64_t get_rflags(void) {
    uint64_t result;
    __asm__ volatile("pushfq; pop %0" : "=r"(result) : : "cc");
    return result;
}

static void save_userland_context(struct thread* curr_thread, struct isr_regs* userland_regs) {
    if (!curr_thread)
        return;

    /* FIXME: should also save FSBASE? It should be in isr_regs I think. */

    memcpy(curr_thread->context.fpregs, userland_regs->fpregs, g_xsave_size);

    curr_thread->context.r8  = userland_regs->r8;
    curr_thread->context.r9  = userland_regs->r9;
    curr_thread->context.r10 = userland_regs->r10;
    curr_thread->context.r11 = userland_regs->r11;
    curr_thread->context.r12 = userland_regs->r12;
    curr_thread->context.r13 = userland_regs->r13;
    curr_thread->context.r14 = userland_regs->r14;
    curr_thread->context.r15 = userland_regs->r15;
    curr_thread->context.rdi = userland_regs->rdi;
    curr_thread->context.rsi = userland_regs->rsi;
    curr_thread->context.rbp = userland_regs->rbp;
    curr_thread->context.rbx = userland_regs->rbx;
    curr_thread->context.rdx = userland_regs->rdx;
    curr_thread->context.rax = userland_regs->rax;
    curr_thread->context.rcx = userland_regs->rcx;

    curr_thread->irq_pseudo_stack.rip    = userland_regs->rip;
    curr_thread->irq_pseudo_stack.cs     = userland_regs->cs;
    curr_thread->irq_pseudo_stack.rflags = userland_regs->rflags;
    curr_thread->irq_pseudo_stack.rsp    = userland_regs->rsp;
    curr_thread->irq_pseudo_stack.ss     = userland_regs->ss;

    curr_thread->context.rip = (uint64_t)&isr_iret_to_userland;
    curr_thread->context.rsp = (uint64_t)&curr_thread->irq_pseudo_stack;
    curr_thread->context.rflags = get_rflags();
}

static struct thread* find_next_thread(struct thread* curr_thread) {
    assert(spinlock_is_locked(&g_thread_list_lock));

    struct thread* next_thread = NULL;

    if (curr_thread) {
        /* move currently executing thread to the back of the list for round robin scheding (but
         * before very-last bottomhalves and idle threads, to not switch to them constantly) */
        LISTP_DEL(curr_thread, &g_thread_list, list);
        LISTP_ADD_TAIL(curr_thread, &g_thread_list, list);

        if (g_bottomhalves_thread) {
            LISTP_DEL(g_bottomhalves_thread, &g_thread_list, list);
            LISTP_ADD_TAIL(g_bottomhalves_thread, &g_thread_list, list);
        }

        if (g_idle_thread) {
            LISTP_DEL(g_idle_thread, &g_thread_list, list);
            LISTP_ADD_TAIL(g_idle_thread, &g_thread_list, list);
        }
    }

    struct thread* thread;
    LISTP_FOR_EACH_ENTRY(thread, &g_thread_list, list) {
        if (thread->state == THREAD_RUNNABLE) {
            next_thread = thread;
            break;
        }
    }

    assert(next_thread);
    return next_thread;
}

void sched_thread_uninterruptable(struct isr_regs* userland_regs) {
    uint64_t curr_gs_base = rdmsr(MSR_IA32_GS_BASE);
    struct thread* curr_thread = curr_gs_base ? get_thread_ptr(curr_gs_base) : NULL;

    /* even though locking is not needed (we are guaranteed to run uncontested), we may jump into
     * the thread_scheduler() context of a thread that grabbed g_thread_list_lock beforehand */
    spinlock_lock(&g_thread_list_lock);
    struct thread* next_thread = find_next_thread(curr_thread);
    spinlock_unlock(&g_thread_list_lock);

    if (next_thread == curr_thread) {
        /* re-scheduled the same thread, no need to save/restore context */
        return;
    }

    /* We cannot save the current ring-0 (kernel) context because we are on the interrupt handler
     * stack which may be clobbered in-between scheduling the current userland thread, and thus the
     * restored ring-0 context will have different values on stack. Instead, we manually save the
     * userland context and rewire RIP to point to a special "return via iret" assembly. */
    save_userland_context(curr_thread, userland_regs);

    /* it is cumbersome to restore FSBASE in asm, so restore explicitly here */
    wrmsr(MSR_IA32_FS_BASE, next_thread->context.user_fsbase);

    uint64_t next_gs_base = (uint64_t)get_gs_base(next_thread);
    save_context_and_restore_next(/*curr_gs_base=*/0x0, next_gs_base, /*lock_to_unlock=*/NULL,
                                  /*clear_child_tid=*/NULL);
}

void sched_thread(uint32_t* lock_to_unlock, int* clear_child_tid) {
    uint64_t curr_gs_base = rdmsr(MSR_IA32_GS_BASE);
    struct thread* curr_thread = curr_gs_base ? get_thread_ptr(curr_gs_base) : NULL;

    spinlock_lock_disable_irq(&g_thread_list_lock);
    struct thread* next_thread = find_next_thread(curr_thread);
    spinlock_unlock_enable_irq(&g_thread_list_lock);

    if (next_thread == curr_thread) {
        /* re-scheduled the same thread, no need to save/restore context */
        return;
    }

    /* it is cumbersome to restore FSBASE in asm, so restore explicitly here */
    wrmsr(MSR_IA32_FS_BASE, next_thread->context.user_fsbase);

    uint64_t next_gs_base = (uint64_t)get_gs_base(next_thread);
    save_context_and_restore_next(curr_gs_base, next_gs_base, lock_to_unlock, clear_child_tid);
}

void sched_thread_wait(int* futex_word, spinlock_t* lock) {
    assert(spinlock_is_locked(lock));
    assert(lock != &g_thread_list_lock);

    /* this order of locks is required to guarantee that we won't miss any wakeup on this futex word
     * (recall that each wakeup grabs g_thread_list_lock) */
    spinlock_lock_disable_irq(&g_thread_list_lock);
    spinlock_unlock(lock);

    uint64_t curr_gs_base = rdmsr(MSR_IA32_GS_BASE);
    struct thread* curr_thread = get_thread_ptr(curr_gs_base);

    curr_thread->state      = THREAD_BLOCKED;
    curr_thread->blocked_on = futex_word;

    spinlock_unlock_enable_irq(&g_thread_list_lock);

    sched_thread(/*lock_to_unlock=*/NULL, /*clear_child_tid=*/NULL);

    /* now this thread is scheduled back, it means that it was unblocked via wakeup */
    spinlock_lock(lock);
}

void sched_thread_wakeup_uninterruptable(int* futex_word) {
    struct thread* thread;
    LISTP_FOR_EACH_ENTRY(thread, &g_thread_list, list) {
        if (thread->state == THREAD_BLOCKED) {
            /* TODO: add loop of iterating through epoll/select futexes as perf optimization */
            if (thread->blocked_on == futex_word) {
                thread->state      = THREAD_RUNNABLE;
                thread->blocked_on = NULL;
            }
        }
    }
}

void sched_thread_wakeup(int* futex_word) {
    spinlock_lock_disable_irq(&g_thread_list_lock);
    sched_thread_wakeup_uninterruptable(futex_word);
    spinlock_unlock_enable_irq(&g_thread_list_lock);
}

void sched_thread_add(struct thread* thread) {
    spinlock_lock_disable_irq(&g_thread_list_lock);
    LISTP_ADD_TAIL(thread, &g_thread_list, list);
    spinlock_unlock_enable_irq(&g_thread_list_lock);
}

void sched_thread_remove(struct thread* thread) {
    spinlock_lock_disable_irq(&g_thread_list_lock);
    LISTP_DEL(thread, &g_thread_list, list);
    spinlock_unlock_enable_irq(&g_thread_list_lock);
}
