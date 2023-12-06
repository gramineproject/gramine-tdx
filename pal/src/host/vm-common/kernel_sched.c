/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Trivial round-robin Single Queue Multiprocessor Scheduler (SQMS) implementation. Takes into
 * account CPU affinity.
 */

#include <stdint.h>

#include "api.h"
#include "cpu.h"
#include "pal_error.h"

#include "kernel_interrupts.h"
#include "kernel_multicore.h"
#include "kernel_sched.h"
#include "kernel_thread.h"
#include "kernel_xsave.h"

/* below functions are located in kernel_events.S */
noreturn void isr_iret_to_userland(void);
int save_context_and_restore_next(uint64_t curr_gs_base, uint64_t next_gs_base,
                                  uint32_t* lock_to_unlock, int* clear_child_tid,
                                  uint32_t* critical_section_lock_to_unlock,
                                  void* scheduling_stack);

static LISTP_TYPE(thread) g_thread_list = LISTP_INIT;

/*
 * Guards operations on g_thread_list. This lock should be acquired in two ways:
 *   - if used in interrupt-handler context, must call spinlock_lock()
 *   - if used in normal (interruptible) context, must call spinlock_lock_disable_irq()
 */
static spinlock_t g_thread_list_lock = INIT_SPINLOCK_UNLOCKED;

/* Atomic variable used to kick sched_thread() into action (instead of waiting for some time) */
bool g_kick_sched_thread = false;

static uint64_t get_rflags(void) {
    uint64_t result;
    __asm__ volatile("pushfq; pop %0" : "=r"(result) : : "cc");
    return result;
}

static void save_userland_context(struct thread* curr_thread, struct isr_regs* userland_regs) {
    if (!curr_thread)
        return;

    /* we don't save the FS register because Gramine doesn't use/modify it; only the app uses and
     * modifies it, and so we can just rely that curr_thread->context.user_fsbase is not affected
     * during these context save/restore */

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

    if (curr_thread && !curr_thread->is_helper) {
        /* move currently executing thread to the back of the list for round robin scheding */
        LISTP_DEL(curr_thread, &g_thread_list, list);
        LISTP_ADD_TAIL(curr_thread, &g_thread_list, list);
    }

    uint32_t cpu_id = get_per_cpu_data()->cpu_id;
    struct thread* next_thread = NULL;

    struct thread* thread;
    LISTP_FOR_EACH_ENTRY(thread, &g_thread_list, list) {
        if (thread->state != THREAD_RUNNABLE)
            continue;

        size_t cpu_mask_idx = cpu_id / BITS_IN_TYPE(unsigned long);
        unsigned long cpu_mask_bit = 1UL << (cpu_id % BITS_IN_TYPE(unsigned long));
        if (!(thread->cpu_mask[cpu_mask_idx] & cpu_mask_bit))
            continue;

        if (!next_thread) {
            /* found first runnable thread, mark it as to-be-run next */
            next_thread = thread;
        } else {
            /* found second runnable thread, kick some other CPU to schedule that thread */
            __atomic_store_n(&g_kick_sched_thread, true, __ATOMIC_RELEASE);
            break;
        }
    }

    if (!next_thread && cpu_id == 0) {
        /* CPU0 must periodically handle incoming events (network packets, stdin) */
        assert(get_per_cpu_data()->bottomhalves_thread);
        assert(get_per_cpu_data()->bottomhalves_thread->state != THREAD_BLOCKED);
        next_thread = get_per_cpu_data()->bottomhalves_thread;
    }

    if (!next_thread) {
        /* absolutely no tasks to do */
        assert(get_per_cpu_data()->idle_thread);
        assert(get_per_cpu_data()->idle_thread->state != THREAD_BLOCKED);
        next_thread = get_per_cpu_data()->idle_thread;
    }

    return next_thread;
}

void sched_thread_uninterruptable(struct isr_regs* userland_regs) {
    uint64_t curr_gs_base = replace_with_null_if_dummy_gs_base(rdmsr(MSR_IA32_GS_BASE));
    struct thread* curr_thread = curr_gs_base ? get_thread_ptr(curr_gs_base) : NULL;

    spinlock_lock(&g_thread_list_lock); /* will be unlocked during save_context */
    struct thread* next_thread = find_next_thread(curr_thread);
    if (curr_thread && curr_thread->state == THREAD_RUNNING)
        curr_thread->state = THREAD_RUNNABLE;
    next_thread->state = THREAD_RUNNING;

    if (next_thread == curr_thread) {
        /* re-scheduled the same thread, no need to save/restore context */
        spinlock_unlock(&g_thread_list_lock);
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
                                  /*clear_child_tid=*/NULL, &g_thread_list_lock.lock,
                                  /*scheduling_stack=*/NULL);
}

void sched_thread(uint32_t* lock_to_unlock, int* clear_child_tid) {
    uint64_t curr_gs_base = replace_with_null_if_dummy_gs_base(rdmsr(MSR_IA32_GS_BASE));
    struct thread* curr_thread = curr_gs_base ? get_thread_ptr(curr_gs_base) : NULL;

    spinlock_lock_disable_irq(&g_thread_list_lock); /* will be unlocked during save_context */
    struct thread* next_thread = find_next_thread(curr_thread);
    if (curr_thread && curr_thread->state == THREAD_RUNNING)
        curr_thread->state = THREAD_RUNNABLE;
    next_thread->state = THREAD_RUNNING;

    if (next_thread == curr_thread) {
        /* re-scheduled the same thread, no need to save/restore context */
        spinlock_unlock_enable_irq(&g_thread_list_lock);
        return;
    }

    /* it is cumbersome to restore FSBASE in asm, so restore explicitly here */
    wrmsr(MSR_IA32_FS_BASE, next_thread->context.user_fsbase);

    uint64_t next_gs_base = (uint64_t)get_gs_base(next_thread);
    save_context_and_restore_next(curr_gs_base, next_gs_base, lock_to_unlock, clear_child_tid,
                                  &g_thread_list_lock.lock, get_per_cpu_data()->scheduling_stack);
}

void sched_thread_wait(int* futex_word, spinlock_t* lock) {
    assert(spinlock_is_locked(lock));
    assert(lock != &g_thread_list_lock);

    /* this order of locks is required to guarantee that we won't miss any wakeup on this futex word
     * (recall that each wakeup grabs g_thread_list_lock) */
    spinlock_lock_disable_irq(&g_thread_list_lock); /* will be unlocked during save_context */
    spinlock_unlock(lock);

    uint64_t curr_gs_base = rdmsr(MSR_IA32_GS_BASE);
    struct thread* curr_thread = get_thread_ptr(curr_gs_base);

    curr_thread->state      = THREAD_BLOCKED;
    curr_thread->blocked_on = futex_word;

    struct thread* next_thread = find_next_thread(curr_thread);
    next_thread->state = THREAD_RUNNING;

    assert(next_thread != curr_thread);

    wrmsr(MSR_IA32_FS_BASE, next_thread->context.user_fsbase);

    uint64_t next_gs_base = (uint64_t)get_gs_base(next_thread);
    save_context_and_restore_next(curr_gs_base, next_gs_base, /*lock_to_unlock=*/NULL,
                                  /*clear_child_tid=*/NULL, &g_thread_list_lock.lock,
                                  get_per_cpu_data()->scheduling_stack);

    /* now this thread is scheduled back, it means that it was unblocked via wakeup */
    spinlock_lock(lock);
}

static void sched_thread_wakeup_common(int* futex_word) {
    assert(spinlock_is_locked(&g_thread_list_lock));

    bool found = false;
    struct thread* thread;
    LISTP_FOR_EACH_ENTRY(thread, &g_thread_list, list) {
        if (thread->state == THREAD_BLOCKED) {
            /* TODO: add loop of iterating through epoll/select futexes as perf optimization */
            if (thread->blocked_on == futex_word) {
                thread->state      = THREAD_RUNNABLE;
                thread->blocked_on = NULL;
                found = true;
            }
        }
    }

    if (found)
        __atomic_store_n(&g_kick_sched_thread, true, __ATOMIC_RELEASE);
}

void sched_thread_wakeup_uninterruptable(int* futex_word) {
    spinlock_lock(&g_thread_list_lock);
    sched_thread_wakeup_common(futex_word);
    spinlock_unlock(&g_thread_list_lock);
}

void sched_thread_wakeup(int* futex_word) {
    spinlock_lock_disable_irq(&g_thread_list_lock);
    sched_thread_wakeup_common(futex_word);
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
    thread->state = THREAD_STOPPED;
    thread->blocked_on = NULL;
    spinlock_unlock_enable_irq(&g_thread_list_lock);
}

void sched_thread_set_cpu_affinity(struct thread* thread, unsigned long* cpu_mask,
                                   size_t cpu_mask_len) {
    assert(g_num_cpus >= 1 && g_num_cpus <= MAX_NUM_CPUS);

    spinlock_lock_disable_irq(&g_thread_list_lock);
    memset(thread->cpu_mask, 0, MAX_NUM_CPU_LONGS * 8);
    for (size_t i = 0; i < g_num_cpus; i++) {
        size_t cpu_mask_idx = i / BITS_IN_TYPE(*cpu_mask);
        if (cpu_mask_idx >= cpu_mask_len)
            break;
        if (cpu_mask[cpu_mask_idx] & (1UL << (i % BITS_IN_TYPE(*cpu_mask)))) {
            thread->cpu_mask[cpu_mask_idx] |= 1UL << (i % BITS_IN_TYPE(*cpu_mask));
        }
    }
    spinlock_unlock_enable_irq(&g_thread_list_lock);
}
