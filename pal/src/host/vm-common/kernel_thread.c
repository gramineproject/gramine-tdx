/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Helpers for threads: currently the only one is for re-using thread stacks.
 *
 * Also implements idle and bottomhalves thread loops.
 *
 * Notes on multi-core synchronization:
 *   - thread_get_stack_and_fpregs() and thread_free_stack_and_die() sync via thread-stack lock
 *   - thread_setup() and thread_helper_create() are thread-safe, operate on args and locally
 *     allocated vars, no sync required
 *    - thread_idle_run() doesn't use any global state
 *    - thread_bottomhalves_run() uses atomics and locks, see this func for details
 */

#include <stdint.h>

#include "api.h"
#include "spinlock.h"

#include "kernel_sched.h"
#include "kernel_thread.h"
#include "kernel_time.h"
#include "kernel_virtio.h"
#include "kernel_xsave.h"

/* below functions are located in kernel_events.S and pal_common_threading.c */
noreturn void pal_common_thread_exit(int* clear_child_tid);
noreturn void thread_main_wrapper(void* callback_args, void* callback, void* terminate_func);

/* We cannot just use malloc/free to allocate/free thread stacks because thread-exit routine needs
 * to execute on the stack and thus can't execute free (it would execute with no stack after such
 * call). Thus, we resort to recycling thread stacks (and fpregs memory regions allocated together
 * with the stack) allocated by previous threads and not used anymore. This still leaks memory but
 * at least it is bounded by the max number of simultaneously executing threads. */
struct thread_stack_map_t {
    void* stack;
    bool  used;
};

static struct thread_stack_map_t* g_thread_stack_map = NULL;
static size_t g_thread_stack_num  = 0;
static size_t g_thread_stack_size = 0;
static spinlock_t g_thread_stack_lock = INIT_SPINLOCK_UNLOCKED;

int thread_get_stack_and_fpregs(void** out_stack, void** out_fpregs) {
    int ret;
    void* stack_base = NULL;

    spinlock_lock(&g_thread_stack_lock);
    for (size_t i = 0; i < g_thread_stack_num; i++) {
        if (!g_thread_stack_map[i].used) {
            /* found allocated and unused stack + fpregs -- use it */
            g_thread_stack_map[i].used = true;
            stack_base = g_thread_stack_map[i].stack;
            ret = 0;
            goto out;
        }
    }

    if (g_thread_stack_num == g_thread_stack_size) {
        /* realloc g_thread_stack_map to accommodate more objects (includes the very first time) */
        g_thread_stack_size += 8;
        struct thread_stack_map_t* tmp = malloc(g_thread_stack_size * sizeof(*tmp));
        if (!tmp) {
            ret = -PAL_ERROR_NOMEM;
            goto out;
        }

        memcpy(tmp, g_thread_stack_map, g_thread_stack_num * sizeof(*tmp));
        free(g_thread_stack_map);
        g_thread_stack_map = tmp;
    }

    /* allocate both the stack and the fpregs (XSAVE) memory region in one go; note that
     * fpregs may be allocated not at VM_XSAVE_ALIGN boundary, so need to add a margin for that */
    assert(g_xsave_size);
    stack_base = malloc(THREAD_STACK_SIZE + ALT_STACK_SIZE + g_xsave_size + VM_XSAVE_ALIGN);
    if (!stack_base) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    g_thread_stack_map[g_thread_stack_num].stack = stack_base;
    g_thread_stack_map[g_thread_stack_num].used  = true;
    g_thread_stack_num++;

    ret = 0;

out:
    if (ret == 0) {
        assert(stack_base);
        *out_stack  = stack_base;
        *out_fpregs = stack_base + THREAD_STACK_SIZE + ALT_STACK_SIZE;
    }
    spinlock_unlock(&g_thread_stack_lock);
    return ret;
}

noreturn void thread_free_stack_and_die(void* thread_stack, int* clear_child_tid) {
    /* we do not free thread stack (and fpregs memory region allocated with it) but instead mark it
     * as recycled, see thread_get_stack_and_fpregs() */
    spinlock_lock(&g_thread_stack_lock);
    for (size_t i = 0; i < g_thread_stack_num; i++) {
        if (g_thread_stack_map[i].stack == thread_stack) {
            g_thread_stack_map[i].used = false;
            break;
        }
    }

    /* we might still be using the stack we just marked as unused until we enter the asm mode,
     * so we do not unlock now but rather when another thread is scheduled */
    set_dummy_gs_base();
    sched_thread(&g_thread_stack_lock.lock, clear_child_tid);
    __builtin_unreachable();
}

void thread_setup(struct thread* thread, void* fpregs, void* stack, int (*callback)(void*),
                  const void* param) {
    memset(fpregs, 0, g_xsave_size + VM_XSAVE_ALIGN);
    memset(stack, 0, THREAD_STACK_SIZE + ALT_STACK_SIZE);

    /* fpregs may have been allocated not at VM_XSAVE_ALIGN boundary, so need to adjust */
    memcpy(ALIGN_UP_PTR(fpregs, VM_XSAVE_ALIGN), &g_xsave_reset_state, VM_XSAVE_RESET_STATE_SIZE);

    /* the context (GPRs, XSAVE pointer, etc.) is initialized with zeros; set only required regs */
    thread->context.rflags = 0x202;                            /* default RFLAGS */
    thread->context.rip = (uint64_t)thread_main_wrapper;       /* wrapper func to start */
    thread->context.rdi = (uint64_t)param;                     /* argument to func */
    thread->context.rsi = (uint64_t)callback;                  /* actual func to start */
    thread->context.rdx = (uint64_t)pal_common_thread_exit;    /* wrapper func to terminate */
    thread->context.rsp = (uint64_t)stack + THREAD_STACK_SIZE; /* stack top */
    thread->context.fpregs = ALIGN_UP_PTR(fpregs, VM_XSAVE_ALIGN);

    thread->context.rsp -= 8; /* x86-64 calling convention: must be 8-odd at entry */

    static uint32_t thread_id = 0;
    thread->thread_id = __atomic_add_fetch(&thread_id, 1, __ATOMIC_SEQ_CST);

    thread->state = THREAD_RUNNABLE;
    thread->blocked_on = NULL;

    memset(thread->cpu_mask, 0xFF, MAX_NUM_CPU_LONGS * 8);

    __atomic_store_n(&g_kick_sched_thread, true, __ATOMIC_RELEASE);
}

/* helper threads are per-core idle and bottomhalves threads; they are never terminated and thus
 * their resources are never freed */
int thread_helper_create(int (*callback)(void*), struct thread** out_thread) {
    struct thread* thread = calloc(1, sizeof(*thread));
    if (!thread)
        return -PAL_ERROR_NOMEM;

    /* allocate both the stack and the fpregs (XSAVE) memory region in one go; note that
     * fpregs may be allocated not at VM_XSAVE_ALIGN boundary, so need to add a margin for that */
    assert(g_xsave_size);
    void* stack_base = malloc(THREAD_STACK_SIZE + ALT_STACK_SIZE + g_xsave_size + VM_XSAVE_ALIGN);
    if (!stack_base) {
        free(thread);
        return -PAL_ERROR_NOMEM;
    }
    void* stack  = stack_base;
    void* fpregs = stack_base + THREAD_STACK_SIZE + ALT_STACK_SIZE;

    thread_setup(thread, fpregs, stack, callback, /*param=*/NULL);
    thread->is_helper = true;

    *out_thread = thread;
    return 0;
}

/* Idle thread (aka idle process) that runs when all other threads are blocked; can happen e.g. when
 * other threads wait on timer interrupt or external-event interrupt */
noreturn int thread_idle_run(void* args) {
    __UNUSED(args);

    while (true) {
        delay(IDLE_THREAD_PERIOD_US, &g_kick_sched_thread);
        __atomic_store_n(&g_kick_sched_thread, false, __ATOMIC_RELEASE);
        sched_thread(/*lock_to_unlock=*/NULL, /*clear_child_tid=*/NULL);
    }

    __builtin_unreachable();
}

/* Thread that performs heavy tasks triggered on IRQs in normal context; runs only on CPU0 */
noreturn int thread_bottomhalves_run(void* args) {
    __UNUSED(args);

    while (true) {
        bool vsock_trigger = !!__atomic_exchange_n(&g_vsock_trigger_bottomhalf, false,
                                                   __ATOMIC_ACQ_REL);
        bool console_trigger = !!__atomic_exchange_n(&g_console_trigger_bottomhalf, false,
                                                     __ATOMIC_ACQ_REL);

        /* FIXME: triple fault on errors? */
        if (vsock_trigger)
            (void)virtio_vsock_bottomhalf();
        if (console_trigger)
            (void)virtio_console_bottomhalf();

        sched_thread(/*lock_to_unlock=*/NULL, /*clear_child_tid=*/NULL);
    }

    __builtin_unreachable();
}
