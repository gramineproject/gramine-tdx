/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Helpers for threads: currently the only one is for re-using thread stacks.
 *
 * Also implements idle and bottomhalves thread loops.
 */

#include <stdint.h>

#include "api.h"
#include "spinlock.h"

#include "kernel_sched.h"
#include "kernel_thread.h"
#include "kernel_virtio.h"

/* Idle thread (aka idle process) that runs when all other threads are blocked; can happen e.g. when
 * other threads wait on timer interrupt or external-event interrupt */
struct thread* g_idle_thread = NULL;

/* Thread that performs heavy tasks triggered on IRQs in normal context; scheduled before any other
 * threads for improved latency */
struct thread* g_bottomhalves_thread = NULL;

/* We cannot just use malloc/free to allocate/free thread stacks because thread-exit routine needs
 * to execute on the stack and thus can't execute free (it would execute with no stack after such
 * call). Thus, we resort to recycling thread stacks allocated by previous threads and not used
 * anymore. This still leaks memory but at least it is bounded by the max number of simultaneously
 * executing threads. */
struct thread_stack_map_t {
    void* stack;
    bool  used;
};

static struct thread_stack_map_t* g_thread_stack_map = NULL;
static size_t g_thread_stack_num  = 0;
static size_t g_thread_stack_size = 0;
static spinlock_t g_thread_stack_lock = INIT_SPINLOCK_UNLOCKED;

void* thread_get_stack(void) {
    void* ret = NULL;
    spinlock_lock(&g_thread_stack_lock);
    for (size_t i = 0; i < g_thread_stack_num; i++) {
        if (!g_thread_stack_map[i].used) {
            /* found allocated and unused stack -- use it */
            g_thread_stack_map[i].used = true;
            ret = g_thread_stack_map[i].stack;
            goto out;
        }
    }

    if (g_thread_stack_num == g_thread_stack_size) {
        /* realloc g_thread_stack_map to accommodate more objects (includes the very first time) */
        g_thread_stack_size += 8;
        struct thread_stack_map_t* tmp = malloc(g_thread_stack_size * sizeof(*tmp));
        if (!tmp)
            goto out;

        memcpy(tmp, g_thread_stack_map, g_thread_stack_num * sizeof(*tmp));
        free(g_thread_stack_map);
        g_thread_stack_map = tmp;
    }

    ret = malloc(THREAD_STACK_SIZE + ALT_STACK_SIZE);
    if (!ret)
        goto out;

    g_thread_stack_map[g_thread_stack_num].stack = ret;
    g_thread_stack_map[g_thread_stack_num].used  = true;
    g_thread_stack_num++;
out:
    spinlock_unlock(&g_thread_stack_lock);
    return ret;
}

noreturn void thread_free_stack_and_die(void* thread_stack, int* clear_child_tid) {
    /* we do not free thread stack but instead mark it as recycled, see thread_get_stack() */
    spinlock_lock(&g_thread_stack_lock);
    for (size_t i = 0; i < g_thread_stack_num; i++) {
        if (g_thread_stack_map[i].stack == thread_stack) {
            g_thread_stack_map[i].used = false;
            break;
        }
    }

    /* we might still be using the stack we just marked as unused until we enter the asm mode,
     * so we do not unlock now but rather when another thread is scheduled */
    sched_thread(&g_thread_stack_lock.lock, clear_child_tid);
    __builtin_unreachable();
}

noreturn int thread_idle_run(void* args) {
    __UNUSED(args);

    while (true) {
        CPU_RELAX();
        CPU_RELAX();
        CPU_RELAX();
        sched_thread(/*lock_to_unlock=*/NULL, /*clear_child_tid=*/NULL);
    }

    __builtin_unreachable();
}

noreturn int thread_bottomhalves_run(void* args) {
    __UNUSED(args);

    while (true) {
        if (g_vsock_trigger_bottomhalf) {
            (void)virtio_vsock_bottomhalf(); /* FIXME: triple fault on errors? */
            g_vsock_trigger_bottomhalf = false;
        }
        if (g_console_trigger_bottomhalf) {
            (void)virtio_console_bottomhalf(); /* FIXME: triple fault on errors? */
            g_console_trigger_bottomhalf = false;
        }

        sched_thread(/*lock_to_unlock=*/NULL, /*clear_child_tid=*/NULL);
    }

    __builtin_unreachable();
}
