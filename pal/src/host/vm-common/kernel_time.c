/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Functions for getting time (in us) and setting/triggering timeouts.
 *
 * Notes on multi-core synchronization:
 *   - Timeout operations happen on different CPUs in both normal and interrupt-handling contexts,
 *     sync via timeouts lock
 *   - get_time_in_us()/delay() are thread-safe, don't use global mutable state, no sync required
 */

#include <stdint.h>

#include "api.h"
#include "list.h"
#include "pal_error.h"
#include "spinlock.h"

#include "kernel_sched.h"
#include "kernel_time.h"
#include "kernel_vmm_inputs.h"

DEFINE_LIST(pending_timeout);
struct pending_timeout {
    uint64_t timeout_absolute_us;
    int* futex;
    LIST_TYPE(pending_timeout) list;
};
DEFINE_LISTP(pending_timeout);

/* List of pending timeouts; wait-with-timeout events add themselves to this list, and
 * notify_about_timeouts_uninterruptable() callback for timer interrupt walks through this list */
static LISTP_TYPE(pending_timeout) g_pending_timeouts_list = LISTP_INIT;
static spinlock_t g_pending_timeouts_list_lock = INIT_SPINLOCK_UNLOCKED;

static uint64_t g_start_tsc = 0;
static uint64_t g_start_us  = 0;

extern uint64_t g_tsc_mhz;

/* may return overflow error, but we hope this never happens in real runs */
int get_time_in_us(uint64_t* out_us) {
    assert(g_tsc_mhz);

    uint64_t diff_tsc = get_tsc() - g_start_tsc;
    uint64_t diff_us = diff_tsc / g_tsc_mhz;

    uint64_t us = g_start_us + diff_us;
    if (us < g_start_us)
        return -PAL_ERROR_OVERFLOW;

    *out_us = us;
    return 0;
}

int delay(uint64_t delay_us, bool* continue_gate) {
    uint64_t curr_tsc = get_tsc();
    uint64_t wait_until_tsc = curr_tsc + delay_us * g_tsc_mhz;

    while (curr_tsc < wait_until_tsc) {
        if (continue_gate && __atomic_load_n(continue_gate, __ATOMIC_ACQUIRE))
            break;
        CPU_RELAX();
        curr_tsc = get_tsc();
    }
    return 0;
}

int register_timeout(uint64_t timeout_absolute_us, int* futex, void** timeout_out) {
    if (!timeout_out)
        return -PAL_ERROR_INVAL;

    struct pending_timeout* timeout = malloc(sizeof(*timeout));
    if (!timeout)
        return -PAL_ERROR_NOMEM;

    assert(futex);
    timeout->timeout_absolute_us = timeout_absolute_us;
    timeout->futex = futex;

    /* g_pending_timeouts_list is used by interrupt-handler's
     * notify_about_timeouts_uninterruptable(); temporarily disable interrupts to avoid deadlock */
    spinlock_lock_disable_irq(&g_pending_timeouts_list_lock);
    LISTP_ADD(timeout, &g_pending_timeouts_list, list);
    spinlock_unlock_enable_irq(&g_pending_timeouts_list_lock);

    *timeout_out = (void*)timeout;
    return 0;
}

void deregister_timeout(void* _timeout) {
    struct pending_timeout* timeout = (struct pending_timeout*)_timeout;

    /* g_pending_timeouts_list is used by interrupt-handler's
     * notify_about_timeouts_uninterruptable(); temporarily disable interrupts to avoid deadlock */
    spinlock_lock_disable_irq(&g_pending_timeouts_list_lock);
    struct pending_timeout* list_timeout;
    struct pending_timeout* tmp;
    LISTP_FOR_EACH_ENTRY_SAFE(list_timeout, tmp, &g_pending_timeouts_list, list) {
        if (list_timeout == timeout) {
            LISTP_DEL(timeout, &g_pending_timeouts_list, list);
        }
    }
    spinlock_unlock_enable_irq(&g_pending_timeouts_list_lock);

    free(timeout);
}

int notify_about_timeouts_uninterruptable(void) {
    int ret;
    uint64_t curr_time_us;

    ret = get_time_in_us(&curr_time_us);
    if (ret < 0)
        return ret;

    /* even though we are in non-interruptable ISR context on CPU0, still need to grab
     * g_pending_timeouts_list_lock because normal-context threads on other CPUs may call
     * register_timeout() and deregister_timeout() */
    spinlock_lock(&g_pending_timeouts_list_lock);
    struct pending_timeout* timeout;
    struct pending_timeout* tmp;
    LISTP_FOR_EACH_ENTRY_SAFE(timeout, tmp, &g_pending_timeouts_list, list) {
        if (timeout->timeout_absolute_us <= curr_time_us) {
            sched_thread_wakeup_uninterruptable(timeout->futex);
            LISTP_DEL(timeout, &g_pending_timeouts_list, list);
        }
    }
    /* to prevent lost wakeups on generic g_streams_waiting_events_futex (e.g., when a thread was
     * already running when the wakeup on this futex triggered), need to periodically kick it */
    sched_thread_wakeup_uninterruptable(&g_streams_waiting_events_futex);
    spinlock_unlock(&g_pending_timeouts_list_lock);
    return 0;
}

int time_init(void) {
    assert(g_tsc_mhz);
    char unixtime_s[TIME_S_STR_MAX];

    g_start_tsc = get_tsc();

    /* Get the UNIX time value on startup from the VMM using "FW CFG" feature of QEMU. Note that
     * this time value is untrusted.
     * TODO: get the UNIX time value from a trusted time source, like a trusted remote server. */
    unixtime_init(unixtime_s, sizeof(unixtime_s));
    uint64_t start_s = atol(unixtime_s);

    /* sanity checks: the obtained untrusted UNIX time must be in a reasonable range e.g., in
     * [1672531200, 1988150400), that is
     * [`TZ=UTC date -d "Jan 1 2023" +%s`, `TZ=UTC date -d "Jan 1 2033" +%s`) */
    if (start_s < 1672531200 || start_s >= 1988150400) {
        return -PAL_ERROR_INVAL;
    }

    g_start_us = start_s * TIME_US_IN_S;

    return 0;
}
