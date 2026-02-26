/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains APIs to handle events (futexes).
 */

#include "api.h"
#include "assert.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "spinlock.h"

#include "kernel_sched.h"
#include "kernel_time.h"

int pal_common_event_create(struct pal_handle** handle_ptr, bool init_signaled, bool auto_clear) {
    struct pal_handle* handle = calloc(1, HANDLE_SIZE(event));
    if (!handle)
        return -PAL_ERROR_NOMEM;

    init_handle_hdr(handle, PAL_TYPE_EVENT);
    spinlock_init(&handle->event.lock);
    handle->event.auto_clear = auto_clear;
    handle->event.waiters_cnt = 0;
    __atomic_store_n(&handle->event.signaled, init_signaled ? 1 : 0, __ATOMIC_RELEASE);

    *handle_ptr = handle;
    return 0;
}

void pal_common_event_set(struct pal_handle* handle) {
    spinlock_lock(&handle->event.lock);
    __atomic_store_n(&handle->event.signaled, 1, __ATOMIC_RELEASE);
    bool need_wake = handle->event.waiters_cnt > 0;
    if (need_wake)
        sched_thread_wakeup(&handle->event.signaled);
    spinlock_unlock(&handle->event.lock);
}

void pal_common_event_clear(struct pal_handle* handle) {
    spinlock_lock(&handle->event.lock);
    __atomic_store_n(&handle->event.signaled, 0, __ATOMIC_RELEASE);
    spinlock_unlock(&handle->event.lock);
}

int pal_common_event_wait(struct pal_handle* handle, uint64_t* timeout_us) {
    int ret;
    uint64_t timeout_absolute_us = 0;
    void* timeout = NULL;

    spinlock_lock(&handle->event.lock);

    if (timeout_us && *timeout_us != 0) {
        uint64_t curr_time_us;
        ret = get_time_in_us(&curr_time_us);
        if (ret < 0) {
            spinlock_unlock(&handle->event.lock);
            return ret;
        }

        timeout_absolute_us = curr_time_us + *timeout_us;
        ret = register_timeout(timeout_absolute_us, &handle->event.signaled, &timeout);
        if (ret < 0) {
            spinlock_unlock(&handle->event.lock);
            return ret;
        }
    }

    handle->event.waiters_cnt++;

    while (1) {
        bool needs_sleep = false;
        if (handle->event.auto_clear) {
            needs_sleep = __atomic_exchange_n(&handle->event.signaled, 0, __ATOMIC_ACQ_REL) == 0;
        } else {
            needs_sleep = __atomic_load_n(&handle->event.signaled, __ATOMIC_ACQUIRE) == 0;
        }

        if (!needs_sleep) {
            ret = 0;
            goto out;
        }

        if (timeout_us) {
            if (*timeout_us == 0) {
                /* user instructed not to sleep, so return immediately */
                ret = -PAL_ERROR_TRYAGAIN;
                goto out;
            }

            /* check if timeout expired */
            assert(timeout_absolute_us);

            uint64_t curr_time_us;
            ret = get_time_in_us(&curr_time_us);
            if (ret < 0)
                goto out;

            if (timeout_absolute_us <= curr_time_us) {
                ret = -PAL_ERROR_TRYAGAIN;
                goto out;
            }
        }

        /* event wasn't yet signalled, need to sleep waiting on this event */
        sched_thread_wait(&handle->event.signaled, &handle->event.lock);
    }

    ret = 0;
out:
    handle->event.waiters_cnt--;
    spinlock_unlock(&handle->event.lock);

    if (timeout)
        deregister_timeout(timeout);

    if (timeout_us && *timeout_us != 0) {
        uint64_t curr_us;
        int get_time_ret = get_time_in_us(&curr_us);
        if (!get_time_ret) {
            *timeout_us = timeout_absolute_us > curr_us ? timeout_absolute_us - curr_us : 0;
        }
    }

    return ret;
}
