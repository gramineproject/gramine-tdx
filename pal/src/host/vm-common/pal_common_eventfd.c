/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains APIs to handle eventfd objects.
 */

#include "api.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "spinlock.h"

#include "kernel_sched.h"

int pal_common_eventfd_open(struct pal_handle** handle, const char* type, const char* uri,
                            enum pal_access access, pal_share_flags_t share,
                            enum pal_create_mode create, pal_stream_options_t options) {
    __UNUSED(access);
    __UNUSED(share);
    __UNUSED(create);
    assert(create == PAL_CREATE_IGNORED);

    if (!WITHIN_MASK(options, PAL_OPTION_MASK))
        return -PAL_ERROR_INVAL;

    if (strcmp(type, URI_TYPE_EVENTFD) != 0 || *uri != '\0')
        return -PAL_ERROR_INVAL;

    struct pal_handle* eventfd = calloc(1, sizeof(*eventfd));
    if (!eventfd)
        return -PAL_ERROR_NOMEM;

    eventfd->hdr.type = PAL_TYPE_EVENTFD;
    eventfd->flags = PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    eventfd->eventfd.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    eventfd->eventfd.semaphore   = !!(options & PAL_OPTION_EFD_SEMAPHORE);

    *handle = eventfd;
    return 0;
}

int64_t pal_common_eventfd_read(struct pal_handle* handle, uint64_t offset, uint64_t len,
                                void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (handle->hdr.type != PAL_TYPE_EVENTFD)
        return -PAL_ERROR_NOTCONNECTION;

    if (len < sizeof(uint64_t))
        return -PAL_ERROR_INVAL;

    spinlock_lock(&handle->eventfd.lock);

    while (!handle->eventfd.val) {
        if (handle->eventfd.nonblocking) {
            spinlock_unlock(&handle->eventfd.lock);
            return -PAL_ERROR_TRYAGAIN;
        }

        sched_thread_wait(&handle->eventfd.reader_futex, &handle->eventfd.lock);
    }

    if (!handle->eventfd.semaphore) {
        memcpy(buffer, &handle->eventfd.val, sizeof(uint64_t));
        handle->eventfd.val = 0;
    } else {
        uint64_t one_val = 1;
        memcpy(buffer, &one_val, sizeof(uint64_t));
        handle->eventfd.val--;
    }

    if (handle->eventfd.poll_waiting)
        sched_thread_wakeup(&g_streams_waiting_events_futex);
    sched_thread_wakeup(&handle->eventfd.writer_futex);
    spinlock_unlock(&handle->eventfd.lock);
    return 8;
}

int64_t pal_common_eventfd_write(struct pal_handle* handle, uint64_t offset, uint64_t len,
                                 const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (handle->hdr.type != PAL_TYPE_EVENTFD)
        return -PAL_ERROR_NOTCONNECTION;

    if (len < sizeof(uint64_t))
        return -PAL_ERROR_INVAL;

    uint64_t buf_val;
    memcpy(&buf_val, buffer, sizeof(uint64_t));
    if (buf_val == UINT64_MAX)
        return -PAL_ERROR_INVAL;

    spinlock_lock(&handle->eventfd.lock);

    uint64_t val;
    while (__builtin_add_overflow(handle->eventfd.val, buf_val, &val) || val > UINT64_MAX - 1) {
        if (handle->eventfd.nonblocking) {
            spinlock_unlock(&handle->eventfd.lock);
            return -PAL_ERROR_TRYAGAIN;
        }

        sched_thread_wait(&handle->eventfd.writer_futex, &handle->eventfd.lock);
    }

    handle->eventfd.val = val;

    if (handle->eventfd.poll_waiting)
        sched_thread_wakeup(&g_streams_waiting_events_futex);
    sched_thread_wakeup(&handle->eventfd.reader_futex);
    spinlock_unlock(&handle->eventfd.lock);
    return 8;
}

void pal_common_eventfd_destroy(struct pal_handle* handle) {
    free(handle);
}

int pal_common_eventfd_attrquerybyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr) {
    attr->handle_type  = handle->hdr.type;
    attr->nonblocking  = handle->eventfd.nonblocking;

    spinlock_lock(&handle->eventfd.lock);
    attr->pending_size = handle->eventfd.val > 0 ? 8 : 0; /* returns a pending 8-byte int */
    spinlock_unlock(&handle->eventfd.lock);

    return 0;
}
