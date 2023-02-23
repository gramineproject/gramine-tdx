/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains APIs for polling PAL handles.
 */

#include "api.h"
#include "list.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "spinlock.h"

#include "kernel_sched.h"
#include "kernel_time.h"
#include "kernel_virtio.h"

/* Global lock and futex for waiting for some events (very naive but good enough) */
static spinlock_t g_streams_waiting_events_lock = INIT_SPINLOCK_UNLOCKED;
int g_streams_waiting_events_futex;

static int check_pipesrv_handle(struct pal_handle* handle, pal_wait_flags_t events,
                                pal_wait_flags_t* out_events) {
    pal_wait_flags_t revents = 0;

    if ((events & PAL_WAIT_READ)) {
        bool any_connecting_pipe_found = false;

        spinlock_lock(&g_connecting_pipes_lock);
        struct pal_handle* connecting_pipe = NULL;
        LISTP_FOR_EACH_ENTRY(connecting_pipe, &g_connecting_pipes_list, list) {
            if (strcmp(connecting_pipe->pipe.name, handle->pipe.name) == 0) {
                any_connecting_pipe_found = true;
                break;
            }
        }
        spinlock_unlock(&g_connecting_pipes_lock);

        if (any_connecting_pipe_found)
            revents |= PAL_WAIT_READ;
    }

    spinlock_lock(&handle->pipe.lock);
    handle->pipe.waitedfor = (revents == 0);
    spinlock_unlock(&handle->pipe.lock);

    *out_events = revents;
    return 0;
}

static int check_pipe_handle(struct pal_handle* handle, pal_wait_flags_t events,
                             pal_wait_flags_t* out_events) {
    pal_wait_flags_t revents = 0;

    spinlock_lock(&handle->pipe.lock);

    if (!(handle->flags & PAL_HANDLE_FD_READABLE) && !(handle->flags & PAL_HANDLE_FD_WRITABLE)) {
        /* pipe was shutdown */
        handle->flags |= PAL_HANDLE_FD_ERROR;
        revents = PAL_WAIT_ERROR;
        goto out;
    }

    if ((events & PAL_WAIT_READ) && (handle->flags & PAL_HANDLE_FD_READABLE)) {
        /* read event requested, and pipe is opened for read... */
        if (handle->pipe.read_pos != handle->pipe.write_pos) {
            /* ...and there is something to read */
            revents |= PAL_WAIT_READ;
        }
    }

    if ((events & PAL_WAIT_WRITE) && (handle->flags & PAL_HANDLE_FD_WRITABLE)) {
        /* write event requested, and pipe is opened for write... */
        if (handle->pipe.write_pos - handle->pipe.read_pos < PIPE_BUF_SIZE) {
            /* ...and there is room to write */
            revents |= PAL_WAIT_WRITE;
        }
    }

out:
    handle->pipe.waitedfor = (revents == 0);
    spinlock_unlock(&handle->pipe.lock);

    *out_events = revents;
    return 0;
}

static int check_socket_handle(struct pal_handle* handle, pal_wait_flags_t events,
                               pal_wait_flags_t* out_events) {
    pal_wait_flags_t revents = 0;

    spinlock_lock(&handle->sock.lock);

    if (events & PAL_WAIT_READ) {
        long peeked = virtio_vsock_peek(handle->sock.fd);
        if (peeked < 0) {
            spinlock_unlock(&handle->sock.lock);
            return peeked;
        }
        if (peeked)
            revents |= PAL_WAIT_READ;
    }

    if (events & PAL_WAIT_WRITE) {
        /* simplification: assume that TCP stream can always be written to */
        revents |= PAL_WAIT_WRITE;
    }

    *out_events = revents;
    spinlock_unlock(&handle->sock.lock);
    return 0;
}

static int check_handle(struct pal_handle* handle, pal_wait_flags_t events,
                        pal_wait_flags_t* out_events) {
    if (!handle) {
        *out_events = PAL_WAIT_ERROR;
        return 0;
    }

    if (handle->hdr.type == PAL_TYPE_PIPESRV) {
        return check_pipesrv_handle(handle, events, out_events);
    } else if (handle->hdr.type == PAL_TYPE_PIPECLI) {
        return check_pipe_handle(handle, events, out_events);
    } else if (handle->hdr.type == PAL_TYPE_PIPE) {
        assert(!handle->pipe.buf);
        assert(handle->pipe.peer);
        return check_pipe_handle(handle->pipe.peer, events, out_events);
    } else if (handle->hdr.type == PAL_TYPE_SOCKET) {
        return check_socket_handle(handle, events, out_events);
    }

    /* cannot recognize this handle */
    return -PAL_ERROR_INVAL;
}

int pal_common_streams_wait_events(size_t count, struct pal_handle** handle_array,
                                   pal_wait_flags_t* events, pal_wait_flags_t* ret_events,
                                   uint64_t* timeout_us) {
    int ret;
    bool any_event_found = false;
    uint64_t timeout_absolute_us = 0;

    if (timeout_us && *timeout_us != 0) {
        uint64_t curr_time_us;
        ret = get_time_in_us(&curr_time_us);
        if (ret < 0)
            return ret;

        timeout_absolute_us = curr_time_us + *timeout_us;
        register_timeout(timeout_absolute_us, &g_streams_waiting_events_futex);
    }

    spinlock_lock(&g_streams_waiting_events_lock);

    while (!any_event_found) {
        for (size_t i = 0; i < count; i++) {
            ret_events[i] = 0;

            pal_wait_flags_t revents = 0;
            ret = check_handle(handle_array[i], events[i], &revents);
            if (ret < 0)
                goto out;

            if (revents) {
                ret_events[i] = revents;
                any_event_found = true;
            }
        }

        if (any_event_found)
            break;

        if (timeout_us) {
            if (*timeout_us == 0) {
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

        /* no events found, need to sleep for any new events */
        sched_thread_wait(&g_streams_waiting_events_futex, &g_streams_waiting_events_lock);
    }

    ret = 0;
out:
    if (timeout_us && *timeout_us != 0) {
        uint64_t curr_us;
        int get_time_ret = get_time_in_us(&curr_us);
        if (!get_time_ret) {
            *timeout_us = timeout_absolute_us > curr_us ? timeout_absolute_us - curr_us : 0;
        }
    }
    spinlock_unlock(&g_streams_waiting_events_lock);
    return ret;
}
