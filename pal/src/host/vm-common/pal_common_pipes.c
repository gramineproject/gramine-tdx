/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains APIs to handle pipes.
 *
 * TODO: Currently two pipe objects share a single buffer that is part of one of these two objects.
 *       We should refactor so that the buffer is a separate object with a refcount of 2.
 */

#include "api.h"
#include "list.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "spinlock.h"

#include "kernel_sched.h"

/* Global lock for all connecting operations: waiting for clients, connecting to server, etc. */
spinlock_t g_connecting_pipes_lock = INIT_SPINLOCK_UNLOCKED;

/* List of "pipesrv" named pipes; this list is used to find corresponding "pipesrv" pipe for each
 * connecting pipe during pipe_connect() */
LISTP_TYPE(pal_handle) g_server_pipes_list = LISTP_INIT;

/* List of "pipe" connecting pipes; this list is used to find corresponding "connecting" pipe for
 * each accepting pipe during pipe_waitforclient() */
LISTP_TYPE(pal_handle) g_connecting_pipes_list = LISTP_INIT;

static int pipe_listen(struct pal_handle** handle, const char* name, pal_stream_options_t options) {
    struct pal_handle* pipe = calloc(1, sizeof(*pipe));
    if (!pipe)
        return -PAL_ERROR_NOMEM;

    pipe->hdr.type = PAL_TYPE_PIPESRV;
    pipe->flags = 0; /* cannot read or write on the server pipe */

    pipe->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    spinlock_init(&pipe->pipe.lock);

    memcpy(&pipe->pipe.name, name, strlen(name) + 1);

    spinlock_lock(&g_connecting_pipes_lock);

    struct pal_handle* server_pipe;
    LISTP_FOR_EACH_ENTRY(server_pipe, &g_server_pipes_list, list) {
        if (strcmp(server_pipe->pipe.name, name) == 0) {
            /* found a server pipe with the same name */
            spinlock_unlock(&g_connecting_pipes_lock);
            free(pipe);
            return -PAL_ERROR_STREAMEXIST;
        }
    }
    LISTP_ADD(pipe, &g_server_pipes_list, list);

    spinlock_unlock(&g_connecting_pipes_lock);

    *handle = pipe;
    return 0;
}

static int pipe_connect(struct pal_handle** handle, const char* name,
                        pal_stream_options_t options) {
    struct pal_handle* pipe = calloc(1, sizeof(*pipe));
    if (!pipe)
        return -PAL_ERROR_NOMEM;

    pipe->hdr.type = PAL_TYPE_PIPE;
    pipe->flags = PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;

    pipe->pipe.peer = NULL; /* the other pipe end ("pipecli") will update this field */
    pipe->pipe.buf  = NULL; /* this "connecting" pipe end will use buf of "pipecli" */

    pipe->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    spinlock_init(&pipe->pipe.lock);

    memcpy(&pipe->pipe.name, name, strlen(name) + 1);

    spinlock_lock(&g_connecting_pipes_lock);

    struct pal_handle* server = NULL;
    struct pal_handle* server_pipe;
    LISTP_FOR_EACH_ENTRY(server_pipe, &g_server_pipes_list, list) {
        if (strcmp(server_pipe->pipe.name, name) == 0) {
            server = server_pipe;
            break;
        }
    }

    if (!server) {
        spinlock_unlock(&g_connecting_pipes_lock);
        free(pipe);
        return -PAL_ERROR_DENIED; /* will be translated to -ECONNREFUSED in LibOS */
    }

    /* Found server pipe, notify the other end's waitforclient() (if it is waiting) and any other
     * waiting events (select/poll) */
    LISTP_ADD(pipe, &g_connecting_pipes_list, list);
    if (server->pipe.waitedfor)
        sched_thread_wakeup(&g_streams_waiting_events_futex);
    sched_thread_wakeup(&server->pipe.connect_futex);

    spinlock_unlock(&g_connecting_pipes_lock);

    *handle = pipe;
    return 0;
}

int pal_common_pipe_open(struct pal_handle** handle, const char* type, const char* uri,
                         enum pal_access access, pal_share_flags_t share,
                         enum pal_create_mode create, pal_stream_options_t options) {
    __UNUSED(access);
    __UNUSED(create);
    assert(create == PAL_CREATE_IGNORED);

    if (!WITHIN_MASK(share, PAL_SHARE_MASK) || !WITHIN_MASK(options, PAL_OPTION_MASK))
        return -PAL_ERROR_INVAL;

    if (!strcmp(type, URI_TYPE_PIPE_SRV))
        return pipe_listen(handle, uri, options);

    if (!strcmp(type, URI_TYPE_PIPE))
        return pipe_connect(handle, uri, options);

    return -PAL_ERROR_INVAL;
}

int pal_common_pipe_waitforclient(struct pal_handle* server, struct pal_handle** client,
                                  pal_stream_options_t options) {
    if (server->hdr.type != PAL_TYPE_PIPESRV)
        return -PAL_ERROR_NOTSERVER;

    struct pal_handle* pipe = calloc(1, sizeof(*pipe) + PIPE_BUF_SIZE);
    if (!pipe)
        return -PAL_ERROR_NOMEM;

    pipe->hdr.type = PAL_TYPE_PIPECLI;
    pipe->flags = PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;

    pipe->pipe.buf         = (char*)pipe + PIPE_BUF_SIZE;
    pipe->pipe.write_pos   = 0;
    pipe->pipe.read_pos    = 0;
    pipe->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    spinlock_init(&pipe->pipe.lock);

    memcpy(&pipe->pipe.name, &server->pipe.name, sizeof(pipe->pipe.name));

    /* emulate accept(): wait for the first pipe connecting on server's name */
    spinlock_lock(&g_connecting_pipes_lock);

    struct pal_handle* peer_pipe = NULL;

    while (!peer_pipe) {
        struct pal_handle* connecting_pipe = NULL;
        LISTP_FOR_EACH_ENTRY(connecting_pipe, &g_connecting_pipes_list, list) {
            if (strcmp(connecting_pipe->pipe.name, server->pipe.name) == 0) {
                /* found a connecting pipe with the same name */
                peer_pipe = connecting_pipe;
                break;
            }
        }

        if (!peer_pipe) {
            if (server->pipe.nonblocking) {
                spinlock_unlock(&g_connecting_pipes_lock);
                free(pipe);
                return -PAL_ERROR_TRYAGAIN;
            }
            sched_thread_wait(&server->pipe.connect_futex, &g_connecting_pipes_lock);
        }
    }
    assert(peer_pipe);

    LISTP_DEL(peer_pipe, &g_connecting_pipes_list, list);

    peer_pipe->pipe.peer = pipe;
    pipe->pipe.peer = peer_pipe;

    sched_thread_wakeup(&peer_pipe->pipe.connect_futex);
    spinlock_unlock(&g_connecting_pipes_lock);

    *client = pipe;
    return 0;
}

int64_t pal_common_pipe_read(struct pal_handle* handle, uint64_t offset, uint64_t len,
                             void* buffer) {
    ssize_t bytes;
    char* buf = buffer;

    if (offset)
        return -PAL_ERROR_INVAL;

    if (handle->hdr.type != PAL_TYPE_PIPECLI && handle->hdr.type != PAL_TYPE_PIPE)
        return -PAL_ERROR_NOTCONNECTION;

    if (!(handle->flags & PAL_HANDLE_FD_READABLE))
        return -PAL_ERROR_INVAL;

    struct pal_handle* real_handle = handle;
    if (!handle->pipe.buf) {
        assert(handle->hdr.type == PAL_TYPE_PIPE);
        assert(handle->pipe.peer);
        real_handle = handle->pipe.peer;
    }

    spinlock_lock(&real_handle->pipe.lock);

    while (real_handle->pipe.read_pos == real_handle->pipe.write_pos) {
        if (!(real_handle->flags & PAL_HANDLE_FD_WRITABLE)) {
            /* pipe was closed for write, no sense in waiting -- always return 0 */
            bytes = 0;
            goto out;
        }

        if (real_handle->pipe.nonblocking) {
            bytes = -PAL_ERROR_TRYAGAIN;
            goto out;
        }

        sched_thread_wait(&real_handle->pipe.reader_futex, &real_handle->pipe.lock);
    }

    /* to correctly handle int overflows, use a loop instead of copying `write_pos - read_pos` */
    assert(real_handle->pipe.read_pos != real_handle->pipe.write_pos);

    for (bytes = 0; bytes < (ssize_t)len; bytes++) {
        if (real_handle->pipe.read_pos == real_handle->pipe.write_pos)
            break;

        buf[bytes] = real_handle->pipe.buf[real_handle->pipe.read_pos % PIPE_BUF_SIZE];
        real_handle->pipe.read_pos++;
    }

out:
    if (real_handle->pipe.waitedfor)
        sched_thread_wakeup(&g_streams_waiting_events_futex);
    sched_thread_wakeup(&real_handle->pipe.writer_futex);
    spinlock_unlock(&real_handle->pipe.lock);
    return bytes;
}

int64_t pal_common_pipe_write(struct pal_handle* handle, uint64_t offset, uint64_t len,
                              const void* buffer) {
    ssize_t bytes;
    const char* buf = buffer;

    if (offset)
        return -PAL_ERROR_INVAL;

    if (handle->hdr.type != PAL_TYPE_PIPECLI && handle->hdr.type != PAL_TYPE_PIPE)
        return -PAL_ERROR_NOTCONNECTION;

    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE))
        return -PAL_ERROR_INVAL;

    struct pal_handle* real_handle = handle;
    if (!handle->pipe.buf) {
        assert(handle->hdr.type == PAL_TYPE_PIPE);
        assert(handle->pipe.peer);
        real_handle = handle->pipe.peer;
    }

    spinlock_lock(&real_handle->pipe.lock);

    /* must guarantee that PIPE_BUF_SIZE bytes are written atomically (for a blocking pipe) */
    for (bytes = 0; bytes < (ssize_t)len; bytes++) {
        while (real_handle->pipe.write_pos - real_handle->pipe.read_pos == PIPE_BUF_SIZE) {
            if (!(real_handle->flags & PAL_HANDLE_FD_READABLE)) {
                /* pipe was closed for read, this write must fail */
                bytes = -PAL_ERROR_CONNFAILED_PIPE;
                goto out;
            }

            if (real_handle->pipe.nonblocking) {
                if (!bytes)
                    bytes = -PAL_ERROR_TRYAGAIN;
                goto out;
            }

            if (real_handle->pipe.waitedfor)
                sched_thread_wakeup(&g_streams_waiting_events_futex);
            sched_thread_wakeup(&real_handle->pipe.reader_futex);
            sched_thread_wait(&real_handle->pipe.writer_futex, &real_handle->pipe.lock);
        }

        real_handle->pipe.buf[real_handle->pipe.write_pos % PIPE_BUF_SIZE] = buf[bytes];
        real_handle->pipe.write_pos++;
    }

out:
    if (real_handle->pipe.waitedfor)
        sched_thread_wakeup(&g_streams_waiting_events_futex);
    sched_thread_wakeup(&real_handle->pipe.reader_futex);
    spinlock_unlock(&real_handle->pipe.lock);
    return bytes;
}

void pal_common_pipe_destroy(struct pal_handle* handle) {
    assert(handle->hdr.type == PAL_TYPE_PIPESRV || handle->hdr.type == PAL_TYPE_PIPECLI
            || handle->hdr.type == PAL_TYPE_PIPE);

    if (handle->hdr.type == PAL_TYPE_PIPESRV) {
        spinlock_lock(&g_connecting_pipes_lock);
        LISTP_DEL(handle, &g_server_pipes_list, list);
        spinlock_unlock(&g_connecting_pipes_lock);
    }

    if (handle->hdr.type == PAL_TYPE_PIPE || handle->hdr.type == PAL_TYPE_PIPECLI) {
        /* must inform the other pipe end that this pipe end is closing */
        struct pal_handle* peer_pipe = handle->pipe.peer;
        spinlock_lock(&peer_pipe->pipe.lock);
        peer_pipe->pipe.peer = NULL;
        sched_thread_wakeup(&peer_pipe->pipe.reader_futex);
        sched_thread_wakeup(&peer_pipe->pipe.writer_futex);
        spinlock_unlock(&peer_pipe->pipe.lock);
    }

    /* emulate closing both ends of the pipe */
    if (handle->pipe.waitedfor) {
        /* FIXME: this should be impossible: some poll/select waits on the pipe that is freed?! */
        sched_thread_wakeup(&g_streams_waiting_events_futex);
    }
    sched_thread_wakeup(&handle->pipe.reader_futex);
    sched_thread_wakeup(&handle->pipe.writer_futex);

    free(handle);
}

int pal_common_pipe_delete(struct pal_handle* handle, enum pal_delete_mode delete_mode) {
    /* emulate closing specified end of the pipe */
    switch (delete_mode) {
        case PAL_DELETE_ALL:
            handle->flags = 0;
            break;
        case PAL_DELETE_READ:
            handle->flags &= ~PAL_HANDLE_FD_READABLE;
            break;
        case PAL_DELETE_WRITE:
            handle->flags &= ~PAL_HANDLE_FD_WRITABLE;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    if (handle->pipe.waitedfor)
        sched_thread_wakeup(&g_streams_waiting_events_futex);

    return 0;
}

int pal_common_pipe_attrquerybyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr) {
    attr->handle_type  = handle->hdr.type;
    attr->nonblocking  = handle->pipe.nonblocking;

    struct pal_handle* real_handle = handle;
    if (!handle->pipe.buf) {
        assert(handle->hdr.type == PAL_TYPE_PIPE);
        assert(handle->pipe.peer);
        real_handle = handle->pipe.peer;
    }

    attr->pending_size = 0;
    if (handle->hdr.type != PAL_TYPE_PIPESRV) {
        /* number of bytes available for reading (doesn't make sense for "listening" pipes) */
        attr->pending_size = real_handle->pipe.write_pos - real_handle->pipe.read_pos;
    }

    return 0;
}

int pal_common_pipe_attrsetbyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr) {
    handle->pipe.nonblocking = attr->nonblocking;
    return 0;
}
