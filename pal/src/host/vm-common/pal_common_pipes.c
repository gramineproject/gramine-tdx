/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains APIs to handle pipes.
 *
 * Two pipes (two ends of the same pipe) share a single buffer object. This buffer object is created
 * when two pipes establish a connection, and it is destroyed when the last of two pipes is closed.
 */

#include "api.h"
#include "list.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "spinlock.h"

#include "kernel_sched.h"

/* Global lock for all connecting operations: waiting for clients, connecting to server, etc.
 * This lock also protects `pal_handle::pipe.pipe_buf` reference. */
spinlock_t g_connecting_pipes_lock = INIT_SPINLOCK_UNLOCKED;

/* List of "pipesrv" named pipes; this list is used to find corresponding "pipesrv" pipe for each
 * connecting pipe during pipe_connect() */
LISTP_TYPE(pal_handle) g_server_pipes_list = LISTP_INIT;

/* List of "pipe" connecting pipes; this list is used to find corresponding "connecting" pipe for
 * each accepting pipe during pipe_waitforclient() */
LISTP_TYPE(pal_handle) g_connecting_pipes_list = LISTP_INIT;

static int pipe_listen(struct pal_handle** handle, const char* name, pal_stream_options_t options) {
    int ret;

    struct pal_handle* pipe = calloc(1, sizeof(*pipe));
    if (!pipe)
        return -PAL_ERROR_NOMEM;

    pipe->hdr.type = PAL_TYPE_PIPESRV;
    pipe->flags = 0; /* cannot read or write on the server pipe */
    pipe->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    memcpy(&pipe->pipe.name, name, strlen(name) + 1);

    spinlock_lock(&g_connecting_pipes_lock);

    struct pal_handle* server_pipe;
    LISTP_FOR_EACH_ENTRY(server_pipe, &g_server_pipes_list, list) {
        if (strcmp(server_pipe->pipe.name, name) == 0) {
            ret = -PAL_ERROR_STREAMEXIST;
            goto out;
        }
    }
    LISTP_ADD(pipe, &g_server_pipes_list, list);

    *handle = pipe;
    ret = 0;
out:
    spinlock_unlock(&g_connecting_pipes_lock);
    if (ret < 0)
        free(pipe);
    return ret;
}

static int pipe_connect(struct pal_handle** handle, const char* name,
                        pal_stream_options_t options) {
    int ret;

    struct pal_handle* pipe = calloc(1, sizeof(*pipe));
    if (!pipe)
        return -PAL_ERROR_NOMEM;

    pipe->hdr.type = PAL_TYPE_PIPE;
    pipe->flags = PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    pipe->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    memcpy(&pipe->pipe.name, name, strlen(name) + 1);

    /* the other pipe end (pipecli) will allocate & set up the pipe_buf object */
    pipe->pipe.pipe_buf = NULL;

    spinlock_lock(&g_connecting_pipes_lock);

    struct pal_handle* found_server_pipe = NULL;
    struct pal_handle* server_pipe;
    LISTP_FOR_EACH_ENTRY(server_pipe, &g_server_pipes_list, list) {
        if (strcmp(server_pipe->pipe.name, name) == 0) {
            found_server_pipe = server_pipe;
            break;
        }
    }

    if (!found_server_pipe) {
        ret = -PAL_ERROR_CONNFAILED;
        goto out;
    }

    /* notify the other end's waitforclient() and any other waiting events (select/poll) */
    LISTP_ADD(pipe, &g_connecting_pipes_list, list);
    if (found_server_pipe->pipe.connect_poll_waiting)
        sched_thread_wakeup(&g_streams_waiting_events_futex);
    sched_thread_wakeup(&found_server_pipe->pipe.connect_futex);

    *handle = pipe;
    ret = 0;
out:
    spinlock_unlock(&g_connecting_pipes_lock);
    if (ret < 0)
        free(pipe);
    return ret;
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
    int ret;

    if (server->hdr.type != PAL_TYPE_PIPESRV)
        return -PAL_ERROR_NOTSERVER;

    struct pal_handle_inner_pipe_buf* pipe_buf = calloc(1, sizeof(*pipe_buf) + PIPE_BUF_SIZE);
    if (!pipe_buf)
        return -PAL_ERROR_NOMEM;

    struct pal_handle* pipe = calloc(1, sizeof(*pipe));
    if (!pipe) {
        free(pipe_buf);
        return -PAL_ERROR_NOMEM;
    }

    pipe->hdr.type = PAL_TYPE_PIPECLI;
    pipe->flags = PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    pipe->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    memcpy(&pipe->pipe.name, &server->pipe.name, sizeof(pipe->pipe.name));

    pipe_buf->writable = pipe_buf->readable = true;
    pipe_buf->write_pos = pipe_buf->read_pos = 0;
    spinlock_init(&pipe_buf->lock);

    /* emulate accept(): wait for the first pipe connecting on server's name */
    spinlock_lock(&g_connecting_pipes_lock);

    struct pal_handle* found_connecting_pipe = NULL;

    while (!found_connecting_pipe) {
        struct pal_handle* connecting_pipe = NULL;
        LISTP_FOR_EACH_ENTRY(connecting_pipe, &g_connecting_pipes_list, list) {
            if (strcmp(connecting_pipe->pipe.name, server->pipe.name) == 0) {
                found_connecting_pipe = connecting_pipe;
                break;
            }
        }

        if (!found_connecting_pipe) {
            if (server->pipe.nonblocking) {
                ret = -PAL_ERROR_TRYAGAIN;
                goto out;
            }
            sched_thread_wait(&server->pipe.connect_futex, &g_connecting_pipes_lock);
        }
    }
    assert(found_connecting_pipe);

    LISTP_DEL(found_connecting_pipe, &g_connecting_pipes_list, list);

    pipe->pipe.pipe_buf = pipe_buf;
    found_connecting_pipe->pipe.pipe_buf = pipe_buf;
    pipe_buf->refcount = 2;

    *client = pipe;
    ret = 0;
out:
    spinlock_unlock(&g_connecting_pipes_lock);
    if (ret < 0) {
        free(pipe_buf);
        free(pipe);
    }
    return ret;
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

    spinlock_lock(&g_connecting_pipes_lock);
    struct pal_handle_inner_pipe_buf* pipe_buf = handle->pipe.pipe_buf;
    spinlock_unlock(&g_connecting_pipes_lock);

    if (!pipe_buf)
        return -PAL_ERROR_NOTCONNECTION;

    spinlock_lock(&pipe_buf->lock);

    while (pipe_buf->read_pos == pipe_buf->write_pos) {
        if (!pipe_buf->writable) {
            /* pipe was closed for write, no sense in waiting -- always return 0 */
            bytes = 0;
            goto out;
        }

        if (handle->pipe.nonblocking) {
            bytes = -PAL_ERROR_TRYAGAIN;
            goto out;
        }

        sched_thread_wait(&pipe_buf->reader_futex, &pipe_buf->lock);
    }

    assert(pipe_buf->read_pos != pipe_buf->write_pos);
    assert(pipe_buf->write_pos - pipe_buf->read_pos <= PIPE_BUF_SIZE);

    bytes = 0;
    while (bytes < (ssize_t)len && pipe_buf->read_pos != pipe_buf->write_pos) {
        /* limited by three factors: how much is requested by caller, how much is available in the
         * pipe buf, and how much left until wrap around in the pipe buf */
        size_t x = MIN(MIN(len - bytes, pipe_buf->write_pos - pipe_buf->read_pos),
                       ALIGN_UP(pipe_buf->read_pos + 1, PIPE_BUF_SIZE) - pipe_buf->read_pos);

        memcpy(&buf[bytes], &pipe_buf->buf[pipe_buf->read_pos % PIPE_BUF_SIZE], x);

        pipe_buf->read_pos += x;
        bytes += x;
    }

out:
    if (pipe_buf->poll_waiting)
        sched_thread_wakeup(&g_streams_waiting_events_futex);
    sched_thread_wakeup(&pipe_buf->writer_futex);
    spinlock_unlock(&pipe_buf->lock);
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

    spinlock_lock(&g_connecting_pipes_lock);
    struct pal_handle_inner_pipe_buf* pipe_buf = handle->pipe.pipe_buf;
    spinlock_unlock(&g_connecting_pipes_lock);

    if (!pipe_buf)
        return -PAL_ERROR_NOTCONNECTION;

    spinlock_lock(&pipe_buf->lock);

    /* must guarantee that PIPE_BUF_SIZE bytes are written atomically (for a blocking pipe) */
    bytes = 0;
    while (bytes < (ssize_t)len) {
        while (pipe_buf->write_pos - pipe_buf->read_pos == PIPE_BUF_SIZE) {
            if (!pipe_buf->readable) {
                /* pipe was closed for read, this write must fail */
                bytes = -PAL_ERROR_CONNFAILED_PIPE;
                goto out;
            }

            if (handle->pipe.nonblocking) {
                if (!bytes)
                    bytes = -PAL_ERROR_TRYAGAIN;
                goto out;
            }

            if (pipe_buf->poll_waiting)
                sched_thread_wakeup(&g_streams_waiting_events_futex);
            sched_thread_wakeup(&pipe_buf->reader_futex);
            sched_thread_wait(&pipe_buf->writer_futex, &pipe_buf->lock);
        }

        /* limited by three factors: how much is requested by caller, how much left for writing in
         * the pipe buf, and how much left until wrap around in the pipe buf */
        size_t x = MIN(MIN(len - bytes, PIPE_BUF_SIZE - (pipe_buf->write_pos - pipe_buf->read_pos)),
                       ALIGN_UP(pipe_buf->write_pos + 1, PIPE_BUF_SIZE) - pipe_buf->write_pos);

        memcpy(&pipe_buf->buf[pipe_buf->write_pos % PIPE_BUF_SIZE], &buf[bytes], x);

        pipe_buf->write_pos += x;
        bytes += x;
    }

out:
    if (pipe_buf->poll_waiting)
        sched_thread_wakeup(&g_streams_waiting_events_futex);
    sched_thread_wakeup(&pipe_buf->reader_futex);
    spinlock_unlock(&pipe_buf->lock);
    return bytes;
}

void pal_common_pipe_destroy(struct pal_handle* handle) {
    assert(handle->hdr.type == PAL_TYPE_PIPESRV || handle->hdr.type == PAL_TYPE_PIPECLI
            || handle->hdr.type == PAL_TYPE_PIPE);

    bool found_server_pipe = false;
    bool found_connecting_pipe = false;
    struct pal_handle_inner_pipe_buf* pipe_buf = NULL;

    spinlock_lock(&g_connecting_pipes_lock);

    if (handle->hdr.type == PAL_TYPE_PIPESRV) {
        struct pal_handle* server_pipe;
        LISTP_FOR_EACH_ENTRY(server_pipe, &g_server_pipes_list, list) {
            if (server_pipe == handle) {
                found_server_pipe = true;
                break;
            }
        }
    }
    if (handle->hdr.type == PAL_TYPE_PIPE) {
        struct pal_handle* connecting_pipe;
        LISTP_FOR_EACH_ENTRY(connecting_pipe, &g_connecting_pipes_list, list) {
            if (connecting_pipe == handle) {
                found_connecting_pipe = true;
                break;
            }
        }
    }

    if (found_server_pipe)
        LISTP_DEL(handle, &g_server_pipes_list, list);
    if (found_connecting_pipe)
        LISTP_DEL(handle, &g_connecting_pipes_list, list);

    if (handle->hdr.type == PAL_TYPE_PIPE || handle->hdr.type == PAL_TYPE_PIPECLI) {
        pipe_buf = handle->pipe.pipe_buf;
    }
    spinlock_unlock(&g_connecting_pipes_lock);

    if (pipe_buf) {
        int new_count = __atomic_sub_fetch(&pipe_buf->refcount, 1, __ATOMIC_ACQ_REL);
        if (new_count < 0) {
            log_error("Reference count dropped below 0 at %s:%d", __FILE_NAME__, __LINE__);
            BUG();
        } else if (new_count > 0) {
            spinlock_lock(&pipe_buf->lock);
            pipe_buf->readable = pipe_buf->writable = false; /* close both pipe ends */
            sched_thread_wakeup(&pipe_buf->reader_futex);
            sched_thread_wakeup(&pipe_buf->writer_futex);
            if (pipe_buf->poll_waiting) {
                /* should be impossible: poll waits on a pipe that is freed?! just in case */
                sched_thread_wakeup(&g_streams_waiting_events_futex);
            }
            spinlock_unlock(&pipe_buf->lock);
        } else {
            assert(!new_count);
            free(pipe_buf);
        }
    }

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

    struct pal_handle_inner_pipe_buf* pipe_buf = NULL;

    spinlock_lock(&g_connecting_pipes_lock);
    if (handle->pipe.connect_poll_waiting)
        sched_thread_wakeup(&g_streams_waiting_events_futex);
    pipe_buf = handle->pipe.pipe_buf;
    spinlock_unlock(&g_connecting_pipes_lock);

    if (pipe_buf) {
        spinlock_lock(&pipe_buf->lock);
        if (delete_mode == PAL_DELETE_ALL || delete_mode == PAL_DELETE_READ)
            pipe_buf->readable = false;
        if (delete_mode == PAL_DELETE_ALL || delete_mode == PAL_DELETE_WRITE)
            pipe_buf->writable = false;
        if (pipe_buf->poll_waiting)
            sched_thread_wakeup(&g_streams_waiting_events_futex);
        spinlock_unlock(&pipe_buf->lock);
    }

    return 0;
}

int pal_common_pipe_attrquerybyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr) {
    attr->handle_type  = handle->hdr.type;
    attr->nonblocking  = handle->pipe.nonblocking;
    attr->pending_size = 0;

    struct pal_handle_inner_pipe_buf* pipe_buf = NULL;
    spinlock_lock(&g_connecting_pipes_lock);
    pipe_buf = handle->pipe.pipe_buf;
    spinlock_unlock(&g_connecting_pipes_lock);

    if (pipe_buf) {
        spinlock_lock(&pipe_buf->lock);
        attr->pending_size = pipe_buf->write_pos - pipe_buf->read_pos;
        assert(attr->pending_size <= PIPE_BUF_SIZE);
        spinlock_unlock(&pipe_buf->lock);
    }

    return 0;
}

int pal_common_pipe_attrsetbyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr) {
    handle->pipe.nonblocking = attr->nonblocking;
    return 0;
}
