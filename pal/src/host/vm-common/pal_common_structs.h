/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains inner structs that are embedded into `struct pal_handle`.
 * The file is included in `pal_host.h` in the corresponding PAL.
 */

#pragma once

#ifndef IN_PAL
#error "cannot be included outside PAL"
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cpu.h"
#include "list.h"
#include "spinlock.h"

#include "kernel_thread.h"

#define PIPE_NAME_MAX 96

struct pal_handle; /* forward declaration */

struct pal_handle_inner_console {
    PAL_IDX fd;
    spinlock_t lock;
};

struct pal_handle_inner_device { /* unused */
    PAL_IDX fd;
};

struct pal_handle_inner_file {
    uint64_t nodeid;
    uint64_t fh;
    char* realpath;

    /* below fields are used only for trusted files */
    size_t size;
    void*  chunk_hashes; /* array of hashes of file chunks (of type tdx_chunk_hash_t) */
};

struct pal_handle_inner_dir {
    uint64_t nodeid;
    uint64_t fh;
    char* realpath;
    void* buf;
    void* ptr;
    void* end;
    bool endofstream;
};

/* sub-object of pal_handle_inner_pipe: two pipe objects share one pipe_buf object */
struct pal_handle_inner_pipe_buf {
    spinlock_t lock;
    int        refcount;
    bool       writable;
    bool       readable;
    uint64_t   write_pos;    /* must be always used as buf[write_pos % PIPE_BUF_SIZE] */
    uint64_t   read_pos;     /* must be always used as buf[read_pos % PIPE_BUF_SIZE] */
    int        writer_futex;
    int        reader_futex;
    bool       poll_waiting; /* for PalStreamsWaitEvents; protected by lock */
    char       buf[];        /* ring buffer of size PIPE_BUF_SIZE */
};

struct pal_handle_inner_pipe {
    bool nonblocking;
    char name[PIPE_NAME_MAX];

    /* only for pipesrv type */
    int  connect_futex;
    bool connect_poll_waiting; /* for PalStreamsWaitEvents; protected by g_connecting_pipes_lock */

    /* only for pipe/pipecli types -- read/write ends of the pipe */
    struct pal_handle_inner_pipe_buf* pipe_buf; /* protected by g_connecting_pipes_lock */
};

struct pal_handle_inner_sock {
    PAL_IDX fd;
    spinlock_t lock;
    enum pal_socket_domain domain;
    enum pal_socket_type type;
    struct socket_ops* ops;
    uint64_t linger;
    size_t recv_buf_size;
    size_t send_buf_size;
    uint64_t recvtimeout_us;
    uint64_t sendtimeout_us;
    bool is_nonblocking;
    bool reuseaddr;
    bool reuseport;
    bool keepalive;
    bool broadcast;
    bool tcp_cork;
    uint32_t tcp_user_timeout;
    uint32_t tcp_keepidle;
    uint32_t tcp_keepintvl;
    uint8_t tcp_keepcnt;
    bool tcp_nodelay;
    bool ipv6_v6only;
};

struct pal_handle_inner_thread {
    uint32_t tid;
    void*    stack;  /* points to base of stack + fpregs mem region, suitable for free(stack) */
    struct thread* kernel_thread;
};

struct pal_handle_inner_event {
    spinlock_t lock;
    uint32_t waiters_cnt;
    int signaled;
    bool auto_clear;
};

struct pal_handle_inner_eventfd {
    bool nonblocking;
    bool semaphore;
    spinlock_t lock; /* protects below fields */
    uint64_t val;
    int  writer_futex;
    int  reader_futex;
    bool poll_waiting; /* for PalStreamsWaitEvents; protected by lock */
};
