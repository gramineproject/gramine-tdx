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

struct pal_handle_inner_pipe {
    spinlock_t lock;
    int        connect_futex;
    int        writer_futex;
    int        reader_futex;
    bool       waitedfor;    /* whether any PalStreamsWaitEvents() waits on this pipe */
    char*      buf;          /* ring buffer of size PIPE_BUF_SIZE */
    uint64_t   write_pos;    /* must be always used as buf[write_pos % PIPE_BUF_SIZE] */
    uint64_t   read_pos;     /* must be always used as buf[read_pos % PIPE_BUF_SIZE] */
    bool       nonblocking;
    char       name[PIPE_NAME_MAX]; /* for server pipe type */
    struct pal_handle* peer;        /* for UNIX domain socket-style pipes */
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
    void*    stack;  /* points to the base of stack, suitable for free(stack) */
    void*    fpregs; /* points to XSAVE memory region, suitable for free(fpregs) */
};

struct pal_handle_inner_event {
    spinlock_t lock;
    uint32_t waiters_cnt;
    uint32_t signaled;
    bool auto_clear;
};
