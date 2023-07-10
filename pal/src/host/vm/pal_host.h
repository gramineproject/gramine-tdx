/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#pragma once

#ifndef IN_PAL
#error "cannot be included outside PAL"
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pal_common_structs.h"

DEFINE_LIST(pal_handle);
typedef struct pal_handle {
    PAL_HDR hdr;
    /* Bitmask of `PAL_HANDLE_FD_*` flags. */
    uint32_t flags;
    LIST_TYPE(pal_handle) list;

    union {
        /* Common field for accessing underlying host fd. See also `PAL_HANDLE_FD_READABLE`. */
        struct {
            PAL_IDX fd;
        } generic;

        struct pal_handle_inner_console console;
        struct pal_handle_inner_device  dev;
        struct pal_handle_inner_file    file;
        struct pal_handle_inner_dir     dir;
        struct pal_handle_inner_pipe    pipe;
        struct pal_handle_inner_sock    sock;
        struct pal_handle_inner_thread  thread;
        struct pal_handle_inner_event   event;

        struct {
            PAL_IDX unused;
        } eventfd;

        struct {
            PAL_IDX unused;
        } process;
    };
}* PAL_HANDLE;
DEFINE_LISTP(pal_handle);

/* These two flags indicate whether the underlying host fd of `PAL_HANDLE` is readable and/or
 * writable respectively. If none of these is set, then the handle has no host-level fd. */
#define PAL_HANDLE_FD_READABLE  1
#define PAL_HANDLE_FD_WRITABLE  2
/* Set if an error was seen on this handle. Currently only set by `_PalStreamsWaitEvents`. */
#define PAL_HANDLE_FD_ERROR     4

noreturn void pal_start_c(void);
