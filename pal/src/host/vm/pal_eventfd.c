/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains operations to handle streams with URIs that have "eventfd:".
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

static int eventfd_pal_open(PAL_HANDLE* handle, const char* type, const char* uri,
                            enum pal_access access, pal_share_flags_t share,
                            enum pal_create_mode create, pal_stream_options_t options) {
    __UNUSED(handle);
    __UNUSED(type);
    __UNUSED(uri);
    __UNUSED(access);
    __UNUSED(share);
    __UNUSED(create);
    __UNUSED(options);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t eventfd_pal_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    __UNUSED(handle);
    __UNUSED(offset);
    __UNUSED(len);
    __UNUSED(buffer);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t eventfd_pal_write(PAL_HANDLE handle, uint64_t offset, uint64_t len,
                                 const void* buffer) {
    __UNUSED(handle);
    __UNUSED(offset);
    __UNUSED(len);
    __UNUSED(buffer);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int eventfd_pal_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    __UNUSED(handle);
    __UNUSED(attr);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static void eventfd_pal_destroy(PAL_HANDLE handle) {
    __UNUSED(handle);
}

struct handle_ops g_eventfd_ops = {
    .open           = &eventfd_pal_open,
    .read           = &eventfd_pal_read,
    .write          = &eventfd_pal_write,
    .destroy        = &eventfd_pal_destroy,
    .attrquerybyhdl = &eventfd_pal_attrquerybyhdl,
};
