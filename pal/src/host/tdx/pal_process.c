/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * VM PALs are single-process currently, so creating processes is not supported.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

#include "kernel_interrupts.h"

noreturn void _PalProcessExit(int exitcode) {
    log_always("[ VM exited with code %d ]", exitcode);
    triple_fault();
}

int _PalProcessCreate(const char** args, uintptr_t (*reserved_mem_ranges)[2],
                      size_t reserved_mem_ranges_len, PAL_HANDLE* out_handle) {
    __UNUSED(args);
    __UNUSED(reserved_mem_ranges);
    __UNUSED(reserved_mem_ranges_len);
    __UNUSED(out_handle);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t proc_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    __UNUSED(handle);
    __UNUSED(offset);
    __UNUSED(count);
    __UNUSED(buffer);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t proc_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    __UNUSED(handle);
    __UNUSED(offset);
    __UNUSED(count);
    __UNUSED(buffer);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static void proc_destroy(PAL_HANDLE handle) {
    __UNUSED(handle);
}

static int proc_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    __UNUSED(handle);
    __UNUSED(delete_mode);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int proc_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    __UNUSED(handle);
    __UNUSED(attr);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int proc_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    __UNUSED(handle);
    __UNUSED(attr);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops g_proc_ops = {
    .read           = &proc_read,
    .write          = &proc_write,
    .destroy        = &proc_destroy,
    .delete         = &proc_delete,
    .attrquerybyhdl = &proc_attrquerybyhdl,
    .attrsetbyhdl   = &proc_attrsetbyhdl,
};
