/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to open, read, write and get attributes of streams.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

#include "kernel_virtio.h"

int _PalSendHandle(struct pal_handle* target_process, struct pal_handle* cargo) {
    __UNUSED(target_process);
    __UNUSED(cargo);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalReceiveHandle(struct pal_handle* source_process, struct pal_handle** out_cargo) {
    __UNUSED(source_process);
    __UNUSED(out_cargo);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalInitDebugStream(const char* path) {
    __UNUSED(path); /* we print debug info to virtio-console currently, no files */
    return 0;
}

int _PalDebugLog(const void* buf, size_t size) {
    return virtio_console_nprint(buf, size);
}
