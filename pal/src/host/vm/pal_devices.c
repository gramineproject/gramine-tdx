/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Operations to handle devices. Currently VM PAL doesn't support any devices.
 */

#include "pal.h"
#include "pal_internal.h"

static int dev_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                    pal_share_flags_t share, enum pal_create_mode create,
                    pal_stream_options_t options) {
    __UNUSED(handle);
    __UNUSED(type);
    __UNUSED(uri);
    __UNUSED(access);
    __UNUSED(share);
    __UNUSED(create);
    __UNUSED(options);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t dev_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    __UNUSED(handle);
    __UNUSED(offset);
    __UNUSED(size);
    __UNUSED(buffer);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t dev_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    __UNUSED(handle);
    __UNUSED(offset);
    __UNUSED(size);
    __UNUSED(buffer);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static void dev_destroy(PAL_HANDLE handle) {
    __UNUSED(handle);
    /* noop */
}

static int dev_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    __UNUSED(handle);
    __UNUSED(delete_mode);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int dev_setlength(PAL_HANDLE handle, uint64_t length) {
    __UNUSED(handle);
    __UNUSED(length);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int dev_flush(PAL_HANDLE handle) {
    __UNUSED(handle);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int dev_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    __UNUSED(type);
    __UNUSED(uri);
    __UNUSED(attr);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int dev_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    __UNUSED(handle);
    __UNUSED(attr);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int dev_map(PAL_HANDLE handle, void* addr, pal_prot_flags_t prot, uint64_t offset,
                   uint64_t size) {
    __UNUSED(handle);
    __UNUSED(addr);
    __UNUSED(prot);
    __UNUSED(offset);
    __UNUSED(size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops g_dev_ops = {
    .open           = &dev_open,
    .read           = &dev_read,
    .write          = &dev_write,
    .destroy        = &dev_destroy,
    .delete         = &dev_delete,
    .map            = &dev_map,
    .setlength      = &dev_setlength,
    .flush          = &dev_flush,
    .attrquery      = &dev_attrquery,
    .attrquerybyhdl = &dev_attrquerybyhdl,
};

int _PalDeviceIoControl(PAL_HANDLE handle, uint32_t cmd, unsigned long arg, int* out_ret) {
    __UNUSED(handle);
    __UNUSED(cmd);
    __UNUSED(arg);
    __UNUSED(out_ret);
    return -PAL_ERROR_NOTIMPLEMENTED;
}
