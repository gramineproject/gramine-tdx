/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include "pal_error.h"
#include "pal_rtld.h"

void _PalDebugMapAdd(const char* name, void* addr) {
    __UNUSED(name);
    __UNUSED(addr);
}

void _PalDebugMapRemove(void* addr) {
    __UNUSED(addr);
}

int _PalDebugDescribeLocation(uintptr_t addr, char* buf, size_t buf_size) {
    __UNUSED(addr);
    __UNUSED(buf);
    __UNUSED(buf_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}
