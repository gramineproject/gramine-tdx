/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include "pal.h"
#include "pal_common.h"
#include "pal_internal.h"

int _PalEventCreate(struct pal_handle** handle_ptr, bool init_signaled, bool auto_clear) {
    return pal_common_event_create(handle_ptr, init_signaled, auto_clear);
}

void _PalEventSet(struct pal_handle* handle) {
    pal_common_event_set(handle);
}

void _PalEventClear(struct pal_handle* handle) {
    pal_common_event_clear(handle);
}

int _PalEventWait(struct pal_handle* handle, uint64_t* timeout_us) {
    return pal_common_event_wait(handle, timeout_us);
}

struct handle_ops g_event_ops = {};
