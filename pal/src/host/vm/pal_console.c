/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include "pal.h"
#include "pal_common.h"
#include "pal_internal.h"

struct handle_ops g_console_ops = {
    .open           = &pal_common_console_open,
    .read           = &pal_common_console_read,
    .write          = &pal_common_console_write,
    .destroy        = &pal_common_console_destroy,
    .flush          = &pal_common_console_flush,
};
