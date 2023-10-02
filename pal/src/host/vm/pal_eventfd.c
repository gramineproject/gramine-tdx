/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include "pal.h"
#include "pal_common.h"
#include "pal_internal.h"

struct handle_ops g_eventfd_ops = {
    .open           = &pal_common_eventfd_open,
    .read           = &pal_common_eventfd_read,
    .write          = &pal_common_eventfd_write,
    .destroy        = &pal_common_eventfd_destroy,
    .attrquerybyhdl = &pal_common_eventfd_attrquerybyhdl,
};
