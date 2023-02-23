/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include "pal.h"
#include "pal_common.h"
#include "pal_internal.h"

struct handle_ops g_pipe_ops = {
    .open           = &pal_common_pipe_open,
    .waitforclient  = &pal_common_pipe_waitforclient,
    .read           = &pal_common_pipe_read,
    .write          = &pal_common_pipe_write,
    .destroy        = &pal_common_pipe_destroy,
    .delete         = &pal_common_pipe_delete,
    .attrquerybyhdl = &pal_common_pipe_attrquerybyhdl,
    .attrsetbyhdl   = &pal_common_pipe_attrsetbyhdl,
};
