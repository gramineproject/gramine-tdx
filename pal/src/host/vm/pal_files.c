/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include "pal.h"
#include "pal_common.h"
#include "pal_internal.h"

struct handle_ops g_file_ops = {
    .open           = &pal_common_file_open,
    .read           = &pal_common_file_read,
    .write          = &pal_common_file_write,
    .destroy        = &pal_common_file_destroy,
    .delete         = &pal_common_file_delete,
    .map            = &pal_common_file_map,
    .setlength      = &pal_common_file_setlength,
    .flush          = &pal_common_file_flush,
    .attrquery      = &pal_common_file_attrquery,
    .attrquerybyhdl = &pal_common_file_attrquerybyhdl,
    .attrsetbyhdl   = &pal_common_file_attrsetbyhdl,
    .rename         = &pal_common_file_rename,
};

struct handle_ops g_dir_ops = {
    .open           = &pal_common_dir_open,
    .read           = &pal_common_dir_read,
    .destroy        = &pal_common_dir_destroy,
    .delete         = &pal_common_dir_delete,
    .attrquery      = &pal_common_file_attrquery,
    .attrquerybyhdl = &pal_common_file_attrquerybyhdl,
    .attrsetbyhdl   = &pal_common_file_attrsetbyhdl,
    .rename         = &pal_common_dir_rename,
};
