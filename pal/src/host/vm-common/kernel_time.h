/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Declarations for time and timeouts. */

#pragma once

#include <stdint.h>

/* the max of Unix time in seconds is `UINT64_MAX`, which has 20 digits in decimal */
#define TIME_S_STR_MAX (20 + 1)

int get_time_in_us(uint64_t* out_us);
int register_timeout(uint64_t timeout_absolute_us, int* futex);
int notify_about_timeouts_uninterruptable(void);

int time_init(void);
