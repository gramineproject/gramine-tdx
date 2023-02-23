/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Debug prints using VMM's serial port. */

#pragma once

#define SERIAL_IO_PORT 0x3F8

#include <stddef.h>
#include <stdint.h>

void log_write_char(char c);
void log_write(const char* str);
void int_to_str(uint64_t x, char* str, size_t str_size);

#define LOG_WRITE_INT(msg, var)                                                   \
    ({                                                                            \
        int_to_str((uint64_t)var, str, sizeof(str));                              \
        log_write(msg);                                                           \
        log_write(str);                                                           \
        log_write("\n");                                                          \
    })
