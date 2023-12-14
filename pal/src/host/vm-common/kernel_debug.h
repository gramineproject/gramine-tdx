/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Debug prints using VMM's serial port. */

#pragma once

#define SERIAL_IO_PORT 0x3F8

#include <stdint.h>

void debug_serial_io_write_char(char c);
void debug_serial_io_write(const char* str);
void debug_serial_io_write_int(const char* str, uint64_t x);
