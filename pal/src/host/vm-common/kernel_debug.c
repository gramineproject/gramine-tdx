/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Debug prints using VMM's serial port. */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "kernel_debug.h"
#include "vm_callbacks.h"

void log_write_char(char c) {
    vm_portio_writeb(SERIAL_IO_PORT, (uint8_t)c);
}

void log_write(const char* str) {
    for (size_t i = 0; str[i] != '\0'; i++)
        log_write_char(str[i]);
}

void int_to_str(uint64_t x, char* str, size_t str_size) {
    memset(str, ' ', str_size - 1);

    if (x == 0) {
        str[0] = '0';
        str[1] = 0;
        return;
    }

    size_t i = str_size - 2;
    while (x != 0) {
        str[i--] = (x % 10) + '0';
        x /= 10;
    }
    str[str_size - 1] = 0;
}
