/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Debug prints using VMM's serial port.
 *
 * Notes on multi-core synchronization:
 *   - `debug_serial_io_write_char()` is an atomic operation, no need for locking.
 *   - `debug_serial_io_write()` and `debug_serial_io_write_int()` are protected by a global lock,
 *      so messages are printed atomically.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "kernel_debug.h"
#include "vm_callbacks.h"

static spinlock_t g_debug_serial_io_write_lock = INIT_SPINLOCK_UNLOCKED;

static void int_to_str(uint64_t x, char* str, size_t str_size) {
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

void debug_serial_io_write_char(char c) {
    vm_portio_writeb(SERIAL_IO_PORT, (uint8_t)c);
}

void debug_serial_io_write(const char* str) {
    spinlock_lock(&g_debug_serial_io_write_lock);
    for (size_t i = 0; str[i] != '\0'; i++)
        debug_serial_io_write_char(str[i]);
    debug_serial_io_write_char('\n');
    spinlock_unlock(&g_debug_serial_io_write_lock);
}

void debug_serial_io_write_int(const char* str, uint64_t x) {
    char x_str[32] = {0};
    int_to_str(x, x_str, sizeof(x_str));

    spinlock_lock(&g_debug_serial_io_write_lock);
    for (size_t i = 0; str[i] != '\0'; i++)
        debug_serial_io_write_char(str[i]);
    for (size_t i = 0; x_str[i] != '\0'; i++)
        debug_serial_io_write_char(x_str[i]);
    debug_serial_io_write_char('\n');
    spinlock_unlock(&g_debug_serial_io_write_lock);
}
