/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Debug prints using VMM's serial port.
 *
 * Notes on multi-core synchronization:
 *   - `debug_serial_io_write_char()` is an atomic operation, no need for locking.
 *   - `debug_serial_io_write()` and `debug_serial_io_write_int()` are protected by a global lock,
 *      so messages are printed atomically.
 *
 * Note that these functions may be used in very early boot stages when Address Sanitizer is not yet
 * initialized, and thus all functions must be marked with `__attribute_no_sanitize_address`.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "kernel_debug.h"
#include "vm_callbacks.h"

/* "unused" attribute is to silence GCC's "variable defined but not used" on ASan builds */
__attribute__((unused)) static spinlock_t g_debug_serial_io_write_lock = INIT_SPINLOCK_UNLOCKED;

__attribute_no_sanitize_address
static void int_to_str(uint64_t x, char* str, size_t str_size) {
    _real_memset(str, ' ', str_size - 1);

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

__attribute_no_sanitize_address
void debug_serial_io_write_char(char c) {
    vm_portio_writeb(SERIAL_IO_PORT, (uint8_t)c);
}

__attribute_no_sanitize_address
void debug_serial_io_write(const char* str) {
#ifndef ASAN /* this func may be called before ASan is set up, and spinlock funcs would break */
    spinlock_lock(&g_debug_serial_io_write_lock);
#endif
    for (size_t i = 0; str[i] != '\0'; i++)
        debug_serial_io_write_char(str[i]);
    debug_serial_io_write_char('\n');
#ifndef ASAN
    spinlock_unlock(&g_debug_serial_io_write_lock);
#endif
}

__attribute_no_sanitize_address
void debug_serial_io_write_int(const char* str, uint64_t x) {
    char x_str[32] = {0};
    int_to_str(x, x_str, sizeof(x_str));

#ifndef ASAN /* this func may be called before ASan is set up, and spinlock funcs would break */
    spinlock_lock(&g_debug_serial_io_write_lock);
#endif
    for (size_t i = 0; str[i] != '\0'; i++)
        debug_serial_io_write_char(str[i]);
    for (size_t i = 0; x_str[i] != '\0'; i++)
        debug_serial_io_write_char(x_str[i]);
    debug_serial_io_write_char('\n');
#ifndef ASAN
    spinlock_unlock(&g_debug_serial_io_write_lock);
#endif
}
