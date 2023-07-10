/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Debug prints using VMM's serial port.
 *
 * Notes on multi-core synchronization:
 *   - `log_write()` is protected by a global lock, so strings are printed atomically
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "kernel_debug.h"
#include "vm_callbacks.h"

static spinlock_t g_log_write_lock = INIT_SPINLOCK_UNLOCKED;

void log_write_char(char c) {
    vm_portio_writeb(SERIAL_IO_PORT, (uint8_t)c);
}

void log_write(const char* str) {
    spinlock_lock(&g_log_write_lock);
    for (size_t i = 0; str[i] != '\0'; i++)
        log_write_char(str[i]);
    spinlock_unlock(&g_log_write_lock);
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
