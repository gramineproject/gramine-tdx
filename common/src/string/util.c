/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2016 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 * Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include "api.h"

char* strdup(const char* str) {
    return alloc_concat3(str, -1, NULL, 0, NULL, 0);
}

char* alloc_substr(const char* start, size_t len) {
    return alloc_concat3(start, len, NULL, 0, NULL, 0);
}

char* alloc_concat(const char* a, size_t a_len, const char* b, size_t b_len) {
    return alloc_concat3(a, a_len, b, b_len, NULL, 0);
}

char* alloc_concat3(const char* a, size_t a_len, const char* b, size_t b_len,
                    const char* c, size_t c_len) {
    a_len = (a_len != (size_t)-1) ? a_len : (a ? strlen(a) : 0);
    b_len = (b_len != (size_t)-1) ? b_len : (b ? strlen(b) : 0);
    c_len = (c_len != (size_t)-1) ? c_len : (c ? strlen(c) : 0);

    char* buf = malloc(a_len + b_len + c_len + 1);
    if (!buf)
        return NULL;

    if (a_len)
        memcpy(buf, a, a_len);
    if (b_len)
        memcpy(buf + a_len, b, b_len);
    if (c_len)
        memcpy(buf + a_len + b_len, c, c_len);

    buf[a_len + b_len + c_len] = '\0';
    return buf;
}

void* alloc_and_copy(const void* src, size_t size) {
    void* dst = malloc(size);
    if (!dst)
        return NULL;
    memcpy(dst, src, size);
    return dst;
}
