/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Declarations for common operations on files. */

#pragma once

#include <stdint.h>

/* underlying virtio-fs driver operates only on limited amount of data (VIRTIO_FS_SHARED_BUF_SIZE),
 * so file-related functions must not exceed this limit when calling into the driver */
#define FILE_CHUNK_SIZE (16 * 1024UL)

#define PATH_MAX      512
#define MAX_READLINKS 32

int read_text_file_to_cstr(const char* path, char** out_buf, uint64_t* out_size);
int emulate_file_map_via_read(uint64_t nodeid, uint64_t fh, void* addr, uint64_t offset,
                              uint64_t size);
int realpath(const char* path, char* got_path, char** out_got_path);
