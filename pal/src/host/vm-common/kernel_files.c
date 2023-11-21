/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Glue code for common operations on files, using virtio-fs commands.
 *
 * Notes on multi-core synchronization:
 *   - All functions are thread-safe (operate on args and locally allocated vars, plus use
 *     thread-safe virtio_fs_fuse_*() operations)
 */

#include <asm/fcntl.h>
#include <stdint.h>

#include "api.h"
#include "pal_error.h"

#include "kernel_files.h"
#include "kernel_virtio.h"
#include "kernel_vmm_inputs.h"

#define MAX_TEXT_FILE_SIZE (1024 * 1024 * 1024) /* 1GB */

int read_text_file_to_cstr(const char* path, char** out_buf, uint64_t* out_size) {
    int ret;
    uint64_t nodeid;
    uint64_t fh;
    bool opened = false;
    char* buf = NULL;

    ret = virtio_fs_fuse_lookup(path, &nodeid);
    if (ret < 0)
        goto out;

    ret = virtio_fs_fuse_open(nodeid, O_RDONLY, &fh);
    if (ret < 0)
        goto out;

    opened = true;

    struct fuse_attr attr;
    ret = virtio_fs_fuse_getattr(nodeid, fh, FUSE_GETATTR_FH, MAX_TEXT_FILE_SIZE, &attr);
    if (ret < 0)
        goto out;

    buf = malloc(attr.size + 1);
    if (!buf) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    uint64_t bytes_read = 0;
    while (bytes_read < attr.size) {
        uint64_t read_size;
        ret = virtio_fs_fuse_read(nodeid, fh, MIN(attr.size - bytes_read, FILE_CHUNK_SIZE),
                                  bytes_read, buf + bytes_read, &read_size);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED)
                continue;
            goto out;
        }
        if (read_size == 0) {
            ret = -PAL_ERROR_INVAL; /* unexpected EOF */
            goto out;
        }
        bytes_read += read_size;
    }
    buf[attr.size] = '\0';
    *out_buf = buf;
    if (out_size)
        *out_size = attr.size;
    buf = NULL;
    ret = 0;
out:
    if (opened) {
        int close_ret = virtio_fs_fuse_release(nodeid, fh);
        if (ret == 0)
            ret = close_ret;
    }
    free(buf);
    return ret;
}

int emulate_file_map_via_read(uint64_t nodeid, uint64_t fh, void* addr, uint64_t offset,
                              uint64_t size) {
    uint64_t dummy;
    if (__builtin_add_overflow(offset, size, &dummy))
        return -PAL_ERROR_INVAL;

    if (!addr)
        return -PAL_ERROR_INVAL;

    uint64_t bytes_read = 0;
    while (bytes_read < size) {
        uint64_t read_size;
        int ret = virtio_fs_fuse_read(nodeid, fh, MIN(size - bytes_read, FILE_CHUNK_SIZE),
                                      offset + bytes_read, addr + bytes_read, &read_size);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED)
                continue;
            return ret;
        }
        if (read_size == 0) {
            /* EOF: must fill the rest of mapped region with zeros */
            break;
        }
        bytes_read += read_size;
    }

    if (bytes_read < size)
        memset(addr + bytes_read, 0, size - bytes_read);

    return 0;
}
