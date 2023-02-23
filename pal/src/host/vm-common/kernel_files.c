/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Glue code for common operations on files, using virtio-fs commands.
 */

#include <asm/fcntl.h>
#include <stdint.h>

#include "api.h"
#include "pal_error.h"

#include "kernel_files.h"
#include "kernel_virtio.h"
#include "kernel_vmm_inputs.h"

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
    ret = virtio_fs_fuse_getattr(nodeid, fh, FUSE_GETATTR_FH, &attr);
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
        ret = virtio_fs_fuse_read(nodeid, fh, MIN(attr.size - bytes_read, FILECHUNK_MAX),
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
        int ret = virtio_fs_fuse_read(nodeid, fh, MIN(size - bytes_read, FILECHUNK_MAX),
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

/*
 * Dmitrii Kuvaiskii: The code below is taken from uclibc-ng project, licensed under LGPL v2.1.
 * The code was slightly modified to fit Gramine codebase.
 *
 * realpath.c -- canonicalize pathname by removing symlinks
 * Copyright (C) 1993 Rick Sladkey <jrs@world.std.com>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

int realpath(const char* path, char* got_path, char** out_got_path) {
    int ret;
    char copy_path[PATH_MAX];

    char* max_path;
    char* new_path;
    char* allocated_path;

    int readlinks = 0;

    if (path == NULL)
        return -PAL_ERROR_INVAL;

    if (*path == '\0')
        return -PAL_ERROR_STREAMNOTEXIST;

    size_t host_pwd_len = strlen(g_host_pwd);
    if (host_pwd_len >= PATH_MAX - 2)
        return -PAL_ERROR_TOOLONG;

    /* Make a copy of the source path since we may need to modify it. */
    size_t path_len = strlen(path);
    if (path_len >= PATH_MAX - 2)
        return -PAL_ERROR_TOOLONG;

    /* Copy so that path is at the end of copy_path[] */
    memcpy(copy_path + (PATH_MAX - 1) - path_len, path, path_len + 1);
    path = copy_path + (PATH_MAX - 1) - path_len;
    allocated_path = got_path ? NULL : (got_path = malloc(PATH_MAX));

    max_path = got_path + PATH_MAX - 2; /* points to last non-NUL char */
    new_path = got_path;
    if (*path != '/') {
        /* If it's a relative pathname use pwd for starters. */
        memcpy(new_path, g_host_pwd, host_pwd_len + 1);
        new_path += strlen(new_path);
        if (new_path[-1] != '/')
            *new_path++ = '/';
    } else {
        *new_path++ = '/';
        path++;
    }

    /* Expand each slash-separated pathname component. */
    while (*path != '\0') {
        /* Ignore stray "/". */
        if (*path == '/') {
            path++;
            continue;
        }
        if (*path == '.') {
            /* Ignore ".". */
            if (path[1] == '\0' || path[1] == '/') {
                path++;
                continue;
            }
            if (path[1] == '.') {
                if (path[2] == '\0' || path[2] == '/') {
                    path += 2;
                    /* Ignore ".." at root. */
                    if (new_path == got_path + 1)
                        continue;
                    /* Handle ".." by backing up. */
                    while ((--new_path)[-1] != '/');
                    continue;
                }
            }
        }

        /* Safely copy the next pathname component. */
        while (*path != '\0' && *path != '/') {
            if (new_path > max_path) {
                ret = -PAL_ERROR_TOOLONG;
                goto out;
            }
            *new_path++ = *path++;
        }

        /* Protect against infinite loops. */
        if (readlinks++ > MAX_READLINKS) {
            ret = -PAL_ERROR_DENIED;
            goto out;
        }

        path_len = strlen(path);

        /* See if last (so far) pathname component is a symlink. */
        *new_path = '\0';

        uint64_t nodeid;
        ret = virtio_fs_fuse_lookup(got_path, &nodeid);
        if (ret < 0)
            goto out;

        /* virtiofs readlink() may overwrite the out buffer even in case of failure, so we use a
         * temporary stack var `link_path` for it and then copy into `copy_path` on success */
        char link_path[PATH_MAX];
        uint64_t link_len = 0;
        ret = virtio_fs_fuse_readlink(nodeid, PATH_MAX - 1, link_path, &link_len);
        if (ret < 0) {
            /* PAL_ERROR_INVAL means the file exists but isn't a symlink, that's benign, simply
             * continue with next pathname component */
            if (ret == -PAL_ERROR_INVAL) {
                *new_path++ = '/';
                continue;
            }
            /* FIXME: virtiofsd for some reason returns ENOENT, tracked at
             *        https://gitlab.com/virtio-fs/virtiofsd/-/issues/91 */
            if (ret == -PAL_ERROR_STREAMNOTEXIST) {
                *new_path++ = '/';
                continue;
            }

            /* all other error codes mean actual failure */
            goto out;
        }

        assert(link_len);
        memcpy(copy_path, link_path, link_len);

        if (path_len + link_len >= PATH_MAX - 2) {
            ret = -PAL_ERROR_TOOLONG;
            goto out;
        }
        /* Note: readlink doesn't add the null byte. */
        /* copy_path[link_len] = '\0'; - we don't need it too */
        if (*copy_path == '/') {
            /* Start over for an absolute symlink. */
            new_path = got_path;
        } else {
            /* Otherwise back up over this component. */
            while (*(--new_path) != '/');
        }
        /* Prepend symlink contents to path. */
        memmove(copy_path + (PATH_MAX - 1) - link_len - path_len, copy_path, link_len);
        path = copy_path + (PATH_MAX - 1) - link_len - path_len;

        *new_path++ = '/';
    }

    /* Delete trailing slash but don't whomp a lone slash. */
    if (new_path != got_path + 1 && new_path[-1] == '/')
        new_path--;
    /* Make sure it's null terminated. */
    *new_path = '\0';

    if (out_got_path)
        *out_got_path = got_path;

    ret = 0;
out:
    if (ret < 0)
        free(allocated_path);
    return ret;
}
