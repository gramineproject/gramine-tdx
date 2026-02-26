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

#include "realpath.h"

#include "api.h"
#include "pal_error.h"

#include "kernel_virtio.h"
#include "kernel_vmm_inputs.h"

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
    if (!got_path)
        return -PAL_ERROR_NOMEM;

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

        uint64_t link_len = 0;
        ret = virtio_fs_fuse_readlink(nodeid, PATH_MAX - 1, copy_path, &link_len);
        if (ret < 0) {
            /* PAL_ERROR_INVAL means the file exists but isn't a symlink, that's benign, simply
             * continue with next pathname component */
            if (ret == -PAL_ERROR_INVAL) {
                *new_path++ = '/';
                continue;
            }
            /* Linux and virtiofsd return -ENOENT on non-symlink files when using the format
             * `readlinkat(dirfd, "")`, see https://gitlab.com/virtio-fs/virtiofsd/-/issues/91 */
            if (ret == -PAL_ERROR_STREAMNOTEXIST) {
                *new_path++ = '/';
                continue;
            }

            /* all other error codes mean actual failure */
            goto out;
        }

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

    *out_got_path = got_path;
    ret = 0;
out:
    if (ret < 0)
        free(allocated_path);
    return ret;
}
