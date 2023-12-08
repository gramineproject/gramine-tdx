/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */


/*
 * This file contains operands to handle streams with URIs that start with "file:" or "dir:".
 */

#include "api.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_common_tf.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "path_utils.h"
#include "stat.h"

#include "external/realpath.h"

#include "kernel_files.h"
#include "kernel_memory.h"
#include "kernel_virtio.h"

#define DIRBUF_SIZE 1024
#define DT_DIR      4

bool g_use_trusted_files = false; /* only TDX PAL will set this */

/* out_modified_path is allocated by this func; must be freed by the caller */
static int extract_dir_and_base(const char* orig_path, char** out_modified_path, char** out_dir,
                                char** out_base) {
    char* modified_path = *orig_path == '/' ? strdup(orig_path)
                                            : alloc_concat("./", -1, orig_path, -1);
    if (!modified_path)
        return -PAL_ERROR_NOMEM;

    /* first remove trailing `/` symbols, then find the last `/` delimeter between dir and base */
    size_t len = strlen(modified_path);
    while (len > 0) {
        len--;
        if (modified_path[len] == '/')
            modified_path[len] = '\0';
        else
            break;
    }
    while (len > 0) {
        len--;
        if (modified_path[len] == '/') {
            modified_path[len] = '\0';
            *out_modified_path = modified_path;
            *out_dir  = &modified_path[0];
            *out_base = &modified_path[len + 1];
            return 0;
        }
    }

    free(modified_path);
    return -PAL_ERROR_INVAL;
}

static int file_or_dir_rename(const char* old, const char* new) {
    int ret;
    char* old_realpath_with_slash = NULL;
    char* old_resolved_path = NULL;
    char* new_realpath_with_slash = NULL;
    char* new_resolved_path = NULL;

    char* old_base_path = NULL;
    char* old_dir_path = NULL;
    ret = extract_dir_and_base(old, &old_realpath_with_slash, &old_dir_path, &old_base_path);
    if (ret < 0)
        goto out;

    ret = realpath(old_dir_path, /*got_path=*/NULL, &old_resolved_path);
    if (ret < 0)
        goto out;

    uint64_t old_dir_nodeid;
    ret = virtio_fs_fuse_lookup(old_resolved_path, &old_dir_nodeid);
    if (ret < 0)
        goto out;

    char* new_base_path = NULL;
    char* new_dir_path = NULL;
    ret = extract_dir_and_base(new, &new_realpath_with_slash, &new_dir_path, &new_base_path);
    if (ret < 0)
        goto out;

    ret = realpath(new_dir_path, /*got_path=*/NULL, &new_resolved_path);
    if (ret < 0)
        goto out;

    uint64_t new_dir_nodeid;
    ret = virtio_fs_fuse_lookup(new_resolved_path, &new_dir_nodeid);
    if (ret < 0)
        goto out;

    ret = virtio_fs_fuse_rename(old_dir_nodeid, old_base_path, new_dir_nodeid, new_base_path);
    if (ret < 0)
        goto out;

    ret = 0;
out:
    free(old_realpath_with_slash);
    free(old_resolved_path);
    free(new_realpath_with_slash);
    free(new_resolved_path);
    return ret;
}

int pal_common_file_open(struct pal_handle** handle, const char* type, const char* uri,
                         enum pal_access access, pal_share_flags_t share,
                         enum pal_create_mode create, pal_stream_options_t options) {
    int ret;
    uint64_t nodeid;
    uint64_t fh;
    bool opened = false;
    struct pal_handle* hdl = NULL;
    char* uri_with_slash = NULL;
    char* norm_path = NULL;
    char* parent_resolved_path = NULL;
    char* resolved_path = NULL;

    /* for cleanup in case the file was created and there is a failure */
    uint64_t created_dir_nodeid = 0;
    char* created_base_path = NULL;

    if (strcmp(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    assert(create != PAL_CREATE_IGNORED);
    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    bool file_exists;

    /* resolve symlinks in provided uri (virtiofs on the host doesn't do it, so we must) */
    ret = realpath(uri, /*got_path=*/NULL, &resolved_path);
    if (ret == -PAL_ERROR_STREAMNOTEXIST)
        file_exists = false;
    else if (ret >= 0)
        file_exists = true;
    else
        return ret;

    if (!file_exists && create == PAL_CREATE_NEVER)
        return -PAL_ERROR_STREAMNOTEXIST;

    if (file_exists && create == PAL_CREATE_ALWAYS)
        return -PAL_ERROR_STREAMEXIST;

    if (!file_exists) {
        /* file doesn't exist and we should create it in corresponding dir */
        char* base_path = NULL;
        char* dir_path = NULL;
        ret = extract_dir_and_base(uri, &uri_with_slash, &dir_path, &base_path);
        if (ret < 0)
            goto out;

        ret = realpath(dir_path, /*got_path=*/NULL, &parent_resolved_path);
        if (ret < 0)
            goto out;

        uint64_t dir_nodeid;
        ret = virtio_fs_fuse_lookup(parent_resolved_path, &dir_nodeid);
        if (ret < 0)
            goto out;

        ret = virtio_fs_fuse_create(dir_nodeid, base_path, PAL_ACCESS_TO_LINUX_OPEN(access)  |
                                                           PAL_CREATE_TO_LINUX_OPEN(create)  |
                                                           PAL_OPTION_TO_LINUX_OPEN(options) |
                                                           O_CLOEXEC,
                                    share, &nodeid, &fh);
        if (ret < 0)
            goto out;

        created_dir_nodeid = dir_nodeid;
        created_base_path = strdup(base_path);
    } else {
        /* file exists (and was already resolved), simply open it */
        ret = virtio_fs_fuse_lookup(resolved_path, &nodeid);
        if (ret < 0)
            goto out;

        ret = virtio_fs_fuse_open(nodeid, PAL_ACCESS_TO_LINUX_OPEN(access)  |
                                          PAL_CREATE_TO_LINUX_OPEN(create)  |
                                          PAL_OPTION_TO_LINUX_OPEN(options) |
                                          O_CLOEXEC,
                                  &fh);
        if (ret < 0)
            goto out;
    }

    /* now that we opened the host file, need to create and populate corresponding PAL handle */
    opened = true;

    hdl = calloc(1, sizeof(*hdl));
    if (!hdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    size_t norm_path_size = strlen(uri) + 1;
    norm_path = malloc(norm_path_size);
    if (!norm_path) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    if (!get_norm_path(uri, norm_path, &norm_path_size)) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    init_handle_hdr(hdl, PAL_TYPE_FILE);
    hdl->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;

    hdl->file.nodeid   = nodeid;
    hdl->file.fh       = fh;
    hdl->file.realpath = norm_path;

    struct trusted_file* tf = NULL;
    if (g_use_trusted_files && !(options & PAL_OPTION_PASSTHROUGH)) {
        tf = get_trusted_or_allowed_file(hdl->file.realpath);
        if (!tf) {
            if (get_file_check_policy() != FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG) {
                log_warning("Disallowing access to file '%s'; file is not trusted or allowed.",
                            hdl->file.realpath);
                ret = -PAL_ERROR_DENIED;
                goto out;
            }
            log_warning("Allowing access to unknown file '%s' due to file_check_policy settings.",
                        hdl->file.realpath);
        }
    }

    if (tf && !tf->allowed && (!file_exists
                || (access == PAL_ACCESS_RDWR)
                || (access == PAL_ACCESS_WRONLY))) {
        log_error("Disallowing create/write/append to a trusted file '%s'", hdl->file.realpath);
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    if (tf) {
        /* now we can learn the size of the trusted file */
        struct fuse_attr attr;
        ret = virtio_fs_fuse_getattr(hdl->file.nodeid, hdl->file.fh, FUSE_GETATTR_FH, UINT64_MAX,
                                     &attr);
        if (ret < 0)
            goto out;
        tf->size = attr.size;

        void* chunk_hashes = NULL;
        ret = load_trusted_or_allowed_file(tf, hdl, !file_exists, &chunk_hashes);
        if (ret < 0)
            goto out;

        hdl->file.chunk_hashes = chunk_hashes;
        hdl->file.size = tf->size;
    }

    *handle = hdl;
    ret = 0;
out:
    free(uri_with_slash);
    free(parent_resolved_path);
    free(resolved_path);
    if (ret < 0) {
        free(norm_path);
        free(hdl);
        if (opened)
            virtio_fs_fuse_release(nodeid, fh);
        if (created_dir_nodeid && created_base_path)
            virtio_fs_fuse_unlink(created_dir_nodeid, created_base_path);
    }
    free(created_base_path);
    return ret;
}

int64_t pal_common_file_read(struct pal_handle* handle, uint64_t offset, uint64_t count,
                             void* buffer) {
    int ret;

    if (!handle->file.chunk_hashes) {
        /* case of passthrough/allowed file */
        uint64_t read_size;
        ret = virtio_fs_fuse_read(handle->file.nodeid, handle->file.fh, MIN(count, FILE_CHUNK_SIZE),
                                  offset, buffer, &read_size);
        if (ret < 0)
            return ret;

        return (int64_t)read_size;
    }


    /* case of trusted file */
    uint64_t file_size = handle->file.size;
    if (offset >= file_size)
        return 0;

    int64_t end = MIN(offset + count, file_size);
    int64_t aligned_offset = ALIGN_DOWN(offset, TRUSTED_CHUNK_SIZE);
    int64_t aligned_end    = ALIGN_UP(end, TRUSTED_CHUNK_SIZE);

    ret = copy_and_verify_trusted_file(handle, buffer, aligned_offset, aligned_end, offset, end,
                                       handle->file.chunk_hashes, file_size);
    if (ret < 0)
        return ret;

    return end - offset;
}

int64_t pal_common_file_write(struct pal_handle* handle, uint64_t offset, uint64_t count,
                              const void* buffer) {
    if (handle->file.chunk_hashes) {
        /* case of trusted file: disallow writing completely */
        log_warning("Writing to a trusted file (%s) is disallowed!", handle->file.realpath);
        return -PAL_ERROR_DENIED;
    }

    /* try to write the whole buffer (this is important for some workloads like Python3); do it in
     * FILE_CHUNK_SIZE chunks because virtio-fs cannot consume more than this limit at a time */
    uint64_t total_written_size = 0;
    while (total_written_size < count) {
        uint64_t written_size;
        int ret = virtio_fs_fuse_write(handle->file.nodeid, handle->file.fh,
                                       buffer + total_written_size,
                                       MIN(count - total_written_size, FILE_CHUNK_SIZE),
                                       offset + total_written_size, &written_size);
        if (ret < 0)
            return total_written_size ? (int64_t)total_written_size : ret;

        if (written_size == 0)
            break;

        total_written_size += written_size;
    }

    return (int64_t)total_written_size;
}

void pal_common_file_destroy(struct pal_handle* handle) {
    assert(handle->hdr.type == PAL_TYPE_FILE);

    int ret = virtio_fs_fuse_release(handle->file.nodeid, handle->file.fh);
    if (ret < 0) {
        log_error("closing file host fd %lu failed: %s", handle->file.nodeid, pal_strerror(ret));
        /* We cannot do anything about it anyway... */
    }

    free(handle->file.realpath);
    free(handle);
}

int pal_common_file_map(struct pal_handle* handle, void* addr, pal_prot_flags_t prot,
                        uint64_t offset, uint64_t size) {
    int ret;

    assert(IS_ALLOC_ALIGNED(offset) && IS_ALLOC_ALIGNED(size));

    if (!(prot & PAL_PROT_WRITECOPY) && (prot & PAL_PROT_WRITE)) {
        log_warning("App tries to create a writable shared file mapping. This is impossible.");
        return -PAL_ERROR_DENIED;
    }

    /* note that we need to first mmap with write permission (to update the mem region with file
     * contents), and then we mprotect back to read-only (if was requested) */
    bool read  = !!(prot & PAL_PROT_READ);
    bool write = !!(prot & (PAL_PROT_WRITE | PAL_PROT_WRITECOPY));
    bool execute = !!(prot & PAL_PROT_EXEC);
    ret = memory_alloc(addr, size, read, /*write=*/true, execute);
    if (ret < 0)
        return ret;

    if (!handle->file.chunk_hashes) {
        /* case of allowed file */
        ret = emulate_file_map_via_read(handle->file.nodeid, handle->file.fh, addr, offset, size);
        goto out;
    }

    /* case of trusted file */
    int64_t end = MIN(offset + size, handle->file.size);
    size_t bytes_filled;

    if ((int64_t)offset >= end) {
        /* file is mmapped at offset beyond file size, there are no trusted-file contents to back
         * mmapped enclave pages; this is a legit case, so simply zero out these enclave pages and
         * return success */
        bytes_filled = 0;
    } else {
        int64_t aligned_offset = ALIGN_DOWN(offset, TRUSTED_CHUNK_SIZE);
        int64_t aligned_end    = ALIGN_UP(end, TRUSTED_CHUNK_SIZE);

        ret = copy_and_verify_trusted_file(handle, addr, aligned_offset, aligned_end, offset, end,
                                           handle->file.chunk_hashes, handle->file.size);
        if (ret < 0) {
            log_error("Verification of trusted file failed during mmap: %s", pal_strerror(ret));
            goto out;
        }

        bytes_filled = end - offset;
    }

    if (size > bytes_filled) {
        /* file ended before all mmapped memory was filled -- remaining memory must be zeroed */
        memset((char*)addr + bytes_filled, 0, size - bytes_filled);
    }

    if (!write) {
        /* restore read-only permission */
        ret = memory_protect(addr, size, read, /*write=*/false, execute);
        if (ret < 0) {
            log_error("Cannot restore read-only permission during file mmap, fatal.");
            BUG();
        }
    }

    ret = 0;
out:
    if (ret < 0)
        (void)memory_free(addr, size);
    return ret;
}

int pal_common_file_setlength(struct pal_handle* handle, uint64_t length) {
    struct fuse_setattr_in setattr = { .valid = FATTR_FH | FATTR_SIZE,
                                       .fh    = handle->file.fh,
                                       .size  = length };
    return virtio_fs_fuse_setattr(handle->file.nodeid, &setattr);
}

int pal_common_file_flush(struct pal_handle* handle) {
    return virtio_fs_fuse_flush(handle->file.nodeid, handle->file.fh);
}

int pal_common_file_attrquerybyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* pal_attr) {
    int ret;

    struct fuse_attr attr;
    ret = virtio_fs_fuse_getattr(handle->file.nodeid, handle->file.fh, FUSE_GETATTR_FH, UINT64_MAX,
                                 &attr);
    if (ret < 0)
        return ret;

    pal_attr->handle_type  = S_ISREG(attr.mode) ? PAL_TYPE_FILE : PAL_TYPE_DIR;
    pal_attr->share_flags  = attr.mode & PAL_SHARE_MASK;
    pal_attr->pending_size = attr.size;
    pal_attr->nonblocking  = false;
    return 0;
}

int pal_common_file_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* pal_attr) {
    if (strcmp(type, URI_TYPE_FILE) && strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    int ret;

    struct pal_handle* hdl = NULL;
    ret = pal_common_file_open(&hdl, type, uri, PAL_ACCESS_RDONLY, /*share_flags=*/0,
                               PAL_CREATE_NEVER, PAL_OPTION_PASSTHROUGH);
    if (ret < 0)
        return ret;

    ret = pal_common_file_attrquerybyhdl(hdl, pal_attr);

    pal_common_file_destroy(hdl);
    return ret;
}

int pal_common_file_attrsetbyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr) {
    struct fuse_setattr_in setattr = { .valid = FATTR_FH | FATTR_MODE,
                                       .fh    = handle->file.fh,
                                       .mode  = attr->share_flags };
    return virtio_fs_fuse_setattr(handle->file.nodeid, &setattr);
}

int pal_common_file_delete(struct pal_handle* handle, enum pal_delete_mode delete_mode) {
    int ret;
    char* realpath_with_slash = NULL;
    char* resolved_path = NULL;

    if (delete_mode != PAL_DELETE_ALL)
        return -PAL_ERROR_INVAL;

    char* base_path = NULL;
    char* dir_path = NULL;
    ret = extract_dir_and_base(handle->file.realpath, &realpath_with_slash, &dir_path, &base_path);
    if (ret < 0)
        goto out;

    ret = realpath(dir_path, /*got_path=*/NULL, &resolved_path);
    if (ret < 0)
        goto out;

    uint64_t dir_nodeid;
    ret = virtio_fs_fuse_lookup(resolved_path, &dir_nodeid);
    if (ret < 0)
        goto out;

    ret = virtio_fs_fuse_unlink(dir_nodeid, base_path);
    if (ret < 0)
        goto out;

    ret = 0;
out:
    free(realpath_with_slash);
    free(resolved_path);
    return ret;
}

int pal_common_file_rename(struct pal_handle* handle, const char* type, const char* uri) {
    if (strcmp(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    char* tmp = strdup(uri);
    if (!tmp)
        return -PAL_ERROR_NOMEM;

    int ret = file_or_dir_rename(handle->file.realpath, uri);
    if (ret < 0) {
        free(tmp);
        return ret;
    }

    free(handle->file.realpath);
    handle->file.realpath = tmp;
    return 0;
}

int pal_common_dir_open(struct pal_handle** handle, const char* type, const char* uri,
                        enum pal_access access, pal_share_flags_t share,
                        enum pal_create_mode create, pal_stream_options_t options) {
    __UNUSED(access);

    int ret;
    uint64_t nodeid;
    uint64_t fh;
    bool opened = false;
    struct pal_handle* hdl = NULL;
    char* uri_with_slash = NULL;
    char* norm_path = NULL;
    char* parent_resolved_path = NULL;
    char* resolved_path = NULL;

    /* for cleanup in case the dir was created and there is a failure */
    uint64_t created_dir_nodeid = 0;
    char* created_base_path = NULL;

    if (strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    assert(create != PAL_CREATE_IGNORED);

    bool dir_exists;

    /* resolve symlinks in provided uri (virtiofs on the host doesn't do it, so we must) */
    ret = realpath(uri, /*got_path=*/NULL, &resolved_path);
    if (ret == -PAL_ERROR_STREAMNOTEXIST)
        dir_exists = false;
    else if (ret >= 0)
        dir_exists = true;
    else
        return ret;

    if (!dir_exists && create == PAL_CREATE_NEVER)
        return -PAL_ERROR_STREAMNOTEXIST;

    if (dir_exists && create == PAL_CREATE_ALWAYS)
        return -PAL_ERROR_STREAMEXIST;

    if (!dir_exists) {
        /* dir doesn't exist and we should create it in corresponding parent dir */
        char* base_path = NULL;
        char* dir_path = NULL;
        ret = extract_dir_and_base(uri, &uri_with_slash, &dir_path, &base_path);
        if (ret < 0)
            goto out;

        ret = realpath(dir_path, /*got_path=*/NULL, &parent_resolved_path);
        if (ret < 0)
            goto out;

        uint64_t parent_dir_nodeid;
        ret = virtio_fs_fuse_lookup(parent_resolved_path, &parent_dir_nodeid);
        if (ret < 0)
            goto out;

        ret = virtio_fs_fuse_mkdir(parent_dir_nodeid, base_path, share, &nodeid);
        if (ret < 0)
            goto out;

        created_dir_nodeid = parent_dir_nodeid;
        created_base_path = strdup(base_path);
    } else {
        /* dir exists (and was already resolved), simply look it up */
        ret = virtio_fs_fuse_lookup(resolved_path, &nodeid);
        if (ret < 0)
            goto out;
    }

    ret = virtio_fs_fuse_opendir(nodeid, PAL_OPTION_TO_LINUX_OPEN(options) | O_CLOEXEC, &fh);
    if (ret < 0)
        goto out;

    /* now that we opened the host dir, need to create and populate corresponding PAL handle */
    opened = true;

    hdl = calloc(1, sizeof(*hdl));
    if (!hdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    size_t norm_path_size = strlen(uri) + 1;
    norm_path = malloc(norm_path_size);
    if (!norm_path) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    if (!get_norm_path(uri, norm_path, &norm_path_size)) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    init_handle_hdr(hdl, PAL_TYPE_DIR);
    hdl->flags |= PAL_HANDLE_FD_READABLE;

    hdl->dir.nodeid   = nodeid;
    hdl->dir.fh       = fh;
    hdl->dir.realpath = norm_path;

    hdl->dir.buf         = NULL;
    hdl->dir.ptr         = NULL;
    hdl->dir.end         = NULL;
    hdl->dir.endofstream = false;

    *handle = hdl;
    ret = 0;
out:
    free(uri_with_slash);
    free(parent_resolved_path);
    free(resolved_path);
    if (ret < 0) {
        free(norm_path);
        free(hdl);
        if (opened)
            virtio_fs_fuse_releasedir(nodeid, fh);
        if (created_dir_nodeid && created_base_path)
            virtio_fs_fuse_rmdir(created_dir_nodeid, created_base_path);
    }
    free(created_base_path);
    return ret;
}

int64_t pal_common_dir_read(struct pal_handle* handle, uint64_t offset, size_t count, void* _buf) {
    int ret;
    size_t bytes_written = 0;
    char* buf = (char*)_buf;

    uint64_t last_fuse_dirent_off = 0;

    if (offset)
        return -PAL_ERROR_INVAL;

    if (handle->dir.endofstream)
        return 0;

    while (1) {
        while ((char*)handle->dir.ptr < (char*)handle->dir.end) {
            struct fuse_dirent* dirent = (struct fuse_dirent*)handle->dir.ptr;

            if (is_dot_or_dotdot(dirent->name))
                goto skip;

            bool is_dir = dirent->type == DT_DIR;
            size_t len = dirent->namelen;
            if ((ssize_t)len >= (char*)handle->dir.end - (char*)handle->dir.ptr)
                return -PAL_ERROR_DENIED;

            if (len + 1 + (is_dir ? 1 : 0) > count)
                goto out;

            memcpy(buf, dirent->name, len);
            if (is_dir)
                buf[len++] = '/';
            buf[len++] = '\0';

            buf += len;
            bytes_written += len;
            count -= len;
        skip:
            handle->dir.ptr = (char*)handle->dir.ptr + FUSE_DIRENT_SIZE(dirent);

            /* fuse_dirent:off contains a unique number (not really an offset) that identifies the
             * last read entry; this off must be specified in the next FUSE READDIR request; see
             * gitlab.com/virtio-fs/virtiofsd/-/blob/v1.6.0/src/filesystem.rs?ref_type=tags#L1000 */
            last_fuse_dirent_off = dirent->off;
        }

        if (!count) {
            /* No space left, returning */
            goto out;
        }

        if (!handle->dir.buf) {
            handle->dir.buf = malloc(DIRBUF_SIZE);
            if (!handle->dir.buf)
                return -PAL_ERROR_NOMEM;
        }

        uint64_t size;
        ret = virtio_fs_fuse_readdir(handle->dir.nodeid, handle->dir.fh, DIRBUF_SIZE,
                                     /*offset=*/last_fuse_dirent_off, handle->dir.buf, &size);
        if (ret < 0) {
            if (bytes_written) {
                /* If something was written just return that and pretend no error was seen - it will
                 * be caught next time. */
                goto out;
            }
            return ret;
        }

        if (!size) {
            handle->dir.endofstream = true;
            goto out;
        }

        handle->dir.ptr = handle->dir.buf;
        handle->dir.end = (char*)handle->dir.buf + size;
    }

out:
    return (int64_t)bytes_written;
}

void pal_common_dir_destroy(struct pal_handle* handle) {
    assert(handle->hdr.type == PAL_TYPE_DIR);

    int ret = virtio_fs_fuse_releasedir(handle->dir.nodeid, handle->dir.fh);
    if (ret < 0) {
        log_error("closing dir host fd %lu failed: %s", handle->dir.nodeid, pal_strerror(ret));
        /* We cannot do anything about it anyway... */
    }

    free(handle->dir.buf);
    free(handle->dir.realpath);
    free(handle);
}

int pal_common_dir_delete(struct pal_handle* handle, enum pal_delete_mode delete_mode) {
    int ret;
    char* realpath_with_slash = NULL;
    char* resolved_path = NULL;

    if (delete_mode != PAL_DELETE_ALL)
        return -PAL_ERROR_INVAL;

    char* base_path = NULL;
    char* dir_path = NULL;
    ret = extract_dir_and_base(handle->dir.realpath, &realpath_with_slash, &dir_path, &base_path);
    if (ret < 0)
        goto out;

    ret = realpath(dir_path, /*got_path=*/NULL, &resolved_path);
    if (ret < 0)
        goto out;

    uint64_t parent_dir_nodeid;
    ret = virtio_fs_fuse_lookup(resolved_path, &parent_dir_nodeid);
    if (ret < 0)
        goto out;

    ret = virtio_fs_fuse_rmdir(parent_dir_nodeid, base_path);
    if (ret < 0)
        goto out;

    ret = 0;
out:
    free(realpath_with_slash);
    free(resolved_path);
    return ret;
}

int pal_common_dir_rename(struct pal_handle* handle, const char* type, const char* uri) {
    if (strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    char* tmp = strdup(uri);
    if (!tmp)
        return -PAL_ERROR_NOMEM;

    int ret = file_or_dir_rename(handle->dir.realpath, uri);
    if (ret < 0) {
        free(tmp);
        return ret;
    }

    free(handle->dir.realpath);
    handle->dir.realpath = tmp;
    return 0;
}
