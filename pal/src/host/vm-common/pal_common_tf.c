/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */


#include <stdbool.h>

#include "api.h"
#include "crypto.h"
#include "hex.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_common_tf.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "path_utils.h"
#include "spinlock.h"
#include "stat.h"
#include "toml.h"
#include "toml_utils.h"

#include "kernel_files.h"
#include "kernel_virtio.h"

DEFINE_LISTP(trusted_file);
static LISTP_TYPE(trusted_file) g_trusted_file_list = LISTP_INIT;
static spinlock_t g_trusted_file_lock = INIT_SPINLOCK_UNLOCKED;
static int g_file_check_policy = FILE_CHECK_POLICY_STRICT;

static int register_file(const char* uri, const char* hash_str, bool check_duplicates);

static int read_whole_buf(struct pal_handle* handle, void* buf, uint64_t size, uint64_t offset) {
    uint64_t bytes_read = 0;
    while (bytes_read < size) {
        uint64_t read_size;
        int ret = virtio_fs_fuse_read(handle->file.nodeid, handle->file.fh,
                                      MIN(size - bytes_read, FILECHUNK_MAX), bytes_read + offset,
                                      buf + bytes_read, &read_size);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED)
                continue;
            return ret;
        }
        if (read_size == 0)
            return -PAL_ERROR_INVAL; /* unexpected EOF */
        bytes_read += read_size;
    }
    assert(bytes_read == size);
    return 0;
}

/* assumes `path` is normalized */
static bool path_is_equal_or_subpath(const struct trusted_file* tf, const char* path,
                                     size_t path_len) {
    const char* tf_path = tf->uri + URI_PREFIX_FILE_LEN;
    size_t tf_path_len  = tf->uri_len - URI_PREFIX_FILE_LEN;

    if (tf_path_len > path_len || memcmp(tf_path, path, tf_path_len)) {
        /* tf path is not a prefix of `path` */
        return false;
    }
    if (tf_path_len == path_len) {
        /* Both are equal */
        return true;
    }
    if (tf_path[tf_path_len - 1] == '/') {
        /* tf path is a subpath of `path` (with slash), e.g. "foo/" and "foo/bar" */
        return true;
    }
    if (path[tf_path_len] == '/') {
        /* tf path is a subpath of `path` (without slash), e.g. "foo" and "foo/bar" */
        return true;
    }
    return false;
}

struct trusted_file* get_trusted_or_allowed_file(const char* path) {
    struct trusted_file* tf = NULL;

    size_t path_len = strlen(path);

    spinlock_lock(&g_trusted_file_lock);

    struct trusted_file* tmp;
    LISTP_FOR_EACH_ENTRY(tmp, &g_trusted_file_list, list) {
        if (tmp->allowed) {
            /* allowed files: must be a subfolder or file */
            if (path_is_equal_or_subpath(tmp, path, path_len)) {
                tf = tmp;
                break;
            }
        } else {
            /* trusted files: must be exactly the same URI */
            const char* tf_path = tmp->uri + URI_PREFIX_FILE_LEN;
            size_t tf_path_len  = tmp->uri_len - URI_PREFIX_FILE_LEN;
            if (tf_path_len == path_len && !memcmp(tf_path, path, path_len + 1)) {
                tf = tmp;
                break;
            }
        }
    }

    spinlock_unlock(&g_trusted_file_lock);

    return tf;
}

int load_trusted_or_allowed_file(struct trusted_file* tf, struct pal_handle* file, bool create,
                                 void** out_chunk_hashes) {
    int ret;

    *out_chunk_hashes = NULL;

    if (create) {
        assert(tf->allowed);
        return register_file(tf->uri, /*hash_str=*/NULL, /*check_duplicates=*/true);
    }

    if (tf->allowed) {
        /* allowed files: do not need any integrity, so no need for chunk hashes */
        return 0;
    }

    /* trusted files: need integrity, so calculate chunk hashes and compare with hash in manifest */
    tdx_chunk_hash_t* chunk_hashes = NULL;
    uint8_t* tmp_chunk = NULL; /* scratch buf to calculate whole-file and chunk-of-file hashes */

    spinlock_lock(&g_trusted_file_lock);
    if (tf->chunk_hashes) {
        *out_chunk_hashes = tf->chunk_hashes;
        spinlock_unlock(&g_trusted_file_lock);
        return 0;
    }
    spinlock_unlock(&g_trusted_file_lock);

    chunk_hashes = malloc(sizeof(tdx_chunk_hash_t) * UDIV_ROUND_UP(tf->size, TRUSTED_CHUNK_SIZE));
    if (!chunk_hashes) {
        ret = -PAL_ERROR_NOMEM;
        goto fail;
    }

    tmp_chunk = malloc(TRUSTED_CHUNK_SIZE);
    if (!tmp_chunk) {
        ret = -PAL_ERROR_NOMEM;
        goto fail;
    }

    tdx_chunk_hash_t* chunk_hashes_item = chunk_hashes;
    uint64_t offset = 0;
    LIB_SHA256_CONTEXT file_sha;

    ret = lib_SHA256Init(&file_sha);
    if (ret < 0)
        goto fail;

    for (; offset < tf->size; offset += TRUSTED_CHUNK_SIZE, chunk_hashes_item++) {
        /* For each file chunk of size TRUSTED_CHUNK_SIZE, generate 128-bit hash from SHA-256 hash
         * over contents of this file chunk (we simply truncate SHA-256 hash to first 128 bits; this
         * is fine for integrity purposes). Also, generate a SHA-256 hash for the whole file
         * contents to compare with the manifest "reference" hash value. */
        uint64_t chunk_size = MIN(tf->size - offset, TRUSTED_CHUNK_SIZE);
        LIB_SHA256_CONTEXT chunk_sha;
        ret = lib_SHA256Init(&chunk_sha);
        if (ret < 0)
            goto fail;

        ret = read_whole_buf(file, tmp_chunk, chunk_size, offset);
        if (ret < 0)
            goto fail;

        ret = lib_SHA256Update(&file_sha, tmp_chunk, chunk_size);
        if (ret < 0)
            goto fail;

        ret = lib_SHA256Update(&chunk_sha, tmp_chunk, chunk_size);
        if (ret < 0)
            goto fail;

        tdx_chunk_hash_t chunk_hash[2]; /* each chunk_hash is 128 bits in size */
        static_assert(sizeof(chunk_hash) * 8 == 256, "");
        ret = lib_SHA256Final(&chunk_sha, (uint8_t*)&chunk_hash[0]);
        if (ret < 0)
            goto fail;

        /* note that we truncate SHA256 to 128 bits */
        memcpy(chunk_hashes_item, &chunk_hash[0], sizeof(*chunk_hashes_item));
    }

    tdx_file_hash_t file_hash;
    ret = lib_SHA256Final(&file_sha, file_hash.bytes);
    if (ret < 0)
        goto fail;

    /* check the generated hash-over-whole-file against the reference hash in the manifest */
    if (memcmp(&file_hash, &tf->file_hash, sizeof(file_hash))) {
        log_warning("Hash of trusted file '%s' does not match with the reference hash in manifest",
                    file->file.realpath);
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    spinlock_lock(&g_trusted_file_lock);
    if (tf->chunk_hashes) {
        *out_chunk_hashes = tf->chunk_hashes;
        spinlock_unlock(&g_trusted_file_lock);
        free(chunk_hashes);
        free(tmp_chunk);
        return 0;
    }
    tf->chunk_hashes = chunk_hashes;
    *out_chunk_hashes = chunk_hashes;
    spinlock_unlock(&g_trusted_file_lock);

    free(tmp_chunk);
    return 0;

fail:
    free(chunk_hashes);
    free(tmp_chunk);
    return ret;
}

int copy_and_verify_trusted_file(struct pal_handle* file, uint8_t* buf, int64_t aligned_offset,
                                 int64_t aligned_end, int64_t offset, int64_t end,
                                 void* _chunk_hashes, size_t file_size) {
    tdx_chunk_hash_t* chunk_hashes = (tdx_chunk_hash_t*)_chunk_hashes;
    int ret = 0;

    assert(IS_ALIGNED(aligned_offset, TRUSTED_CHUNK_SIZE));
    assert(offset >= aligned_offset && end <= aligned_end);

    uint8_t* tmp_chunk = malloc(TRUSTED_CHUNK_SIZE);
    if (!tmp_chunk) {
        ret = -PAL_ERROR_NOMEM;
        goto failed;
    }

    tdx_chunk_hash_t* chunk_hashes_item = chunk_hashes + aligned_offset / TRUSTED_CHUNK_SIZE;

    uint8_t* buf_pos = buf;
    int64_t chunk_offset = aligned_offset;
    for (; chunk_offset < aligned_end; chunk_offset += TRUSTED_CHUNK_SIZE, chunk_hashes_item++) {
        size_t chunk_size = MIN(file_size - chunk_offset, TRUSTED_CHUNK_SIZE);
        int64_t chunk_end   = chunk_offset + chunk_size;

        tdx_chunk_hash_t chunk_hash[2]; /* each chunk_hash is 128 bits in size but we need 256 */

        LIB_SHA256_CONTEXT chunk_sha;
        ret = lib_SHA256Init(&chunk_sha);
        if (ret < 0)
            goto failed;

        if (chunk_offset >= offset && chunk_end <= end) {
            /* if current chunk-to-copy completely resides in the requested region-to-copy,
             * directly copy into buf (without a scratch buffer) and hash in-place */
            ret = read_whole_buf(file, buf_pos, chunk_size, chunk_offset);
            if (ret < 0)
                goto failed;

            ret = lib_SHA256Update(&chunk_sha, buf_pos, chunk_size);
            if (ret < 0)
                goto failed;

            buf_pos += chunk_size;
        } else {
            /* if current chunk-to-copy only partially overlaps with the requested region-to-copy,
             * read the file contents into a scratch buffer, verify hash and then copy only the part
             * needed by the caller */
            ret = read_whole_buf(file, tmp_chunk, chunk_size, chunk_offset);
            if (ret < 0)
                goto failed;

            ret = lib_SHA256Update(&chunk_sha, tmp_chunk, chunk_size);
            if (ret < 0)
                goto failed;

            /* determine which part of the chunk is needed by the caller */
            int64_t copy_start = MAX(chunk_offset, offset);
            int64_t copy_end   = MIN(chunk_offset + (int64_t)chunk_size, end);
            assert(copy_end > copy_start);

            memcpy(buf_pos, tmp_chunk + copy_start - chunk_offset, copy_end - copy_start);
            buf_pos += copy_end - copy_start;
        }

        ret = lib_SHA256Final(&chunk_sha, (uint8_t*)&chunk_hash[0]);
        if (ret < 0)
            goto failed;

        if (memcmp(chunk_hashes_item, &chunk_hash[0], sizeof(*chunk_hashes_item))) {
            log_error("Accessing file '%s' is denied: incorrect hash of file chunk at %lu-%lu.",
                      file->file.realpath, chunk_offset, chunk_end);
            ret = -PAL_ERROR_DENIED;
            goto failed;
        }
    }

    free(tmp_chunk);
    return 0;

failed:
    free(tmp_chunk);
    memset(buf, 0, end - offset);
    return ret;
}

static int register_file(const char* uri, const char* hash_str, bool check_duplicates) {
    if (hash_str && strlen(hash_str) != sizeof(tdx_file_hash_t) * 2) {
        log_error("Hash (%s) of a trusted file %s is not a SHA256 hash", hash_str, uri);
        return -PAL_ERROR_INVAL;
    }

    size_t uri_len = strlen(uri);
    if (uri_len >= URI_MAX) {
        log_error("Size of file exceeds maximum %dB: %s", URI_MAX, uri);
        return -PAL_ERROR_INVAL;
    }

    if (check_duplicates) {
        /* this check is only done during runtime (when creating a new file) and not needed during
         * initialization (because manifest is assumed to have no duplicates); skipping this check
         * significantly improves startup time */
        spinlock_lock(&g_trusted_file_lock);
        struct trusted_file* tf;
        LISTP_FOR_EACH_ENTRY(tf, &g_trusted_file_list, list) {
            if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
                spinlock_unlock(&g_trusted_file_lock);
                return 0;
            }
        }
        spinlock_unlock(&g_trusted_file_lock);
    }

    struct trusted_file* new = malloc(sizeof(*new) + uri_len + 1);
    if (!new)
        return -PAL_ERROR_NOMEM;

    INIT_LIST_HEAD(new, list);
    new->size = 0;
    new->chunk_hashes = NULL;
    new->allowed = false;
    new->uri_len = uri_len;
    memcpy(new->uri, uri, uri_len + 1);

    if (hash_str) {
        assert(strlen(hash_str) == sizeof(tdx_file_hash_t) * 2);

        char* bytes = hex2bytes(hash_str, strlen(hash_str), new->file_hash.bytes,
                                sizeof(new->file_hash.bytes));
        if (!bytes) {
            log_error("Could not parse hash of file: %s", uri);
            free(new);
            return -PAL_ERROR_INVAL;
        }
    } else {
        memset(&new->file_hash, 0, sizeof(new->file_hash));
        new->allowed = true;
    }

    spinlock_lock(&g_trusted_file_lock);

    if (check_duplicates) {
        /* this check is only done during runtime and not needed during initialization (see above);
         * we check again because same file could have been added by another thread in meantime */
        struct trusted_file* tf;
        LISTP_FOR_EACH_ENTRY(tf, &g_trusted_file_list, list) {
            if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
                spinlock_unlock(&g_trusted_file_lock);
                free(new);
                return 0;
            }
        }
    }

    LISTP_ADD_TAIL(new, &g_trusted_file_list, list);
    spinlock_unlock(&g_trusted_file_lock);

    return 0;
}

static int normalize_and_register_file(const char* uri, const char* hash_str) {
    int ret;

    if (!strstartswith(uri, URI_PREFIX_FILE)) {
        log_error("Invalid URI [%s]: Trusted/allowed files must start with 'file:'", uri);
        return -PAL_ERROR_INVAL;
    }

    const size_t norm_uri_size = strlen(uri) + 1;
    char* norm_uri = malloc(norm_uri_size);
    if (!norm_uri) {
        return -PAL_ERROR_NOMEM;
    }

    memcpy(norm_uri, URI_PREFIX_FILE, URI_PREFIX_FILE_LEN);
    size_t norm_path_size = norm_uri_size - URI_PREFIX_FILE_LEN;
    if (!get_norm_path(uri + URI_PREFIX_FILE_LEN, norm_uri + URI_PREFIX_FILE_LEN,
                       &norm_path_size)) {
        log_error("Path (%s) normalization failed", uri);
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    ret = register_file(norm_uri, hash_str, /*check_duplicates=*/false);
out:
    free(norm_uri);
    return ret;
}

int init_trusted_files(void) {
    int ret;

    toml_table_t* manifest_tdx = toml_table_in(g_pal_public_state.manifest_root, "tdx");
    if (!manifest_tdx) {
        /* hack to re-use `sgx` key if `tdx` not found */
        manifest_tdx = toml_table_in(g_pal_public_state.manifest_root, "sgx");
    }
    if (!manifest_tdx)
        return 0;

    toml_array_t* toml_trusted_files = toml_array_in(manifest_tdx, "trusted_files");
    if (!toml_trusted_files)
        return 0;

    ssize_t toml_trusted_files_cnt = toml_array_nelem(toml_trusted_files);
    if (toml_trusted_files_cnt < 0)
        return -PAL_ERROR_DENIED;
    if (toml_trusted_files_cnt == 0)
        return 0;

    char* toml_trusted_uri_str = NULL;
    char* toml_trusted_sha256_str = NULL;

    for (ssize_t i = 0; i < toml_trusted_files_cnt; i++) {
        /* read `tdx.trusted_file = {uri = "file:foo", sha256 = "deadbeef"}` entry from manifest */
        toml_table_t* toml_trusted_file = toml_table_at(toml_trusted_files, i);
        if (!toml_trusted_file) {
            log_error("Invalid trusted file in manifest at index %ld (not a TOML table)", i);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        toml_raw_t toml_trusted_uri_raw = toml_raw_in(toml_trusted_file, "uri");
        if (!toml_trusted_uri_raw) {
            log_error("Invalid trusted file in manifest at index %ld (no 'uri' key)", i);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        ret = toml_rtos(toml_trusted_uri_raw, &toml_trusted_uri_str);
        if (ret < 0) {
            log_error("Invalid trusted file in manifest at index %ld ('uri' is not a string)", i);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        toml_raw_t toml_trusted_sha256_raw = toml_raw_in(toml_trusted_file, "sha256");
        if (!toml_trusted_sha256_raw) {
            log_error("Invalid trusted file in manifest at index %ld (no 'sha256' key)", i);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        ret = toml_rtos(toml_trusted_sha256_raw, &toml_trusted_sha256_str);
        if (ret < 0 || !toml_trusted_sha256_str) {
            log_error("Invalid trusted file in manifest at index %ld ('sha256' is not a string)",
                      i);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        ret = normalize_and_register_file(toml_trusted_uri_str, toml_trusted_sha256_str);
        if (ret < 0) {
            log_error("normalize_and_register_file(\"%s\", \"%s\") failed with error code: %s",
                      toml_trusted_uri_str, toml_trusted_sha256_str, pal_strerror(ret));
            goto out;
        }

        free(toml_trusted_uri_str);
        free(toml_trusted_sha256_str);
        toml_trusted_uri_str = NULL;
        toml_trusted_sha256_str = NULL;
    }

    ret = 0;
out:
    free(toml_trusted_uri_str);
    free(toml_trusted_sha256_str);
    return ret;
}

int init_allowed_files(void) {
    int ret;

    toml_table_t* manifest_tdx = toml_table_in(g_pal_public_state.manifest_root, "tdx");
    if (!manifest_tdx) {
        /* hack to re-use `sgx` key if `tdx` not found */
        manifest_tdx = toml_table_in(g_pal_public_state.manifest_root, "sgx");
    }
    if (!manifest_tdx)
        return 0;

    toml_array_t* toml_allowed_files = toml_array_in(manifest_tdx, "allowed_files");
    if (!toml_allowed_files)
        return 0;

    ssize_t toml_allowed_files_cnt = toml_array_nelem(toml_allowed_files);
    if (toml_allowed_files_cnt < 0)
        return -PAL_ERROR_DENIED;
    if (toml_allowed_files_cnt == 0)
        return 0;

    char* toml_allowed_file_str = NULL;

    for (ssize_t i = 0; i < toml_allowed_files_cnt; i++) {
        toml_raw_t toml_allowed_file_raw = toml_raw_at(toml_allowed_files, i);
        if (!toml_allowed_file_raw) {
            log_error("Invalid allowed file in manifest at index %ld", i);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        ret = toml_rtos(toml_allowed_file_raw, &toml_allowed_file_str);
        if (ret < 0) {
            log_error("Invalid allowed file in manifest at index %ld (not a string)", i);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        ret = normalize_and_register_file(toml_allowed_file_str, /*hash_str=*/NULL);
        if (ret < 0) {
            log_error("normalize_and_register_file(\"%s\", NULL) failed with error: %s",
                      toml_allowed_file_str, pal_strerror(ret));
            goto out;
        }

        free(toml_allowed_file_str);
        toml_allowed_file_str = NULL;
    }

    ret = 0;
out:
    free(toml_allowed_file_str);
    return ret;
}

int get_file_check_policy(void) {
    return g_file_check_policy;
}

int init_file_check_policy(void) {
    int ret;

    char* file_check_policy_str = NULL;
    ret = toml_string_in(g_pal_public_state.manifest_root, "tdx.file_check_policy",
                         &file_check_policy_str);
    if (ret < 0) {
        log_error("Cannot parse 'tdx.file_check_policy'");
        return -PAL_ERROR_INVAL;
    }

    /* hack to re-use `sgx` key if `tdx` not found */
    if (!file_check_policy_str) {
        ret = toml_string_in(g_pal_public_state.manifest_root, "sgx.file_check_policy",
                             &file_check_policy_str);
        if (ret < 0) {
            log_error("Cannot parse 'sgx.file_check_policy'");
            return -PAL_ERROR_INVAL;
        }
    }

    if (!file_check_policy_str)
        return 0;

    if (!strcmp(file_check_policy_str, "strict")) {
        g_file_check_policy = FILE_CHECK_POLICY_STRICT;
    } else if (!strcmp(file_check_policy_str, "allow_all_but_log")) {
        g_file_check_policy = FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG;
    } else {
        log_error("Unknown value for 'tdx.file_check_policy' "
                  "(allowed: `strict`, `allow_all_but_log`)'");
        free(file_check_policy_str);
        return -PAL_ERROR_INVAL;
    }

    log_debug("File check policy: %s", file_check_policy_str);
    free(file_check_policy_str);
    return 0;
}
