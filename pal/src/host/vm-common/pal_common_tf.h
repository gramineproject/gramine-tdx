/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Trusted files (TF) are integrity protected and transparently verified when accessed by Gramine
 * or by app running inside Gramine. For each file that requires authentication (specified in the
 * manifest as "tdx.trusted_files"), a SHA256 hash is generated and stored in the manifest, signed
 * and verified as part of the enclave's crypto measurement. When user opens such a file, Gramine
 * loads the whole file, calculates its SHA256 hash, and checks against the corresponding hash in
 * the manifest. If the hashes do not match, the file access will be rejected.
 *
 * During the generation of the SHA256 hash, a 128-bit hash (truncated SHA256) is also generated for
 * each chunk (of size TRUSTED_CHUNK_SIZE) in the file. The per-chunk hashes are used for partial
 * verification in future reads, to avoid re-verifying the whole file again or the need of caching
 * file contents.
 */

/*
 * TODO:
 *
 * The logic is 95% copy-pasted from Linux-SGX. Differences:
 *   - no optimization of umem (no "whole file mmapped in untrusted memory"),
 *   - no `pal_handle::file::seekable` field in VM/TDX (all files considered seekable always),
 *   - `total` is renamed to `file_size`,
 *   - `off_t` is replaced with `int64_t` (as we rely on x86-64 arch)
 *
 * Deduplicate it when upstreamed.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "api.h"
#include "list.h"
#include "pal.h"

#define TRUSTED_CHUNK_SIZE (PRESET_PAGESIZE * 4UL)

enum {
    FILE_CHECK_POLICY_STRICT = 0,
    FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG,
};

typedef struct {
    uint8_t bytes[32];
} tdx_file_hash_t;

typedef struct {
    uint8_t bytes[16];
} tdx_chunk_hash_t;

/*
 * Perhaps confusingly, `struct trusted_file` describes not only "tdx.trusted_files" but also
 * "tdx.allowed_files". For allowed files, `allowed = true`, `chunk_hashes = NULL`, and `uri` can be
 * not only a file but also a directory. TODO: Perhaps split "allowed_files" into a separate struct?
 */
DEFINE_LIST(trusted_file);
struct trusted_file {
    LIST_TYPE(trusted_file) list;
    uint64_t size;
    bool allowed;
    tdx_file_hash_t file_hash;      /* hash over the whole file, retrieved from the manifest */
    tdx_chunk_hash_t* chunk_hashes; /* array of hashes over separate file chunks */
    size_t uri_len;
    char uri[]; /* must be NULL-terminated */
};

/*!
 * \brief Get trusted/allowed file struct, if corresponding path entry exists in the manifest.
 *
 * \param path  Normalized path to search for trusted/allowed files.
 *
 * \returns trusted/allowed file struct if found, NULL otherwise.
 */
struct trusted_file* get_trusted_or_allowed_file(const char* path);

/*!
 * \brief Open the file as trusted or allowed, according to the manifest.
 *
 * \param tf                Trusted file struct corresponding to this file.
 * \param file              File handle to be opened.
 * \param create            Whether this file is newly created.
 * \param out_chunk_hashes  Array of hashes over file chunks.
 * \param out_size          Returns size of opened file.
 *
 * \returns 0 on success, negative error code on failure
 */
int load_trusted_or_allowed_file(struct trusted_file* tf, struct pal_handle* file, bool create,
                                 void** out_chunk_hashes);

/*!
 * \brief Copy and check file contents from untrusted outside buffer to in-enclave buffer
 *
 * \param file            File handle.
 * \param buf             In-enclave buffer where contents of the file are copied.
 * \param aligned_offset  Offset into file contents to copy, aligned to TRUSTED_CHUNK_SIZE.
 * \param aligned_end     End of file contents to copy, aligned to TRUSTED_CHUNK_SIZE.
 * \param offset          Unaligned offset into file contents to copy.
 * \param end             Unaligned end of file contents to copy.
 * \param chunk_hashes    Array of hashes of all file chunks.
 * \param file_size       Total size of the file.
 *
 * \returns 0 on success, negative error code on failure
 */
int copy_and_verify_trusted_file(struct pal_handle* file, uint8_t* buf, int64_t aligned_offset,
                                 int64_t aligned_end, int64_t offset, int64_t end,
                                 void* chunk_hashes, size_t file_size);

int init_trusted_files(void);
int init_allowed_files(void);

int get_file_check_policy(void);
int init_file_check_policy(void);
