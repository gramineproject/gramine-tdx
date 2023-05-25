/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Implementation of virtio-fs (uses FUSE messages for communication).
 *
 * See `man 4 fuse` for descriptions of used FUSE messages. We currently implement the following:
 *
 *   - FUSE_INIT     -- very first message, negotiates the protocol between guest (us) and host
 *   - FUSE_LOOKUP   -- find file based on filename on the host and return its nodeid
 *   - FUSE_READLINK -- resolve symbolic link of nodeid and put it into out_buf
 *
 *   - FUSE_OPEN     -- open file based on nodeid on the host and return fh (handle for opened file)
 *   - FUSE_CREATE   -- create new file in directory dir_nodeid and immediately open it
 *   - FUSE_RELEASE  -- close file based on fh; there is no return value
 *   - FUSE_UNLINK   -- remove file in directory dir_nodeid
 *
 *   - FUSE_READ     -- read from file based on fh and return contents in out_buf
 *   - FUSE_WRITE    -- write to file based on fh and return how many bytes were written
 *   - FUSE_FLUSH    -- flush buffered contents of file based on nodeid or fh
 *
 *   - FUSE_GETATTR  -- get stat-like attrs of file based on nodeid or fh (depends on supplied flag)
 *   - FUSE_SETATTR  -- set stat-like attrs of file based on nodeid or fh (depends on supplied flag)
 *
 *   - FUSE_OPENDIR     -- same as FUSE_OPEN but for directories
 *   - FUSE_MKDIR       -- same as FUSE_CREATE but for directories
 *   - FUSE_RELEASEDIR  -- same as FUSE_RELEASE but for directories
 *   - FUSE_RMDIR       -- same as FUSE_UNLINK but for directories
 *
 *   - FUSE_READDIR     -- read entries in the directory
 *
 * Reference: https://github.com/oasis-tcs/virtio-spec (currently only available in draft version,
 *            use master branch and build the Latex-based PDF yourself)
 */

#include "api.h"
#include "pal_error.h"
#include "pal_linux_error.h"

#include "external/fuse_kernel.h"

#include "kernel_apic.h"
#include "kernel_memory.h"
#include "kernel_pci.h"
#include "kernel_virtio.h"
#include "kernel_vmm_inputs.h"
#include "vm_callbacks.h"

#define VIRTIO_FS_QUEUE_SIZE 128
#define VIRTIO_FS_HIPRIO_QUEUE_SIZE 16

#define VIRTIO_FS_SHARED_BUF_SIZE (1024 * 1024)

struct virtio_fs* g_fs = NULL;

struct virtio_fs_desc {
    void*    addr;
    size_t   size;
    bool     in;        /* true: "in desc", false: "out desc" (with VIRTQ_DESC_F_WRITE) */
    bool     allocated; /* true: was already allocated via virtq_alloc_desc(), must be freed */
    uint16_t idx;       /* assigned desc index during allocation */
};

/* interrupt handler (interrupt service routine), called by generic handler `isr_c()` */
int virtio_fs_isr(void) {
    if (!g_fs)
        return 0;

    uint32_t interrupt_status = vm_mmio_readl(g_fs->interrupt_status_reg);
    if (!WITHIN_MASK(interrupt_status, VIRTIO_INTERRUPT_STATUS_MASK)) {
        log_error("Panic: ISR status register has reserved bits set (0x%x)", interrupt_status);
        triple_fault();
    }

    if (interrupt_status & VIRTIO_INTERRUPT_STATUS_USED) {
        uint16_t host_used_idx = vm_shared_readw(&g_fs->requests->used->idx);

        uint16_t expected_used_idx = g_fs->requests->seen_used + 1; /* also works for int wrap */
        if (host_used_idx != expected_used_idx)
            goto out;

        /* it is an actual change in "used" ring (not a spurious one), memorize it and kick the
         * waiting thread that issued the request */
        g_fs->requests->seen_used = host_used_idx;
        g_fs->device_done = true;
    }

    if (interrupt_status & VIRTIO_INTERRUPT_STATUS_CONFIG) {
        /* we don't currently care about changes in device config, so noop */
    }

out:
    return 0;
}

/* execute a single virtio-fs FUSE request to completion: copy relevant contents to shared memory,
 * submit `count` chained descriptors, kick the device, wait until the device processed the request
 * and then copy contents from device's shared memory to secure memory */
static int virtio_fs_exec_request(size_t count, struct virtio_fs_desc* descs) {
    int ret;

    if (count < 3) {
        /* no FUSE request has less that 3 descriptors (at least fuse_in, data_in, fuse_out) */
        return -PAL_ERROR_INVAL;
    }

    if (g_fs->device_done) {
        /* sanity check: must not happen because we are single-core and interrupt routines never
         * send FS requests -- i.e. only one kernel-thread context can send FS request at a time */
        return -PAL_ERROR_DENIED;
    }

    size_t total_in_size  = 0;
    size_t total_out_size = 0;
    for (size_t i = 0; i < count; i++) {
        if (descs[i].in)
            total_in_size += descs[i].size;
        else
            total_out_size += descs[i].size;
    }

    if (total_in_size + total_out_size > VIRTIO_FS_SHARED_BUF_SIZE) {
        /* FS request doesn't fit into shared buffer, cannot send it */
        return -PAL_ERROR_NOMEM;
    }

    /* we spin on device_done (until it becomes true) to wait for the device notification; since
     * this is a global var, it's not thread-safe (not suitable for multi-core) */
    g_fs->device_done = false;

    struct fuse_in_header* hdr_in = descs[0].addr;
    hdr_in->len = total_in_size;

    char* shared_buf_addr = g_fs->shared_buf;
    for (size_t i = 0; i < count; i++) {
        uint16_t flags = i == count - 1 ? 0 : VIRTQ_DESC_F_NEXT;
        if (descs[i].in) {
            /* write to untrusted shared memory, safe */
			vm_shared_memcpy(shared_buf_addr, descs[i].addr, descs[i].size);
        } else {
            /* zero out in untrusted shared memory and mark desc as to-be-written by device */
            vm_shared_memset(shared_buf_addr, 0, descs[i].size);
            flags |= VIRTQ_DESC_F_WRITE;
        }

        descs[i].allocated = false; /* reset for sanity */
        ret = virtq_alloc_desc(g_fs->requests, shared_buf_addr, descs[i].size, flags,
                               &descs[i].idx);
        if (ret < 0)
            goto out;

        descs[i].allocated = true;
        shared_buf_addr += descs[i].size;
    }

    for (size_t i = 0; i < count - 1; i++) {
        vm_shared_writew(&g_fs->requests->desc[descs[i].idx].next, descs[i + 1].idx);
    }
    vm_shared_writew(&g_fs->requests->desc[descs[count - 1].idx].next, 0);

    uint16_t avail_idx = g_fs->requests->cached_avail_idx;
    g_fs->requests->cached_avail_idx++;

    vm_shared_writew(&g_fs->requests->avail->ring[avail_idx % g_fs->requests->queue_size],
                     descs[0].idx);
    vm_shared_writew(&g_fs->requests->avail->idx, g_fs->requests->cached_avail_idx);

	vm_mmio_writew(g_fs->requests_notify_addr, /*queue_sel=*/1);

    while (__atomic_load_n(&g_fs->device_done, __ATOMIC_RELAXED) != true)
        CPU_RELAX();

    shared_buf_addr = g_fs->shared_buf;
    for (size_t i = 0; i < count; i++) {
        if (!descs[i].in) {
            /* copy from untrusted shared memory, these contents should be verified */
            vm_shared_memcpy(descs[i].addr, shared_buf_addr, descs[i].size);
        }
        shared_buf_addr += descs[i].size;
    }

    g_fs->device_done = false; /* reset for the next FS request */
    ret = 0;
out:
    for (size_t i = 0; i < count; i++)
        if (descs[i].allocated)
            virtq_free_desc(g_fs->requests, descs[i].idx);
    return ret;
}

int virtio_fs_fuse_init(void) {
    int ret;

    if (g_fs->initialized)
        return 0;

    struct fuse_in_header  hdr_in   = { .opcode = FUSE_INIT };
    struct fuse_init_in    init_in  = { .major = FUSE_KERNEL_VERSION,
                                        .minor = FUSE_KERNEL_MINOR_VERSION};
    struct fuse_out_header hdr_out  = {0};
    struct fuse_init_out   init_out = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,   .size = sizeof(hdr_in),   .in = true },
        { .addr = &init_in,  .size = sizeof(init_in),  .in = true },
        { .addr = &hdr_out,  .size = sizeof(hdr_out),  .in = false },
        { .addr = &init_out, .size = sizeof(init_out), .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/4, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    if (init_in.major != init_out.major)
        return -PAL_ERROR_DENIED;

    if (init_out.minor < 9) {
        /* to avoid subtle issues with legacy FUSE struct layouts, we need at least v7.9;
         * for one example of subtle issues, search for `FUSE_COMPAT_WRITE_IN_SIZE` in
         * https://www.mail-archive.com/git-commits-head@vger.kernel.org/msg27852.html */
        return -PAL_ERROR_DENIED;
    }

    /* TODO: check other fields, also make sure we pin to a specific minor version */
    g_fs->host_fuse_ver_major = init_out.major;
    g_fs->host_fuse_ver_minor = init_out.minor;

    g_fs->initialized = true;
    return 0;
}

int virtio_fs_fuse_lookup(const char* filename, uint64_t* out_nodeid) {
    int ret;

    if (!g_fs->initialized || strlen(filename) == 0)
        return -PAL_ERROR_DENIED;

    /* lookup is always started at root dir, so filename should be absolute */
    char* abs_filename = filename[0] == '/' ? strdup(filename)
                                            : alloc_concat3(g_host_pwd, -1, "/", 1, filename, -1);
    if (!abs_filename)
        return -PAL_ERROR_NOMEM;

    struct fuse_in_header  hdr_in    = { .opcode = FUSE_LOOKUP, .nodeid = FUSE_ROOT_ID };
    struct fuse_out_header hdr_out   = {0};
    struct fuse_entry_out  entry_out = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,      .size = sizeof(hdr_in),           .in = true },
        { .addr = abs_filename, .size = strlen(abs_filename) + 1, .in = true },
        { .addr = &hdr_out,     .size = sizeof(hdr_out),          .in = false },
        { .addr = &entry_out,   .size = sizeof(entry_out),        .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/4, descs);

    free(abs_filename);

    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* TODO: take into account `generation` and optionally parse/memorize returned attrs */
    *out_nodeid = entry_out.nodeid;
    return 0;
}

int virtio_fs_fuse_readlink(uint64_t nodeid, uint64_t size, char* out_buf, uint64_t* out_size) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in  = { .opcode = FUSE_READLINK, .nodeid = nodeid };
    struct fuse_out_header hdr_out = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,  .size = sizeof(hdr_in),  .in = true },
        { .addr = &hdr_out, .size = sizeof(hdr_out), .in = false },
        { .addr = out_buf,  .size = size,            .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/3, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* verify possibly-malicious `hdr_out.len` */
    if (hdr_out.len < sizeof(hdr_out) || hdr_out.len > sizeof(hdr_out) + size)
        return -PAL_ERROR_DENIED;

    /* out_buf was already populated by the above call, let's populate out_size (recall that
     * `hdr_out->len` returns the *total* size of the host's reply, including the header) */
    *out_size = hdr_out.len - sizeof(hdr_out);
    return 0;
}

int virtio_fs_fuse_open(uint64_t nodeid, uint32_t flags, uint64_t* out_fh) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in    = { .opcode = FUSE_OPEN, .nodeid = nodeid };
    struct fuse_open_in    open_in   = { .flags = flags };
    struct fuse_out_header hdr_out   = {0};
    struct fuse_open_out   open_out  = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,   .size = sizeof(hdr_in),   .in = true },
        { .addr = &open_in,  .size = sizeof(open_in),  .in = true },
        { .addr = &hdr_out,  .size = sizeof(hdr_out),  .in = false },
        { .addr = &open_out, .size = sizeof(open_out), .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/4, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* TODO: take into account `open_flags` */
    *out_fh = open_out.fh;
    return 0;
}

int virtio_fs_fuse_create(uint64_t dir_nodeid, const char* filename, uint32_t flags, uint32_t mode,
                          uint64_t* out_nodeid, uint64_t* out_fh) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in    = { .opcode = FUSE_CREATE, .nodeid = dir_nodeid };
    struct fuse_create_in  create_in = { .flags = flags, .mode = mode,
                                         .umask = /*default permissive*/0022 };
    struct fuse_out_header hdr_out   = {0};
    struct fuse_entry_out  entry_out = {0};
    struct fuse_open_out   open_out  = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,         .size = sizeof(hdr_in),       .in = true },
        { .addr = &create_in,      .size = sizeof(create_in),    .in = true },
        { .addr = (void*)filename, .size = strlen(filename) + 1, .in = true },
        { .addr = &hdr_out,        .size = sizeof(hdr_out),      .in = false },
        { .addr = &entry_out,      .size = sizeof(entry_out),    .in = false },
        { .addr = &open_out,       .size = sizeof(open_out),     .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/6, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* TODO: take into account `generation` and optionally parse/memorize returned attrs */
    *out_nodeid = entry_out.nodeid;

    /* TODO: take into account `open_flags` */
    *out_fh = open_out.fh;
    return 0;
}

int virtio_fs_fuse_release(uint64_t nodeid, uint64_t fh) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in      = { .opcode = FUSE_RELEASE, .nodeid = nodeid };
    struct fuse_release_in release_in  = { .fh = fh }; /* TODO: use `flags`? */
    struct fuse_out_header hdr_out     = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,     .size = sizeof(hdr_in),     .in = true },
        { .addr = &release_in, .size = sizeof(release_in), .in = true },
        { .addr = &hdr_out,    .size = sizeof(hdr_out),    .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/3, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    return 0;
}

int virtio_fs_fuse_unlink(uint64_t dir_nodeid, const char* filename) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in    = { .opcode = FUSE_UNLINK, .nodeid = dir_nodeid };
    struct fuse_out_header hdr_out   = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,         .size = sizeof(hdr_in),       .in = true },
        { .addr = (void*)filename, .size = strlen(filename) + 1, .in = true },
        { .addr = &hdr_out,  .size = sizeof(hdr_out),            .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/3, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    return 0;
}

int virtio_fs_fuse_rename(uint64_t old_dir_nodeid, const char* old_filename,
                          uint64_t new_dir_nodeid, const char* new_filename) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in    = { .opcode = FUSE_RENAME, .nodeid = old_dir_nodeid };
    struct fuse_rename_in  rename_in = { .newdir = new_dir_nodeid };
    struct fuse_out_header hdr_out   = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,             .size = sizeof(hdr_in),           .in = true },
        { .addr = &rename_in,          .size = sizeof(rename_in),        .in = true },
        { .addr = (void*)old_filename, .size = strlen(old_filename) + 1, .in = true },
        { .addr = (void*)new_filename, .size = strlen(new_filename) + 1, .in = true },
        { .addr = &hdr_out,            .size = sizeof(hdr_out),          .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/5, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    return 0;
}

int virtio_fs_fuse_read(uint64_t nodeid, uint64_t fh, uint64_t size, uint64_t offset,
                        char* out_buf, uint64_t* out_size) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    /* NOTE: we don't use any read flags (currently the only one is FUSE_READ_LOCKOWNER) */
    struct fuse_in_header  hdr_in  = { .opcode = FUSE_READ, .nodeid = nodeid };
    struct fuse_read_in    read_in = { .fh = fh, .offset = offset, .size = size };
    struct fuse_out_header hdr_out = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,  .size = sizeof(hdr_in),  .in = true },
        { .addr = &read_in, .size = sizeof(read_in), .in = true },
        { .addr = &hdr_out, .size = sizeof(hdr_out), .in = false },
        { .addr = out_buf,  .size = size,            .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/4, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* verify possibly-malicious `hdr_out.len` */
    if (hdr_out.len < sizeof(hdr_out) || hdr_out.len > sizeof(hdr_out) + size)
        return -PAL_ERROR_DENIED;

    /* out_buf was already populated by the above call, let's populate out_size (recall that
     * `hdr_out->len` returns the *total* size of the host's reply, including the header) */
    *out_size = hdr_out.len - sizeof(hdr_out);
    return 0;
}

int virtio_fs_fuse_write(uint64_t nodeid, uint64_t fh, const char* buf, uint64_t size,
                         uint64_t offset, uint64_t* out_size) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    /* NOTE: we don't use any write flags (search FUSE_WRITE_* for available flags) */
    struct fuse_in_header  hdr_in    = { .opcode = FUSE_WRITE, .nodeid = nodeid };
    struct fuse_write_in   write_in  = { .fh = fh, .offset = offset, .size = size };
    struct fuse_out_header hdr_out   = {0};
    struct fuse_write_out  write_out = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,    .size = sizeof(hdr_in),    .in = true },
        { .addr = &write_in,  .size = sizeof(write_in),  .in = true },
        { .addr = (void*)buf, .size = size,              .in = true },
        { .addr = &hdr_out,   .size = sizeof(hdr_out),   .in = false },
        { .addr = &write_out, .size = sizeof(write_out), .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/5, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* verify possibly-malicious `write_out.size` */
    if (write_out.size > size)
        return -PAL_ERROR_DENIED;

    *out_size = write_out.size;
    return 0;
}

int virtio_fs_fuse_flush(uint64_t nodeid, uint64_t fh) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in  = { .opcode = FUSE_FLUSH, .nodeid = nodeid };
    struct fuse_flush_in   flush_in = { .fh = fh };
    struct fuse_out_header hdr_out = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,   .size = sizeof(hdr_in),   .in = true },
        { .addr = &flush_in, .size = sizeof(flush_in), .in = true },
        { .addr = &hdr_out,  .size = sizeof(hdr_out),  .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/3, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    return 0;
}

/* `fh` may be dummy if `flags & FUSE_GETATTR_FH == false` (then `nodeid` is used) */
int virtio_fs_fuse_getattr(uint64_t nodeid, uint64_t fh, uint32_t flags,
                           struct fuse_attr* out_attr) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in     = { .opcode = FUSE_GETATTR, .nodeid = nodeid };
    struct fuse_getattr_in getattr_in = { .getattr_flags = flags, .fh = fh };
    struct fuse_out_header hdr_out    = {0};
    struct fuse_attr_out   attr_out   = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,     .size = sizeof(hdr_in),     .in = true },
        { .addr = &getattr_in, .size = sizeof(getattr_in), .in = true },
        { .addr = &hdr_out,    .size = sizeof(hdr_out),    .in = false },
        { .addr = &attr_out,   .size = sizeof(attr_out),   .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/4, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* NOTE: we don't cache file attrs and thus don't care about `attr_valid` fields */
    /* FIXME: maybe verify & sanitize possibly-malicious `attr_out.attr` for TDX? */
    *out_attr = attr_out.attr;
    return 0;
}

int virtio_fs_fuse_setattr(uint64_t nodeid, const struct fuse_setattr_in* setattr) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in     = { .opcode = FUSE_SETATTR, .nodeid = nodeid };
    struct fuse_setattr_in setattr_in = *setattr;
    struct fuse_out_header hdr_out    = {0};
    struct fuse_attr_out   attr_out   = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,     .size = sizeof(hdr_in),     .in = true },
        { .addr = &setattr_in, .size = sizeof(setattr_in), .in = true },
        { .addr = &hdr_out,    .size = sizeof(hdr_out),    .in = false },
        { .addr = &attr_out,   .size = sizeof(attr_out),   .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/4, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* TODO: return `attr_out` to caller? e.g., to update the PAL file handle attrs */
    return 0;
}

int virtio_fs_fuse_opendir(uint64_t nodeid, uint32_t flags, uint64_t* out_fh) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in    = { .opcode = FUSE_OPENDIR, .nodeid = nodeid };
    struct fuse_open_in    open_in   = { .flags = flags };
    struct fuse_out_header hdr_out   = {0};
    struct fuse_open_out   open_out  = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,   .size = sizeof(hdr_in),   .in = true },
        { .addr = &open_in,  .size = sizeof(open_in),  .in = true },
        { .addr = &hdr_out,  .size = sizeof(hdr_out),  .in = false },
        { .addr = &open_out, .size = sizeof(open_out), .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/4, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* TODO: take into account `open_flags` */
    *out_fh = open_out.fh;
    return 0;
}

int virtio_fs_fuse_mkdir(uint64_t dir_nodeid, const char* dirname, uint32_t mode,
                         uint64_t* out_nodeid) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in    = { .opcode = FUSE_MKDIR, .nodeid = dir_nodeid };
    struct fuse_mkdir_in   mkdir_in  = { .mode = mode, .umask = /*default permissive*/0022};
    struct fuse_out_header hdr_out   = {0};
    struct fuse_entry_out  entry_out = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,        .size = sizeof(hdr_in),      .in = true },
        { .addr = &mkdir_in,      .size = sizeof(mkdir_in),    .in = true },
        { .addr = (void*)dirname, .size = strlen(dirname) + 1, .in = true },
        { .addr = &hdr_out,       .size = sizeof(hdr_out),     .in = false },
        { .addr = &entry_out,     .size = sizeof(entry_out),   .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/5, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* TODO: take into account `generation` and optionally parse/memorize returned attrs */
    *out_nodeid = entry_out.nodeid;
    return 0;
}

int virtio_fs_fuse_releasedir(uint64_t nodeid, uint64_t fh) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in    = { .opcode = FUSE_RELEASEDIR, .nodeid = nodeid };
    struct fuse_release_in release_in  = { .fh = fh };
    struct fuse_out_header hdr_out     = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,     .size = sizeof(hdr_in),     .in = true },
        { .addr = &release_in, .size = sizeof(release_in), .in = true },
        { .addr = &hdr_out,    .size = sizeof(hdr_out),    .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/3, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    return 0;
}

int virtio_fs_fuse_rmdir(uint64_t dir_nodeid, const char* dirname) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    struct fuse_in_header  hdr_in    = { .opcode = FUSE_RMDIR, .nodeid = dir_nodeid };
    struct fuse_out_header hdr_out   = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,        .size = sizeof(hdr_in),      .in = true },
        { .addr = (void*)dirname, .size = strlen(dirname) + 1, .in = true },
        { .addr = &hdr_out,       .size = sizeof(hdr_out),     .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/3, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    return 0;
}

int virtio_fs_fuse_readdir(uint64_t nodeid, uint64_t fh, uint64_t size, uint64_t offset,
                           struct fuse_dirent* out_dirents, uint64_t* out_size) {
    int ret;

    if (!g_fs->initialized)
        return -PAL_ERROR_DENIED;

    /* NOTE: we don't use any read flags (currently the only one is FUSE_READ_LOCKOWNER) */
    struct fuse_in_header  hdr_in  = { .opcode = FUSE_READDIR, .nodeid = nodeid };
    struct fuse_read_in    read_in = { .fh = fh, .offset = offset, .size = size };
    struct fuse_out_header hdr_out = {0};

    struct virtio_fs_desc descs[] = {
        { .addr = &hdr_in,     .size = sizeof(hdr_in),  .in = true },
        { .addr = &read_in,    .size = sizeof(read_in), .in = true },
        { .addr = &hdr_out,    .size = sizeof(hdr_out), .in = false },
        { .addr = out_dirents, .size = size,            .in = false },
    };

    ret = virtio_fs_exec_request(/*count=*/4, descs);
    if (ret < 0)
        return ret;
    if (hdr_out.error < 0)
        return unix_to_pal_error(hdr_out.error);

    /* verify possibly-malicious `hdr_out.len` */
    if (hdr_out.len < sizeof(hdr_out) || hdr_out.len > sizeof(hdr_out) + size)
        return -PAL_ERROR_DENIED;

    /* out_dirents was already populated by the above call, let's populate out_size (recall that
     * `hdr_out->len` returns the *total* size of the host's reply, including the header) */
    *out_size = hdr_out.len - sizeof(hdr_out);
    return 0;
}

static int virtio_fs_negotiate_features(struct virtio_fs* fs) {
    struct virtio_pci_regs* pci_regs = fs->pci_regs;

    uint32_t understood_features = 0;
    uint32_t advertised_features = 0;

    /* negotiate feature bits 31..0 */
    vm_mmio_writel(&pci_regs->device_feature_select, 0);
    advertised_features = vm_mmio_readl(&pci_regs->device_feature);

    if (advertised_features & (1 << VIRTIO_FS_F_NOTIFICATION)) {
        /* NOTE: we don't currently support FUSE notify messages */
    }

    vm_mmio_writel(&pci_regs->driver_feature_select, 0);
    vm_mmio_writel(&pci_regs->driver_feature, understood_features);

    /* negotiate feature bits 63..32 (need to set VIRTIO_F_VERSION_1 bit, see
     * https://www.mail-archive.com/osv-dev@googlegroups.com/msg06088.html for details) */
    vm_mmio_writel(&pci_regs->device_feature_select, 1);
    advertised_features = vm_mmio_readl(&pci_regs->device_feature);

    if (!(advertised_features & (1 << VIRTIO_F_VERSION_1)))
        return -PAL_ERROR_DENIED;

    understood_features = 1 << VIRTIO_F_VERSION_1;

    vm_mmio_writel(&pci_regs->driver_feature_select, 1);
    vm_mmio_writel(&pci_regs->driver_feature, understood_features);
    return 0;
}

static int virtio_fs_alloc(struct virtio_fs** out_fs) {
    int ret;
    struct virtio_fs* fs = NULL;
    char* shared_buf = NULL;
    struct virtqueue* hiprio = NULL;
    struct virtqueue* notify = NULL; /* currently not used */
    struct virtqueue* requests = NULL;

    fs = malloc(sizeof(*fs));
    if (!fs)
        return -PAL_ERROR_NOMEM;
    memset(fs, 0, sizeof(*fs)); /* for sanity */

    shared_buf = memory_get_shared_region(VIRTIO_FS_SHARED_BUF_SIZE);
    if (!shared_buf) {
        ret = -PAL_ERROR_NOMEM;
        goto fail;
    }

    ret = virtq_create(VIRTIO_FS_HIPRIO_QUEUE_SIZE, &hiprio);
    if (ret < 0)
        goto fail;

    ret = virtq_create(VIRTIO_FS_QUEUE_SIZE, &requests);
    if (ret < 0)
        goto fail;

    fs->shared_buf = shared_buf;
    fs->hiprio   = hiprio;
    fs->notify   = notify;
    fs->requests = requests;

    *out_fs = fs;
    return 0;
fail:
    memory_free_shared_region(shared_buf, VIRTIO_FS_SHARED_BUF_SIZE);
    virtq_free(hiprio, VIRTIO_FS_HIPRIO_QUEUE_SIZE);
    /* notify is currently not used; if used later, needs to be freed */
    virtq_free(requests, VIRTIO_FS_QUEUE_SIZE);
    free(fs);
    return ret;
}

static int virtio_fs_free(struct virtio_fs* fs) {
    memory_free_shared_region(fs->shared_buf, VIRTIO_FS_SHARED_BUF_SIZE);
    virtq_free(fs->hiprio, VIRTIO_FS_HIPRIO_QUEUE_SIZE);
    /* notify is currently not used; if used later, needs to be freed */
    virtq_free(fs->requests, VIRTIO_FS_QUEUE_SIZE);
    free(fs);
    return 0;
}

int virtio_fs_init(struct virtio_pci_regs* pci_regs, struct virtio_fs_config* pci_config,
                   uint64_t notify_off_addr, uint32_t notify_off_multiplier,
                   uint32_t* interrupt_status_reg) {
    int ret;
    uint32_t status;

    struct virtio_fs* fs;
    ret = virtio_fs_alloc(&fs);
    if (ret < 0)
        return ret;

    fs->pci_regs = pci_regs;
    fs->pci_config = pci_config;
    fs->interrupt_status_reg = interrupt_status_reg;

    ret = virtio_fs_negotiate_features(fs);
    if (ret < 0)
        goto fail;

    status = vm_mmio_readb(&pci_regs->device_status);
    vm_mmio_writeb(&pci_regs->device_status, status | VIRTIO_STATUS_FEATURES_OK);

    status = vm_mmio_readb(&pci_regs->device_status);
    if (!(status & VIRTIO_STATUS_FEATURES_OK)) {
        /* host device (vhost-fs or virtiofsd) did not accept our features */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    ret = virtq_add_to_device(pci_regs, fs->hiprio, /*queue_sel=*/0);
    if (ret < 0)
        goto fail;

    /* don't add virtqueue `notification queue` to virtio-fs device
     *
     * NOTE: In draft of virtio-fs spec, there is a notification queue with queue selector 1,
     *       but in current Linux and virtiofsd, there is no notification queue, and thus queue
     *       selector 1 is used for the first `requests` queue. See e.g. Linux v5.15 source:
     *       https://elixir.bootlin.com/linux/v5.15/source/fs/fuse/virtio_fs.c#L33
     */

    ret = virtq_add_to_device(pci_regs, fs->requests, /*queue_sel=*/1);
    if (ret < 0)
        goto fail;

    vm_mmio_writew(&pci_regs->queue_select, 1);
    uint64_t requests_notify_off = vm_mmio_readw(&pci_regs->queue_notify_off);
    fs->requests_notify_addr = (uint16_t*)(notify_off_addr
                                               + requests_notify_off * notify_off_multiplier);

    if (!(PCI_MMIO_START_ADDR <= (uintptr_t)fs->requests_notify_addr &&
                (uintptr_t)fs->requests_notify_addr < PCI_MMIO_END_ADDR)) {
        /* incorrect or malicious queue notify addr */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    status = vm_mmio_readb(&pci_regs->device_status);
    vm_mmio_writeb(&pci_regs->device_status, status | VIRTIO_STATUS_DRIVER_OK);

    g_fs = fs;
    return 0;

fail:
    virtio_fs_free(fs);
    status = vm_mmio_readb(&pci_regs->device_status);
    vm_mmio_writeb(&pci_regs->device_status, status | VIRTIO_STATUS_FAILED);
    return ret;
}
