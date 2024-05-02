/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Common virtio declarations (mmio, queue) and virtio drivers (console, fs, vsock).
 *
 * Helpful links:
 * - https://www.redhat.com/en/blog/virtqueues-and-virtio-ring-how-data-travels
 *   diagrams with buffer flows in Descriptor Area + Driver Area (Avail) + Device Area (Used)
 */

#pragma once

#include <stdint.h>

#include "external/fuse_kernel.h"
#include "kernel_virtio_vsock.h"

/* --------------------------------------- Common ---------------------------------------------- */

/* possible virtio_pci_regs::driver_feature flags, for driver_feature_select=1 */
#define VIRTIO_F_VERSION_1 0 /* feature bit 32, required by QEMU, see the link below: */
                             /* www.mail-archive.com/osv-dev@googlegroups.com/msg06088.html */
#define VIRTIO_F_ACCESS_PLATFORM 1 /* feature bit 33 */

/* possible virtio_regs::device_status flags */
#define VIRTIO_STATUS_ACKNOWLEDGE        1   /* guest found device and recognized it as valid */
#define VIRTIO_STATUS_DRIVER             2   /* guest knows how to drive the device */
#define VIRTIO_STATUS_DRIVER_OK          4   /* driver is set up and ready to drive the device */
#define VIRTIO_STATUS_FEATURES_OK        8   /* driver has acked all features it understands */
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET 64  /* device has experienced an unrecoverable error */
#define VIRTIO_STATUS_FAILED             128 /* smth went wrong in guest (it gave up on device) */

/* possible virtio_regs::interrupt_status_reg flags, bits 0 and 1 are defined, others reserved */
#define VIRTIO_INTERRUPT_STATUS_USED     1   /* device used buffer in at least one virtual queue */
#define VIRTIO_INTERRUPT_STATUS_CONFIG   2   /* configuration of device changed */
#define VIRTIO_INTERRUPT_STATUS_MASK (VIRTIO_INTERRUPT_STATUS_USED | VIRTIO_INTERRUPT_STATUS_CONFIG)

/* See Section 4.1.4.3 of VIRTIO 1.1 Spec */
struct virtio_pci_regs {
    /* About the whole device. */
    uint32_t device_feature_select; /* read-write */
    uint32_t device_feature;        /* read-only for driver */
    uint32_t driver_feature_select; /* read-write */
    uint32_t driver_feature;        /* read-write */
    uint16_t config_msix_vector;    /* read-write */
    uint16_t num_queues;            /* read-only for driver */
    uint8_t  device_status;         /* read-write */
    uint8_t  config_generation;     /* read-only for driver */

    /* About a specific virtqueue. */
    uint16_t queue_select;          /* read-write */
    uint16_t queue_size;            /* read-write */
    uint16_t queue_msix_vector;     /* read-write */
    uint16_t queue_enable;          /* read-write */
    uint16_t queue_notify_off;      /* read-only for driver */
    uint32_t queue_desc_low;        /* read-write */
    uint32_t queue_desc_high;       /* read-write */
    uint32_t queue_driver_low;      /* read-write */
    uint32_t queue_driver_high;     /* read-write */
    uint32_t queue_device_low;      /* read-write */
    uint32_t queue_device_high;     /* read-write */
    uint16_t queue_notify_data;     /* read-only for driver */
};

/* possible virtq_desc::flags */
#define VIRTQ_DESC_F_NEXT     1 /* mark buffer as continuing via the next field */
#define VIRTQ_DESC_F_WRITE    2 /* mark buffer as device write-only (otherwise device read-only) */
#define VIRTQ_DESC_F_INDIRECT 4 /* buffer contains a list of buffer descriptors */

struct virtq_desc {
    uint64_t addr;  /* guest-physical address */
    uint32_t len;
    uint16_t flags;
    uint16_t next;  /* next descriptor buffer (index in Descriptor Area) if flags & NEXT */
} __attribute__((packed));

/* possible virtq_avail::flags */
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1 /* don't interrupt driver when device consumes a buffer */

struct virtq_avail {
    uint16_t flags;
    uint16_t idx;     /* where driver puts next descriptor entry (`ring[idx % queue_size]`) */
    uint16_t ring[0]; /* number of elements is queue_size; each entry is index in Descriptor Area */
} __attribute__((packed));

/* field `id` is 32-bit for padding reasons (actual data is 16-bit in size) */
struct virtq_used_elem {
    uint32_t id;  /* start of used descriptor chain (matches earlier virtq_avail::idx) */
    uint32_t len; /* total length of descriptor chain written to */
} __attribute__((packed));

/* possible virtq_used::flags */
#define VIRTQ_USED_F_NO_NOTIFY 1 /* driver shouldn't kick device after adding a buffer */

struct virtq_used {
    uint16_t flags;
    uint16_t idx;                   /* where device puts next descriptor entry */
    struct virtq_used_elem ring[0]; /* number of elements is queue_size */
} __attribute__((packed));

#define VIRTQUEUE_MAX_QUEUE_SIZE 32768

/* See virtq_create() for the layout and alignment requirements. */
struct virtqueue {
    /* in private memory */
    uint16_t queue_size;
    uint16_t seen_used;
    uint16_t free_desc; /* head of linked list of free descriptors (ends in sentinel queue_size) */

    uint16_t cached_avail_idx;
    uint16_t* next_free_desc;

    /* statically allocated in shared memory, accesses via vm_shared_writex() */
    struct virtq_desc* desc;
    struct virtq_avail* avail;
    struct virtq_used* used;
    uint16_t* used_event;
    uint16_t* avail_event;
} __attribute__((packed));

int virtq_create(uint16_t queue_size, struct virtqueue** out_virtq);
int virtq_free(struct virtqueue* virtq, uint16_t queue_size);
int virtq_alloc_desc(struct virtqueue* virtq, void* addr, uint32_t len, uint16_t flags,
                     uint16_t* out_desc_idx);
bool virtq_is_desc_free(struct virtqueue* virtq, uint16_t desc_idx);
void virtq_free_desc(struct virtqueue* virtq, uint16_t desc_idx);
int virtq_add_to_device(struct virtio_pci_regs* regs, struct virtqueue* virtq, uint16_t queue_sel);

/* ----------------------------------- virtio-console ------------------------------------------ */
/* See Section 5.3 of VIRTIO 1.1 Spec */
#define VIRTIO_CONSOLE_F_SIZE        0
#define VIRTIO_CONSOLE_F_MULTIPORT   1
#define VIRTIO_CONSOLE_F_EMERG_WRITE 2

struct virtio_console_config {
    uint16_t cols;         /* console "column", read-only, when VIRTIO_CONSOLE_F_SIZE is set */
    uint16_t rows;         /* console "row", read-only, when VIRTIO_CONSOLE_F_SIZE is set */
    uint32_t max_nr_ports; /* currently no multiport support, this field is unused */
    uint32_t emerg_wr;     /* for early boot debugging, write-only, VIRTIO_CONSOLE_F_EMERG_WRITE */
};

/*
 * Notes on multi-core synchronization:
 *   - rq_buf_pos used in RX handling and virtio_console_read(), sync via receive-side lock
 *   - rq_buf is set at init, no sync required
 *   - rq_notify_addr is set at init and used by CPU0-tied bottomhalves thread, no sync required
 *   - shared_tq_buf_pos used in virtio_console_nprint(), sync via transmit-side lock
 *   - tq_notify_addr is set at init, used in virtio_console_nprint(), sync via transmit-side lock
 *   - shared_rq_buf is set at init, no sync required
 *   - shared_tq_buf is set at init, no sync required
 *   - rq is used by CPU0 interrupt handler and CPU0-tied bottomhalves thread, no sync required
 *   - tq is used in virtio_console_nprint(), sync via transmit-side lock
 *   - control_rq and control_tq are unused
 *   - pci_regs is used only at init, no sync required
 *   - pci_config is unused
 *   - interrupt_status_reg is used by CPU0 interrupt handler, no sync required
 */
struct virtio_console {
    /* in private memory */
    uint64_t rq_buf_pos;        /* current position (where to put incoming messages) in rq_buf */
    char* rq_buf;               /* private ring buffer where incoming messages are copied to */
    uint16_t* rq_notify_addr;   /* calculated MMIO notify addr for rq */

    uint64_t shared_tq_buf_pos; /* current position (where to put outgoing) in shared TQ buf */
    uint16_t* tq_notify_addr;   /* calculated MMIO notify addr for tq */

    /* statically allocated in shared memory, accesses via vm_shared_writex() */
    char* shared_rq_buf;          /* ring buffer where host puts incoming messages */
    char* shared_tq_buf;          /* ring buffer where outgoing messages are put for host */
    struct virtqueue* rq;         /* for incoming messages (stdin) */
    struct virtqueue* tq;         /* for outgoing messages (stdout/stderr) */
    struct virtqueue* control_rq; /* for multiport control messages, currently not used */
    struct virtqueue* control_tq; /* for multiport control messages, currently not used */

    /* VMM-allocated in MMIO memory, accesses via vm_mmio_writex() */
    struct virtio_pci_regs* pci_regs;         /* PCI BAR device control regs */
    struct virtio_console_config* pci_config; /* PCI BAR config space */
    uint32_t* interrupt_status_reg;           /* PCI BAR interrupt: used buffer/conf change */
};

int virtio_console_isr(void);
int virtio_console_bottomhalf(void);
int64_t virtio_console_read(char* buffer, size_t size);
int virtio_console_nprint(const char* s, size_t size);
int virtio_console_print(const char* s);
int virtio_console_printf(const char* fmt, ...);
int virtio_console_init(struct virtio_pci_regs* pci_regs, struct virtio_console_config* pci_config,
                        uint64_t notify_off_addr, uint32_t notify_off_multiplier,
                        uint32_t* interrupt_status_reg);

extern struct virtio_console* g_console;
extern bool g_console_trigger_bottomhalf;
void thread_wakeup_console(void);

/* -------------------------------------- virtio-fs -------------------------------------------- */
/* See Section 5.11 of VIRTIO 1.2 Spec (draft) and see `fuse_kernel.h`.
 * NOTE: we don't use the DAX window but instead rely on old-fashioned FUSE_READ/FUSE_WRITE. */
#define VIRTIO_FS_F_NOTIFICATION 0

struct virtio_fs_config {
    uint8_t  tag[36];            /* name associated with FS in UTF-8 (padded with NUL bytes) */
    uint32_t num_request_queues; /* number of request virtqueues, currently 1 (more helps perf) */
    uint32_t notify_buf_size;    /* currently no FUSE notify msgs support, this field is unused */
};

/*
 * Each request in virtio_fs is composed of four parts (in general case, it may vary): the generic
 * FUSE in-header, the FUSE-request-specific in-data, the generic FUSE out-header and the
 * FUSE-request-specific out-data.
 *
 * It is impossible to put these four parts in one C struct because (1) the out parts must be marked
 * with VIRTQ_DESC_F_WRITE and (2) in-data and out-data are of variable size. So instead we
 * represent this logical C struct as four chained decriptors which are always used together. I.e.,
 * the first descriptor points to a `fuse_in_header` object and has `flags & VIRTQ_DESC_F_NEXT`
 * and `next = <second descriptor idx>`. The second descriptor points to a `datain` object and also
 * has `flags & VIRTQ_DESC_F_NEXT` and `next = <third descriptor idx>`. Similarly for the third and
 * fourth descriptors. The logical C struct looks like this:
 *
 * struct virtio_fs_req {
 *    struct fuse_in_header in;   // FUSE request guest sends to VMM, write-only
 *    uint8_t datain[0];          // FUSE request's data guest sends to VMM, write-only
 *    struct fuse_out_header out; // FUSE response VMM sends to guest, read-only
 *    uint8_t dataout[0];         // FUSE response's data VMM sends to guest, read-only
 * };
 *
 * Note that the words `in` and `out` follow the FUSE meaning and do not indicate the direction of
 * data transfer under virtio. `In` means input to a request and `out` means output from processing
 * a request.
 *
 * Also note that some requests may have three (e.g. FUSE_RELEASE) or five parts (e.g. FUSE_WRITE).
 * See examples in kernel_virtio_fs.c.
 */

/*
 * Notes on multi-core synchronization:
 *   - requests_notify_addr is set at init and used in virtio_fs_exec_request(), sync via lock
 *   - initialized is set at init, no sync required
 *   - shared_buf is set at init, no sync required
 *   - hiprio and notify are unused
 *   - requests is used by CPU0 interrupt handler and in virtio_fs_exec_request(), sync via lock
 *   - pci_regs is used only at init, no sync required
 *   - pci_config is unused
 *   - interrupt_status_reg is used by CPU0 interrupt handler, no sync required
 */
struct virtio_fs {
    /* in private memory */
    uint16_t* requests_notify_addr; /* calculated MMIO notify addr for requests queue */

    bool initialized;

    /* statically allocated in shared memory, accesses via vm_shared_writex() */
    char* shared_buf;           /* internal buf where FUSE requests/responses are copied to */
    struct virtqueue* hiprio;   /* only FUSE_{INTERRUPT,FORGET,BATCH_FORGET} go here */
    struct virtqueue* notify;   /* for incoming notifications, currently not used */
    struct virtqueue* requests; /* single queue for normal FUSE requests/responses */

    /* VMM-allocated in MMIO memory, accesses via vm_mmio_writex() */
    struct virtio_pci_regs* pci_regs;    /* PCI BAR device control regs */
    struct virtio_fs_config* pci_config; /* PCI BAR config space */
    uint32_t* interrupt_status_reg;      /* PCI BAR interrupt: used buffer/conf change */
};

int virtio_fs_fuse_init(void);

int virtio_fs_fuse_lookup(const char* filename, uint64_t* out_nodeid);
int virtio_fs_fuse_readlink(uint64_t nodeid, uint64_t size, char* out_buf, uint64_t* out_size);

int virtio_fs_fuse_open(uint64_t nodeid, uint32_t flags, uint64_t* out_fh);
int virtio_fs_fuse_create(uint64_t dir_nodeid, const char* filename, uint32_t flags, uint32_t mode,
                          uint64_t* out_nodeid, uint64_t* out_fh);
int virtio_fs_fuse_release(uint64_t nodeid, uint64_t fh);
int virtio_fs_fuse_unlink(uint64_t dir_nodeid, const char* filename);
int virtio_fs_fuse_rename(uint64_t old_dir_nodeid, const char* old_filename,
                          uint64_t new_dir_nodeid, const char* new_filename);

int virtio_fs_fuse_read(uint64_t nodeid, uint64_t fh, uint64_t size, uint64_t offset,
                        char* out_buf, uint64_t* out_size);
int virtio_fs_fuse_write(uint64_t nodeid, uint64_t fh, const char* buf, uint64_t size,
                         uint64_t offset, uint64_t* out_size);
int virtio_fs_fuse_flush(uint64_t nodeid, uint64_t fh);

int virtio_fs_fuse_getattr(uint64_t nodeid, uint64_t fh, uint32_t flags, uint64_t max_size,
                           struct fuse_attr* out_attr);
int virtio_fs_fuse_setattr(uint64_t nodeid, const struct fuse_setattr_in* setattr);

int virtio_fs_fuse_opendir(uint64_t nodeid, uint32_t flags, uint64_t* out_fh);
int virtio_fs_fuse_mkdir(uint64_t dir_nodeid, const char* dirname, uint32_t mode,
                         uint64_t* out_nodeid);
int virtio_fs_fuse_releasedir(uint64_t nodeid, uint64_t fh);
int virtio_fs_fuse_rmdir(uint64_t dir_nodeid, const char* dirname);

int virtio_fs_fuse_readdir(uint64_t nodeid, uint64_t fh, uint64_t size, uint64_t offset,
                           struct fuse_dirent* out_dirents, uint64_t* out_size);

int virtio_fs_isr(void);
int virtio_fs_init(struct virtio_pci_regs* pci_regs, struct virtio_fs_config* pci_config,
                   uint64_t notify_off_addr, uint32_t notify_off_multiplier,
                   uint32_t* interrupt_status_reg);

extern struct virtio_fs* g_fs;

/* -------------------------------------- virtio-vsock -------------------------------------------- */
/* See Section 5.10 of VIRTIO 1.2 Spec (draft) and see `vsock.h`. */

struct virtio_vsock_config {
    uint64_t guest_cid;
};

/*
 * Notes on multi-core synchronization:
 *   - rq_notify_addr is set at init and used by CPU0-tied bottomhalves thread, no sync required
 *   - tq_notify_addr is set at init and used in copy_into_tq(), sync via transmit-side lock
 *   - host_cid is set at init, no sync required
 *   - guest_cid is set at init, no sync required
 *   - conns_size, conns, conns_by_host_port used in many places, sync via connections lock
 *   - pending_tq_control_packets and co. used during TX, sync via transmit-side lock
 *   - shared_rq_buf is set at init and used during RX, sync via receive-side lock
 *   - shared_tq_buf is set at init and used in copy_into_tq(), sync via transmit-side lock
 *   - rq is used during RX, sync via receive-side lock
 *   - tq is used in copy_into_tq() and cleanup_tq(), sync via transmit-side lock
 *   - eq is unused
 *   - pci_regs is used only at init, no sync required
 *   - pci_config is used only at init, no sync required
 *   - interrupt_status_reg is used by CPU0 interrupt handler, no sync required
 */
struct virtio_vsock {
    /* in private memory */
    uint16_t* rq_notify_addr;       /* calculated MMIO notify addr for RQ queue */
    uint16_t* tq_notify_addr;       /* calculated MMIO notify addr for TQ queue */

    uint64_t host_cid;
    uint64_t guest_cid;

    uint32_t conns_size;                    /* size of dynamic array */
    struct virtio_vsock_connection** conns; /* dynamic array: fd -> connection */
    struct virtio_vsock_connection* conns_by_host_port; /* hash table: host port -> connection */

    struct virtio_vsock_packet** pending_tq_control_packets;
    uint32_t pending_tq_control_packets_cnt;
    uint32_t pending_tq_control_packets_idx; /* first prepared-but-not-yet-sent pending packet */

    /* statically allocated in shared memory, accesses via vm_shared_writex() */
    char* shared_rq_buf;  /* internal buffer where incoming packets are copied from */
    char* shared_tq_buf;  /* internal buffer where outgoing packets are copied to */
    struct virtqueue* rq; /* for incoming packets (RX) */
    struct virtqueue* tq; /* for outgoing packets (TX) */
    struct virtqueue* eq; /* for event messages, currently not used */

    /* VMM-allocated in MMIO memory, accesses via vm_mmio_writex() */
    struct virtio_pci_regs* pci_regs;       /* PCI BAR device control regs */
    struct virtio_vsock_config* pci_config; /* PCI BAR config space */
    uint32_t* interrupt_status_reg;         /* PCI BAR interrupt: used buffer/conf change */
};

int virtio_vsock_socket(int domain, int type, int protocol);
int virtio_vsock_bind(int sockfd, const void* addr, size_t addrlen, uint16_t* out_new_port,
                      bool is_ipv4, bool ipv6_v6only, bool reuseport);
int virtio_vsock_listen(int sockfd, int backlog);
int virtio_vsock_accept(int sockfd, void* addr, size_t* addrlen);
int virtio_vsock_connect(int sockfd, const void* addr, size_t addrlen, uint64_t timeout_us);
int virtio_vsock_shutdown(int sockfd, enum virtio_vsock_shutdown shutdown);
int virtio_vsock_close(int sockfd, uint64_t timeout_us);
long virtio_vsock_peek(int sockfd);
long virtio_vsock_read(int sockfd, void* buf, size_t count);
long virtio_vsock_write(int sockfd, const void* buf, size_t count);
int virtio_vsock_getsockname(int sockfd, const void* addr, size_t* addrlen);
int virtio_vsock_set_socket_options(int sockfd, bool ipv6_v6only, bool reuseport);

int virtio_vsock_isr(void);
int virtio_vsock_bottomhalf(void);
bool virtio_vsock_can_write(void);
int virtio_vsock_init(struct virtio_pci_regs* pci_regs, struct virtio_vsock_config* pci_config,
                      uint64_t notify_off_addr, uint32_t notify_off_multiplier,
                      uint32_t* interrupt_status_reg);

extern struct virtio_vsock* g_vsock;
extern bool g_vsock_trigger_bottomhalf;
