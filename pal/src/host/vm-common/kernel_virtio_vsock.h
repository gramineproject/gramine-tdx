/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Declarations for virtio-vsock driver implementation. */

#pragma once

#include <stdint.h>

#include "pal_internal.h"
#include "spinlock.h"
#include "uthash.h"

#define AF_VSOCK 40
#define VSOCK_HOST_CID 2

#define VSOCK_STARTING_PORT 1000 /* start port numbering from 1000, for no particular reason */

/* Initial size of g_vsock->conns array. */
#define VIRTIO_VSOCK_CONNS_INIT_SIZE 4

/* Maximum length to which the queue of pending connections may grow. Our queue of pending
 * connections is a simple static array, so we choose a small number (note that Linux v5.4 has 4096
 * by default). The corresponding array is a circular buffer, so this macro must be a power of 2. */
#define VSOCK_MAX_PENDING_CONNS 256

/* Max number of packets stored per connection. The corresponding array is a circular buffer, so
 * this macro must be a power of 2. */
#define VSOCK_MAX_PACKETS 256

/* For simplicity, each packet has statically allocated buffer for recv/send data. We choose the
 * size such that the total vsock packet size (44B header + payload) is a power of 2. The total
 * send/recv buffer size becomes then 1024 * 256 = 262144, which corresponds to the default Linux
 * buffer size. */
#define VSOCK_MAX_PAYLOAD_SIZE 980U

/* Sizes of RX and TX virtio queues. */
#define VIRTIO_VSOCK_QUEUE_SIZE 256

/* Size of the Event virtio queue (currently unused). */
#define VIRTIO_VSOCK_EVENT_QUEUE_SIZE 32

/* TX queue may be full, so it is impossible to immediately send a reply to some control message
 * (e.g. RESPONSE to REQUEST). Since such control messages are not visible to the higher-level
 * interfaces, we cannot ask the callers to retry (like we do with RW messages). */
#define VIRTIO_VSOCK_PENDING_TQ_CONTROL_SIZE 4096

/* On Linux, initial SYNs for an active TCP connection attempt will be retransmitted 6 times by
 * default. For example, with the current initial RTO (Retransmission Timeout) of 1s, the retries
 * are staggered at 1s, 3s, 7s, 15s, 31s, 63s (the inter-retry time starts at 2s and then doubles
 * each time). Thus the final timeout for an active TCP connection attempt will happen after 127s.
 * See https://elixir.bootlin.com/linux/v6.3/source/include/net/tcp.h#L107. */
#define VSOCK_CONNECT_TIMEOUT_US (127 * TIME_US_IN_S)

/* IETF RFC 793 requires the `TIME-WAIT` state to last twice the time of the MSL (Maximum Segment
 * Lifetime). On Linux, this duration is set to 60s, see:
 * https://elixir.bootlin.com/linux/v6.3/source/include/net/tcp.h#L123. */
#define VSOCK_CLOSE_TIMEOUT_US (60 * TIME_US_IN_S)

enum virtio_vsock_state {
    VIRTIO_VSOCK_CLOSE,
    VIRTIO_VSOCK_LISTEN,
    VIRTIO_VSOCK_CONNECT,
    VIRTIO_VSOCK_ESTABLISHED,
    VIRTIO_VSOCK_CLOSING,
};

enum virtio_vsock_type {
    VIRTIO_VSOCK_TYPE_STREAM = 1, /* in-order guaranteed connection-oriented, w/o msg boundaries */
};

enum virtio_vsock_packet_op {
    VIRTIO_VSOCK_OP_INVALID,
    /* Connect operations */
    VIRTIO_VSOCK_OP_REQUEST,
    VIRTIO_VSOCK_OP_RESPONSE,
    VIRTIO_VSOCK_OP_RST,
    VIRTIO_VSOCK_OP_SHUTDOWN,
    /* To send payload */
    VIRTIO_VSOCK_OP_RW,
    /* Tell the peer our credit info */
    VIRTIO_VSOCK_OP_CREDIT_UPDATE,
    /* Request the peer to send the credit info to us */
    VIRTIO_VSOCK_OP_CREDIT_REQUEST,
    VIRTIO_VSOCK_OP_MAX,
};

/* VIRTIO_VSOCK_OP_SHUTDOWN flags */
enum virtio_vsock_shutdown {
    VIRTIO_VSOCK_SHUTDOWN_RCV = 1,
    VIRTIO_VSOCK_SHUTDOWN_SEND,
    VIRTIO_VSOCK_SHUTDOWN_COMPLETE, /* both RCV and SEND (bitmask) */
};

/* VIRTIO_VSOCK_OP_RW flags (not used but kept here for future) */
enum virtio_vsock_rw {
    VIRTIO_VSOCK_SEQ_EOM = 1, /* end of msg: data sent/received by a single system call */
    VIRTIO_VSOCK_SEQ_EOR = 2, /* end of record: data consisting of any number of subsequent msgs */
};

struct virtio_vsock_hdr {
    uint64_t src_cid;
    uint64_t dst_cid;
    uint32_t src_port;
    uint32_t dst_port;
    uint32_t size;       /* size of the payload; this field is called "len" in spec */
    uint16_t type;       /* VIRTIO_VSOCK_TYPE_ */
    uint16_t op;         /* VIRTIO_VSOCK_OP_ */
    uint32_t flags;      /* flags specific to the operation `op` */
    uint32_t buf_alloc;  /* helper info: total buffer space of sender of this packet */
    uint32_t fwd_cnt;    /* helper info: total bytes already consumed by sender of this packet */
} __attribute__((packed));

struct virtio_vsock_packet {
    struct virtio_vsock_hdr header;
    uint8_t payload[VSOCK_MAX_PAYLOAD_SIZE];
};

struct virtio_vsock_connection {
    uint32_t fd; /* UINT32_MAX if not attached to any fd; synced via g_vsock_connections_lock */

    enum virtio_vsock_state state;
    int state_futex;

    UT_hash_handle hh_host_port;
    uint64_t host_port;
    uint64_t guest_port;

    /* allocated and used only in LISTENING state */
    uint32_t* pending_conn_fds;
    uint32_t pending_conn_fds_cnt;
    uint32_t pending_conn_fds_idx; /* first received-but-not-yet-accepted pending conn */

    struct virtio_vsock_packet* packets_for_user[VSOCK_MAX_PACKETS];
    uint32_t prepared_for_user;
    uint32_t consumed_by_user;

    /* below three fields needed to correctly support dualstack (only IPv4, only IPv6 or both);
     * note that all packets will actually be received/sent on only one of the dualstack sockets
     * (the first of the sockets to be bound to the same port) */
    bool ipv4_bound;
    bool ipv6_bound;
    bool ipv6_v6only;
};

struct sockaddr_vm {
    unsigned int   svm_family;     /* Address family: AF_VSOCK */
    unsigned short svm_reserved1;
    unsigned int   svm_port;       /* Port # in host byte order */
    unsigned int   svm_cid;        /* Address in host byte order */
};

void thread_wakeup_vsock(bool is_read);
