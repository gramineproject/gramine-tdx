/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Declarations for virtio-vsock driver implementation. */

#pragma once

#include <stdint.h>

#define AF_VSOCK 40

#define VSOCK_HOST_CID 2
#define VSOCK_MAX_CONNECTIONS 10
#define VSOCK_MAX_PACKETS     32 /* circular buffer, so must be a power of 2 */

/* for simplicity, each packet has statically allocated buffer for recv/send data */
#define VSOCK_MAX_PAYLOAD_SIZE 16U /* FIXME: this small size is for testing, actually want ~4K */

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
    enum virtio_vsock_state state;
    uint64_t host_port;
    uint64_t guest_port;
    uint32_t pending_conn; /* only for LISTENING state, = VSOCK_MAX_CONNECTIONS if no pending */

    struct virtio_vsock_packet* packets_for_user[VSOCK_MAX_PACKETS];
    uint32_t prepared_for_user;
    uint32_t consumed_by_user;
};

struct sockaddr_vm {
    unsigned int   svm_family;     /* Address family: AF_VSOCK */
    unsigned short svm_reserved1;
    unsigned int   svm_port;       /* Port # in host byte order */
    unsigned int   svm_cid;        /* Address in host byte order */
};

void thread_wakeup_vsock(bool is_read);
