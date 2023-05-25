/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Implementation of virtio-vsock.
 *
 * Reference: https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.pdf
 *
 * TODO:
 * - Buffer space management via buf_alloc, fwd_cnt, tx_cnt (see section 5.10.6.3 in spec)
 */

#include "api.h"
#include "pal_error.h"

#include "kernel_apic.h"
#include "kernel_memory.h"
#include "kernel_pci.h"
#include "kernel_virtio.h"
#include "kernel_virtio_vsock.h"
#include "vm_callbacks.h"

#define VIRTIO_VSOCK_QUEUE_SIZE 128
#define VIRTIO_VSOCK_EVENT_QUEUE_SIZE 32

#define VIRTIO_VSOCK_SHARED_BUF_SIZE (VIRTIO_VSOCK_QUEUE_SIZE * sizeof(struct virtio_vsock_packet))

struct virtio_vsock* g_vsock = NULL;
bool g_vsock_trigger_bottomhalf = false;

static int process_packet(struct virtio_vsock_packet* packet);

/* interrupt handler (interrupt service routine), called by generic handler `isr_c()` */
int virtio_vsock_isr(void) {
    if (!g_vsock)
        return 0;

    uint32_t interrupt_status = vm_mmio_readl(g_vsock->interrupt_status_reg);
    if (!WITHIN_MASK(interrupt_status, VIRTIO_INTERRUPT_STATUS_MASK)) {
        log_error("Panic: ISR status register has reserved bits set (0x%x)", interrupt_status);
        triple_fault();
    }

    if (interrupt_status & VIRTIO_INTERRUPT_STATUS_USED) {
        /* real work is done in the bottomhalf called in normal context, see below */
        g_vsock_trigger_bottomhalf = true;
    }

    if (interrupt_status & VIRTIO_INTERRUPT_STATUS_CONFIG) {
        /* we don't currently care about changes in device config, so noop */
    }

    return 0;
}

static int handle_rq(void) {
    bool received = false;

    uint16_t host_used_idx = vm_shared_readw(&g_vsock->rq->used->idx);

    if (host_used_idx - g_vsock->rq->seen_used > g_vsock->rq->queue_size) {
        /* malicious (impossible) value reported by the host; note that this check works also in
         * cases of int wrap */
        return -PAL_ERROR_DENIED;
    }

    while (host_used_idx != g_vsock->rq->seen_used) {
        uint16_t used_idx = g_vsock->rq->seen_used % g_vsock->rq->queue_size;
        uint16_t desc_idx = (uint16_t)vm_shared_readl(&g_vsock->rq->used->ring[used_idx].id);

        if (desc_idx >= g_vsock->rq->queue_size) {
            /* malicious (out of bounds) descriptor index */
            return -PAL_ERROR_DENIED;
        }

        uint64_t addr = vm_shared_readq(&g_vsock->rq->desc[desc_idx].addr);
        uint32_t size = vm_shared_readl(&g_vsock->rq->desc[desc_idx].len);

        uint64_t shared_rq_buf_size = g_vsock->rq->queue_size * sizeof(struct virtio_vsock_packet);
        if (addr < (uintptr_t)g_vsock->shared_rq_buf ||
                addr >= (uintptr_t)g_vsock->shared_rq_buf + shared_rq_buf_size) {
            /* malicious (out of bounds) address of the incoming packet */
            return -PAL_ERROR_DENIED;
        }

        if ((addr - (uintptr_t)g_vsock->shared_rq_buf) % sizeof(struct virtio_vsock_packet)) {
            /* malicious (not aligned on packet struct size) offset of the incoming packet */
            return -PAL_ERROR_DENIED;
        }

        if (size < sizeof(struct virtio_vsock_hdr) || size > sizeof(struct virtio_vsock_packet)) {
            /* malicious (out of bounds) size of the incoming packet */
            return -PAL_ERROR_DENIED;
        }

        struct virtio_vsock_packet* packet = malloc(sizeof(*packet));
        if (!packet)
            return -PAL_ERROR_NOMEM;

        /* copy from untrusted shared memory, these contents should be verified in process_packet */
        vm_shared_memcpy(packet, (struct virtio_vsock_packet*)addr, sizeof(*packet));
        process_packet(packet);

        vm_shared_writeq(&g_vsock->rq->desc[desc_idx].addr,  addr);
        vm_shared_writel(&g_vsock->rq->desc[desc_idx].len,   sizeof(struct virtio_vsock_packet));
        vm_shared_writew(&g_vsock->rq->desc[desc_idx].flags, VIRTQ_DESC_F_WRITE);
        vm_shared_writew(&g_vsock->rq->desc[desc_idx].next,  0);

        uint16_t avail_idx = g_vsock->rq->cached_avail_idx;
        g_vsock->rq->cached_avail_idx++;

        vm_shared_writew(&g_vsock->rq->avail->ring[avail_idx % g_vsock->rq->queue_size], desc_idx);
        vm_shared_writew(&g_vsock->rq->avail->idx, g_vsock->rq->cached_avail_idx);

        g_vsock->rq->seen_used++;
        received = true;
    }

    if (received) {
        vm_mmio_writew(g_vsock->rq_notify_addr, /*queue_sel=*/0);
        thread_wakeup_vsock(/*is_read=*/true);
    }

    return 0;
}

static int copy_into_tq(struct virtio_vsock_packet* packet) {
    int ret;

    if (!g_vsock)
        return -PAL_ERROR_BADHANDLE;

    uint64_t packet_size = sizeof(struct virtio_vsock_hdr) + packet->header.size;

    uint16_t desc_idx;
    ret = virtq_alloc_desc(g_vsock->tq, /*addr=*/NULL, packet_size, /*flags=*/0, &desc_idx);
    if (ret < 0)
        return ret;

    /* we found a free descriptor above and used a dummy NULL address, now let's rewire it */
    char* shared_packet = (char*)g_vsock->shared_tq_buf + desc_idx * sizeof(*packet);
    vm_shared_writeq(&g_vsock->tq->desc[desc_idx].addr, (uint64_t)shared_packet);

    /* write to untrusted shared memory, safe */
    vm_shared_memcpy(shared_packet, packet, packet_size);

    uint16_t avail_idx = g_vsock->tq->cached_avail_idx;
    g_vsock->tq->cached_avail_idx++;

    vm_shared_writew(&g_vsock->tq->avail->ring[avail_idx % g_vsock->tq->queue_size], desc_idx);
    vm_shared_writew(&g_vsock->tq->avail->idx, g_vsock->tq->cached_avail_idx);

    g_vsock->tx_cnt += packet->header.size;

    vm_mmio_writew(g_vsock->tq_notify_addr, /*queue_sel=*/1);
    return 0;
}

static int cleanup_tq(void) {
    bool sent = false;

    uint16_t host_used_idx = vm_shared_readw(&g_vsock->tq->used->idx);

    if (host_used_idx - g_vsock->tq->seen_used > g_vsock->tq->queue_size) {
        /* malicious (impossible) value reported by the host; note that this check works also in
         * cases of int wrap */
        return -PAL_ERROR_DENIED;
    }

    while (host_used_idx != g_vsock->tq->seen_used) {
        uint16_t used_idx = g_vsock->tq->seen_used % g_vsock->tq->queue_size;
        uint16_t desc_idx = (uint16_t)vm_shared_readl(&g_vsock->tq->used->ring[used_idx].id);

        if (desc_idx >= g_vsock->tq->queue_size) {
            /* malicious (out of bounds) descriptor index */
            return -PAL_ERROR_DENIED;
        }

        virtq_free_desc(g_vsock->tq, desc_idx);
        g_vsock->tq->seen_used++;
        sent = true;
    }

    if (sent)
        thread_wakeup_vsock(/*is_read=*/false);

    return 0;
}

/* called from the bottomhalf thread in normal context (not interrupt context) */
int virtio_vsock_bottomhalf(void) {
    int ret = handle_rq();
    if (ret < 0)
        return ret;

    ret = cleanup_tq();
    if (ret < 0)
        return ret;

    return 0;
}

static uint32_t pick_new_port(void) {
    uint32_t max_port = 1000; /* start port numbering from 1000, for no particular reason */
    for (int i = 0; i < VSOCK_MAX_CONNECTIONS; i++)
        if (g_vsock->conns[i].guest_port > max_port)
            max_port = g_vsock->conns[i].guest_port;
    return max_port + 1;
}

static void init_connection(struct virtio_vsock_connection* conn) {
    conn->state = VIRTIO_VSOCK_CLOSE;
    conn->host_port    = 0;
    conn->guest_port   = 0;
    conn->pending_conn = VSOCK_MAX_CONNECTIONS;
    conn->prepared_for_user = 0;
    conn->consumed_by_user  = 0;
}

static void reinit_connection(struct virtio_vsock_connection* conn) {
    while (conn->consumed_by_user != conn->prepared_for_user) {
        free(conn->packets_for_user[conn->consumed_by_user % VSOCK_MAX_PACKETS]);
        conn->consumed_by_user++;
    }
    init_connection(conn);
}

static struct virtio_vsock_packet* generate_packet(struct virtio_vsock_connection* conn,
                                                   enum virtio_vsock_packet_op op,
                                                   const char* payload, size_t payload_size,
                                                   uint32_t flags) {
    assert(conn);
    assert(payload_size <= VSOCK_MAX_PAYLOAD_SIZE);

    struct virtio_vsock_packet* packet = malloc(sizeof(*packet));
    if (!packet)
        return NULL;
    memset(packet, 0, sizeof(*packet)); /* for sanity */

    packet->header.dst_cid  = g_vsock->host_cid;
    packet->header.src_cid  = g_vsock->guest_cid;

    packet->header.dst_port = conn->host_port;
    packet->header.src_port = conn->guest_port;

    packet->header.type  = VIRTIO_VSOCK_TYPE_STREAM;
    packet->header.op    = op;
    packet->header.flags = flags;

    packet->header.buf_alloc = g_vsock->buf_alloc;
    packet->header.fwd_cnt   = g_vsock->fwd_cnt;

    packet->header.size = payload_size;
    memcpy(packet->payload, payload, payload_size);

    return packet;
}

/* sends the RST response packet and frees the `in` packet */
static int neglect_packet_and_free(struct virtio_vsock_packet* in) {
    int ret;
    struct virtio_vsock_packet* packet = NULL;

    if (in->header.op == VIRTIO_VSOCK_OP_RST) {
        ret = 0;
        goto out;
    }

    packet = malloc(sizeof(*packet));
    if (!packet) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    memset(packet, 0, sizeof(*packet)); /* for sanity */

    packet->header.dst_cid  = in->header.src_cid;
    packet->header.src_cid  = in->header.dst_cid;
    packet->header.dst_port = in->header.src_port;
    packet->header.src_port = in->header.dst_port;

    packet->header.type  = in->header.type;
    packet->header.op    = VIRTIO_VSOCK_OP_RST;
    packet->header.flags = 0;

    packet->header.buf_alloc = g_vsock->buf_alloc;
    packet->header.fwd_cnt   = g_vsock->fwd_cnt;

    packet->header.size = 0;

    ret = copy_into_tq(packet);
out:
    free(packet);
    free(in);
    return ret;
}

static int send_reset_packet(struct virtio_vsock_connection* conn) {
    struct virtio_vsock_packet* packet;

    packet = generate_packet(conn, VIRTIO_VSOCK_OP_RST,
                             /*payload=*/NULL, /*payload_size=*/0, /*flags=*/0);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    int ret = copy_into_tq(packet);
	free(packet);
    return ret;
}

static int send_request_packet(struct virtio_vsock_connection* conn) {
    struct virtio_vsock_packet* packet;

    packet = generate_packet(conn, VIRTIO_VSOCK_OP_REQUEST,
                             /*payload=*/NULL, /*payload_size=*/0, /*flags=*/0);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    int ret = copy_into_tq(packet);
	free(packet);
    return ret;
}

static int send_response_packet(struct virtio_vsock_connection* conn) {
    struct virtio_vsock_packet* packet;

    packet = generate_packet(conn, VIRTIO_VSOCK_OP_RESPONSE,
                             /*payload=*/NULL, /*payload_size=*/0, /*flags=*/0);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    int ret = copy_into_tq(packet);
	free(packet);
    return ret;
}

static int send_credit_update_packet(struct virtio_vsock_connection* conn) {
    struct virtio_vsock_packet* packet;

    packet = generate_packet(conn, VIRTIO_VSOCK_OP_CREDIT_UPDATE,
                             /*payload=*/NULL, /*payload_size=*/0, /*flags=*/0);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    /* packet is already updated with fwd_cnt and buf_alloc */

    int ret = copy_into_tq(packet);
	free(packet);
    return ret;
}

static int send_shutdown_packet(struct virtio_vsock_connection* conn,
                                enum virtio_vsock_shutdown flags) {
    struct virtio_vsock_packet* packet;

    packet = generate_packet(conn, VIRTIO_VSOCK_OP_SHUTDOWN,
                             /*payload=*/NULL, /*payload_size=*/0, flags);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    int ret = copy_into_tq(packet);
	free(packet);
    return ret;
}

static int send_rw_packet(struct virtio_vsock_connection* conn, const char* payload,
                          size_t payload_size) {
    struct virtio_vsock_packet* packet;

    /* payload is memcpy'd into the generated packet, so payload may be freed later */
    packet = generate_packet(conn, VIRTIO_VSOCK_OP_RW, payload, payload_size, /*flags=*/0);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    int ret = copy_into_tq(packet);
	free(packet);
    return ret;
}

/* takes ownership of the packet */
static int recv_rw_packet(struct virtio_vsock_connection* conn,
                          struct virtio_vsock_packet* packet) {
    uint32_t in_flight_packets_cnt = conn->prepared_for_user - conn->consumed_by_user;
    if (in_flight_packets_cnt >= VSOCK_MAX_PACKETS) {
        log_warning("RX vsock queue is full, have to drop incoming RW packet (payload size %u)",
                     packet->header.size);
        free(packet);
        return -PAL_ERROR_NOMEM;
    }

    uint32_t idx = conn->prepared_for_user % VSOCK_MAX_PACKETS;
    conn->packets_for_user[idx] = packet; /* packet is now owned by conn */
    conn->prepared_for_user++;

    g_vsock->msg_cnt++;
    g_vsock->fwd_cnt += packet->header.size;
    return 0;
}

/* takes ownership of the packet and frees it in the end */
static int process_packet(struct virtio_vsock_packet* packet) {
    int ret;
    struct virtio_vsock_connection* conn = NULL;

    if (packet->header.size > VSOCK_MAX_PAYLOAD_SIZE) {
        log_error("malicious size of packet (%u)", packet->header.size);
        neglect_packet_and_free(packet);
        return -PAL_ERROR_DENIED;
    }

    if (packet->header.type != VIRTIO_VSOCK_TYPE_STREAM) {
        log_error("only stream type packets are supported in vsock");
        neglect_packet_and_free(packet);
        return -PAL_ERROR_NOTSUPPORT;
    }

    if (packet->header.op == VIRTIO_VSOCK_OP_INVALID || packet->header.op >= VIRTIO_VSOCK_OP_MAX) {
        log_error("wrong operation (%d) on vsock packet is received", packet->header.op);
        neglect_packet_and_free(packet);
        return -PAL_ERROR_NOTSUPPORT;
    }

    if (packet->header.dst_cid != g_vsock->guest_cid ||
            packet->header.src_cid != g_vsock->host_cid) {
        log_error("vsock packet guest/host CIDs do not match guest/host");
        neglect_packet_and_free(packet);
        return -PAL_ERROR_INVAL;
    }

    for (int i = 0; i < VSOCK_MAX_CONNECTIONS; i++) {
        /* guest and host CIDs are set in stone, so it is enough to distinguish connections based
         * on the host's port (which is the `src_port` in the incoming packet) */
        if (packet->header.src_port == g_vsock->conns[i].host_port) {
            conn = &g_vsock->conns[i];
            break;
        }
    }

    if (!conn && packet->header.op == VIRTIO_VSOCK_OP_REQUEST) {
        for (size_t i = 0; i < VSOCK_MAX_CONNECTIONS; i++) {
            if (g_vsock->conns[i].state == VIRTIO_VSOCK_LISTEN &&
                    packet->header.dst_port == g_vsock->conns[i].guest_port) {
                conn = &g_vsock->conns[i];
                break;
            }
        }
    }

    if (!conn) {
        neglect_packet_and_free(packet);
        return -PAL_ERROR_INVAL;
    }

    g_vsock->peer_fwd_cnt   = packet->header.fwd_cnt;
    g_vsock->peer_buf_alloc = packet->header.buf_alloc;

    switch (conn->state) {
        case VIRTIO_VSOCK_LISTEN:
            if (packet->header.op != VIRTIO_VSOCK_OP_REQUEST) {
                neglect_packet_and_free(packet);
                return -PAL_ERROR_DENIED;
            }
            if (conn->pending_conn != VSOCK_MAX_CONNECTIONS) {
                /* there is already one pending connection on this listening socket */
                log_warning("vsock backlog full, dropping connection");
                neglect_packet_and_free(packet);
                return -PAL_ERROR_NOMEM;
            }
            /* create new connection */
            struct virtio_vsock_connection* new_conn = NULL;
            int i;
            for (i = 0; i < VSOCK_MAX_CONNECTIONS; i++) {
                if (g_vsock->conns[i].state == VIRTIO_VSOCK_CLOSE) {
                    new_conn = &g_vsock->conns[i];
                    break;
                }
            }
            if (!new_conn) {
                log_warning("no free vsock FDs for new connection");
                neglect_packet_and_free(packet);
                return -PAL_ERROR_NOMEM;
            }
            new_conn->state      = VIRTIO_VSOCK_ESTABLISHED;
            new_conn->host_port  = packet->header.src_port;
            new_conn->guest_port = pick_new_port();
            ret = send_response_packet(new_conn);
            if (ret < 0) {
                neglect_packet_and_free(packet);
                reinit_connection(new_conn);
                return ret;
            }
            /* unblock accept() syscall */
            conn->pending_conn = i;
            free(packet);
            return 0;

        case VIRTIO_VSOCK_CONNECT:
            if (packet->header.op != VIRTIO_VSOCK_OP_RESPONSE) {
                neglect_packet_and_free(packet);
                return -PAL_ERROR_DENIED;
            }
            conn->state = VIRTIO_VSOCK_ESTABLISHED;
            free(packet);
            return 0;

        case VIRTIO_VSOCK_ESTABLISHED:
            switch (packet->header.op) {
                case VIRTIO_VSOCK_OP_RW:
                    return recv_rw_packet(conn, packet);
                case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
                    free(packet);
                    return send_credit_update_packet(conn);
                case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
                    /* we already updated peer_fwd_cnt and peer_buf_alloc above */
                    free(packet);
					return 0;
                case VIRTIO_VSOCK_OP_SHUTDOWN:
                    /* FIXME: we do not look at packet.header.flags currently */
                    send_reset_packet(conn); /* notify host that we ack this shutdown cleanly */
                    /* fallthrough */
                case VIRTIO_VSOCK_OP_RST:
                    free(packet);
                    reinit_connection(conn);
					return 0;
                default:
                    /* unknown operation */
                    neglect_packet_and_free(packet);
                    return -PAL_ERROR_DENIED;
            }

        case VIRTIO_VSOCK_CLOSING:
            if (packet->header.op != VIRTIO_VSOCK_OP_RST &&
                    packet->header.op != VIRTIO_VSOCK_OP_SHUTDOWN) {
                neglect_packet_and_free(packet);
                return -PAL_ERROR_DENIED;
            }
            conn->state = VIRTIO_VSOCK_CLOSE;
            free(packet);
            return 0;

        case VIRTIO_VSOCK_CLOSE:
            /* all packets are wrong in this state */
            neglect_packet_and_free(packet);
            return -PAL_ERROR_DENIED;
    }

    free(packet);
    return -PAL_ERROR_DENIED;
}

static int virtio_vsock_negotiate_features(struct virtio_vsock* vsock) {
    struct virtio_pci_regs* pci_regs = vsock->pci_regs;

    uint32_t understood_features = 0;
    uint32_t advertised_features = 0;

    /* negotiate feature bits 31..0 */
    vm_mmio_writel(&pci_regs->device_feature_select, 0);
    advertised_features = vm_mmio_readl(&pci_regs->device_feature);

    (void)advertised_features; /* currently no feature bits for vsock device */

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

static int virtio_vsock_alloc(struct virtio_vsock** out_vsock) {
    int ret;
    struct virtio_vsock* vsock = NULL;
    char* shared_rq_buf = NULL;
    char* shared_tq_buf = NULL;
    struct virtqueue* rq = NULL;
    struct virtqueue* tq = NULL;
    struct virtqueue* eq = NULL; /* currently not used */

    vsock = malloc(sizeof(*vsock));
    if (!vsock)
        return -PAL_ERROR_NOMEM;
    memset(vsock, 0, sizeof(*vsock)); /* for sanity */

    shared_rq_buf = memory_get_shared_region(VIRTIO_VSOCK_SHARED_BUF_SIZE);
    shared_tq_buf = memory_get_shared_region(VIRTIO_VSOCK_SHARED_BUF_SIZE);
    if (!shared_rq_buf || !shared_tq_buf) {
        ret = -PAL_ERROR_NOMEM;
        goto fail;
    }

    ret = virtq_create(VIRTIO_VSOCK_QUEUE_SIZE, &rq);
    if (ret < 0)
        goto fail;

    ret = virtq_create(VIRTIO_VSOCK_QUEUE_SIZE, &tq);
    if (ret < 0)
        goto fail;

    ret = virtq_create(VIRTIO_VSOCK_EVENT_QUEUE_SIZE, &eq);
    if (ret < 0)
        goto fail;

    vsock->rq = rq;
    vsock->tq = tq;
    vsock->eq = eq;

    /* prepare all buffers in RX for usage by host */
    for (size_t i = 0; i < VIRTIO_VSOCK_QUEUE_SIZE; i++) {
        uint16_t desc_idx;
        ret = virtq_alloc_desc(rq, /*addr=*/NULL, sizeof(struct virtio_vsock_packet),
                               VIRTQ_DESC_F_WRITE, &desc_idx);
        if (ret < 0)
            goto fail;

        /* we found a free descriptor above and used a dummy NULL address, now let's rewire it */
        char* shared_packet = (char*)shared_rq_buf + desc_idx * sizeof(struct virtio_vsock_packet);
        vm_shared_writeq(&rq->desc[desc_idx].addr, (uint64_t)shared_packet);

        vm_shared_writew(&rq->avail->ring[i], desc_idx);
    }

    rq->cached_avail_idx = VIRTIO_VSOCK_QUEUE_SIZE;
    vm_shared_writew(&rq->avail->idx, rq->cached_avail_idx);

    vsock->shared_rq_buf = shared_rq_buf;
    vsock->shared_tq_buf = shared_tq_buf;
    vsock->rq = rq;
    vsock->tq = tq;
    vsock->eq = eq;

    *out_vsock = vsock;
    return 0;
fail:
    memory_free_shared_region(shared_rq_buf, VIRTIO_VSOCK_SHARED_BUF_SIZE);
    memory_free_shared_region(shared_tq_buf, VIRTIO_VSOCK_SHARED_BUF_SIZE);
    virtq_free(rq, VIRTIO_VSOCK_QUEUE_SIZE);
    virtq_free(tq, VIRTIO_VSOCK_QUEUE_SIZE);
    virtq_free(eq, VIRTIO_VSOCK_EVENT_QUEUE_SIZE);
    free(vsock);
    return ret;
}

static int virtio_vsock_free(struct virtio_vsock* vsock) {
    memory_free_shared_region(vsock->shared_rq_buf, VIRTIO_VSOCK_SHARED_BUF_SIZE);
    memory_free_shared_region(vsock->shared_tq_buf, VIRTIO_VSOCK_SHARED_BUF_SIZE);
    virtq_free(vsock->rq, VIRTIO_VSOCK_QUEUE_SIZE);
    virtq_free(vsock->tq, VIRTIO_VSOCK_QUEUE_SIZE);
    virtq_free(vsock->eq, VIRTIO_VSOCK_EVENT_QUEUE_SIZE);
    free(vsock);
    return 0;
}

int virtio_vsock_init(struct virtio_pci_regs* pci_regs, struct virtio_vsock_config* pci_config,
                      uint64_t notify_off_addr, uint32_t notify_off_multiplier,
                      uint32_t* interrupt_status_reg) {
    int ret;
    uint32_t status;

    struct virtio_vsock* vsock;
    ret = virtio_vsock_alloc(&vsock);
    if (ret < 0)
        return ret;

    vsock->pci_regs = pci_regs;
    vsock->pci_config = pci_config;
    vsock->interrupt_status_reg = interrupt_status_reg;

    ret = virtio_vsock_negotiate_features(vsock);
    if (ret < 0)
        goto fail;

    status = vm_mmio_readb(&pci_regs->device_status);
    vm_mmio_writeb(&pci_regs->device_status, status | VIRTIO_STATUS_FEATURES_OK);


    status = vm_mmio_readb(&pci_regs->device_status);
    if (!(status & VIRTIO_STATUS_FEATURES_OK)) {
        /* host device (vhost-vsock) did not accept our features */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    ret = virtq_add_to_device(pci_regs, vsock->rq, /*queue_sel=*/0);
    if (ret < 0)
        goto fail;

    ret = virtq_add_to_device(pci_regs, vsock->tq, /*queue_sel=*/1);
    if (ret < 0)
        goto fail;

    ret = virtq_add_to_device(pci_regs, vsock->eq, /*queue_sel=*/2);
    if (ret < 0)
        goto fail;

    vm_mmio_writew(&pci_regs->queue_select, 0);
    uint64_t rq_notify_off = vm_mmio_readw(&pci_regs->queue_notify_off);
    vsock->rq_notify_addr = (uint16_t*)(notify_off_addr + rq_notify_off * notify_off_multiplier);

    if (!(PCI_MMIO_START_ADDR <= (uintptr_t)vsock->rq_notify_addr &&
                (uintptr_t)vsock->rq_notify_addr < PCI_MMIO_END_ADDR)) {
        /* incorrect or malicious RQ queue notify addr */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    vm_mmio_writew(&pci_regs->queue_select, 1);
    uint64_t tq_notify_off = vm_mmio_readw(&pci_regs->queue_notify_off);
    vsock->tq_notify_addr = (uint16_t*)(notify_off_addr + tq_notify_off * notify_off_multiplier);

    if (!(PCI_MMIO_START_ADDR <= (uintptr_t)vsock->tq_notify_addr &&
                (uintptr_t)vsock->tq_notify_addr < PCI_MMIO_END_ADDR)) {
        /* incorrect or malicious TQ queue notify addr */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    status = vm_mmio_readb(&pci_regs->device_status);
    vm_mmio_writeb(&pci_regs->device_status, status | VIRTIO_STATUS_DRIVER_OK);

    vsock->guest_cid = vm_mmio_readq(&vsock->pci_config->guest_cid);
    if (vsock->guest_cid <= 2 || vsock->guest_cid >= 0xffffffff) {
        /* incorrect or malicious guest CID: CIDs 0,1,0xffffffff are reserved, CID 2 is for the
         * host, and upper 32 bits of CID must be zeroed */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    for (size_t i = 0; i < VSOCK_MAX_CONNECTIONS; i++)
        init_connection(&g_vsock->conns[i]);

    vsock->host_cid  = VSOCK_HOST_CID;
    vsock->tx_cnt    = 0;
    vsock->fwd_cnt   = 0;
    vsock->buf_alloc = VSOCK_MAX_PACKETS * sizeof(struct virtio_vsock_packet);

    g_vsock = vsock;
    return 0;

fail:
    virtio_vsock_free(vsock);
    status = vm_mmio_readb(&pci_regs->device_status);
    vm_mmio_writeb(&pci_regs->device_status, status | VIRTIO_STATUS_FAILED);
    return ret;
}

int virtio_vsock_socket(int domain, int type, int protocol) {
    if (domain != AF_VSOCK)
        return -PAL_ERROR_AFNOSUPPORT;

    if (type != VIRTIO_VSOCK_TYPE_STREAM)
        return -PAL_ERROR_INVAL;

    if (protocol != 0)
        return -PAL_ERROR_NOTSUPPORT;

    struct virtio_vsock_connection* conn = NULL;
    int i;
    for (i = 0; i < VSOCK_MAX_CONNECTIONS; i++) {
        if (g_vsock->conns[i].state == VIRTIO_VSOCK_CLOSE) {
            conn = &g_vsock->conns[i];
            break;
        }
    }

    if (!conn)
        return -PAL_ERROR_DENIED;

    init_connection(conn);
    return i;
}

int virtio_vsock_bind(int sockfd, const void* addr, size_t addrlen, uint16_t* out_new_port) {
    if (!addr || addrlen < sizeof(struct sockaddr_vm))
        return -PAL_ERROR_INVAL;

    if (sockfd < 0 || sockfd >= VSOCK_MAX_CONNECTIONS)
        return -PAL_ERROR_BADHANDLE;

    struct virtio_vsock_connection* conn = &g_vsock->conns[sockfd];
    if (conn->state != VIRTIO_VSOCK_CLOSE || conn->guest_port != 0)
        return -PAL_ERROR_INVAL;

    struct sockaddr_vm* addr_vm = (struct sockaddr_vm*)addr;
    if (addr_vm->svm_family != AF_VSOCK || addr_vm->svm_cid != g_vsock->guest_cid)
        return -PAL_ERROR_INVAL;

    uint32_t bind_to_port = addr_vm->svm_port;
    if (bind_to_port == 0) {
        bind_to_port = pick_new_port();
    } else {
        for (int i = 0; i < VSOCK_MAX_CONNECTIONS; i++) {
            if (i == sockfd || g_vsock->conns[i].state == VIRTIO_VSOCK_CLOSE)
                continue;
            if (g_vsock->conns[i].guest_port == bind_to_port)
                return -PAL_ERROR_STREAMEXIST;
        }
    }

    if (out_new_port)
        *out_new_port = bind_to_port;

    conn->guest_port = bind_to_port;
    conn->host_port  = 0;
    return 0;
}

int virtio_vsock_listen(int sockfd, int backlog) {
    __UNUSED(backlog);

    if (sockfd < 0 || sockfd >= VSOCK_MAX_CONNECTIONS)
        return -PAL_ERROR_BADHANDLE;

    struct virtio_vsock_connection* conn = &g_vsock->conns[sockfd];
    if (conn->state != VIRTIO_VSOCK_CLOSE)
        return -PAL_ERROR_STREAMEXIST;

    if (conn->guest_port == 0) /* not yet bound */
        return -PAL_ERROR_STREAMNOTEXIST;

    conn->state = VIRTIO_VSOCK_LISTEN;
    conn->pending_conn = VSOCK_MAX_CONNECTIONS;
    return 0;
}

int virtio_vsock_accept(int sockfd, void* addr, size_t* addrlen) {
    if (!addr || !addrlen || *addrlen < sizeof(struct sockaddr_vm))
        return -PAL_ERROR_INVAL;

    if (sockfd < 0 || sockfd >= VSOCK_MAX_CONNECTIONS)
        return -PAL_ERROR_BADHANDLE;

    struct virtio_vsock_connection* conn = &g_vsock->conns[sockfd];
    if (conn->state != VIRTIO_VSOCK_LISTEN)
        return -PAL_ERROR_INVAL;

    if (conn->pending_conn == VSOCK_MAX_CONNECTIONS) {
        /* non-blocking caller must return TRYAGAIN; blocking caller must sleep on this */
        return -PAL_ERROR_TRYAGAIN;
    }

    uint32_t accepted_conn = conn->pending_conn;

    *addrlen = sizeof(struct sockaddr_vm);
    struct sockaddr_vm* addr_vm = (struct sockaddr_vm*)addr;
    addr_vm->svm_family = AF_VSOCK;
    addr_vm->svm_reserved1 = 0;
    addr_vm->svm_cid = g_vsock->host_cid;
    addr_vm->svm_port = g_vsock->conns[accepted_conn].host_port;

    conn->pending_conn = VSOCK_MAX_CONNECTIONS;
    return accepted_conn;
}

int virtio_vsock_connect(int sockfd, const void* addr, size_t addrlen) {
    if (!addr || addrlen < sizeof(struct sockaddr_vm))
        return -PAL_ERROR_INVAL;

    if (sockfd < 0 || sockfd >= VSOCK_MAX_CONNECTIONS)
        return -PAL_ERROR_BADHANDLE;

    struct virtio_vsock_connection* conn = &g_vsock->conns[sockfd];
    if (conn->state != VIRTIO_VSOCK_CLOSE)
        return -PAL_ERROR_STREAMEXIST;

    struct sockaddr_vm* addr_vm = (struct sockaddr_vm*)addr;
    conn->host_port  = addr_vm->svm_port;
    conn->guest_port = pick_new_port();

    int ret = send_request_packet(conn);
    if (ret < 0)
        return ret;

    conn->state = VIRTIO_VSOCK_CONNECT;

    uint32_t tries = 0;
    while (conn->state != VIRTIO_VSOCK_ESTABLISHED) {
        /* FIXME: we emulate timeout via a counter */
        if (tries++ == 1024 * 1024) {
            init_connection(conn);
            return -PAL_ERROR_CONNFAILED;
        }
		CPU_RELAX();
    }

    return 0;
}

int virtio_vsock_getsockname(int sockfd, const void* addr, size_t* addrlen) {
    if (!addr || !addrlen || *addrlen < sizeof(struct sockaddr_vm))
        return -PAL_ERROR_INVAL;

    if (sockfd < 0 || sockfd >= VSOCK_MAX_CONNECTIONS)
        return -PAL_ERROR_BADHANDLE;

    struct virtio_vsock_connection* conn = &g_vsock->conns[sockfd];
    if (conn->state == VIRTIO_VSOCK_CLOSE)
        return -PAL_ERROR_BADHANDLE;

    *addrlen = sizeof(struct sockaddr_vm);
    struct sockaddr_vm* addr_vm = (struct sockaddr_vm*)addr;
    addr_vm->svm_family = AF_VSOCK;
    addr_vm->svm_reserved1 = 0;
    addr_vm->svm_cid = g_vsock->guest_cid;
    addr_vm->svm_port = conn->guest_port;
    return 0;
}

long virtio_vsock_peek(int sockfd) {
    if (sockfd < 0 || sockfd >= VSOCK_MAX_CONNECTIONS)
        return -PAL_ERROR_BADHANDLE;

    struct virtio_vsock_connection* conn = &g_vsock->conns[sockfd];

    if (conn->state == VIRTIO_VSOCK_LISTEN) {
        return conn->pending_conn == VSOCK_MAX_CONNECTIONS ? 0 : 1;
    } else if (conn->state == VIRTIO_VSOCK_ESTABLISHED) {
        size_t peeked = 0;
        uint32_t peek_at = conn->consumed_by_user;
        while (conn->prepared_for_user != peek_at) {
            peeked += conn->packets_for_user[peek_at % VSOCK_MAX_PACKETS]->header.size;
            peek_at++;
        }
        return (long)peeked;
    }

    return -PAL_ERROR_INVAL;
}

long virtio_vsock_read(int sockfd, void* buf, size_t count) {
    if (!buf)
        return -PAL_ERROR_BADADDR;

    if (sockfd < 0 || sockfd >= VSOCK_MAX_CONNECTIONS)
        return -PAL_ERROR_BADHANDLE;

    struct virtio_vsock_connection* conn = &g_vsock->conns[sockfd];
    if (conn->state != VIRTIO_VSOCK_ESTABLISHED)
        return -PAL_ERROR_INVAL;

    if (count == 0)
        return 0;

    if (conn->prepared_for_user == conn->consumed_by_user) {
        /* non-blocking caller must return TRYAGAIN; blocking caller must sleep on this */
        return -PAL_ERROR_TRYAGAIN;
    }

    size_t copied = 0;
    while (conn->prepared_for_user != conn->consumed_by_user) {
        uint32_t idx = conn->consumed_by_user % VSOCK_MAX_PACKETS;
        if (copied + conn->packets_for_user[idx]->header.size > count) {
            /* user-supplied buffer won't fit the next message: copy whatever is possible,
             * trim the message and return the result */
            memcpy(buf + copied, conn->packets_for_user[idx]->payload, count - copied);

            size_t payload_bytes_copied = count - copied;
            memmove(conn->packets_for_user[idx]->payload,
                    conn->packets_for_user[idx]->payload + payload_bytes_copied,
                    conn->packets_for_user[idx]->header.size - payload_bytes_copied);
            conn->packets_for_user[idx]->header.size -= payload_bytes_copied;

            copied = count;
            break;
        }

        memcpy(buf + copied, conn->packets_for_user[idx]->payload,
               conn->packets_for_user[idx]->header.size);
        copied += conn->packets_for_user[idx]->header.size;
        conn->consumed_by_user++;
        free(conn->packets_for_user[idx]);
    }

    return (long)copied;
}

long virtio_vsock_write(int sockfd, const void* buf, size_t count) {
    int ret;

    if (!buf)
        return -PAL_ERROR_BADADDR;

    if (sockfd < 0 || sockfd >= VSOCK_MAX_CONNECTIONS)
        return -PAL_ERROR_BADHANDLE;

    struct virtio_vsock_connection* conn = &g_vsock->conns[sockfd];
    if (conn->state != VIRTIO_VSOCK_ESTABLISHED)
        return -PAL_ERROR_INVAL;

    if (count == 0)
        return 0;

    size_t sent = 0;
    while (sent < count) {
        size_t payload_size = MIN(count - sent, VSOCK_MAX_PAYLOAD_SIZE);
        ret = send_rw_packet(conn, buf + sent, payload_size);
        if (ret < 0) {
            if (ret == -PAL_ERROR_NOMEM && sent != 0) {
                /* TX buffer is full, do not return error but instead whatever was sent */
                return (long)sent;
            }
            if (ret == -PAL_ERROR_NOMEM) {
                /* TX buffer is full and we haven't sent anything -> a write would block;
                 * non-blocking caller must return TRYAGAIN; blocking caller must sleep on this */
                return -PAL_ERROR_TRYAGAIN;
            }
            return ret;
        }
        sent += payload_size;
    }

    return sent;
}

int virtio_vsock_shutdown(int sockfd, int how) {
    __UNUSED(how);

    if (sockfd < 0 || sockfd >= VSOCK_MAX_CONNECTIONS)
        return -PAL_ERROR_BADHANDLE;

    struct virtio_vsock_connection* conn = &g_vsock->conns[sockfd];
    if (conn->state == VIRTIO_VSOCK_ESTABLISHED || conn->state == VIRTIO_VSOCK_LISTEN) {
        int ret = send_shutdown_packet(conn, VIRTIO_VSOCK_SHUTDOWN_COMPLETE);
        if (ret < 0)
            return ret;

        conn->state = VIRTIO_VSOCK_CLOSING;
        uint32_t tries = 0;
        while (conn->state != VIRTIO_VSOCK_CLOSE) {
            /* FIXME: we emulate timeout via a counter */
            if (tries++ == 1024 * 1024)
                break;
            CPU_RELAX();
        }
    }

    reinit_connection(conn);
    return 0;
}

int virtio_vsock_close(int sockfd) {
    return virtio_vsock_shutdown(sockfd, VIRTIO_VSOCK_SHUTDOWN_COMPLETE);
}
