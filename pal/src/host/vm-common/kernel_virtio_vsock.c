/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Implementation of virtio-vsock.
 *
 * Reference: https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.pdf
 *
 * TODO:
 * - Buffer space management via buf_alloc, fwd_cnt, tx_cnt (see section 5.10.6.3 in spec)
 *
 * Diagram with flows:
 *
 *   Bottomhalves thread (CPU0)                       +  App threads (CPU0-CPUn)
 *                                                    |
 *   handle_rq()                                      |  virtio_vsock_socket()
 *     +                                              |  virtio_vsock_bind()
 *     +--> g_vsock->rq ops                           |  virtio_vsock_listen()
 *          malloc(packet)                            |  virtio_vsock_accept()
 *          memcpy(packet, g_vsock->rq->rq_buf)       |  virtio_vsock_getsockname()
 *          process_packet(packet)                    |  virtio_vsock_peek()
 *            +                                       |  virtio_vsock_read()
 *            +--> g_vsock->conns ops                 |    +
 *            |    existing conn ops                  |    +--> g_vsock->conns ops
 *            |    new conn ops (on LISTEN)           |         existing conn ops
 *            |    send new (response) packet or...   |         new conn ops where applicable
 *            |      +                                |
 *            |      | neglect_packet()               |  virtio_vsock_connect()
 *            |      | send_response_packet()         |    +
 *            |      | send_credit_update_packet()    |    +--> g_vsock->conns ops
 *            |      | send_reset_packet()            |    |    existing conn ops
 *            |      |                                |    |    send_request_packet()
 *            |      +--> copy_into_tq(new_packet)    |    |      +
 *            |             +                         |    |      +--> copy_into_tq(new_packet)
 *            |             +--> g_vsock->tq ops      |    |
 *            |                                       |    +--> wait(conn) for response packet
 *            +--> free(packet)                       |
 *            |                                       |  virtio_vsock_write()
 *            +--> ...or recv_rw_packet()             |    +
 *                   +                                |    +--> g_vsock->conns ops
 *                   +--> mv packet to existing conn  |         existing conn ops
 *                                                    |         send_rw_packet()
 *   cleanup_tq()                                     |           +
 *     +                                              |           +--> copy_into_tq(new_packet)
 *     +--> g_vsock->tq ops                           |
 *                                                    |  virtio_vsock_shutdown()
 *                                                    |  virtio_vsock_close()
 *                                                    |    +
 *                                                    |    +--> g_vsock->conns ops
 *                                                    |    |    existing conn ops
 *                                                    |    |    send_shutdown_packet()
 *                                                    |    |      +
 *                                                    |    |      +--> copy_into_tq(new_packet)
 *                                                    |    |
 *                                                    +    +--> wait(conn) for response packet
 *
 * Notes:
 *   - g_vsock->rq operations happen only in the CPU0-tied bottomhalves thread, thus they do not
 *     really need any sync/locking. But we add a "receive" lock anyway, for uniformity and to be
 *     future proof.
 *   - g_vsock->tq operations happen on different CPUs, thus they must be protected with a single
 *     global "transmit" lock.
 *   - g_vsock->pending_tq_control_packets operations happen on different CPUs and operate on the
 *     TQ, thus they must be protected with a single global "transmit" lock.
 *   - g_vsock->conns operations happen on different CPUs, thus they must be protected with a single
 *     global "connections" lock.
 *   - Operations on the same connection happen on different CPUs, thus each connection must be
 *     protected with a lock. For simplicity, all connections are protected with a single global
 *     "connections" lock.
 *   - Packets always belong to RQ or TQ or a certain connection, so they can reuse RQ/TQ/conn locks
 *     and don't need separate locks.
 *
 * Order of locks must be: g_vsock->rq --> g_vsock->conns --> g_vsock->tq. This order guarantees no
 * deadlocks.
 */

#include "api.h"
#include "pal_error.h"

#include "kernel_apic.h"
#include "kernel_memory.h"
#include "kernel_pci.h"
#include "kernel_sched.h"
#include "kernel_time.h"
#include "kernel_virtio.h"
#include "kernel_virtio_vsock.h"
#include "vm_callbacks.h"

#define VIRTIO_VSOCK_SHARED_BUF_SIZE (VIRTIO_VSOCK_QUEUE_SIZE * sizeof(struct virtio_vsock_packet))

struct virtio_vsock* g_vsock = NULL;
bool g_vsock_trigger_bottomhalf = false;

/* coarse-grained locks to sync RX, TX and connections' operations on multi-core systems, see also
 * flow diagram above and kernel_virtio.h */
static spinlock_t g_vsock_receive_lock = INIT_SPINLOCK_UNLOCKED;
static spinlock_t g_vsock_transmit_lock = INIT_SPINLOCK_UNLOCKED;
static spinlock_t g_vsock_connections_lock = INIT_SPINLOCK_UNLOCKED;

static int cleanup_tq(void);
static int process_packet(struct virtio_vsock_packet* packet);
static void remove_connection(struct virtio_vsock_connection* conn);

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
        __atomic_store_n(&g_vsock_trigger_bottomhalf, true, __ATOMIC_RELEASE);
    }

    if (interrupt_status & VIRTIO_INTERRUPT_STATUS_CONFIG) {
        /* we don't currently care about changes in device config, so noop */
    }

    return 0;
}

static int handle_rq(uint16_t host_used_idx, bool* out_received) {
    assert(spinlock_is_locked(&g_vsock_receive_lock));

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
        *out_received = true;
    }

    return 0;
}

static int handle_rq_with_disabled_notifications(void) {
    int ret;
    bool received = false;

    spinlock_lock(&g_vsock_receive_lock);

    /* disable interrupts (we anyhow will consume all inputs on RX) */
    vm_shared_writew(&g_vsock->rq->avail->flags, VIRTQ_AVAIL_F_NO_INTERRUPT);

    while (true) {
        uint16_t host_used_idx = vm_shared_readw(&g_vsock->rq->used->idx);
        if (host_used_idx != g_vsock->rq->seen_used) {
            ret = handle_rq(host_used_idx, &received);
            if (ret < 0)
                goto fail;
        }

        vm_shared_writew(&g_vsock->rq->avail->flags, 0); /* reenable interrupts */
        uint16_t reread_host_used_idx = vm_shared_readw(&g_vsock->rq->used->idx);
        if (reread_host_used_idx == g_vsock->rq->seen_used)
            break;

        /* disable interrupts and process RX again (that's a corner case: after the last check and
         * before enabling interrupts, an interrupt has been suppressed by the device) */
        vm_shared_writew(&g_vsock->rq->avail->flags, VIRTQ_AVAIL_F_NO_INTERRUPT);
    }

    spinlock_unlock(&g_vsock_receive_lock);

    if (received) {
        uint16_t host_device_used_flags = vm_shared_readw(&g_vsock->rq->used->flags);
        if (!(host_device_used_flags & VIRTQ_USED_F_NO_NOTIFY))
            vm_mmio_writew(g_vsock->rq_notify_addr, /*queue_sel=*/0);
        thread_wakeup_vsock(/*is_read=*/true);
    }

    return 0;

fail:
    vm_shared_writew(&g_vsock->rq->avail->flags, 0); /* reenable interrupts */
    spinlock_unlock(&g_vsock_receive_lock);
    return ret;
}

/* called only by copy_into_tq_and_free() and copy_into_tq_or_add_to_pending() */
static void copy_into_tq_internal(struct virtio_vsock_packet* packet, uint64_t packet_size,
                                 uint16_t desc_idx) {
    assert(spinlock_is_locked(&g_vsock_transmit_lock));

    /* the received free descriptor uses a dummy NULL address, let's rewire it */
    char* shared_packet = (char*)g_vsock->shared_tq_buf + desc_idx * sizeof(*packet);
    vm_shared_writeq(&g_vsock->tq->desc[desc_idx].addr, (uint64_t)shared_packet);

    /* write to untrusted shared memory, safe */
    vm_shared_memcpy(shared_packet, packet, packet_size);

    uint16_t avail_idx = g_vsock->tq->cached_avail_idx;
    g_vsock->tq->cached_avail_idx++;

    vm_shared_writew(&g_vsock->tq->avail->ring[avail_idx % g_vsock->tq->queue_size], desc_idx);
    vm_shared_writew(&g_vsock->tq->avail->idx, g_vsock->tq->cached_avail_idx);

    g_vsock->tx_cnt += packet->header.size;

    uint16_t host_device_used_flags = vm_shared_readw(&g_vsock->tq->used->flags);
    if (!(host_device_used_flags & VIRTQ_USED_F_NO_NOTIFY))
        vm_mmio_writew(g_vsock->tq_notify_addr, /*queue_sel=*/1);
}

/* used only for data-flow packets (RW) */
static int copy_into_tq_and_free(struct virtio_vsock_packet* packet) {
    assert(g_vsock);
    assert(packet->header.op == VIRTIO_VSOCK_OP_RW);

    spinlock_lock(&g_vsock_transmit_lock);

    uint16_t desc_idx;
    uint64_t packet_size = sizeof(struct virtio_vsock_hdr) + packet->header.size;
    int ret = virtq_alloc_desc(g_vsock->tq, /*addr=*/NULL, packet_size, /*flags=*/0, &desc_idx);
    if (ret < 0) {
        /* if TQ buffer is full, drain TQ and try again */
        if (ret != -PAL_ERROR_NOMEM)
            goto out;

        spinlock_unlock(&g_vsock_transmit_lock);
        (void)cleanup_tq();
        spinlock_lock(&g_vsock_transmit_lock);

        ret = virtq_alloc_desc(g_vsock->tq, /*addr=*/NULL, packet_size, /*flags=*/0, &desc_idx);
        if (ret < 0) {
            log_warning("TX vsock queue is full, dropping outgoing RW packet (payload size %lu)",
                        packet_size);
            goto out;
        }
    }

    copy_into_tq_internal(packet, packet_size, desc_idx);
    ret = 0;
out:
    spinlock_unlock(&g_vsock_transmit_lock);
    (void)cleanup_tq();
    free(packet);
    return ret;
}

/* used only for control packets */
static int copy_into_tq_or_add_to_pending(struct virtio_vsock_packet* packet) {
    assert(g_vsock);
    assert(packet->header.op == VIRTIO_VSOCK_OP_REQUEST
              || packet->header.op == VIRTIO_VSOCK_OP_RESPONSE
              || packet->header.op == VIRTIO_VSOCK_OP_RST
              || packet->header.op == VIRTIO_VSOCK_OP_SHUTDOWN
              || packet->header.op == VIRTIO_VSOCK_OP_CREDIT_UPDATE
              || packet->header.op == VIRTIO_VSOCK_OP_CREDIT_REQUEST);

    bool packet_ownership_transferred = false;

    spinlock_lock(&g_vsock_transmit_lock);

    uint16_t desc_idx;
    uint64_t packet_size = sizeof(struct virtio_vsock_hdr) + packet->header.size;
    int ret = virtq_alloc_desc(g_vsock->tq, /*addr=*/NULL, packet_size, /*flags=*/0, &desc_idx);
    if (ret < 0 && ret != -PAL_ERROR_NOMEM)
        goto out;

    if (ret == 0) {
        copy_into_tq_internal(packet, packet_size, desc_idx);
        goto out;
    }

    /* TX buffer is full, append this control packet to a queue of pending packets */
    assert(ret == -PAL_ERROR_NOMEM);
    if (g_vsock->pending_tq_control_packets_cnt == VIRTIO_VSOCK_PENDING_TQ_CONTROL_SIZE) {
        log_error("vsock queue of pending TX control packets is full, unstable behavior possible");
        ret = -PAL_ERROR_DENIED;
        goto out;
    }
    uint32_t idx = g_vsock->pending_tq_control_packets_idx
                       + g_vsock->pending_tq_control_packets_cnt;
    g_vsock->pending_tq_control_packets[idx % VIRTIO_VSOCK_PENDING_TQ_CONTROL_SIZE] = packet;
    g_vsock->pending_tq_control_packets_cnt++;
    packet_ownership_transferred = true;

    ret = 0;
out:
    spinlock_unlock(&g_vsock_transmit_lock);
    (void)cleanup_tq();
    if (!packet_ownership_transferred)
        free(packet);
    return ret;
}

static int cleanup_tq(void) {
    int ret;
    bool sent = false;

    spinlock_lock(&g_vsock_transmit_lock);
    uint16_t host_used_idx = vm_shared_readw(&g_vsock->tq->used->idx);

    if (host_used_idx - g_vsock->tq->seen_used > g_vsock->tq->queue_size) {
        /* malicious (impossible) value reported by the host; note that this check works also in
         * cases of int wrap */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    while (host_used_idx != g_vsock->tq->seen_used) {
        uint16_t used_idx = g_vsock->tq->seen_used % g_vsock->tq->queue_size;
        uint16_t desc_idx = (uint16_t)vm_shared_readl(&g_vsock->tq->used->ring[used_idx].id);

        if (desc_idx >= g_vsock->tq->queue_size) {
            /* malicious (out of bounds) descriptor index */
            ret = -PAL_ERROR_DENIED;
            goto fail;
        }

        if (virtq_is_desc_free(g_vsock->tq, desc_idx)) {
            /* malicious descriptor index (attempt at double-free attack) */
            ret = -PAL_ERROR_DENIED;
            goto fail;
        }

        virtq_free_desc(g_vsock->tq, desc_idx);
        g_vsock->tq->seen_used++;
        sent = true;
    }
    spinlock_unlock(&g_vsock_transmit_lock);

    if (sent)
        thread_wakeup_vsock(/*is_read=*/false);

    return 0;
fail:
    spinlock_unlock(&g_vsock_transmit_lock);
    return ret;
}

static int send_pending_tq_control_packets(void) {
    int ret;

    spinlock_lock(&g_vsock_transmit_lock);

    /* prefer to use this while loop instead of for loop to handle uint overflow */
    uint32_t end_idx = g_vsock->pending_tq_control_packets_idx
                           + g_vsock->pending_tq_control_packets_cnt;
    while (g_vsock->pending_tq_control_packets_idx != end_idx) {
        uint32_t idx = g_vsock->pending_tq_control_packets_idx
                           % VIRTIO_VSOCK_PENDING_TQ_CONTROL_SIZE;
        struct virtio_vsock_packet* packet = g_vsock->pending_tq_control_packets[idx];

        uint16_t desc_idx;
        uint64_t packet_size = sizeof(struct virtio_vsock_hdr) + packet->header.size;
        ret = virtq_alloc_desc(g_vsock->tq, /*addr=*/NULL, packet_size, /*flags=*/0, &desc_idx);
        if (ret < 0) {
            /* TX buffer is full, postpone sending the rest of TQ control packets to next time */
            goto out;
        }

        copy_into_tq_internal(packet, packet_size, desc_idx);
        free(packet);

        g_vsock->pending_tq_control_packets_idx++;
        g_vsock->pending_tq_control_packets_cnt--;
    }

    ret = 0;
out:
    spinlock_unlock(&g_vsock_transmit_lock);
    return ret;
}

bool virtio_vsock_can_write(void) {
    spinlock_lock(&g_vsock_transmit_lock);
    bool can_write = (g_vsock && g_vsock->tq->free_desc != g_vsock->tq->queue_size);
    spinlock_unlock(&g_vsock_transmit_lock);
    return can_write;
}

/* called from the bottomhalf thread in normal context (not interrupt context) */
int virtio_vsock_bottomhalf(void) {
    int handle_rq_ret = handle_rq_with_disabled_notifications();
    int cleanup_tq_ret = cleanup_tq();
    int pending_tq_ret = send_pending_tq_control_packets();
    return handle_rq_ret ? handle_rq_ret : (cleanup_tq_ret ? cleanup_tq_ret : pending_tq_ret);
}

static int enlarge_conns(uint32_t new_size) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    if (new_size <= g_vsock->conns_size)
        return 0;

    struct virtio_vsock_connection** new_conns = calloc(new_size, sizeof(*new_conns));
    if (!new_conns)
        return -PAL_ERROR_NOMEM;

    memcpy(new_conns, g_vsock->conns, g_vsock->conns_size * sizeof(*new_conns));
    free(g_vsock->conns);

    g_vsock->conns_size = new_size;
    g_vsock->conns      = new_conns;
    return 0;
}

static struct virtio_vsock_connection* get_connection(uint32_t fd) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    if (fd >= g_vsock->conns_size)
        return NULL;

    struct virtio_vsock_connection* conn = g_vsock->conns[fd];
    if (!conn)
        return NULL;

    assert(conn->fd == fd);
    return conn;
}

static int attach_connection(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    uint32_t idx = 0;
    while (idx < g_vsock->conns_size) {
        if (!g_vsock->conns[idx]) {
            /* found unused idx */
            break;
        }
        idx++;
    }

    if (idx == g_vsock->conns_size) {
        uint32_t new_size = g_vsock->conns_size;
        if (__builtin_mul_overflow(new_size, 2, &new_size))
            return -PAL_ERROR_DENIED;
        int ret = enlarge_conns(new_size);
        if (ret < 0)
            return ret;
    }

    assert(idx < g_vsock->conns_size);
    g_vsock->conns[idx] = conn;
    conn->fd = idx;
    return 0;
}

static void detach_connection(uint32_t fd) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    struct virtio_vsock_connection* conn = get_connection(fd);
    if (!conn)
        return;

    g_vsock->conns[fd] = NULL;
    conn->fd = UINT32_MAX;
}

static void host_port_add(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));
    HASH_ADD(hh_host_port, g_vsock->conns_by_host_port, host_port, sizeof(conn->host_port), conn);
}

static void host_port_delete(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));
    HASH_DELETE(hh_host_port, g_vsock->conns_by_host_port, conn);
}

static void host_port_find(uint64_t host_port, struct virtio_vsock_connection** out_conn) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));
    struct virtio_vsock_connection* conn = NULL;
    HASH_FIND(hh_host_port, g_vsock->conns_by_host_port, &host_port, sizeof(host_port), conn);
    *out_conn = conn;
}

/* TODO: Use a better scheme (e.g., a bitmap vector) to allow the reuse of the closed ports. */
static uint64_t pick_new_port(void) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    uint64_t max_port = VSOCK_STARTING_PORT;
    for (uint32_t i = 0; i < g_vsock->conns_size; i++) {
        struct virtio_vsock_connection* conn = g_vsock->conns[i];
        if (conn && conn->guest_port > max_port)
            max_port = conn->guest_port;
    }
    return max_port + 1;
}

static void cleanup_connection(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    while (conn->consumed_by_user != conn->prepared_for_user) {
        free(conn->packets_for_user[conn->consumed_by_user % VSOCK_MAX_PACKETS]);
        conn->consumed_by_user++;
    }

    if (conn->host_port)
        host_port_delete(conn);
    conn->host_port = 0;
    conn->guest_port = 0;

    for (uint32_t i = 0; i < conn->pending_conn_fds_cnt; i++) {
        /* there may be pending connections, and we clean up a connection that could accept them */
        uint32_t idx = (conn->pending_conn_fds_idx + i) % VSOCK_MAX_PENDING_CONNS;
        struct virtio_vsock_connection* pending_conn = get_connection(conn->pending_conn_fds[idx]);
        if (pending_conn)
            remove_connection(pending_conn);
    }
    conn->pending_conn_fds_idx = 0;
    conn->pending_conn_fds_cnt = 0;
    free(conn->pending_conn_fds);

    conn->state_futex = 0; /* the value doesn't matter, set just for sanity */
    conn->state = VIRTIO_VSOCK_CLOSE;
    sched_thread_wakeup(&conn->state_futex);
}

static struct virtio_vsock_connection* create_connection(uint64_t host_port, uint64_t guest_port,
                                                         enum virtio_vsock_state state) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    struct virtio_vsock_connection* conn = calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;

    conn->state = state;
    conn->host_port  = host_port;
    conn->guest_port = guest_port;

    if (attach_connection(conn) < 0) {
        free(conn);
        return NULL;
    }
    if (host_port)
        host_port_add(conn);

    return conn;
}

static void remove_connection(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));
    detach_connection(conn->fd);
    cleanup_connection(conn);
    free(conn);
}

static struct virtio_vsock_packet* generate_packet(struct virtio_vsock_connection* conn,
                                                   enum virtio_vsock_packet_op op,
                                                   const char* payload, size_t payload_size,
                                                   uint32_t flags) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

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
    packet->header.fwd_cnt   = __atomic_load_n(&g_vsock->fwd_cnt, __ATOMIC_ACQUIRE);

    packet->header.size = payload_size;
    memcpy(packet->payload, payload, payload_size);

    return packet;
}

/* sends the RST response packet and frees the `in` packet */
static int neglect_packet(struct virtio_vsock_packet* in) {
    assert(spinlock_is_locked(&g_vsock_receive_lock));

    struct virtio_vsock_packet* packet = NULL;

    if (in->header.op == VIRTIO_VSOCK_OP_RST)
        return 0;

    packet = malloc(sizeof(*packet));
    if (!packet)
        return -PAL_ERROR_NOMEM;

    memset(packet, 0, sizeof(*packet)); /* for sanity */

    packet->header.dst_cid  = in->header.src_cid;
    packet->header.src_cid  = in->header.dst_cid;
    packet->header.dst_port = in->header.src_port;
    packet->header.src_port = in->header.dst_port;

    packet->header.type  = in->header.type;
    packet->header.op    = VIRTIO_VSOCK_OP_RST;
    packet->header.flags = 0;

    packet->header.buf_alloc = g_vsock->buf_alloc;
    packet->header.fwd_cnt   = __atomic_load_n(&g_vsock->fwd_cnt, __ATOMIC_ACQUIRE);

    packet->header.size = 0;

    return copy_into_tq_or_add_to_pending(packet);
}

static int send_reset_packet(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_receive_lock));
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    struct virtio_vsock_packet* packet;

    packet = generate_packet(conn, VIRTIO_VSOCK_OP_RST,
                             /*payload=*/NULL, /*payload_size=*/0, /*flags=*/0);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    return copy_into_tq_or_add_to_pending(packet);
}

static int send_request_packet(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    struct virtio_vsock_packet* packet;

    packet = generate_packet(conn, VIRTIO_VSOCK_OP_REQUEST,
                             /*payload=*/NULL, /*payload_size=*/0, /*flags=*/0);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    return copy_into_tq_or_add_to_pending(packet);
}

static int send_response_packet(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_receive_lock));
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    struct virtio_vsock_packet* packet;

    packet = generate_packet(conn, VIRTIO_VSOCK_OP_RESPONSE,
                             /*payload=*/NULL, /*payload_size=*/0, /*flags=*/0);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    return copy_into_tq_or_add_to_pending(packet);
}

static int send_credit_update_packet(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_receive_lock));
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    struct virtio_vsock_packet* packet;

    packet = generate_packet(conn, VIRTIO_VSOCK_OP_CREDIT_UPDATE,
                             /*payload=*/NULL, /*payload_size=*/0, /*flags=*/0);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    /* packet is already updated with fwd_cnt and buf_alloc */

    return copy_into_tq_or_add_to_pending(packet);
}

static int send_shutdown_packet(struct virtio_vsock_connection* conn,
                                enum virtio_vsock_shutdown flags) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    struct virtio_vsock_packet* packet;

    packet = generate_packet(conn, VIRTIO_VSOCK_OP_SHUTDOWN,
                             /*payload=*/NULL, /*payload_size=*/0, flags);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    return copy_into_tq_or_add_to_pending(packet);
}

static int send_rw_packet(struct virtio_vsock_connection* conn, const char* payload,
                          size_t payload_size) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    struct virtio_vsock_packet* packet;

    /* payload is memcpy'd into the generated packet, so payload may be freed later */
    packet = generate_packet(conn, VIRTIO_VSOCK_OP_RW, payload, payload_size, /*flags=*/0);
    if (!packet)
        return -PAL_ERROR_NOMEM;

    return copy_into_tq_and_free(packet);
}

/* takes ownership of the packet */
static int recv_rw_packet(struct virtio_vsock_connection* conn,
                          struct virtio_vsock_packet* packet) {
    assert(spinlock_is_locked(&g_vsock_receive_lock));
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    uint32_t in_flight_packets_cnt = conn->prepared_for_user - conn->consumed_by_user;
    if (in_flight_packets_cnt >= VSOCK_MAX_PACKETS) {
        log_warning("RX vsock queue is full, dropping incoming RW packet (payload size %u)",
                     packet->header.size);
        return -PAL_ERROR_NOMEM;
    }

    uint32_t idx = conn->prepared_for_user % VSOCK_MAX_PACKETS;
    conn->packets_for_user[idx] = packet; /* packet is now owned by conn */
    conn->prepared_for_user++;

    __atomic_add_fetch(&g_vsock->msg_cnt, 1, __ATOMIC_ACQ_REL);
    __atomic_add_fetch(&g_vsock->fwd_cnt, packet->header.size, __ATOMIC_ACQ_REL);
    return 0;
}

static int verify_packet(struct virtio_vsock_packet* packet) {
    assert(spinlock_is_locked(&g_vsock_receive_lock));

    if (packet->header.size > VSOCK_MAX_PAYLOAD_SIZE) {
        log_error("malicious size of packet (%u)", packet->header.size);
        return -PAL_ERROR_DENIED;
    }

    if (packet->header.type != VIRTIO_VSOCK_TYPE_STREAM) {
        log_error("only stream type packets are supported in vsock");
        return -PAL_ERROR_NOTSUPPORT;
    }

    if (packet->header.op == VIRTIO_VSOCK_OP_INVALID || packet->header.op >= VIRTIO_VSOCK_OP_MAX) {
        log_error("wrong operation (%d) on vsock packet is received", packet->header.op);
        return -PAL_ERROR_NOTSUPPORT;
    }

    if (packet->header.dst_cid != g_vsock->guest_cid ||
            packet->header.src_cid != g_vsock->host_cid) {
        log_error("vsock packet guest/host CIDs do not match guest/host");
        return -PAL_ERROR_INVAL;
    }

    return 0;
}

/* takes ownership of the packet and frees it in the end */
static int process_packet(struct virtio_vsock_packet* packet) {
    assert(spinlock_is_locked(&g_vsock_receive_lock));

    int ret;

    ret = verify_packet(packet);
    if (ret < 0) {
        neglect_packet(packet);
        free(packet);
        return ret;
    }

    bool packet_ownership_transferred = false;
    struct virtio_vsock_connection* conn = NULL;

    spinlock_lock(&g_vsock_connections_lock);

    /* guest and host CIDs are set in stone, so it is enough to distinguish connections based on the
     * host's port (which is the `src_port` in the incoming packet) */
    uint64_t host_port = packet->header.src_port;
    host_port_find(host_port, &conn);

    if (!conn && packet->header.op == VIRTIO_VSOCK_OP_REQUEST) {
        /* loop through all connections, trying to find a listening conn on this port; this is a
         * slow O(n) implementation but such ops should be rare */
        for (uint32_t i = 0; i < g_vsock->conns_size; i++) {
            struct virtio_vsock_connection* check_conn = g_vsock->conns[i];
            if (check_conn && check_conn->state == VIRTIO_VSOCK_LISTEN
                    && check_conn->guest_port == packet->header.dst_port) {
                conn = check_conn;
                break;
            }
        }
    }

    if (!conn) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    g_vsock->peer_fwd_cnt   = packet->header.fwd_cnt;
    g_vsock->peer_buf_alloc = packet->header.buf_alloc;

    switch (conn->state) {
        case VIRTIO_VSOCK_LISTEN:
            if (packet->header.op != VIRTIO_VSOCK_OP_REQUEST) {
                if (packet->header.op == VIRTIO_VSOCK_OP_RST)
                    cleanup_connection(conn);
                ret = -PAL_ERROR_DENIED;
                goto out;
            }
            if (conn->pending_conn_fds_cnt == VSOCK_MAX_PENDING_CONNS) {
                log_warning("vsock backlog full, dropping connection");
                ret = -PAL_ERROR_OVERFLOW;
                goto out;
            }
            /* create new connection */
            struct virtio_vsock_connection* new_conn = create_connection(packet->header.src_port,
                                                                         pick_new_port(),
                                                                         VIRTIO_VSOCK_ESTABLISHED);
            if (!new_conn) {
                log_error("no memory for new connection");
                ret = -PAL_ERROR_NOMEM;
                goto out;
            }
            ret = send_response_packet(new_conn);
            if (ret < 0) {
                remove_connection(new_conn);
                goto out;
            }
            /* unblock accept() syscall */
            uint32_t idx = conn->pending_conn_fds_idx + conn->pending_conn_fds_cnt;
            conn->pending_conn_fds[idx % VSOCK_MAX_PENDING_CONNS] = new_conn->fd;
            conn->pending_conn_fds_cnt++;
            ret = 0;
            goto out;

        case VIRTIO_VSOCK_CONNECT:
            if (packet->header.op != VIRTIO_VSOCK_OP_RESPONSE) {
                if (packet->header.op == VIRTIO_VSOCK_OP_RST)
                    cleanup_connection(conn);
                ret = -PAL_ERROR_DENIED;
                goto out;
            }
            conn->state = VIRTIO_VSOCK_ESTABLISHED;
            sched_thread_wakeup(&conn->state_futex);
            ret = 0;
            goto out;

        case VIRTIO_VSOCK_ESTABLISHED:
            switch (packet->header.op) {
                case VIRTIO_VSOCK_OP_RW:
                    if (conn->recv_disallowed) {
                        /* we were instructed to not receive more packets, silently drop packet */
                        ret = 0;
                    } else {
                        ret = recv_rw_packet(conn, packet);
                        packet_ownership_transferred = ret < 0 ? false : true;
                    }
                    goto out;
                case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
                    ret = send_credit_update_packet(conn);
                    goto out;
                case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
                    /* we already updated peer_fwd_cnt and peer_buf_alloc above */
                    ret = 0;
                    goto out;
                case VIRTIO_VSOCK_OP_SHUTDOWN:
                    if (packet->header.flags == VIRTIO_VSOCK_SHUTDOWN_RCV
                            || packet->header.flags == VIRTIO_VSOCK_SHUTDOWN_COMPLETE) {
                        conn->send_disallowed = true;
                    }
                    if (packet->header.flags == VIRTIO_VSOCK_SHUTDOWN_SEND
                            || packet->header.flags == VIRTIO_VSOCK_SHUTDOWN_COMPLETE) {
                        conn->recv_disallowed = true;
                    }
                    if (conn->recv_disallowed && conn->send_disallowed) {
                        /* notify host that we ack this shutdown cleanly */
                        send_reset_packet(conn);
                    }
                    ret = 0;
                    goto out;
                case VIRTIO_VSOCK_OP_RST:
                    if (conn->recv_disallowed && conn->send_disallowed) {
                        /* clean shutdown happened, now we can safely ignore RSTs from peer */
                        ret = 0;
                        goto out;
                    }
                    cleanup_connection(conn);
                    /* fallthrough */
                default:
                    ret = -PAL_ERROR_DENIED;
                    goto out;
            }

        case VIRTIO_VSOCK_CLOSING:
            if (packet->header.op == VIRTIO_VSOCK_OP_RST) {
                /* we initiated full shutdown, wait for RST and ignore all other packets */
                cleanup_connection(conn); /* moves to CLOSE state */
            }
            ret = 0;
            goto out;

        case VIRTIO_VSOCK_CLOSE:
            /* all packets are wrong in this state */
            ret = -PAL_ERROR_DENIED;
            goto out;
    }

out:
    spinlock_unlock(&g_vsock_connections_lock);
    if (ret < 0 && packet->header.op != VIRTIO_VSOCK_OP_RST)
        neglect_packet(packet);
    if (!packet_ownership_transferred)
        free(packet);
    return ret;
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

    /* instruct the host to NOT send interrupts on TX upon consuming messages; the guest performs TX
     * cleanup itself on demand, see `cleanup_tq()` usage */
    vm_shared_writew(&tq->avail->flags, VIRTQ_AVAIL_F_NO_INTERRUPT);
    vm_shared_writew(&eq->avail->flags, VIRTQ_AVAIL_F_NO_INTERRUPT); /* for sanity */

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

    struct virtio_vsock_connection** conns = NULL;
    struct virtio_vsock_packet** control_packets = NULL;

    conns = calloc(VIRTIO_VSOCK_CONNS_INIT_SIZE, sizeof(*conns));
    if (!conns) {
        ret = -PAL_ERROR_NOMEM;
        goto fail;
    }

    control_packets = calloc(VIRTIO_VSOCK_PENDING_TQ_CONTROL_SIZE, sizeof(*control_packets));
    if (!control_packets) {
        ret = -PAL_ERROR_NOMEM;
        goto fail;
    }

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

    size_t rq_notify_addr_size = sizeof(*vsock->rq_notify_addr);
    if (!(PCI_MMIO_START_ADDR <= (uintptr_t)vsock->rq_notify_addr &&
                (uintptr_t)vsock->rq_notify_addr + rq_notify_addr_size < PCI_MMIO_END_ADDR)) {
        /* incorrect or malicious RQ queue notify addr */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    vm_mmio_writew(&pci_regs->queue_select, 1);
    uint64_t tq_notify_off = vm_mmio_readw(&pci_regs->queue_notify_off);
    vsock->tq_notify_addr = (uint16_t*)(notify_off_addr + tq_notify_off * notify_off_multiplier);

    size_t tq_notify_addr_size = sizeof(*vsock->tq_notify_addr);
    if (!(PCI_MMIO_START_ADDR <= (uintptr_t)vsock->tq_notify_addr &&
                (uintptr_t)vsock->tq_notify_addr + tq_notify_addr_size < PCI_MMIO_END_ADDR)) {
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

    vsock->host_cid  = VSOCK_HOST_CID;
    vsock->tx_cnt    = 0;
    vsock->fwd_cnt   = 0;
    vsock->buf_alloc = VSOCK_MAX_PACKETS * sizeof(struct virtio_vsock_packet);

    vsock->conns_size  = VIRTIO_VSOCK_CONNS_INIT_SIZE;
    vsock->conns       = conns;

    vsock->pending_tq_control_packets     = control_packets;
    vsock->pending_tq_control_packets_cnt = 0;
    vsock->pending_tq_control_packets_idx = 0;

    vsock->conns_by_host_port = NULL;

    g_vsock = vsock;
    return 0;

fail:
    free(conns);
    free(control_packets);
    virtio_vsock_free(vsock);
    status = vm_mmio_readb(&pci_regs->device_status);
    vm_mmio_writeb(&pci_regs->device_status, status | VIRTIO_STATUS_FAILED);
    return ret;
}

int virtio_vsock_socket(int domain, int type, int protocol) {
    int ret;

    if (domain != AF_VSOCK)
        return -PAL_ERROR_AFNOSUPPORT;

    if (type != VIRTIO_VSOCK_TYPE_STREAM)
        return -PAL_ERROR_INVAL;

    if (protocol != 0)
        return -PAL_ERROR_NOTSUPPORT;

    spinlock_lock(&g_vsock_connections_lock);
    struct virtio_vsock_connection* conn = create_connection(/*host_port=*/0, /*guest_port=*/0,
                                                             VIRTIO_VSOCK_CLOSE);
    if (!conn) {
        log_error("no memory for new connection");
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }
    ret = conn->fd;
out:
    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}

int virtio_vsock_bind(int sockfd, const void* addr, size_t addrlen, uint16_t* out_new_port,
                      bool is_ipv4, bool ipv6_v6only, bool reuseport) {
    int ret;

    if (!addr || addrlen < sizeof(struct sockaddr_vm))
        return -PAL_ERROR_INVAL;

    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        ret = -PAL_ERROR_BADHANDLE;
        goto out;
    }

    if (conn->state != VIRTIO_VSOCK_CLOSE || conn->guest_port != 0) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    struct sockaddr_vm* addr_vm = (struct sockaddr_vm*)addr;
    if (addr_vm->svm_family != AF_VSOCK || addr_vm->svm_cid != g_vsock->guest_cid) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    uint32_t bind_to_port = addr_vm->svm_port;
    if (bind_to_port == 0) {
        bind_to_port = pick_new_port();
    } else {
        /* loop through all connections, checking whether the port-to-bind is already occupied; this
         * is a slow O(n) implementation but such ops should be rare */
        for (uint32_t i = 0; i < g_vsock->conns_size; i++) {
            struct virtio_vsock_connection* check_conn = g_vsock->conns[i];
            if (!check_conn || check_conn->guest_port != bind_to_port)
                continue;

            if (is_ipv4 && check_conn->ipv6_bound && check_conn->ipv6_v6only) {
                /* IPv4 socket wants to bind to IPv6-bound port; allow only if not dualstack */
                continue;
            }
            if (!is_ipv4 && check_conn->ipv4_bound && ipv6_v6only) {
                /* IPv6 socket wants to bind to IPv4-bound port; allow only if not dualstack */
                continue;
            }

            if (reuseport && check_conn->reuseport) {
                /* SO_REUSEPORT is allowed by both the bound and to-be-bound sockets */
                continue;
            }

            ret = -PAL_ERROR_STREAMEXIST;
            goto out;
        }
    }

    if (out_new_port)
        *out_new_port = bind_to_port;

    conn->guest_port = bind_to_port;
    conn->host_port  = 0;

    conn->ipv6_v6only = ipv6_v6only;
    if (is_ipv4) {
        assert(conn->ipv4_bound == false);
        conn->ipv4_bound = true;
    } else {
        assert(conn->ipv6_bound == false);
        conn->ipv6_bound = true;
    }
    conn->reuseport = reuseport;

    ret = 0;
out:
    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}

int virtio_vsock_listen(int sockfd, int backlog) {
    __UNUSED(backlog);
    int ret;

    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        ret = -PAL_ERROR_BADHANDLE;
        goto out;
    }

    if (conn->state != VIRTIO_VSOCK_CLOSE) {
        ret = -PAL_ERROR_STREAMEXIST;
        goto out;
    }

    if (conn->guest_port == 0) {
        /* not yet bound */
        ret = -PAL_ERROR_STREAMNOTEXIST;
        goto out;
    }

    uint32_t* pending_conn_fds = calloc(VSOCK_MAX_PENDING_CONNS, sizeof(*pending_conn_fds));
    if (!pending_conn_fds) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    conn->state = VIRTIO_VSOCK_LISTEN;
    conn->pending_conn_fds = pending_conn_fds;
    conn->pending_conn_fds_cnt = 0;
    conn->pending_conn_fds_idx = 0;

    ret = 0;
out:
    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}

int virtio_vsock_accept(int sockfd, void* addr, size_t* addrlen) {
    int ret;

    if (!addr || !addrlen || *addrlen < sizeof(struct sockaddr_vm))
        return -PAL_ERROR_INVAL;

    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        ret = -PAL_ERROR_BADHANDLE;
        goto out;
    }

    if (conn->state != VIRTIO_VSOCK_LISTEN) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (conn->pending_conn_fds_cnt == 0) {
        /* non-blocking caller must return TRYAGAIN; blocking caller must sleep on this */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    uint32_t idx = conn->pending_conn_fds_idx % VSOCK_MAX_PENDING_CONNS;
    uint32_t accepted_conn_fd = conn->pending_conn_fds[idx];
    struct virtio_vsock_connection* accepted_conn = get_connection(accepted_conn_fd);
    if (!accepted_conn) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    *addrlen = sizeof(struct sockaddr_vm);
    struct sockaddr_vm* addr_vm = (struct sockaddr_vm*)addr;
    addr_vm->svm_family = AF_VSOCK;
    addr_vm->svm_reserved1 = 0;
    addr_vm->svm_cid = g_vsock->host_cid;
    addr_vm->svm_port = accepted_conn->host_port;

    conn->pending_conn_fds_idx++;
    conn->pending_conn_fds_cnt--;

    ret = accepted_conn_fd;
out:
    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}

int virtio_vsock_connect(int sockfd, const void* addr, size_t addrlen, uint64_t timeout_us) {
    int ret;
    void* timeout = NULL;
    uint64_t timeout_absolute_us = 0;
    struct sockaddr_vm* addr_vm = (struct sockaddr_vm*)addr;

    if (!addr || addrlen < sizeof(struct sockaddr_vm))
        return -PAL_ERROR_INVAL;

    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    if (timeout_us == 0)
        return -PAL_ERROR_INVAL;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        ret = -PAL_ERROR_BADHANDLE;
        goto out;
    }

    if (conn->state != VIRTIO_VSOCK_CLOSE) {
        ret = -PAL_ERROR_STREAMEXIST;
        goto out;
    }

    uint64_t curr_time_us;
    ret = get_time_in_us(&curr_time_us);
    if (ret < 0)
        goto out;

    timeout_absolute_us = curr_time_us + timeout_us;
    ret = register_timeout(timeout_absolute_us, &conn->state_futex, &timeout);
    if (ret < 0)
        goto out;

    assert(conn->host_port == 0 && conn->guest_port == 0);
    conn->host_port  = addr_vm->svm_port;
    conn->guest_port = pick_new_port();
    host_port_add(conn);

    ret = send_request_packet(conn);
    if (ret < 0)
        goto out;

    conn->state = VIRTIO_VSOCK_CONNECT;

    while (conn->state != VIRTIO_VSOCK_ESTABLISHED) {
        if (conn->state != VIRTIO_VSOCK_CONNECT) {
            ret = -PAL_ERROR_CONNFAILED;
            goto out;
        }

        /* check if timeout expired */
        assert(timeout_absolute_us);

        uint64_t curr_time_us;
        ret = get_time_in_us(&curr_time_us);
        if (ret < 0)
            goto out;

        if (timeout_absolute_us <= curr_time_us) {
            ret = -PAL_ERROR_CONNFAILED; /* must return ETIMEOUT but PAL doesn't have such code */
            goto out;
        }

        /* connection state not changed to ESTABLISHED, need to sleep */
        sched_thread_wait(&conn->state_futex, &g_vsock_connections_lock);
    }

    ret = 0;
out:
    spinlock_unlock(&g_vsock_connections_lock);
    if (timeout)
        deregister_timeout(timeout);
    return ret;
}

int virtio_vsock_getsockname(int sockfd, const void* addr, size_t* addrlen) {
    int ret;

    if (!addr || !addrlen || *addrlen < sizeof(struct sockaddr_vm))
        return -PAL_ERROR_INVAL;

    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        ret = -PAL_ERROR_BADHANDLE;
        goto out;
    }

    if (conn->state == VIRTIO_VSOCK_CLOSE) {
        ret = -PAL_ERROR_BADHANDLE;
        goto out;
    }

    *addrlen = sizeof(struct sockaddr_vm);
    struct sockaddr_vm* addr_vm = (struct sockaddr_vm*)addr;
    addr_vm->svm_family = AF_VSOCK;
    addr_vm->svm_reserved1 = 0;
    addr_vm->svm_cid = g_vsock->guest_cid;
    addr_vm->svm_port = conn->guest_port;

    ret = 0;
out:
    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}

int virtio_vsock_set_socket_options(int sockfd, bool ipv6_v6only, bool reuseport) {
    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        spinlock_unlock(&g_vsock_connections_lock);
        return -PAL_ERROR_BADHANDLE;
    }

    conn->ipv6_v6only = ipv6_v6only;
    conn->reuseport = reuseport;

    spinlock_unlock(&g_vsock_connections_lock);
    return 0;
}

long virtio_vsock_peek(int sockfd) {
    long ret;

    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        spinlock_unlock(&g_vsock_connections_lock);
        return -PAL_ERROR_BADHANDLE;
    }

    switch (conn->state) {
        case VIRTIO_VSOCK_LISTEN:
            ret = conn->pending_conn_fds_cnt;
            break;
        case VIRTIO_VSOCK_CONNECT:
            ret = 0;
            break;
        case VIRTIO_VSOCK_ESTABLISHED: {
            size_t peeked = 0;
            uint32_t peek_at = conn->consumed_by_user;
            while (conn->prepared_for_user != peek_at) {
                peeked += conn->packets_for_user[peek_at % VSOCK_MAX_PACKETS]->header.size;
                peek_at++;
            }
            ret = (long)peeked;
            break;
        }
        default:
            /* CLOSE or CLOSING states -- connection is shutdown or in the process of closing */
            ret = -PAL_ERROR_DENIED;
            break;
    }

    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}

long virtio_vsock_read(int sockfd, void* buf, size_t count) {
    long ret;

    if (!buf)
        return -PAL_ERROR_BADADDR;

    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        ret = -PAL_ERROR_BADHANDLE;
        goto out;
    }

    if (conn->state != VIRTIO_VSOCK_ESTABLISHED) {
        ret = -PAL_ERROR_NOTCONNECTION;
        goto out;
    }

    /* must be after all checks on connection, otherwise could return success on broken conn */
    if (count == 0) {
        ret = 0;
        goto out;
    }

    if (conn->prepared_for_user == conn->consumed_by_user) {
        if (conn->recv_disallowed) {
            /* we were instructed that there will be no more packets, so return "end-of-file" */
            ret = 0;
            goto out;
        }
        /* non-blocking caller must return TRYAGAIN; blocking caller must sleep on this */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
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

    ret = (long)copied;
out:
    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}

long virtio_vsock_write(int sockfd, const void* buf, size_t count) {
    long ret;

    if (!buf)
        return -PAL_ERROR_BADADDR;

    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        ret = -PAL_ERROR_BADHANDLE;
        goto out;
    }

    if (conn->state != VIRTIO_VSOCK_ESTABLISHED) {
        ret = -PAL_ERROR_NOTCONNECTION;
        goto out;
    }

    if (conn->send_disallowed) {
        /* we were instructed to not send more packets, return -EPIPE type of error */
        ret = -PAL_ERROR_CONNFAILED_PIPE;
        goto out;
    }

    /* must be after all checks on connection, otherwise could return success on broken conn */
    if (count == 0) {
        ret = 0;
        goto out;
    }

    size_t sent = 0;
    while (sent < count) {
        size_t payload_size = MIN(count - sent, VSOCK_MAX_PAYLOAD_SIZE);
        ret = send_rw_packet(conn, buf + sent, payload_size);
        if (ret < 0) {
            if (ret == -PAL_ERROR_NOMEM && sent != 0) {
                /* TX buffer is full, do not return error but instead whatever was sent */
                ret = (long)sent;
            }
            if (ret == -PAL_ERROR_NOMEM) {
                /* TX buffer is full and we haven't sent anything -> a write would block;
                 * non-blocking caller must return TRYAGAIN; blocking caller must sleep on this */
                ret = -PAL_ERROR_TRYAGAIN;
            }
            goto out;
        }
        sent += payload_size;
    }

    ret = (long)sent;
out:
    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}

static int virtio_vsock_close_common(struct virtio_vsock_connection* conn, uint64_t timeout_us) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    int ret;
    uint64_t timeout_absolute_us = 0;
    void* timeout = NULL;

    if (conn->state == VIRTIO_VSOCK_CLOSE || conn->state == VIRTIO_VSOCK_CLOSING) {
        ret = 0;
        goto out;
    }

    if (conn->state == VIRTIO_VSOCK_LISTEN) {
        /* listening socket doesn't have a shutdown/disconnect operation */
        ret = 0;
        goto out;
    }

    if (conn->state != VIRTIO_VSOCK_ESTABLISHED) {
        ret = -PAL_ERROR_NOTCONNECTION;
        goto out;
    }

    uint64_t curr_time_us;
    ret = get_time_in_us(&curr_time_us);
    if (ret < 0)
        goto out;

    timeout_absolute_us = curr_time_us + timeout_us;
    ret = register_timeout(timeout_absolute_us, &conn->state_futex, &timeout);
    if (ret < 0)
        goto out;

    ret = send_shutdown_packet(conn, VIRTIO_VSOCK_SHUTDOWN_COMPLETE);
    if (ret < 0)
        goto out;

    conn->state = VIRTIO_VSOCK_CLOSING;

    while (conn->state != VIRTIO_VSOCK_CLOSE) {
        if (conn->state != VIRTIO_VSOCK_CLOSING) {
            ret = -PAL_ERROR_DENIED;
            goto out;
        }

        /* check if timeout expired */
        assert(timeout_absolute_us);

        uint64_t curr_time_us;
        ret = get_time_in_us(&curr_time_us);
        if (ret < 0)
            goto out;

        if (timeout_absolute_us <= curr_time_us) {
            ret = -PAL_ERROR_DENIED;
            goto out;
        }

        /* connection state not changed to CLOSE, need to sleep */
        sched_thread_wait(&conn->state_futex, &g_vsock_connections_lock);
    }

    ret = 0;
out:
    if (timeout)
        deregister_timeout(timeout);
    return ret;
}

int virtio_vsock_shutdown(int sockfd, enum virtio_vsock_shutdown shutdown) {
    int ret;

    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        ret = -PAL_ERROR_BADHANDLE;
        goto out;
    }

    if (conn->state != VIRTIO_VSOCK_ESTABLISHED && conn->state != VIRTIO_VSOCK_LISTEN) {
        ret = -PAL_ERROR_NOTCONNECTION;
        goto out;
    }

    if (shutdown == VIRTIO_VSOCK_SHUTDOWN_RCV || shutdown == VIRTIO_VSOCK_SHUTDOWN_COMPLETE)
        conn->recv_disallowed = true;
    if (shutdown == VIRTIO_VSOCK_SHUTDOWN_SEND || shutdown == VIRTIO_VSOCK_SHUTDOWN_COMPLETE)
        conn->send_disallowed = true;

    ret = send_shutdown_packet(conn, shutdown);
out:
    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}

int virtio_vsock_close(int sockfd, uint64_t timeout_us) {
    int ret;

    if (sockfd < 0)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_connections_lock);

    struct virtio_vsock_connection* conn = get_connection(sockfd);
    if (!conn) {
        ret = -PAL_ERROR_BADHANDLE;
        goto out;
    }

    ret = 0;
    if (conn->state != VIRTIO_VSOCK_CLOSE) {
        ret = virtio_vsock_close_common(conn, timeout_us);
    }

    remove_connection(conn);
out:
    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}
