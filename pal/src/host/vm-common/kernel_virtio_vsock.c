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

#define VIRTIO_VSOCK_QUEUE_SIZE 128
#define VIRTIO_VSOCK_EVENT_QUEUE_SIZE 32

#define VIRTIO_VSOCK_SHARED_BUF_SIZE (VIRTIO_VSOCK_QUEUE_SIZE * sizeof(struct virtio_vsock_packet))

struct virtio_vsock* g_vsock = NULL;
bool g_vsock_trigger_bottomhalf = false;

/* coarse-grained locks to sync RX, TX and connections' operations on multi-core systems, see also
 * flow diagram above and kernel_virtio.h */
static spinlock_t g_vsock_receive_lock = INIT_SPINLOCK_UNLOCKED;
static spinlock_t g_vsock_transmit_lock = INIT_SPINLOCK_UNLOCKED;
static spinlock_t g_vsock_connections_lock = INIT_SPINLOCK_UNLOCKED;

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

static int handle_rq(void) {
    int ret;
    bool received = false;

    spinlock_lock(&g_vsock_receive_lock);
    uint16_t host_used_idx = vm_shared_readw(&g_vsock->rq->used->idx);

    if (host_used_idx - g_vsock->rq->seen_used > g_vsock->rq->queue_size) {
        /* malicious (impossible) value reported by the host; note that this check works also in
         * cases of int wrap */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    while (host_used_idx != g_vsock->rq->seen_used) {
        uint16_t used_idx = g_vsock->rq->seen_used % g_vsock->rq->queue_size;
        uint16_t desc_idx = (uint16_t)vm_shared_readl(&g_vsock->rq->used->ring[used_idx].id);

        if (desc_idx >= g_vsock->rq->queue_size) {
            /* malicious (out of bounds) descriptor index */
            ret = -PAL_ERROR_DENIED;
            goto fail;
        }

        uint64_t addr = vm_shared_readq(&g_vsock->rq->desc[desc_idx].addr);
        uint32_t size = vm_shared_readl(&g_vsock->rq->desc[desc_idx].len);

        uint64_t shared_rq_buf_size = g_vsock->rq->queue_size * sizeof(struct virtio_vsock_packet);
        if (addr < (uintptr_t)g_vsock->shared_rq_buf ||
                addr >= (uintptr_t)g_vsock->shared_rq_buf + shared_rq_buf_size) {
            /* malicious (out of bounds) address of the incoming packet */
            ret = -PAL_ERROR_DENIED;
            goto fail;
        }

        if ((addr - (uintptr_t)g_vsock->shared_rq_buf) % sizeof(struct virtio_vsock_packet)) {
            /* malicious (not aligned on packet struct size) offset of the incoming packet */
            ret = -PAL_ERROR_DENIED;
            goto fail;
        }

        if (size < sizeof(struct virtio_vsock_hdr) || size > sizeof(struct virtio_vsock_packet)) {
            /* malicious (out of bounds) size of the incoming packet */
            ret = -PAL_ERROR_DENIED;
            goto fail;
        }

        struct virtio_vsock_packet* packet = malloc(sizeof(*packet));
        if (!packet) {
            ret = -PAL_ERROR_NOMEM;
            goto fail;
        }

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
    spinlock_unlock(&g_vsock_receive_lock);

    if (received) {
        vm_mmio_writew(g_vsock->rq_notify_addr, /*queue_sel=*/0);
        thread_wakeup_vsock(/*is_read=*/true);
    }

    return 0;
fail:
    spinlock_unlock(&g_vsock_receive_lock);
    return ret;
}

static int copy_into_tq(struct virtio_vsock_packet* packet) {
    int ret;

    if (!g_vsock)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_vsock_transmit_lock);
    uint64_t packet_size = sizeof(struct virtio_vsock_hdr) + packet->header.size;

    uint16_t desc_idx;
    ret = virtq_alloc_desc(g_vsock->tq, /*addr=*/NULL, packet_size, /*flags=*/0, &desc_idx);
    if (ret < 0)
        goto out;

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
    ret = 0;
out:
    spinlock_unlock(&g_vsock_transmit_lock);
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

static void init_connection(struct virtio_vsock_connection* conn, uint64_t host_port,
                            uint64_t guest_port, enum virtio_vsock_state state) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    /* do not reset conn->fd, it will be done via attach_connection() if needed */

    conn->state_futex = 0; /* the value doesn't matter, set just for sanity */
    conn->state = state;
    if (state == VIRTIO_VSOCK_CLOSE)
        sched_thread_wakeup(&conn->state_futex);

    conn->host_port  = host_port;
    conn->guest_port = guest_port;

    conn->pending_conn_fd = UINT32_MAX;

    conn->prepared_for_user = 0;
    conn->consumed_by_user  = 0;
}

static void cleanup_connection(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    while (conn->consumed_by_user != conn->prepared_for_user) {
        free(conn->packets_for_user[conn->consumed_by_user % VSOCK_MAX_PACKETS]);
        conn->consumed_by_user++;
    }

    if (conn->host_port)
        host_port_delete(conn);

    if (conn->pending_conn_fd != UINT32_MAX) {
        /* there is a pending connection, and we clean up a connection that could accept it */
        struct virtio_vsock_connection* pending_conn = get_connection(conn->pending_conn_fd);
        if (pending_conn)
            remove_connection(pending_conn);
    }
}

static void reinit_connection(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));
    cleanup_connection(conn);
    init_connection(conn, /*host_port=*/0, /*guest_port=*/0, VIRTIO_VSOCK_CLOSE);
}

static struct virtio_vsock_connection* create_connection(uint64_t host_port, uint64_t guest_port,
                                                         enum virtio_vsock_state state) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    struct virtio_vsock_connection* conn = calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;

    init_connection(conn, host_port, guest_port, state);
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
    if (!conn->waiters) {
        /* no other threads are waiting on this connection, this thread is single owner of conn */
        free(conn);
    } else {
        /* some threads are waiting on this connection, defer freeing and move to CLOSE state */
        reinit_connection(conn);
    }
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
    packet->header.fwd_cnt   = __atomic_load_n(&g_vsock->fwd_cnt, __ATOMIC_ACQUIRE);

    packet->header.size = 0;

    ret = copy_into_tq(packet);
out:
    free(packet);
    return ret;
}

static int send_reset_packet(struct virtio_vsock_connection* conn) {
    assert(spinlock_is_locked(&g_vsock_receive_lock));
    assert(spinlock_is_locked(&g_vsock_connections_lock));

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
    assert(spinlock_is_locked(&g_vsock_connections_lock));

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
    assert(spinlock_is_locked(&g_vsock_receive_lock));
    assert(spinlock_is_locked(&g_vsock_connections_lock));

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
    assert(spinlock_is_locked(&g_vsock_receive_lock));
    assert(spinlock_is_locked(&g_vsock_connections_lock));

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
    assert(spinlock_is_locked(&g_vsock_connections_lock));

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
    assert(spinlock_is_locked(&g_vsock_connections_lock));

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
    assert(spinlock_is_locked(&g_vsock_receive_lock));
    assert(spinlock_is_locked(&g_vsock_connections_lock));

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

    if (packet->header.op == VIRTIO_VSOCK_OP_RST) {
        reinit_connection(conn);
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    g_vsock->peer_fwd_cnt   = packet->header.fwd_cnt;
    g_vsock->peer_buf_alloc = packet->header.buf_alloc;

    switch (conn->state) {
        case VIRTIO_VSOCK_LISTEN:
            if (packet->header.op != VIRTIO_VSOCK_OP_REQUEST) {
                ret = -PAL_ERROR_DENIED;
                goto out;
            }
            if (conn->pending_conn_fd != UINT32_MAX) {
                /* there is already one pending connection on this listening socket */
                log_warning("vsock backlog full, dropping connection");
                ret = -PAL_ERROR_NOMEM;
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
            conn->pending_conn_fd = new_conn->fd;
            ret = 0;
            goto out;

        case VIRTIO_VSOCK_CONNECT:
            if (packet->header.op != VIRTIO_VSOCK_OP_RESPONSE) {
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
                    ret = recv_rw_packet(conn, packet);
                    packet_ownership_transferred = ret < 0 ? false : true;
                    goto out;
                case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
                    ret = send_credit_update_packet(conn);
                    goto out;
                case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
                    /* we already updated peer_fwd_cnt and peer_buf_alloc above */
                    ret = 0;
                    goto out;
                case VIRTIO_VSOCK_OP_SHUTDOWN:
                    /* FIXME: we do not look at packet.header.flags currently */
                    send_reset_packet(conn); /* notify host that we ack this shutdown cleanly */
                    reinit_connection(conn);
                    ret = 0;
                    goto out;
                default:
                    ret = -PAL_ERROR_DENIED;
                    goto out;
            }

        case VIRTIO_VSOCK_CLOSING:
            if (packet->header.op != VIRTIO_VSOCK_OP_SHUTDOWN) {
                ret = -PAL_ERROR_DENIED;
                goto out;
            }
            reinit_connection(conn);
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

    size_t conns_size = VIRTIO_VSOCK_CONNS_INIT_SIZE;
    struct virtio_vsock_connection** conns = calloc(conns_size, sizeof(*conns));
    if (!conns) {
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

    vsock->conns_size  = conns_size;
    vsock->conns       = conns;

    vsock->conns_by_host_port = NULL;

    g_vsock = vsock;
    return 0;

fail:
    free(conns);
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

int virtio_vsock_bind(int sockfd, const void* addr, size_t addrlen, uint16_t* out_new_port) {
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
            if (check_conn && check_conn->guest_port == bind_to_port) {
                ret = -PAL_ERROR_STREAMEXIST;
                goto out;
            }
        }
    }

    if (out_new_port)
        *out_new_port = bind_to_port;

    conn->guest_port = bind_to_port;
    conn->host_port  = 0;
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

    conn->state = VIRTIO_VSOCK_LISTEN;
    conn->pending_conn_fd = UINT32_MAX;
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

    if (conn->pending_conn_fd == UINT32_MAX) {
        /* non-blocking caller must return TRYAGAIN; blocking caller must sleep on this */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    uint32_t accepted_conn_fd = conn->pending_conn_fd;
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

    conn->pending_conn_fd = UINT32_MAX;
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
    register_timeout(timeout_absolute_us, &conn->state_futex, &timeout);
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
            break;
        }

        /* check if timeout expired */
        assert(timeout_absolute_us);

        uint64_t curr_time_us;
        ret = get_time_in_us(&curr_time_us);
        if (ret < 0)
            break;

        if (timeout_absolute_us <= curr_time_us) {
            ret = -PAL_ERROR_CONNFAILED; /* must return ETIMEOUT but PAL doesn't have such code */
            break;
        }

        /* connection state not changed to ESTABLISHED, need to sleep */
        conn->waiters++;
        sched_thread_wait(&conn->state_futex, &g_vsock_connections_lock);
        conn->waiters--;

        if (!conn->waiters && conn->state == VIRTIO_VSOCK_CLOSE) {
            /* connection was closed while we were asleep, freeing was deferred, try now */
            remove_connection(conn);
            ret = -PAL_ERROR_NOTCONNECTION;
            goto out;
        }
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
            ret = conn->pending_conn_fd == UINT32_MAX ? 0 : 1;
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
            /* CONNECT, CLOSE or CLOSING states -- connection is not active, so nothing pending */
            ret = 0;
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
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    /* must be after all checks on connection, otherwise could return success on broken conn */
    if (count == 0) {
        ret = 0;
        goto out;
    }

    if (conn->prepared_for_user == conn->consumed_by_user) {
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
        ret = -PAL_ERROR_INVAL;
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

static int virtio_vsock_shutdown_common(struct virtio_vsock_connection* conn, uint64_t timeout_us) {
    assert(spinlock_is_locked(&g_vsock_connections_lock));

    int ret;
    uint64_t timeout_absolute_us = 0;
    void* timeout = NULL;

    if (conn->state != VIRTIO_VSOCK_ESTABLISHED && conn->state != VIRTIO_VSOCK_LISTEN) {
        ret = -PAL_ERROR_NOTCONNECTION;
        goto out;
    }

    uint64_t curr_time_us;
    ret = get_time_in_us(&curr_time_us);
    if (ret < 0)
        goto out;

    timeout_absolute_us = curr_time_us + timeout_us;
    register_timeout(timeout_absolute_us, &conn->state_futex, &timeout);
    if (ret < 0)
        goto out;

    ret = send_shutdown_packet(conn, VIRTIO_VSOCK_SHUTDOWN_COMPLETE);
    if (ret < 0)
        goto out;

    conn->state = VIRTIO_VSOCK_CLOSING;

    while (conn->state != VIRTIO_VSOCK_CLOSE) {
        if (conn->state != VIRTIO_VSOCK_CLOSING) {
            ret = -PAL_ERROR_DENIED;
            break;
        }

        /* check if timeout expired */
        assert(timeout_absolute_us);

        uint64_t curr_time_us;
        ret = get_time_in_us(&curr_time_us);
        if (ret < 0)
            break;

        if (timeout_absolute_us <= curr_time_us) {
            ret = -PAL_ERROR_DENIED;
            break;
        }

        /* connection state not changed to CLOSE, need to sleep */
        conn->waiters++;
        sched_thread_wait(&conn->state_futex, &g_vsock_connections_lock);
        conn->waiters--;
    }

    ret = 0;
out:
    if (timeout)
        deregister_timeout(timeout);
    return ret;
}

int virtio_vsock_shutdown(int sockfd, int how, uint64_t timeout_us) {
    int ret;
    __UNUSED(how);

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

    ret = virtio_vsock_shutdown_common(conn, timeout_us);
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
        ret = virtio_vsock_shutdown_common(conn, timeout_us);
    }

    remove_connection(conn);
out:
    spinlock_unlock(&g_vsock_connections_lock);
    return ret;
}
