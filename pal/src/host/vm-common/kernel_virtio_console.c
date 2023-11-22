/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Implementation of virtio-console (aka virtio-serial).
 *
 * Reference: https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.pdf
 */

#include "api.h"
#include "pal_error.h"

#include "kernel_apic.h"
#include "kernel_debug.h"
#include "kernel_memory.h"
#include "kernel_pci.h"
#include "kernel_time.h"
#include "kernel_virtio.h"
#include "vm_callbacks.h"

#define VIRTIO_CONSOLE_QUEUE_SIZE 128
#define VIRTIO_CONSOLE_CONTROL_QUEUE_SIZE 32

#define VIRTIO_CONSOLE_ITEM_SIZE 32
#define VIRTIO_CONSOLE_SHARED_BUF_SIZE (VIRTIO_CONSOLE_QUEUE_SIZE * VIRTIO_CONSOLE_ITEM_SIZE)

#define VIRTIO_CONSOLE_RQ_BUF_SIZE VIRTIO_CONSOLE_SHARED_BUF_SIZE

struct virtio_console* g_console = NULL;
bool g_console_trigger_bottomhalf = false;

/* coarse-grained locks to sync RX and TX operations on multi-core systems, see kernel_virtio.h */
static spinlock_t g_console_receive_lock = INIT_SPINLOCK_UNLOCKED;
static spinlock_t g_console_transmit_lock = INIT_SPINLOCK_UNLOCKED;

/* interrupt handler (interrupt service routine), called by generic handler `isr_c()` */
int virtio_console_isr(void) {
    if (!g_console)
        return 0;

    uint32_t interrupt_status = vm_mmio_readl(g_console->interrupt_status_reg);
    if (!WITHIN_MASK(interrupt_status, VIRTIO_INTERRUPT_STATUS_MASK)) {
        log_write("[console] Panic: ISR status register has reserved bits set\n");
        triple_fault();
    }

    if (interrupt_status & VIRTIO_INTERRUPT_STATUS_USED) {
        /* real work is done in the bottomhalf called in normal context, see below */
        uint16_t host_used_idx = vm_shared_readw(&g_console->rq->used->idx);
        if (host_used_idx != g_console->rq->seen_used) {
            /* we only care about the RX queue, so only kick bottomhalf when received input */
            __atomic_store_n(&g_console_trigger_bottomhalf, true, __ATOMIC_RELEASE);
        }
    }

    if (interrupt_status & VIRTIO_INTERRUPT_STATUS_CONFIG) {
        /* we don't currently care about changes in device config, so noop */
    }

    return 0;
}

static int handle_rq(uint16_t host_used_idx, bool* out_received) {
    assert(spinlock_is_locked(&g_console_receive_lock));

    if (host_used_idx - g_console->rq->seen_used > g_console->rq->queue_size) {
        /* malicious (impossible) value reported by the host; note that this check works also in
         * cases of int wrap */
        return -PAL_ERROR_DENIED;
    }

    while (host_used_idx != g_console->rq->seen_used) {
        uint16_t used_idx = g_console->rq->seen_used % g_console->rq->queue_size;
        uint16_t desc_idx = (uint16_t)vm_shared_readl(&g_console->rq->used->ring[used_idx].id);

        if (desc_idx >= g_console->rq->queue_size) {
            /* malicious (out of bounds) descriptor index */
            return -PAL_ERROR_DENIED;
        }

        uint64_t addr = vm_shared_readq(&g_console->rq->desc[desc_idx].addr);
        uint32_t size = vm_shared_readl(&g_console->rq->desc[desc_idx].len);

        if (addr < (uintptr_t)g_console->shared_rq_buf ||
                addr >= (uintptr_t)g_console->shared_rq_buf + VIRTIO_CONSOLE_SHARED_BUF_SIZE) {
            /* malicious (out of bounds) incoming message */
            return -PAL_ERROR_DENIED;
        }

        if ((addr - (uintptr_t)g_console->shared_rq_buf) % VIRTIO_CONSOLE_ITEM_SIZE) {
            /* malicious (not aligned on max item size) offset of the incoming message */
            return -PAL_ERROR_DENIED;
        }

        if (size > VIRTIO_CONSOLE_ITEM_SIZE) {
            /* malicious (out of bounds) size of the incoming message */
            return -PAL_ERROR_DENIED;
        }

        if (g_console->rq_buf_pos + size > VIRTIO_CONSOLE_RQ_BUF_SIZE) {
            /* this message exceeds rq_buf; need to wait until app reads and empties rq_buf */
            break;
        }

        /* copy from untrusted shared memory into internal rq buffer */
        char* rq_buf_addr = g_console->rq_buf + g_console->rq_buf_pos;
        vm_shared_memcpy(rq_buf_addr, (void*)addr, size);

        /* host may put messages that contain NUL symbols, find the first one and use it as delim */
        size_t end_of_msg = 0;
        while (end_of_msg < size && rq_buf_addr[end_of_msg])
            end_of_msg++;
        g_console->rq_buf_pos += end_of_msg;

        vm_shared_writeq(&g_console->rq->desc[desc_idx].addr,  addr);
        vm_shared_writel(&g_console->rq->desc[desc_idx].len,   VIRTIO_CONSOLE_ITEM_SIZE);
        vm_shared_writew(&g_console->rq->desc[desc_idx].flags, VIRTQ_DESC_F_WRITE);
        vm_shared_writew(&g_console->rq->desc[desc_idx].next,  0);

        uint16_t avail_idx = g_console->rq->cached_avail_idx;
        g_console->rq->cached_avail_idx++;

        vm_shared_writew(&g_console->rq->avail->ring[avail_idx % g_console->rq->queue_size], desc_idx);
        vm_shared_writew(&g_console->rq->avail->idx, g_console->rq->cached_avail_idx);

        g_console->rq->seen_used++;
        *out_received = true;
    }

    return 0;
}

static int handle_rq_with_disabled_notifications(void) {
    int ret;
    bool received = false;

    spinlock_lock(&g_console_receive_lock);

    /* disable interrupts (we anyhow will consume all inputs on RX) */
    vm_shared_writew(&g_console->rq->avail->flags, VIRTQ_AVAIL_F_NO_INTERRUPT);

    while (true) {
        uint16_t host_used_idx = vm_shared_readw(&g_console->rq->used->idx);
        if (host_used_idx != g_console->rq->seen_used) {
            ret = handle_rq(host_used_idx, &received);
            if (ret < 0)
                goto fail;
        }

        vm_shared_writew(&g_console->rq->avail->flags, 0); /* reenable interrupts */
        uint16_t reread_host_used_idx = vm_shared_readw(&g_console->rq->used->idx);
        if (reread_host_used_idx == g_console->rq->seen_used)
            break;

        /* disable interrupts and process RX again (that's a corner case: after the last check and
         * before enabling interrupts, an interrupt has been suppressed by the device) */
        vm_shared_writew(&g_console->rq->avail->flags, VIRTQ_AVAIL_F_NO_INTERRUPT);
    }

    spinlock_unlock(&g_console_receive_lock);

    if (received) {
        uint16_t host_device_used_flags = vm_shared_readw(&g_console->rq->used->flags);
        if (!(host_device_used_flags & VIRTQ_USED_F_NO_NOTIFY))
            vm_mmio_writew(g_console->rq_notify_addr, /*queue_sel=*/0);
        thread_wakeup_console();
    }

    return 0;

fail:
    vm_shared_writew(&g_console->rq->avail->flags, 0); /* reenable interrupts */
    spinlock_unlock(&g_console_receive_lock);
    return ret;
}

/* called from the bottomhalf thread in normal context (not interrupt context) */
int virtio_console_bottomhalf(void) {
    return handle_rq_with_disabled_notifications();
}

int64_t virtio_console_read(char* buffer, size_t size) {
    int ret;
    size_t bytes_read;

    if (!g_console)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_console_receive_lock);
    if (g_console->rq_buf_pos == 0) {
        if (!__atomic_load_n(&g_console_trigger_bottomhalf, __ATOMIC_ACQUIRE)) {
            /* there is nothing in the RQ buffer and VMM stopped sending us any new input */
            bytes_read = 0;
            ret = 0;
            goto out;
        }
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    if (g_console->rq_buf[g_console->rq_buf_pos - 1] != '\n') {
        /* non-blocking caller must return TRYAGAIN; blocking caller must sleep on this */
        ret = -PAL_ERROR_TRYAGAIN;
        goto out;
    }

    bytes_read = MIN(g_console->rq_buf_pos, size);
    memcpy(buffer, g_console->rq_buf, bytes_read);

    if (size < g_console->rq_buf_pos) {
        size_t left_in_rq_buf = g_console->rq_buf_pos - size;
        memmove(g_console->rq_buf, g_console->rq_buf + size, left_in_rq_buf);
    }

    g_console->rq_buf_pos = 0;
    ret = 0;
out:
    spinlock_unlock(&g_console_receive_lock);
    return ret < 0 ? ret : (int64_t)bytes_read;
}

static int cleanup_tq(void) {
    assert(spinlock_is_locked(&g_console_transmit_lock));

    uint16_t host_used_idx = vm_shared_readw(&g_console->tq->used->idx);

    if (host_used_idx - g_console->tq->seen_used > g_console->tq->queue_size) {
        /* malicious (impossible) value reported by the host; note that this check works also in
         * cases of int wrap */
        return -PAL_ERROR_DENIED;
    }

    while (host_used_idx != g_console->tq->seen_used) {
        uint16_t used_idx = g_console->tq->seen_used % g_console->tq->queue_size;
        uint16_t desc_idx = (uint16_t)vm_shared_readl(&g_console->tq->used->ring[used_idx].id);

        if (desc_idx >= g_console->tq->queue_size) {
            /* malicious (out of bounds) descriptor index */
            return -PAL_ERROR_DENIED;
        }

        if (virtq_is_desc_free(g_console->tq, desc_idx)) {
            /* malicious descriptor index (attempt at double-free attack) */
            return -PAL_ERROR_DENIED;
        }

        virtq_free_desc(g_console->tq, desc_idx);
        g_console->tq->seen_used++;
    }

    return 0;
}

static int cleanup_tq_completely(void) {
    assert(spinlock_is_locked(&g_console_transmit_lock));
    int ret;

    while (true) {
        ret = cleanup_tq();
        if (ret < 0)
            return ret;

        uint16_t curr_host_used_idx = g_console->tq->seen_used;
        uint16_t expected_host_used_idx = g_console->tq->cached_avail_idx;
        if (curr_host_used_idx == expected_host_used_idx) {
            /* host consumed all pending messages (descriptors), we can repopulate tq */
            break;
        }
        /* still some pending messages (descriptors) left to be consumed, let's wait */
        ret = delay(/*delay_us=*/100UL, /*continue_gate=*/NULL);
        if (ret < 0)
            return ret;
    }

    return 0;
}

/* expects a null-terminated string */
int virtio_console_nprint(const char* s, size_t size) {
    int ret;

    if (!g_console)
        return -PAL_ERROR_BADHANDLE;

    spinlock_lock(&g_console_transmit_lock);
    if (size > VIRTIO_CONSOLE_SHARED_BUF_SIZE) {
        /* message cannot fit into shared_tq_buf, cannot print it */
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    if (g_console->shared_tq_buf_pos + size > VIRTIO_CONSOLE_SHARED_BUF_SIZE) {
        /* this message exceeds shared_tq_buf, wait until all messages in shared_tq_buf are consumed
         * (and printed) by VMM and start overwriting the buffer */
        ret = cleanup_tq_completely();
        if (ret < 0)
            goto out;
        g_console->shared_tq_buf_pos = 0;
    }
    assert(size <= VIRTIO_CONSOLE_SHARED_BUF_SIZE - g_console->shared_tq_buf_pos);

    /*
     * We copy original message into shared_tq_buf for two reasons:
     *   - in case of Intel TDX, message may be allocated in secure TD memory, so it needs to be
     *     copied to shared mem,
     *   - message may be allocated on stack or freed by the caller before hypervisor had time to
     *     consume the message.
     */
    char* shared_tq_buf_addr = (char*)g_console->shared_tq_buf + g_console->shared_tq_buf_pos;
    vm_shared_memcpy(shared_tq_buf_addr, s, size);
    g_console->shared_tq_buf_pos += size;

    uint16_t desc_idx;
    ret = virtq_alloc_desc(g_console->tq, shared_tq_buf_addr, size, /*flags=*/0, &desc_idx);
    if (ret < 0)
        goto out;

    /* place the descriptor with message in the queue for host-printing */
    uint16_t avail_idx = g_console->tq->cached_avail_idx;
    g_console->tq->cached_avail_idx++;

    vm_shared_writew(&g_console->tq->avail->ring[avail_idx % g_console->tq->queue_size], desc_idx);
    vm_shared_writew(&g_console->tq->avail->idx, g_console->tq->cached_avail_idx);

    uint16_t host_device_used_flags = vm_shared_readw(&g_console->tq->used->flags);
    if (!(host_device_used_flags & VIRTQ_USED_F_NO_NOTIFY))
        vm_mmio_writew(g_console->tq_notify_addr, /*queue_sel=*/1);

    ret = 0;
out:
    spinlock_unlock(&g_console_transmit_lock);
    return ret;
}

/* expects a null-terminated string */
int virtio_console_print(const char* s) {
    int ret = virtio_console_nprint(s, strlen(s) + 1);
    if (ret < 0)
        log_write("[console] Warning: could not print to console\n");
    return ret;
}

int virtio_console_printf(const char* fmt, ...) {
    char buf[128];

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);

    buf[sizeof(buf) - 1] = 0;

    return virtio_console_print(buf);
}

static int virtio_console_negotiate_features(struct virtio_console* console) {
    struct virtio_pci_regs* pci_regs = console->pci_regs;

    uint32_t understood_features = 0;
    uint32_t advertised_features = 0;

    /* negotiate feature bits 31..0 */
    vm_mmio_writel(&pci_regs->device_feature_select, 0);
    advertised_features = vm_mmio_readl(&pci_regs->device_feature);

    if (advertised_features & (1 << VIRTIO_CONSOLE_F_SIZE)
            || advertised_features & (1 << VIRTIO_CONSOLE_F_MULTIPORT)
            || advertised_features & (1 << VIRTIO_CONSOLE_F_EMERG_WRITE)) {
        /* NOTE: we don't support console size, multi-port, emergency writes;
         *       currently simply ignore */
    }

    vm_mmio_writel(&pci_regs->driver_feature_select, 0);
    vm_mmio_writel(&pci_regs->driver_feature, understood_features);

    /* negotiate feature bits 63..32 */
    vm_mmio_writel(&pci_regs->device_feature_select, 1);
    advertised_features = vm_mmio_readl(&pci_regs->device_feature);

    if (!(advertised_features & (1 << VIRTIO_F_VERSION_1)))
        return -PAL_ERROR_DENIED;

    understood_features  = 1 << VIRTIO_F_VERSION_1;

    vm_mmio_writel(&pci_regs->driver_feature_select, 1);
    vm_mmio_writel(&pci_regs->driver_feature, understood_features);
    return 0;
}

static int virtio_console_alloc(struct virtio_console** out_console) {
    int ret;
    struct virtio_console* console = NULL;
    char* rq_buf = NULL;
    char* shared_rq_buf = NULL;
    char* shared_tq_buf = NULL;
    struct virtqueue* rq = NULL;
    struct virtqueue* tq = NULL;
    struct virtqueue* control_rq = NULL;
    struct virtqueue* control_tq = NULL;

    console = malloc(sizeof(*console));
    if (!console)
        return -PAL_ERROR_NOMEM;
    memset(console, 0, sizeof(*console)); /* for sanity */

    rq_buf = malloc(VIRTIO_CONSOLE_RQ_BUF_SIZE);
    if (!rq_buf) {
        ret = -PAL_ERROR_NOMEM;
        goto fail;
    }
    memset(rq_buf, 0, VIRTIO_CONSOLE_RQ_BUF_SIZE); /* for sanity */

    shared_rq_buf = memory_get_shared_region(VIRTIO_CONSOLE_SHARED_BUF_SIZE);
    shared_tq_buf = memory_get_shared_region(VIRTIO_CONSOLE_SHARED_BUF_SIZE);
    if (!shared_rq_buf || !shared_tq_buf) {
        ret = -PAL_ERROR_NOMEM;
        goto fail;
    }

    ret = virtq_create(VIRTIO_CONSOLE_QUEUE_SIZE, &rq);
    if (ret < 0)
        goto fail;

    ret = virtq_create(VIRTIO_CONSOLE_QUEUE_SIZE, &tq);
    if (ret < 0)
        goto fail;

    ret = virtq_create(VIRTIO_CONSOLE_CONTROL_QUEUE_SIZE, &control_rq);
    if (ret < 0)
        goto fail;

    ret = virtq_create(VIRTIO_CONSOLE_CONTROL_QUEUE_SIZE, &control_tq);
    if (ret < 0)
        goto fail;

    /* instruct the host to NOT send interrupts on TX upon consuming messages; the guest performs TX
     * cleanup itself on demand, see `cleanup_tq_completely()` usage */
    vm_shared_writew(&tq->avail->flags, VIRTQ_AVAIL_F_NO_INTERRUPT);

    /* prepare all buffers in RX for usage by host */
    for (size_t i = 0; i < VIRTIO_CONSOLE_QUEUE_SIZE; i++) {
        uint16_t desc_idx;
        ret = virtq_alloc_desc(rq, /*addr=*/NULL, VIRTIO_CONSOLE_ITEM_SIZE, VIRTQ_DESC_F_WRITE,
                               &desc_idx);
        if (ret < 0)
            goto fail;

        /* we found a free descriptor above and used a dummy NULL address, now let's rewire it */
        char* shared_addr = (char*)shared_rq_buf + desc_idx * VIRTIO_CONSOLE_ITEM_SIZE;
        vm_shared_writeq(&rq->desc[desc_idx].addr, (uint64_t)shared_addr);

        vm_shared_writew(&rq->avail->ring[i], desc_idx);
    }

    rq->cached_avail_idx = VIRTIO_CONSOLE_QUEUE_SIZE;
    vm_shared_writew(&rq->avail->idx, rq->cached_avail_idx);

    console->rq_buf = rq_buf;
    console->shared_rq_buf = shared_rq_buf;
    console->shared_tq_buf = shared_tq_buf;
    console->rq = rq;
    console->tq = tq;
    console->control_rq = control_rq;
    console->control_tq = control_tq;

    *out_console = console;
    return 0;
fail:
    memory_free_shared_region(shared_rq_buf, VIRTIO_CONSOLE_SHARED_BUF_SIZE);
    memory_free_shared_region(shared_tq_buf, VIRTIO_CONSOLE_SHARED_BUF_SIZE);
    virtq_free(rq, VIRTIO_CONSOLE_QUEUE_SIZE);
    virtq_free(tq, VIRTIO_CONSOLE_QUEUE_SIZE);
    virtq_free(control_rq, VIRTIO_CONSOLE_CONTROL_QUEUE_SIZE);
    virtq_free(control_tq, VIRTIO_CONSOLE_CONTROL_QUEUE_SIZE);
    free(rq_buf);
    free(console);
    return ret;
}

static int virtio_console_free(struct virtio_console* console) {
    memory_free_shared_region(console->shared_rq_buf, VIRTIO_CONSOLE_SHARED_BUF_SIZE);
    memory_free_shared_region(console->shared_tq_buf, VIRTIO_CONSOLE_SHARED_BUF_SIZE);
    virtq_free(console->rq, VIRTIO_CONSOLE_QUEUE_SIZE);
    virtq_free(console->tq, VIRTIO_CONSOLE_QUEUE_SIZE);
    virtq_free(console->control_rq, VIRTIO_CONSOLE_CONTROL_QUEUE_SIZE);
    virtq_free(console->control_tq, VIRTIO_CONSOLE_CONTROL_QUEUE_SIZE);
    free(console->rq_buf);
    free(console);
    return 0;
}

int virtio_console_init(struct virtio_pci_regs* pci_regs, struct virtio_console_config* pci_config,
                        uint64_t notify_off_addr, uint32_t notify_off_multiplier,
                        uint32_t* interrupt_status_reg) {
    int ret;
    uint8_t status;

    struct virtio_console* console;
    ret = virtio_console_alloc(&console);
    if (ret < 0)
        return ret;

    console->pci_regs = pci_regs;
    console->pci_config = pci_config;
    console->interrupt_status_reg = interrupt_status_reg;

    ret = virtio_console_negotiate_features(console);
    if (ret < 0)
        goto fail;

    status = vm_mmio_readb(&pci_regs->device_status);
    vm_mmio_writeb(&pci_regs->device_status, status | VIRTIO_STATUS_FEATURES_OK);

    status = vm_mmio_readb(&pci_regs->device_status);
    if (!(status & VIRTIO_STATUS_FEATURES_OK)) {
        /* host device (vhost-console) did not accept our features */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    ret = virtq_add_to_device(pci_regs, console->rq, /*queue_sel=*/0);
    if (ret < 0)
        goto fail;

    ret = virtq_add_to_device(pci_regs, console->tq, /*queue_sel=*/1);
    if (ret < 0)
        goto fail;

    ret = virtq_add_to_device(pci_regs, console->control_rq, /*queue_sel=*/2);
    if (ret < 0)
        goto fail;

    ret = virtq_add_to_device(pci_regs, console->control_tq, /*queue_sel=*/3);
    if (ret < 0)
        goto fail;

    vm_mmio_writew(&pci_regs->queue_select, 0);
    uint64_t rq_notify_off = vm_mmio_readw(&pci_regs->queue_notify_off);
    console->rq_notify_addr = (uint16_t*)(notify_off_addr + rq_notify_off * notify_off_multiplier);

    size_t rq_notify_addr_size = sizeof(*console->rq_notify_addr);
    if (!(PCI_MMIO_START_ADDR <= (uintptr_t)console->rq_notify_addr &&
                (uintptr_t)console->rq_notify_addr + rq_notify_addr_size < PCI_MMIO_END_ADDR)) {
        /* incorrect or malicious RQ queue notify addr */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    vm_mmio_writew(&pci_regs->queue_select, 1);
    uint64_t tq_notify_off = vm_mmio_readw(&pci_regs->queue_notify_off);
    console->tq_notify_addr = (uint16_t*)(notify_off_addr + tq_notify_off * notify_off_multiplier);

    size_t tq_notify_addr_size = sizeof(*console->tq_notify_addr);
    if (!(PCI_MMIO_START_ADDR <= (uintptr_t)console->tq_notify_addr &&
                (uintptr_t)console->tq_notify_addr + tq_notify_addr_size < PCI_MMIO_END_ADDR)) {
        /* incorrect or malicious TQ queue notify addr */
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    status = vm_mmio_readb(&pci_regs->device_status);
    vm_mmio_writeb(&pci_regs->device_status, status | VIRTIO_STATUS_DRIVER_OK);

    g_console = console;
    return 0;

fail:
    virtio_console_free(console);
    status = vm_mmio_readb(&pci_regs->device_status);
    vm_mmio_writeb(&pci_regs->device_status, status | VIRTIO_STATUS_FAILED);
    return ret;
}
