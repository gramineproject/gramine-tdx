/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Common functionality of virtio device drivers.
 *
 * Reference: https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.pdf
 */

#include "api.h"
#include "pal_error.h"

#include "kernel_memory.h"
#include "kernel_virtio.h"
#include "vm_callbacks.h"

int virtq_create(uint16_t queue_size, struct virtqueue** out_virtq) {
    if (queue_size > VIRTQUEUE_MAX_QUEUE_SIZE)
        return -PAL_ERROR_INVAL;

    struct virtqueue* virtq = malloc(sizeof(*virtq));
    if (!virtq)
        return -PAL_ERROR_NOMEM;
    memset(virtq, 0, sizeof(*virtq));

    void* events = memory_get_shared_region(sizeof(uint16_t) + sizeof(uint16_t));
    if (!events) {
        free(virtq);
        return -PAL_ERROR_NOMEM;
    }

    virtq->next_free_desc = malloc(queue_size * sizeof(uint16_t));
    if (!virtq->next_free_desc)
        goto fail;

    virtq->used_event  = (uint16_t*)events;
    virtq->avail_event = (uint16_t*)((char*)events + sizeof(uint16_t));

    virtq->desc  = memory_get_shared_region(queue_size * sizeof(struct virtq_desc));
    virtq->avail = memory_get_shared_region(sizeof(struct virtq_avail) +
                                                queue_size * sizeof(uint16_t));
    virtq->used  = memory_get_shared_region(sizeof(struct virtq_used) +
                                                queue_size * sizeof(struct virtq_used_elem));
    if (!virtq->desc || !virtq->avail || !virtq->used)
        goto fail;

    virtq->queue_size = queue_size;
    virtq->seen_used  = 0;
    virtq->free_desc  = 0;
    virtq->cached_avail_idx = 0;

    for (uint16_t i = 0; i < queue_size; i++) {
        /* for each descriptor (in untrusted shared memory), we keep a shadow "next free desciptor"
         * (in trusted memory) -- for descriptor alloc/free, we use this shadow array */
        virtq->next_free_desc[i] = i + 1;
    }

    vm_shared_writew(virtq->used_event, 0);
    vm_shared_writew(virtq->avail_event, 0);

    vm_shared_writew(&virtq->avail->flags, 0);
    vm_shared_writew(&virtq->avail->idx, 0);
    /* for simplicity, we don't zero out elements of available ring */

    vm_shared_writew(&virtq->used->flags, 0);
    vm_shared_writew(&virtq->used->idx, 0);
    /* for simplicity, we don't zero out elements of used ring */

    /* for simplicity, we don't zero out descriptors */

    *out_virtq = virtq;
    return 0;

fail:
    virtq_free(virtq, queue_size);
    return -PAL_ERROR_NOMEM;
}

int virtq_free(struct virtqueue* virtq, uint16_t queue_size) {
    memory_free_shared_region(virtq->used_event, sizeof(uint16_t) + sizeof(uint16_t));
    memory_free_shared_region(virtq->desc, queue_size * sizeof(struct virtq_desc));
    memory_free_shared_region(virtq->avail, sizeof(struct virtq_avail) +
                                  queue_size * sizeof(uint16_t));
    memory_free_shared_region(virtq->used, sizeof(struct virtq_used) +
                                  queue_size * sizeof(struct virtq_used_elem));
    free(virtq->next_free_desc);
    free(virtq);
    return 0;
}

/* addr must be guest-physical address (currently we have flat space, so virtual = physical) */
int virtq_alloc_desc(struct virtqueue* virtq, void* addr, uint32_t len, uint16_t flags,
                     uint16_t* out_desc_idx) {
    if (flags & VIRTQ_DESC_F_INDIRECT) {
        /* current implementation doesn't allow indirect descriptors */
        return -PAL_ERROR_INVAL;
    }

    uint16_t idx = virtq->free_desc;
    if (idx == virtq->queue_size) {
        /* ran out of free descriptors, can try again after at least one virtq_free_desc() */
        return -PAL_ERROR_NOMEM;
    }

    /* rewire head of free-descriptors linked list to the next free descriptor (which could also be
    * the end-of-descriptors sentinel) */
    virtq->free_desc = virtq->next_free_desc[idx];
    virtq->next_free_desc[idx] = 0;

    vm_shared_writeq(&virtq->desc[idx].addr,  (uint64_t)addr);
    vm_shared_writel(&virtq->desc[idx].len,   len);
    vm_shared_writew(&virtq->desc[idx].flags, flags);
    vm_shared_writew(&virtq->desc[idx].next,  0);

    *out_desc_idx = idx;
    return 0;
}

bool virtq_is_desc_free(struct virtqueue* virtq, uint16_t desc_idx) {
    return virtq->next_free_desc[desc_idx] != 0;
}

void virtq_free_desc(struct virtqueue* virtq, uint16_t desc_idx) {
    /* rewire head of free-descriptors linked list to this newly-freed descriptor */
    uint32_t old_free_desc_head = virtq->free_desc;
    virtq->free_desc = desc_idx;
    virtq->next_free_desc[desc_idx] = old_free_desc_head;
}

int virtq_add_to_device(struct virtio_pci_regs* regs, struct virtqueue* virtq, uint16_t queue_sel) {
    vm_mmio_writew(&regs->queue_select, queue_sel);

    uint16_t queue_available_hint = vm_mmio_readw(&regs->queue_size);
    if (queue_available_hint == 0x0) {
        /* queue with this index is not available (not supported by the device) */
        return -PAL_ERROR_DENIED;
    }

    vm_mmio_writew(&regs->queue_size, virtq->queue_size);

    /* regs::queue addresses must be guest-physical, we rely on the fact that currently there is no
     * virtual-to-physical mapping (flat address space, virtual address = physical address) */
    vm_mmio_writel(&regs->queue_desc_low,    (uint32_t)((uintptr_t)virtq->desc));
    vm_mmio_writel(&regs->queue_desc_high,   (uint32_t)((uintptr_t)virtq->desc >> 32));
    vm_mmio_writel(&regs->queue_driver_low,  (uint32_t)((uintptr_t)virtq->avail));
    vm_mmio_writel(&regs->queue_driver_high, (uint32_t)((uintptr_t)virtq->avail >> 32));
    vm_mmio_writel(&regs->queue_device_low,  (uint32_t)((uintptr_t)virtq->used));
    vm_mmio_writel(&regs->queue_device_high, (uint32_t)((uintptr_t)virtq->used >> 32));

    vm_mmio_writew(&regs->queue_enable, 1);
    return 0;
}
