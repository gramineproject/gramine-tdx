/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include "api.h"
#include "kernel_memory.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

int _PalVirtualMemoryAlloc(void* addr, size_t size, pal_prot_flags_t prot) {
    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    assert(addr);

    bool read    = !!(prot & PAL_PROT_READ);
    bool write   = !!(prot & (PAL_PROT_WRITE | PAL_PROT_WRITECOPY));
    bool execute = !!(prot & PAL_PROT_EXEC);
    return memory_alloc(addr, size, read, write, execute);
}

int _PalVirtualMemoryFree(void* addr, size_t size) {
    assert(addr);
    return memory_free(addr, size);
}

int _PalVirtualMemoryProtect(void* addr, size_t size, pal_prot_flags_t prot) {
    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    assert(addr);

    if ((uintptr_t)addr < SHARED_MEM_ADDR + SHARED_MEM_SIZE &&
            SHARED_MEM_ADDR < (uintptr_t)addr + size) {
        /* [addr, addr+size) at least partially overlaps shared memory, should be impossible */
        return -PAL_ERROR_DENIED;
    }

    bool read    = !!(prot & PAL_PROT_READ);
    bool write   = !!(prot & (PAL_PROT_WRITE | PAL_PROT_WRITECOPY));
    bool execute = !!(prot & PAL_PROT_EXEC);
    return memory_protect(addr, size, read, write, execute);
}

unsigned long _PalMemoryQuota(void) {
    return g_pal_public_state.memory_address_end - g_pal_public_state.memory_address_start;
}

void pal_read_next_reserved_range(uintptr_t last_range_start, uintptr_t* out_next_range_start,
                                  uintptr_t* out_next_range_end) {
    __UNUSED(last_range_start);

    /* this callback is used only in child processes, but we don't support multi-process */
    *out_next_range_start = 0;
    *out_next_range_end = 0;
}
