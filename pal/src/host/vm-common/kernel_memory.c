/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Memory helpers.
 */

#include <stdint.h>

#include "api.h"
#include "pal_error.h"

#include "kernel_memory.h"

/* Beginning of the page table hierarchy */
static uint64_t g_pml4_table_base;

void* memory_get_shared_region(size_t size) {
	/* trivial shared memory management: allocations in the shared-memory range
	 * [SHARED_MEM_ADDR, SHARED_MEM_ADDR + SHARED_MEM_SIZE) are ever increasing */
	static void* g_shared_heap_pos = (void*)SHARED_MEM_ADDR;

    if (!size)
        return NULL;

    size = ALIGN_UP(size, PRESET_PAGESIZE);

    assert((uintptr_t)g_shared_heap_pos >= SHARED_MEM_ADDR);
    assert(access_ok(g_shared_heap_pos, size));
    if ((uintptr_t)g_shared_heap_pos + size > SHARED_MEM_ADDR + SHARED_MEM_SIZE)
        return NULL;

    void* ret = g_shared_heap_pos;
    g_shared_heap_pos = (char*)g_shared_heap_pos + size;
    return ret;
}

int memory_free_shared_region(void* addr, size_t size) {
    /* dummy; we never free shared regions for simplicity */
    __UNUSED(addr);
    __UNUSED(size);
    return 0;
}

int memory_find_page_table_entry(uint64_t addr, uint64_t** out_pte_addr) {
    uint64_t* pml4_table = (uint64_t*)g_pml4_table_base;

    /* there is a single entry in the PML4 table, see also memory_pagetables_init();
     * in this entry, bits 12:51 contain the address of the PDPT table */
    uint64_t* pdpt_table = (uint64_t*)(pml4_table[0] & 0x000ffffffffff000UL);

    /* each PDPT table entry covers 1GB of memory, starting from addr 0x00 */
    size_t pdpt_table_idx = addr / 1024 / 1024 / 1024;
    uint64_t* pd_table = (uint64_t*)(pdpt_table[pdpt_table_idx] & 0x000ffffffffff000UL);

    /* each PD table entry covers 2MB of memory in the 1GB memory region determined via PDPT table
     * entry (recall that there are 512 PD entries in one PD table) */
    size_t pd_table_idx = (addr / 1024 / 1024 / 2) % 512;
    uint64_t* pt_table = (uint64_t*)(pd_table[pd_table_idx] & 0x000ffffffffff000UL);

    /* each PT table entry covers 4KB of memory in the 2MB memory region determined via PD table
     * entry (recall that there are 512 PD entries in one PT table) */
    size_t pt_table_idx = (addr / 1024 / 4) % 512;

    /* sanity check: must arrive at the same page address as in `addr` */
    uint64_t page_addr = pt_table[pt_table_idx] & 0xfffffffe00000UL;
    if ((addr & 0xfffffffe00000UL) != page_addr)
        return -PAL_ERROR_INVAL;

    *out_pte_addr = &pt_table[pt_table_idx];
    return 0;
}

/* sets up the new page tables hierarchy (with 4KB pages) in range [0x0, memory_address_end)
 * (aligned to the next power of 2); page tables have 1:1 virtual-to-physical address translation */
int memory_pagetables_init(void* memory_address_end) {
    /* paged-in memory size must be a power of two; possible values from 4GB to 512GB */
    size_t max_memory_size = 1;
    while (max_memory_size < (uintptr_t)memory_address_end)
        max_memory_size *= 2;

    if (max_memory_size < 4UL * 1024 * 1024 * 1024)
        max_memory_size = 4UL * 1024 * 1024 * 1024;

    if (max_memory_size > 512UL * 1024 * 1024 * 1024)
        return -PAL_ERROR_OVERFLOW;

    uint64_t flags = 0x7; /* User, Writable, Present */

    size_t pages_4k_cnt = max_memory_size / (4 * 1024);
    size_t pages_2m_cnt = max_memory_size / (2 * 1024 * 1024);
    size_t pages_1g_cnt = max_memory_size / (1 * 1024 * 1024 * 1024);

    size_t page_tables_cnt     = pages_4k_cnt / 512;
    size_t page_dir_tables_cnt = pages_2m_cnt / 512;

    size_t total_tables_cnt = page_tables_cnt + page_dir_tables_cnt + /*PDP=*/1 + /*PML4=*/1;
    if (total_tables_cnt * 4096 > PAGE_TABLES_SIZE) {
        /* page tables can occupy no more than PAGE_TABLES_SIZE (see below) */
        return -PAL_ERROR_NOMEM;
    }

    /* region [PAGE_TABLES_ADDR, PAGE_TABLES_ADDR + PAGE_TABLES_SIZE) is reserved for page tables */
    uint64_t ptr = PAGE_TABLES_ADDR;

    /* page tables with PTE leaf entries */
    uint64_t page_tables_base = ptr;
    for (size_t i = 0; i < pages_4k_cnt; i++) {
        uint64_t entry = ((ptr - page_tables_base) / 8) * 4096 + flags;
        memcpy((void*)ptr, &entry, sizeof(entry));
        ptr += sizeof(entry);
    }

    if (!IS_ALIGNED(ptr, 4096))
        return -PAL_ERROR_INVAL;

    /* page directory tables with PDE entries */
    uint64_t page_dir_tables_base = ptr;
    for (size_t i = 0; i < pages_2m_cnt; i++) {
        uint64_t entry = page_tables_base + ((ptr - page_dir_tables_base) / 8) * 4096 + flags;
        memcpy((void*)ptr, &entry, sizeof(entry));
        ptr += sizeof(entry);
    }

    if (!IS_ALIGNED(ptr, 4096))
        return -PAL_ERROR_INVAL;

    /* one PDP page with up to 512 PDPE entries */
    uint64_t pdp_table_base = ptr;
    for (size_t i = 0; i < pages_1g_cnt; i++) {
        uint64_t entry = page_dir_tables_base + ((ptr - pdp_table_base) / 8) * 4096 + flags;
        memcpy((void*)ptr, &entry, sizeof(entry));
        ptr += sizeof(entry);
    }
    ptr = ALIGN_UP(ptr, 4096);

    /* one PML4 page with a single PML4E entry */
    uint64_t pml4_table_base = ptr;
    uint64_t entry = (uint64_t)pdp_table_base + flags;
    memcpy((void*)ptr, &entry, sizeof(entry));

    __asm__ volatile("mov %%rax, %%cr3" : : "a"(pml4_table_base));
    g_pml4_table_base = pml4_table_base;
    return 0;
}

int memory_preload_ranges(e820_table_entry* e820_entries, size_t e820_entries_size,
                          int (*callback)(uintptr_t addr, size_t size, const char* comment)) {
    int ret;

    for (size_t i = 0; i < e820_entries_size / sizeof(*e820_entries); i++) {
        if (e820_entries[i].type == E820_ADDRESS_RANGE_MEMORY)
            continue;

        if (e820_entries[i].type == E820_ADDRESS_RANGE_RESERVED &&
                e820_entries[i].address == 0x000800000UL) {
            /* special handling of TD-Shim: it puts initial page tables at [0x800000, 0x820000) and
             * marks them as Reserved, but we use our own page tables so we can re-use this range */
            continue;
        }

        if (e820_entries[i].address < PAGE_TABLES_ADDR + PAGE_TABLES_SIZE &&
                PAGE_TABLES_ADDR < e820_entries[i].address + e820_entries[i].size) {
            /* a reserved range overlaps with our page tables range */
            return -PAL_ERROR_DENIED;
        }

        ret = callback(e820_entries[i].address, e820_entries[i].size, "E820 reserved");
        if (ret < 0)
            return -PAL_ERROR_NOMEM;
    }

    /* Mark the following memory regions as reserved (in addition to the above ones, extracted from
     * the E820 table), so that memory allocator doesn't use them:
     *   - [0, 1MB):       legacy DOS (includes DOS area, SMM memory, System BIOS)
     *   - [146MB, 256MB): page tables
     *   - [256MB, 512MB): shared memory for virtqueues
     *   - [2GB, 3GB):     memory hole (QEMU doesn't map any memory here)
     *   - [3GB, 4GB):     PCI (includes BARs, LAPIC, IOAPIC)
     */
    ret = callback(0x0UL, 0x100000UL, "dos_memory_addr");
    if (ret < 0)
        return -PAL_ERROR_NOMEM;
    ret = callback(PAGE_TABLES_ADDR, PAGE_TABLES_SIZE, "page_tables");
    if (ret < 0)
        return -PAL_ERROR_NOMEM;
    ret = callback(SHARED_MEM_ADDR, SHARED_MEM_SIZE, "shared_memory");
    if (ret < 0)
        return -PAL_ERROR_NOMEM;
    ret = callback(0x80000000UL, 0x80000000UL, "qemu_pci_hole");
    if (ret < 0)
        return -PAL_ERROR_NOMEM;

    return 0;
}

int memory_init(e820_table_entry* e820_entries, size_t e820_entries_size,
                void** out_memory_address_start, void** out_memory_address_end) {
    assert(e820_entries_size % sizeof(*e820_entries) == 0);

    uint64_t memory_address_start = UINT64_MAX;
    uint64_t memory_address_end   = 0;
    for (size_t i = 0; i < e820_entries_size / sizeof(*e820_entries); i++) {
        if (e820_entries[i].type != E820_ADDRESS_RANGE_MEMORY)
            continue;

        if (memory_address_start > e820_entries[i].address)
            memory_address_start = e820_entries[i].address;

        if (memory_address_end < e820_entries[i].address + e820_entries[i].size)
            memory_address_end = e820_entries[i].address + e820_entries[i].size;
    }

    if (memory_address_start >= memory_address_end)
        return -PAL_ERROR_DENIED;

    if (memory_address_start > PAGE_TABLES_ADDR ||
            memory_address_end < PAGE_TABLES_ADDR + PAGE_TABLES_SIZE)
        return -PAL_ERROR_DENIED;

    *out_memory_address_start = (void*)memory_address_start;
    *out_memory_address_end   = (void*)memory_address_end;
    return 0;
}
