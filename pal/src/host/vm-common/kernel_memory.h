/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Declarations for memory-specific operations. */

#pragma once

#include <stdint.h>

#define PAGE_TABLES_ADDR 0x20000000UL          /* page tables occupy [512MB, 658MB) */
#define PAGE_TABLES_SIZE (146UL * 1024 * 1024) /* 146MB, enough to describe 64GB of addr space +
                                                * AddressSanitizer shadow memory for these 64GB */

#define SHARED_MEM_ADDR  0x29200000UL          /* shared memory occupies [658MB, 896MB) */
#define SHARED_MEM_SIZE  (238UL * 1024 * 1024) /* 238MB */

/* equivalent to E820_TABLE_ENTRY in EFI_HOB_E820_TABLE (needs to be packed) */
#define E820_ADDRESS_RANGE_MEMORY   1
#define E820_ADDRESS_RANGE_RESERVED 2
typedef struct {
    uint64_t  address;
    uint64_t  size;
    uint32_t  type;
} __attribute__((packed)) e820_table_entry;

extern uint64_t g_pml4_table_base;

void* memory_get_shared_region(size_t size);
int memory_free_shared_region(void* addr, size_t size);

int memory_find_page_table_entry(uint64_t addr, uint64_t** out_pte_addr);
int memory_mark_pages_on(uint64_t addr, size_t size, bool write, bool execute, bool usermode);
int memory_mark_pages_off(uint64_t addr, size_t size);
int memory_mark_pages_strong_uncacheable(uint64_t addr, size_t size, bool mark);

int memory_pagetables_init(void* memory_address_end, bool current_page_tables_cover_1gb);
int memory_preload_ranges(e820_table_entry* e820_entries, size_t e820_entries_size,
                          int (*callback)(uintptr_t addr, size_t size, const char* comment));
int memory_tighten_permissions(void);

int memory_alloc(void* addr, size_t size, bool read, bool write, bool execute);
int memory_protect(void* addr, size_t size, bool read, bool write, bool execute);
int memory_free(void* addr, size_t size);

int memory_init(e820_table_entry* e820_entries, size_t e820_entries_size,
                void** out_memory_address_start, void** out_memory_address_end);
