/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Declarations for memory-specific operations. */

#pragma once

#include <stdint.h>

#define PAGE_TABLES_ADDR 0x9200000UL           /* page tables occupy [146MB, 256MB) */
#define PAGE_TABLES_SIZE (110UL * 1024 * 1024) /* 110MB, enough to describe 24GB of addr space */

#define SHARED_MEM_ADDR 0x10000000UL           /* memory for virtqueues occupies [256MB, 512MB) */
#define SHARED_MEM_SIZE (256UL * 1024 * 1024)  /* 256MB */

/* equivalent to E820_TABLE_ENTRY in EFI_HOB_E820_TABLE (needs to be packed) */
#define E820_ADDRESS_RANGE_MEMORY   1
#define E820_ADDRESS_RANGE_RESERVED 2
typedef struct {
    uint64_t  address;
    uint64_t  size;
    uint32_t  type;
} __attribute__((packed)) e820_table_entry;

extern bool g_enable_lazy_memory_alloc;

void* memory_get_shared_region(size_t size);
int memory_free_shared_region(void* addr, size_t size);

int memory_find_page_table_entry(uint64_t addr, uint64_t** out_pte_addr);
int memory_mark_pages_present(uint64_t addr, size_t size, bool present);

int memory_pagetables_init(void* memory_address_end);
int memory_preload_ranges(e820_table_entry* e820_entries, size_t e820_entries_size,
                          int (*callback)(uintptr_t addr, size_t size, const char* comment));

int memory_alloc(void* addr, size_t size);
int memory_free(void* addr, size_t size);

int memory_init(e820_table_entry* e820_entries, size_t e820_entries_size,
                void** out_memory_address_start, void** out_memory_address_end);
