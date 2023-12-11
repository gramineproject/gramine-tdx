/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Memory helpers.
 *
 * Notes on multi-core synchronization:
 *   - memory_get_shared_region()/memory_free_shared_region() are used on init, no sync required
 *   - g_pml4_table_base is set on init, no sync required
 *   - ops on page tables are currently used on init, no sync required
 *   - memory_alloc() relies on the fact that no other thread will access/free newly allocated
 *     memory, so no sync required
 *   - memory_free() does nothing, no sync required
 *   - all other funcs are used only at init, no sync required
 */

#include <stdint.h>

#include "api.h"
#include "asan.h"
#include "pal_error.h"

#include "kernel_debug.h"
#include "kernel_interrupts.h"
#include "kernel_memory.h"
#include "kernel_multicore.h"
#include "kernel_virtio.h"

static_assert(PAGE_SIZE == 4096, "unexpected PAGE_SIZE (expected 4K)");

/* Beginning of the page table hierarchy */
uint64_t g_pml4_table_base = 0;

/* Address Sanitizer shadow memory (physical memory range) */
static uint64_t g_asan_shadow_phys_start = 0;
static uint64_t g_asan_shadow_phys_end   = 0;

void* memory_get_shared_region(size_t size) {
	/* trivial shared memory management: allocations in the shared-memory range
	 * [SHARED_MEM_ADDR, SHARED_MEM_ADDR + SHARED_MEM_SIZE) are ever increasing */
	static void* g_shared_heap_pos = (void*)SHARED_MEM_ADDR;

    if (!size)
        return NULL;

#ifdef ASAN
    size_t original_size = size;
#endif
    size = ALIGN_UP(size, PAGE_SIZE);

    assert((uintptr_t)g_shared_heap_pos >= SHARED_MEM_ADDR);
    assert(access_ok(g_shared_heap_pos, size));
    if ((uintptr_t)g_shared_heap_pos + size > SHARED_MEM_ADDR + SHARED_MEM_SIZE)
        return NULL;

    void* ret = g_shared_heap_pos;
    g_shared_heap_pos = (char*)g_shared_heap_pos + size;
#ifdef ASAN
    asan_unpoison_region((uintptr_t)ret, original_size);
#endif
    return ret;
}

int memory_free_shared_region(void* addr, size_t size) {
    /* dummy; we never free shared regions for simplicity */
    __UNUSED(addr);
    __UNUSED(size);
#ifdef ASAN
    asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
#endif
    return 0;
}

__attribute_no_sanitize_address
int memory_find_page_table_entry(uint64_t addr, uint64_t** out_pte_addr) {
    assert(g_pml4_table_base);
    uint64_t* pml4_table = (uint64_t*)g_pml4_table_base;

    /* the mask covers bits 12:43 which covers the address space [0, 16TB); note that we do not
     * cover up to 12:51 because bit 47 or 51 can be specially used (e.g. "shared" bit in TDX) */
    const uint64_t page_table_entry_addr_mask = 0x00000ffffffff000UL;

    /* there is a single entry in the PML4 table, see also memory_pagetables_init();
     * in this entry, bits 12:51 contain the address of the PDPT table */
    uint64_t* pdpt_table = (uint64_t*)(pml4_table[0] & page_table_entry_addr_mask);

    /* each PDPT table entry covers 1GB of memory, starting from addr 0x00 */
    size_t pdpt_table_idx = addr / 1024 / 1024 / 1024;
    uint64_t* pd_table = (uint64_t*)(pdpt_table[pdpt_table_idx] & page_table_entry_addr_mask);

    /* each PD table entry covers 2MB of memory in the 1GB memory region determined via PDPT table
     * entry (recall that there are 512 PD entries in one PD table) */
    size_t pd_table_idx = (addr / 1024 / 1024 / 2) % 512;
    uint64_t* pt_table = (uint64_t*)(pd_table[pd_table_idx] & page_table_entry_addr_mask);

    /* each PT table entry covers 4KB of memory in the 2MB memory region determined via PD table
     * entry (recall that there are 512 PD entries in one PT table) */
    size_t pt_table_idx = (addr / 1024 / 4) % 512;

    /* sanity check: must arrive at the same page address as in `addr` */
    uint64_t page_addr = pt_table[pt_table_idx] & page_table_entry_addr_mask;
    if ((addr & page_table_entry_addr_mask) != page_addr)
        return -PAL_ERROR_INVAL;

    *out_pte_addr = &pt_table[pt_table_idx];
    return 0;
}

__attribute_no_sanitize_address
int memory_mark_pages_off(uint64_t addr, size_t size) {
    for (uint64_t mark_addr = addr; mark_addr < addr + size; mark_addr += PAGE_SIZE) {
        uint64_t* pte_addr;
        int ret = memory_find_page_table_entry(mark_addr, &pte_addr);
        if (ret < 0)
            return ret;
        *pte_addr &= ~1UL;
    }
    return send_invalidate_tlb_ipi_and_wait((void*)addr, size, /*invalidate_on_this_cpu=*/true);
}

__attribute_no_sanitize_address
int memory_mark_pages_on(uint64_t addr, size_t size, bool write, bool execute, bool usermode) {
    for (uint64_t mark_addr = addr; mark_addr < addr + size; mark_addr += PAGE_SIZE) {
        uint64_t* pte_addr;
        int ret = memory_find_page_table_entry(mark_addr, &pte_addr);
        if (ret < 0)
            return ret;

        uint64_t bits = 1UL; /* present bit is always set, since page is at least readable */
        if (write)
            bits |= 1UL << 1;
        if (usermode)
            bits |= 1UL << 2;
        if (!execute)
            bits |= 1UL << 63; /* NX/XD bit */
        *pte_addr = (*pte_addr & ~((1UL << 63) + 7UL)) | bits;
    }
    return send_invalidate_tlb_ipi_and_wait((void*)addr, size, /*invalidate_on_this_cpu=*/true);
}

__attribute_no_sanitize_address
int memory_mark_pages_strong_uncacheable(uint64_t addr, size_t size, bool mark) {
    for (uint64_t mark_addr = addr; mark_addr < addr + size; mark_addr += PAGE_SIZE) {
        uint64_t* pte_addr;
        int ret = memory_find_page_table_entry(mark_addr, &pte_addr);
        if (ret < 0)
            return ret;

        if (mark)
            *pte_addr |= 1UL << 4; /* PCD = Page-level cache disable */
        else
            *pte_addr &= ~(1UL << 4);
    }
    return send_invalidate_tlb_ipi_and_wait((void*)addr, size, /*invalidate_on_this_cpu=*/true);
}

/*
 * For Address Sanitizer, we reserve 1/8th of the total VM address space (which includes the memory
 * and PCI holes at [2GB, 4GB)) to ASan shadow memory. We carve out this 1/8th of the space at the
 * very end of the usable VM address space:
 *   - If VM has 8GB of RAM, then ASan needs 1GB, i.e. [7G, 8G).
 *   - Current max amount of RAM for VM is 64GB, which roughly corresponds to 8GB of shadow memory.
 *
 * We force VM size to be at least 8GB for simplicity: to avoid overlapping with reserved and
 * MMIO memory regions (e.g., shared memory region, page tables region, PCI MMIO region). Otherwise
 * for example, if VM size would be 4GB, then ASan shadow memory could not be put at [3.5GB, 4GB) as
 * it overlaps with PCI MMIO region.
 *
 * In addition, this ASan shadow memory must be reflected in ASan-specific page tables. These page
 * tables do not have 1:1 mapping, as ASan shadow memory has virtual addresses [1.5TB, 1.5TB + 8GB).
 * Thus, these page tables must create virtual-to-physical mapping as:
 *
 *     1.5TB + offset -> ASAN_SHADOW_PHYSICAL_START + offset
 *
 * Also, the "normal" page tables must disable "normal" virtual mappings to these physical-shadow
 * memory pages (otherwise normal memory would alias ASan shadow memory).
 */
__attribute_no_sanitize_address
static int asan_init(void* memory_address_end, uint64_t page_tables_addr, size_t page_tables_size,
                     uint64_t pml4_table_base, size_t normal_tables_cnt) {
#ifdef ASAN
    assert((uint64_t)memory_address_end <= ASAN_SHADOW_START);

    uint64_t vm_address_space_size = (uint64_t)memory_address_end;

    /* with ASan, Gramine requires at least 8GB of VM space; not that we use "7" in the expression
     * below to take into account situations when the VMM hides a bit of space at the end of 8GB for
     * its own purposes (this happens in TDX case) */
    if (vm_address_space_size < 7UL * 1024 * 1024 * 1024) {
        /* FIXME: print error via Port I/O because normal log fails at this early boot stage */
        debug_serial_io_write("Failed to initialize Address Sanitizer: VM size is less than 8GB");
        return -PAL_ERROR_NOMEM;
    }

    uint64_t asan_shadow_phys_start = (uint64_t)memory_address_end - vm_address_space_size / 8;
    asan_shadow_phys_start = ALIGN_DOWN(asan_shadow_phys_start, PAGE_SIZE);

    uint64_t asan_shadow_phys_end = asan_shadow_phys_start + vm_address_space_size / 8;
    asan_shadow_phys_end = ALIGN_DOWN(asan_shadow_phys_end, PAGE_SIZE);

    uint64_t asan_shadow_size = asan_shadow_phys_end - asan_shadow_phys_start;
    assert(asan_shadow_phys_start >= SHARED_MEM_ADDR + SHARED_MEM_SIZE);
    assert(asan_shadow_phys_end <= (uint64_t)memory_address_end);
    assert(asan_shadow_size <= vm_address_space_size / 8);
    assert(!(asan_shadow_phys_start < 0x100000000UL && 0x80000000UL < asan_shadow_phys_end));

    /* reset ASan shadow memory for sanity; we rely on 1:1 mapping set up by pagetables_init() */
    _real_memset((void*)asan_shadow_phys_start, 0, asan_shadow_size);

    size_t pages_4k_cnt = UDIV_ROUND_UP(asan_shadow_size, 4UL * 1024);
    size_t pages_2m_cnt = UDIV_ROUND_UP(asan_shadow_size, 2UL * 1024 * 1024);
    size_t pages_1g_cnt = UDIV_ROUND_UP(asan_shadow_size, 1UL * 1024 * 1024 * 1024);

    size_t page_tables_cnt     = UDIV_ROUND_UP(pages_4k_cnt, 512);
    size_t page_dir_tables_cnt = UDIV_ROUND_UP(pages_2m_cnt, 512);

    assert(pages_4k_cnt && pages_2m_cnt && pages_1g_cnt && page_tables_cnt && page_dir_tables_cnt);

    /* we reuse the same PML4 page that is used for normal page tables */
    size_t asan_tables_cnt = page_tables_cnt + page_dir_tables_cnt + /*PDP=*/1 + /*PML4=*/0;
    if ((normal_tables_cnt + asan_tables_cnt) * PAGE_SIZE > page_tables_size) {
        /* normal + asan page tables can occupy no more than page_tables_size, check for sanity */
        return -PAL_ERROR_NOMEM;
    }

    /* ASan memory is accessible only from kernel mode (ring 0), RW, present, non-executable */
    uint64_t flags = 0x3 + (1UL << 63);

    /* page tables for ASan shadow memory start after PML4 table (ASan PTs follow normal PTs) */
    uint64_t ptr = pml4_table_base;
    assert(IS_ALIGNED(ptr, PAGE_SIZE));
    ptr += PAGE_SIZE;

    /* page tables with PTE leaf entries */
    uint64_t page_tables_base = ptr;
    uint64_t asan_shadow_phys_addr = asan_shadow_phys_start;
    for (size_t i = 0; i < pages_4k_cnt; i++) {
        uint64_t entry = asan_shadow_phys_addr + flags;
        _real_memcpy((void*)ptr, &entry, sizeof(entry));
        ptr += sizeof(entry);
        asan_shadow_phys_addr += PAGE_SIZE;
    }
    ptr = ALIGN_UP(ptr, PAGE_SIZE);

    /* page directory tables with PDE entries */
    uint64_t page_dir_tables_base = ptr;
    for (size_t i = 0; i < pages_2m_cnt; i++) {
        uint64_t entry = page_tables_base + ((ptr - page_dir_tables_base) / 8) * PAGE_SIZE + flags;
        _real_memcpy((void*)ptr, &entry, sizeof(entry));
        ptr += sizeof(entry);
    }
    ptr = ALIGN_UP(ptr, PAGE_SIZE);

    /* one PDP page with up to 8 PDPE entries (to cover up to 8GB of shadow memory) */
    uint64_t pdp_table_base = ptr;
    for (size_t i = 0; i < pages_1g_cnt; i++) {
        uint64_t entry = page_dir_tables_base + ((ptr - pdp_table_base) / 8) * PAGE_SIZE + flags;
        _real_memcpy((void*)ptr, &entry, sizeof(entry));
        ptr += sizeof(entry);
    }
    uint64_t first_unused_page_in_page_tables = ALIGN_UP(ptr, PAGE_SIZE);

    /* update the "normal" PML4 page with an additional PML4E entry */
    assert(ASAN_SHADOW_START % (512UL * 1024 * 1024 * 1024) == 0);
    uint64_t entry_in_pml4_idx = ASAN_SHADOW_START / (512UL * 1024 * 1024 * 1024);
    assert(entry_in_pml4_idx != 0);

    ptr = pml4_table_base;
    for (size_t i = 0; i < entry_in_pml4_idx; i++)
        ptr += sizeof(uint64_t);

    uint64_t entry = (uint64_t)pdp_table_base + flags;
    _real_memcpy((void*)ptr, &entry, sizeof(entry));

    __asm__ volatile("mov %%rax, %%cr3" : : "a"(pml4_table_base));

    /* explicitly disallow accesses to the whole shared memory region to catch bugs in shared memory
     * (e.g. in virtio drivers or in the TDX Quote protocol); see also memory_get_shared_region()
     * and memory_free_shared_region() */
    asan_poison_region(SHARED_MEM_ADDR, SHARED_MEM_SIZE, ASAN_POISON_USER);

    size_t unused_pages_in_page_tables_size = page_tables_addr + page_tables_size
                                                  - first_unused_page_in_page_tables;
    asan_poison_region(first_unused_page_in_page_tables, unused_pages_in_page_tables_size,
                       ASAN_POISON_USER);

    g_asan_shadow_phys_start = asan_shadow_phys_start;
    g_asan_shadow_phys_end   = asan_shadow_phys_end;
#else
    __UNUSED(memory_address_end);
    __UNUSED(page_tables_addr);
    __UNUSED(page_tables_size);
    __UNUSED(pml4_table_base);
    __UNUSED(normal_tables_cnt);
#endif
    return 0;
}

/* sets up the new page tables hierarchy (with 4KB pages) to cover memory range [0x0, memory_size);
 * page tables have 1:1 virtual-to-physical address translation */
__attribute_no_sanitize_address
static int pagetables_init(size_t memory_size, uint64_t page_tables_addr, size_t page_tables_size,
                           size_t* out_total_tables_cnt, uint64_t* out_pml4_table_base) {
    /* all memory is initially accessible only from kernel mode (ring 0), RW and present */
    uint64_t leaf_flags = 0x3;

    /* for MMU traversal in user mode, mid-tree entries must be accessible also in ring-3 */
    uint64_t tree_flags = 0x7;

    size_t pages_4k_cnt = UDIV_ROUND_UP(memory_size, 4 * 1024);
    size_t pages_2m_cnt = UDIV_ROUND_UP(memory_size, 2 * 1024 * 1024);
    size_t pages_1g_cnt = UDIV_ROUND_UP(memory_size, 1 * 1024 * 1024 * 1024);

    size_t page_tables_cnt     = UDIV_ROUND_UP(pages_4k_cnt, 512);
    size_t page_dir_tables_cnt = UDIV_ROUND_UP(pages_2m_cnt, 512);

    assert(pages_4k_cnt && pages_2m_cnt && pages_1g_cnt && page_tables_cnt && page_dir_tables_cnt);

    assert(pages_4k_cnt && pages_2m_cnt && pages_1g_cnt && page_tables_cnt && page_dir_tables_cnt);

    size_t total_tables_cnt = page_tables_cnt + page_dir_tables_cnt + /*PDP=*/1 + /*PML4=*/1;
    if (total_tables_cnt * PAGE_SIZE > page_tables_size) {
        /* page tables can occupy no more than page_tables_size, check for sanity */
        return -PAL_ERROR_NOMEM;
    }

    uint64_t ptr = page_tables_addr;

    /* page tables with PTE leaf entries */
    uint64_t page_tables_base = ptr;
    for (size_t i = 0; i < pages_4k_cnt; i++) {
        uint64_t entry = ((ptr - page_tables_base) / 8) * PAGE_SIZE + leaf_flags;
        _real_memcpy((void*)ptr, &entry, sizeof(entry));
        ptr += sizeof(entry);
    }

    if (!IS_ALIGNED(ptr, PAGE_SIZE))
        return -PAL_ERROR_INVAL;

    /* page directory tables with PDE entries */
    uint64_t page_dir_tables_base = ptr;
    for (size_t i = 0; i < pages_2m_cnt; i++) {
        uint64_t entry = page_tables_base + ((ptr - page_dir_tables_base) / 8) * PAGE_SIZE
                                          + tree_flags;
        _real_memcpy((void*)ptr, &entry, sizeof(entry));
        ptr += sizeof(entry);
    }

    if (!IS_ALIGNED(ptr, PAGE_SIZE))
        return -PAL_ERROR_INVAL;

    /* one PDP page with up to 512 PDPE entries */
    uint64_t pdp_table_base = ptr;
    for (size_t i = 0; i < pages_1g_cnt; i++) {
        uint64_t entry = page_dir_tables_base + ((ptr - pdp_table_base) / 8) * PAGE_SIZE
                                              + tree_flags;
        _real_memcpy((void*)ptr, &entry, sizeof(entry));
        ptr += sizeof(entry);
    }
    ptr = ALIGN_UP(ptr, PAGE_SIZE);

    /* one PML4 page with a single PML4E entry */
    uint64_t pml4_table_base = ptr;
    uint64_t entry = (uint64_t)pdp_table_base + tree_flags;
    _real_memcpy((void*)ptr, &entry, sizeof(entry));

    __asm__ volatile("mov %%rax, %%cr3" : : "a"(pml4_table_base));

    if (out_total_tables_cnt)
        *out_total_tables_cnt = total_tables_cnt;
    if (out_pml4_table_base)
        *out_pml4_table_base = pml4_table_base;
    return 0;
}

__attribute_no_sanitize_address
int memory_pagetables_init(void* memory_address_end, bool current_page_tables_cover_1gb) {
    int ret;

    /*
     * First set up temporary page tables hierarchy to cover range [0x0, 1GB), if current page
     * tables don't do this already. To cover this range, it's enough to have page tables in the
     * region [4MB, 8MB) -- these temporary page tables will be overwritten anyway by the actual
     * page tables hierarchy set up below.
     *
     * Note that at this point only the PAL binary is loaded into memory, and it is either located
     * at [1MB, 4MB) in non-TDX case, or somewhere at 1GB or higher in TDX case. So there will be no
     * overlap with this temporary page tables hierarchy at [4MB, 8MB).
     *
     * We need this temporary hierarchy because bootloaders of some PALs (e.g. VM) set up static
     * page tables that cover small range [0x0, 32MB) which doesn't contain the [PAGE_TABLES_ADDR,
     * PAGE_TABLES_ADDR + PAGE_TABLES_SIZE) final page-tables region.
     */
    if (!current_page_tables_cover_1gb) {
        ret = pagetables_init(/*memory_size=*/1UL * 1024 * 1024 * 1024,
                              /*page_tables_addr=*/4UL * 1024 * 1024,
                              /*page_tables_size=*/4UL * 1024 * 1024,
                              /*out_total_tables_cnt=*/NULL, /*out_pml4_table_base=*/NULL);
        if (ret < 0)
            return ret;
    }

    /* now set up the new page tables hierarchy to cover range [0x0, memory_address_end) (aligned to
     * the next power of 2); we will use these page tables until the end of execution */
    size_t memory_size = 1;
    while (memory_size < (uintptr_t)memory_address_end)
        memory_size *= 2;

    /* memory size must be at least 4GB in size, because [3GB, 4GB) range is used for PCI, etc. */
    if (memory_size < 4UL * 1024 * 1024 * 1024)
        memory_size = 4UL * 1024 * 1024 * 1024;

    /* memory size must be at most 512GB in size, because the current construction of page tables
     * relies on a single PDP page which limits max addressable memory to 512GB */
    if (memory_size > 512UL * 1024 * 1024 * 1024)
        return -PAL_ERROR_OVERFLOW;

    size_t total_tables_cnt;
    uint64_t pml4_table_base;
    ret = pagetables_init(memory_size, PAGE_TABLES_ADDR, PAGE_TABLES_SIZE, &total_tables_cnt,
                          &pml4_table_base);
    if (ret < 0)
        return ret;

    ret = asan_init(memory_address_end, PAGE_TABLES_ADDR, PAGE_TABLES_SIZE, pml4_table_base,
                    total_tables_cnt);
    if (ret < 0)
        return ret;

    g_pml4_table_base = pml4_table_base;
    return 0;
}

int memory_preload_ranges(e820_table_entry* e820_entries, size_t e820_entries_size,
                          int (*callback)(uintptr_t addr, size_t size, const char* comment)) {
    int ret;

    for (size_t i = 0; i < e820_entries_size / sizeof(*e820_entries); i++) {
        if (e820_entries[i].type == E820_ADDRESS_RANGE_MEMORY)
            continue;

        if (e820_entries[i].address < PAGE_TABLES_ADDR + PAGE_TABLES_SIZE &&
                PAGE_TABLES_ADDR < e820_entries[i].address + e820_entries[i].size) {
            /* a reserved range overlaps with our page tables range */
            return -PAL_ERROR_DENIED;
        }

        if (e820_entries[i].address < SHARED_MEM_ADDR + SHARED_MEM_SIZE &&
                SHARED_MEM_ADDR < e820_entries[i].address + e820_entries[i].size) {
            /* a reserved range overlaps with our shared memory range */
            return -PAL_ERROR_DENIED;
        }

        ret = callback(e820_entries[i].address, e820_entries[i].size, "E820 reserved");
        if (ret < 0)
            return -PAL_ERROR_NOMEM;
    }

    /*
     * Mark the following memory regions as reserved (in addition to the above ones, extracted from
     * the E820 table), so that memory allocator doesn't use them:
     *   - [0, 1MB):       legacy DOS (includes DOS area, SMM memory, System BIOS),
     *   - [512MB, 658MB): page tables (for app memory and ASan shadow memory),
     *   - [658MB, 896MB): shared memory for virtqueues and for Quote (in TDX case),
     *   - [2GB, 3GB):     memory hole (QEMU doesn't map any memory here),
     *   - [3GB, 4GB):     PCI (includes BARs, LAPIC, IOAPIC).
     *   - [VM_RAM_END - 1/8th VM_RAM, VM_RAM_END):
     *                     Address Sanitizer shadow memory (physical memory region).
     *
     * Some notes on how this layout interplays with other regions:
     *   - In non-TDX case, the PAL binary is put at [1MB, 4MB).
     *   - In TDX case, the PAL binary is put at the top of RAM (but below 2GB). We enforce RAM to
     *     be at least 1GB, so in the worst case, the PAL binary + other TDShim data is put at
     *     [896MB, 1024MB). TDShim uses up to 128MB for the payload (PAL binary) and other data.
     *   - Applications may be EXEC programs, which means they will be put at 4MB. The largest app
     *     binaries we've seen in the wild have up to 300MB. Our layout allows to put such app
     *     binary at [4MB, 512MB), which is enough to host a 508MB-sized binary.
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

    if (g_asan_shadow_phys_start && g_asan_shadow_phys_end) {
        ret = callback(g_asan_shadow_phys_start, g_asan_shadow_phys_end - g_asan_shadow_phys_start,
                       "asan_shadow_memory");
        if (ret < 0)
            return -PAL_ERROR_DENIED;
    }

    return 0;
}

/* a counterpart to memory_preload_ranges(), must be executed after all PAL VM initialization is
 * done; we tighten page permissions on PAL-kernel specific memory regions, see the list in
 * memory_preload_ranges() above */
__attribute_no_sanitize_address
int memory_tighten_permissions(void) {
    int ret;

    /*
     * [0, 1MB): Legacy DOS (includes DOS area, SMM memory, System BIOS). We could not disable these
     *           pages at PAL init, because a sub-region was used for AP multicore init code/stack.
     */
    ret = memory_mark_pages_off(0x0UL, 0x100000UL);
    if (ret < 0)
        return ret;
    /*
     * [512MB, 658MB): Page tables. Should be RW (to allow page-permission changes), but accessible
     *                 only from ring-0 (no usermode) and cannot be executed.
     */
    ret = memory_mark_pages_on(PAGE_TABLES_ADDR, PAGE_TABLES_SIZE, /*write=*/true,
                               /*execute=*/false, /*usermode=*/false);
    if (ret < 0)
        return ret;
    /*
     * [658MB, 896MB): Shared memory for virtqueues and for Quote (in TDX case). Same as PTs.
     */
    ret = memory_mark_pages_on(SHARED_MEM_ADDR, SHARED_MEM_SIZE, /*write=*/true,
                               /*execute=*/false, /*usermode=*/false);
    if (ret < 0)
        return ret;
    /*
     * [2GB, 3GB): Memory hole (QEMU doesn't map any memory here),
     * [3GB, 4GB): PCI (includes BARs, LAPIC, IOAPIC).
     *
     * NOTE: We would need to perform the following logic: disable the whole region, with exceptions
     * of virtio drivers' (1) interrupt status reg, and (2) RQ/TQ notify addresses. This logic is
     * complicated, and environments like Intel TDX do not allow direct MMIO access anyway, so we
     * don't disable this hole/PCI region as it doesn't affect security.
     */

    /*
     * "Normal" page tables must disable "normal" virtual mappings to the physical-shadow memory
     * pages reserved for Address Sanitizer (otherwise normal memory would alias ASan shadow
     * memory, leading to both the app/Gramine and ASan using the same memory).
     */
    if (g_asan_shadow_phys_start && g_asan_shadow_phys_end) {
        ret = memory_mark_pages_off(g_asan_shadow_phys_start,
                                    g_asan_shadow_phys_end - g_asan_shadow_phys_start);
        if (ret < 0)
            return -PAL_ERROR_DENIED;
    }

    return 0;
}

__attribute_no_sanitize_address
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

    if (memory_address_start > SHARED_MEM_ADDR ||
            memory_address_end < SHARED_MEM_ADDR + SHARED_MEM_SIZE)
        return -PAL_ERROR_DENIED;

    *out_memory_address_start = (void*)memory_address_start;
    *out_memory_address_end   = (void*)memory_address_end;
    return 0;
}

int memory_alloc(void* addr, size_t size, bool read, bool write, bool execute) {
    if ((uintptr_t)addr < SHARED_MEM_ADDR + SHARED_MEM_SIZE &&
            SHARED_MEM_ADDR < (uintptr_t)addr + size) {
        /* [addr, addr+size) at least partially overlaps shared memory, should be impossible */
        return -PAL_ERROR_DENIED;
    }

    if (!read && !write && !execute) {
        memory_mark_pages_off((uint64_t)addr, size);
#ifdef ASAN
        asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
#endif
        return 0;
    }

    /* we rely on CR0.WP == 0 (Write Protect disabled), which allows to write even into read-only
     * pages in ring 0 (otherwise for read-only allocs, we would need to call below function twice:
     * once with W permission, and after memset-to-zero again, without W permission) */
    int ret = memory_mark_pages_on((uint64_t)addr, size, write, execute, /*usermode=*/true);
    if (ret < 0)
        return ret;

#ifdef ASAN
    asan_unpoison_region((uintptr_t)addr, size);
#endif
    memset(addr, 0, size);
    return 0;
}

int memory_protect(void* addr, size_t size, bool read, bool write, bool execute) {
    if ((uintptr_t)addr < SHARED_MEM_ADDR + SHARED_MEM_SIZE &&
            SHARED_MEM_ADDR < (uintptr_t)addr + size) {
        /* [addr, addr+size) at least partially overlaps shared memory, should be impossible */
        return -PAL_ERROR_DENIED;
    }

    if (!read && !write && !execute) {
#ifdef ASAN
        asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
#endif
        memory_mark_pages_off((uint64_t)addr, size);
        return 0;
    }

#ifdef ASAN
    asan_unpoison_region((uintptr_t)addr, size);
#endif
    return memory_mark_pages_on((uint64_t)addr, size, write, execute, /*usermode=*/true);
}

int memory_free(void* addr, size_t size) {
    if ((uintptr_t)addr < SHARED_MEM_ADDR + SHARED_MEM_SIZE &&
            SHARED_MEM_ADDR < (uintptr_t)addr + size) {
        /* [addr, addr+size) at least partially overlaps shared memory, should be impossible */
        return -PAL_ERROR_DENIED;
    }

#ifdef ASAN
    asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
#endif
    return memory_mark_pages_off((uint64_t)addr, size);
}
