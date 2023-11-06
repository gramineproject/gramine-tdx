/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kernel_sched.h"
#include "kernel_thread.h"

#define SCHEDULING_STACK_SIZE    128     /* temp stack used by save_context_and_restore_next() */

#define AP_STARTUP_PAGE_ADDRESS 0x8000UL /* copy AP asm startup code to 32K address */
#define AP_STARTUP_PAGE_SIZE    0x1000UL /* asm startup code must fit into 4K */

#define AP_STARTUP_PAGE_AP_LOCK 0x8fc0UL /* will contain pointer to g_lock_single_ap_cpu */
#define AP_STARTUP_PAGE_C_FUNC  0x8fd0UL /* will contain pointer to pal_start_ap_c */
#define AP_STARTUP_PAGE_COUNTER 0x8fe0UL /* will contain pointer to g_started_cpus */
#define AP_STARTUP_PAGE_PML4    0x8ff0UL /* will contain pointer to initial_ap_pml4_table_base */

/* Mailbox 4K page used for sync between BSP and APs (used in Intel TDX); location can be found from
 * the ACPI MADT table, in the ACPI_MADT_MP_WAKEUP_TYPE entry */
#define MP_WAKEUP_MAILBOX_COMMAND_NOOP   0
#define MP_WAKEUP_MAILBOX_COMMAND_WAKEUP 1
struct mp_wakeup_mailbox {
    uint16_t command;              /* 0: noop, 1: wakeup, 2-0xFFFF: reserved */
    uint16_t reserved;
    uint32_t apic_id;              /* AP will check if this field matches its own APIC ID */
    uint64_t wakeup_vector;        /* wakeup address for AP (AP starts in 64-bit mode) */
    /* rest 2032 bytes (first half of 4K page) is reserved for OS kernel;
     * then 2048 bytes (second half of 4K page) is reserved for TD-Shim firmware */
} __attribute__((packed));

struct per_cpu_data {
    uint32_t cpu_id;               /* 0 .. num_cpus-1 */
    uint32_t apic_id_unused;       /* currently unused, left here for padding */
    void*    interrupt_stack;      /* start address of the stack used for interrupts */
    void*    interrupt_xsave_area; /* start address of the XSAVE save area used for interrupts */

    void* scheduling_stack;        /* temporary stack used in save_context_and_restore_next() */

    struct thread* idle_thread;         /* each CPU has its own idle thread */
    struct thread* bottomhalves_thread; /* only CPU0 has a bottomhalves thread currently */

    uint8_t  reserved[16];
} __attribute__((packed));
static_assert(sizeof(struct per_cpu_data) == 64, "incorrect struct size");

extern uint32_t g_num_cpus;

extern struct per_cpu_data* g_per_cpu_data;
extern void* g_per_cpu_interrupt_stack;
extern void* g_per_cpu_interrupt_xsave_area;

static inline struct per_cpu_data* get_per_cpu_data(void) {
    uint64_t per_cpu_data_ptr = rdmsr(MSR_IA32_GS_KERNEL_BASE);
    return (struct per_cpu_data*)per_cpu_data_ptr;
}

noreturn void pal_start_ap_c(uint32_t cpu_idx);

int init_multicore_prepare(uint32_t num_cpus);
int init_multicore(uint32_t num_cpus, void* hob_list_addr);
