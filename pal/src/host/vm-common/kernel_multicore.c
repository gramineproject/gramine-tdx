/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains multicore support: BSP/AP initialization, synchronization.
 */

#include <stdint.h>

#include "api.h"
#include "cpu.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_host.h"
#include "pal_internal.h"

#include "kernel_acpi_madt.h"
#include "kernel_apic.h"
#include "kernel_memory.h"
#include "kernel_multicore.h"
#include "kernel_sched.h"
#include "kernel_syscalls.h"
#include "kernel_time.h"
#include "kernel_xsave.h"
#include "vm_callbacks.h"

uint32_t g_num_cpus = 0;
struct per_cpu_data* g_per_cpu_data = NULL;

static uint32_t g_started_cpus = 0; /* CPUs that started initialization; accessed atomically */
static uint32_t g_ready_cpus   = 0; /* CPUs that finished initialization; accessed atomically */

static uint32_t g_lock_single_ap_cpu = 0; /* lock to run only one AP CPU at a time */

/* AP initialization code that will be relocated; see kernel_multicore.S */
extern void ap_startup_page_start(void);
extern void ap_startup_page_end(void);
extern uint64_t initial_ap_pml4_table_base;

int init_multicore_prepare(uint32_t num_cpus) {
    int ret;

    g_started_cpus = 1; /* 1 because this BSP CPU is started */
    g_ready_cpus = 1;   /* 1 because this BSP CPU is ready */

    /* see below for + 1 in interrupt stack/xsave area arrays */
    g_per_cpu_data = calloc(num_cpus, sizeof(struct per_cpu_data));
    char* per_cpu_interrupt_stack = calloc(num_cpus + 1, INTERRUPT_STACK_SIZE);
    char* per_cpu_interrupt_xsave_area = calloc(num_cpus + 1, INTERRUPT_XSAVE_AREA_SIZE);
    char* per_cpu_scheduling_stack = calloc(num_cpus, SCHEDULING_STACK_SIZE);
    if (!g_per_cpu_data || !per_cpu_interrupt_stack || !per_cpu_interrupt_xsave_area
            || !per_cpu_scheduling_stack) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    /* interrupt stacks/xsave areas may be allocated not at page boundary, so need to adjust */
    per_cpu_interrupt_stack = ALIGN_UP_PTR(per_cpu_interrupt_stack, INTERRUPT_STACK_SIZE);
    per_cpu_interrupt_xsave_area = ALIGN_UP_PTR(per_cpu_interrupt_xsave_area,
                                                INTERRUPT_XSAVE_AREA_SIZE);

    for (uint32_t i = 0; i < num_cpus; i++) {
        struct thread* thread;
        ret = thread_helper_create(thread_idle_run, &thread);
        if (ret < 0)
            goto out;

        g_per_cpu_data[i].idle_thread = thread;
        g_per_cpu_data[i].interrupt_stack = per_cpu_interrupt_stack + i * INTERRUPT_STACK_SIZE;
        g_per_cpu_data[i].interrupt_xsave_area = per_cpu_interrupt_xsave_area
                                                     + i * INTERRUPT_XSAVE_AREA_SIZE;
        g_per_cpu_data[i].scheduling_stack = per_cpu_scheduling_stack + i * SCHEDULING_STACK_SIZE;
    }

    /* only CPU0 has a bottomhalves thread currently (i.e. CPU0 handles all incoming events) */
    ret = thread_helper_create(thread_bottomhalves_run, &g_per_cpu_data[0].bottomhalves_thread);
    if (ret < 0)
        goto out;

    g_per_cpu_data[0].cpu_id = 0;
    wrmsr(MSR_IA32_GS_KERNEL_BASE, (uint64_t)&g_per_cpu_data[0]);

    g_num_cpus = num_cpus;
    ret = 0;
out:
    if (ret < 0) {
        free(g_per_cpu_data);
        free(per_cpu_interrupt_stack);
        free(per_cpu_interrupt_xsave_area);
        free(per_cpu_scheduling_stack);
    }
    return ret;
}

static int init_multicore_mp_wakeup_mailbox(uint32_t num_cpus, void* hob_list_addr) {
    assert(num_cpus <= MAX_NUM_CPUS);

    void* mailbox_addr = NULL;
    uint8_t apic_ids[num_cpus];
    size_t apic_ids_size = num_cpus;

    int ret = extract_multicore_info_from_hobs(hob_list_addr, &mailbox_addr, apic_ids,
                                               &apic_ids_size);
    if (ret < 0)
        return ret;
    if (!mailbox_addr || apic_ids_size != num_cpus)
        return -PAL_ERROR_INVAL;

    struct mp_wakeup_mailbox* mailbox = (struct mp_wakeup_mailbox*)mailbox_addr;
    mailbox->wakeup_vector = AP_STARTUP_PAGE_ADDRESS;

    uint16_t initial_command = __atomic_load_n(&mailbox->command, __ATOMIC_SEQ_CST);
    if (initial_command != MP_WAKEUP_MAILBOX_COMMAND_NOOP)
        return - PAL_ERROR_DENIED;

    /* note that we start with CPU1; we assume that CPU0 is our BSP */
    for (size_t i = 1; i < apic_ids_size; i++) {
        mailbox->apic_id = apic_ids[i];
        __atomic_store_n(&mailbox->command, MP_WAKEUP_MAILBOX_COMMAND_WAKEUP, __ATOMIC_SEQ_CST);

        size_t tries = 0;
        while (__atomic_load_n(&mailbox->command, __ATOMIC_SEQ_CST) !=
                MP_WAKEUP_MAILBOX_COMMAND_NOOP) {
            /* BSP waits until the AP acknowledges the receipt of the wakeup command */
            if (tries++ > 5) {
                log_error("Waited for CPU %lu to wakeup via mailbox, but timed out", i);
                return -PAL_ERROR_DENIED;
            }
            ret = delay(/*delay_us=*/100UL, /*continue_gate=*/NULL);
            if (ret < 0)
                return ret;
        }
    }

    return 0;
}

static int init_multicore_init_sipi_sipi(uint32_t num_cpus) {
    /*
     * Send the INIT request first, by encoding 0x000C4500 in the ICR register:
     *   - bits 7-0:   vector field, must be programmed to all-zeros for compatibility
     *   - bits 10-8:  delivery mode = INIT (bits 101)
     *   - bit 11:     destination mode 0 (physical)
     *   - bit 12:     delivery status 0 (idle)
     *   - bit 14:     level 1 (assert)
     *   - bit 15:     trigger mode 0 (edge)
     *   - bits 19-18: destination shorthand = all excluding self (bits 11)
     */
    uint64_t icr_init_request = 0x000C4500UL;
    vm_shared_wrmsr(MSR_INSECURE_IA32_LAPIC_ICR, icr_init_request);

    /* wait for 10ms */
    int ret = delay(/*delay_us=*/10000UL, /*continue_gate=*/NULL);
    if (ret < 0)
        return ret;

    /*
     * Send the SIPI request, by encoding 0x000C4608 in the ICR register:
     *   - bits 7-0:   vector field, points to a start-up routine (at 0x8000, encoded as 0x8)
     *   - bits 10-8:  delivery mode = Start-Up (bits 110)
     *   - bit 11:     destination mode 0 (physical)
     *   - bit 12:     delivery status 0 (idle)
     *   - bit 14:     level 1 (assert)
     *   - bit 15:     trigger mode 0 (edge)
     *   - bits 19-18: destination shorthand = all excluding self (bits 11)
     */
    uint64_t icr_sipi_request = 0x000C4608UL;
    vm_shared_wrmsr(MSR_INSECURE_IA32_LAPIC_ICR, icr_sipi_request);

    /* wait for 200us */
    ret = delay(/*delay_us=*/200UL, /*continue_gate=*/NULL);
    if (ret < 0)
        return ret;

    uint32_t actually_started_cpus = __atomic_load_n(&g_started_cpus, __ATOMIC_SEQ_CST);
    if (actually_started_cpus != num_cpus) {
        /* send a second SIPI request and wait a bit more */
        vm_shared_wrmsr(MSR_INSECURE_IA32_LAPIC_ICR, icr_sipi_request);
        ret = delay(/*delay_us=*/100UL, /*continue_gate=*/NULL);
        if (ret < 0)
            return ret;
    }

    return 0;
}

int init_multicore(uint32_t num_cpus, void* hob_list_addr) {
    int ret;

    if (num_cpus == 1)
        return 0;

    if (strcmp(XSTRINGIFY(HOST_TYPE), "TDX")) {
        /* in TDX, cannot access MSR_IA32_APIC_BASE, so skip this check */
        uint64_t msr = rdmsr(MSR_IA32_APIC_BASE);
        if (!(msr & (1 << 8))) {
            log_error("Initial CPU is not a BSP, impossible (APIC_BASE MSR is 0x%lx)", msr);
            return -PAL_ERROR_DENIED;
        }
    }

    size_t ap_start_page_size = (uintptr_t)&ap_startup_page_end - (uintptr_t)&ap_startup_page_start;
    if (ap_start_page_size > AP_STARTUP_PAGE_SIZE) {
        log_error("AP startup code page size exceeds 4KB, impossible (size is %lu)",
                  ap_start_page_size);
        return -PAL_ERROR_DENIED;
    }

    /* Copy asm code of AP (Application Processors) startup to lower 1MB in memory; before copying
     * we must make sure the memory region is marked as present and after copying we must mark it as
     * strong uncacheable, according to Intel SDM, Vol. 3A, Section 9.4.4.1. */
    ret = memory_mark_pages_present(AP_STARTUP_PAGE_ADDRESS, AP_STARTUP_PAGE_SIZE,
                                    /*present=*/true);
    if (ret < 0)
        return ret;

    memcpy((void*)AP_STARTUP_PAGE_ADDRESS, &ap_startup_page_start, AP_STARTUP_PAGE_SIZE);

    uint32_t* g_lock_single_ap_cpu_addr = &g_lock_single_ap_cpu;
    memcpy((uint32_t**)AP_STARTUP_PAGE_AP_LOCK, &g_lock_single_ap_cpu_addr, sizeof(uint32_t*));

    void* pal_start_ap_c_addr = &pal_start_ap_c;
    memcpy((void**)AP_STARTUP_PAGE_C_FUNC, &pal_start_ap_c_addr, sizeof(void*));

    uint32_t* g_started_cpus_addr = &g_started_cpus;
    memcpy((uint32_t**)AP_STARTUP_PAGE_COUNTER, &g_started_cpus_addr, sizeof(uint32_t*));

    uint64_t* initial_ap_pml4_table_base_addr = &initial_ap_pml4_table_base;
    memcpy((uint64_t**)AP_STARTUP_PAGE_PML4, &initial_ap_pml4_table_base_addr, sizeof(uint64_t*));

    ret = memory_mark_pages_strong_uncacheable(AP_STARTUP_PAGE_ADDRESS, AP_STARTUP_PAGE_SIZE,
                                               /*mark=*/true);
    if (ret < 0)
        return ret;

    if (strcmp(XSTRINGIFY(HOST_TYPE), "TDX") == 0) {
        /* in TDX environments, need to use MP Wakeup mailbox */
        ret = init_multicore_mp_wakeup_mailbox(num_cpus, hob_list_addr);
    } else {
        /* in non-TDX environments, use classic INIT-SIPI-SIPI AP bootstrap sequence */
        ret = init_multicore_init_sipi_sipi(num_cpus);
    }
    if (ret < 0)
        return ret;

    size_t tries = 0;
    while (__atomic_load_n(&g_started_cpus, __ATOMIC_SEQ_CST) != num_cpus) {
        if (tries++ > num_cpus * 5) {
            log_error("Waited for %u CPUs to start initialization, but timed out", num_cpus);
            return -PAL_ERROR_DENIED;
        }
        ret = delay(/*delay_us=*/10000UL, /*continue_gate=*/NULL);
        if (ret < 0)
            return ret;
    }

    tries = 0;
    while (__atomic_load_n(&g_ready_cpus, __ATOMIC_SEQ_CST) != num_cpus) {
        if (tries++ > num_cpus * 5) {
            log_error("Waited for %u CPUs to finish initialization, but timed out", num_cpus);
            return -PAL_ERROR_DENIED;
        }
        ret = delay(/*delay_us=*/10000UL, /*continue_gate=*/NULL);
        if (ret < 0)
            return ret;
    }

    return 0;
}

/* called by `kernel_multicore.S` on AP startup; must not allocate heap memory! */
noreturn void pal_start_ap_c(uint32_t cpu_idx) {
    wrmsr(MSR_IA32_GS_BASE, 0x0); /* just for sanity: no current-thread TCB at init */

    /* BSP (main processor) created page table hierarchy, AP just needs to use it */
    __asm__ volatile("mov %%rax, %%cr3" : : "a"(g_pml4_table_base));

    /* BSP (main processor) should have found XCR0 features, AP just needs to set them */
    __asm__ volatile("xsetbv" : : "a"(g_xcr0), "c"(0), "d"(0));

    if (strcmp(XSTRINGIFY(HOST_TYPE), "TDX")) {
        /* in TDX, APIC is already in x2APIC mode */
        uint64_t msr = rdmsr(MSR_IA32_APIC_BASE);
        msr |= (1 << 11) + (1 << 10); /* xAPIC global enable and Enable x2APIC mode */
        wrmsr(MSR_IA32_APIC_BASE, msr);
    }

    assert(g_per_cpu_data && cpu_idx >= 1);
    g_per_cpu_data[cpu_idx].cpu_id = cpu_idx;
    wrmsr(MSR_IA32_GS_KERNEL_BASE, (uint64_t)&g_per_cpu_data[cpu_idx]);

    lapic_enable();
    lapic_timer_init();
    syscalls_init();
    interrupts_init();

    __atomic_add_fetch(&g_ready_cpus, 1, __ATOMIC_SEQ_CST);

    sched_thread(&g_lock_single_ap_cpu, /*clear_child_tid=*/NULL);
    __builtin_unreachable();
}
