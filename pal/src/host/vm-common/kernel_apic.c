/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Local and I/O APIC, also called LAPIC and IOAPIC. Currently used only for IRQ routing (remapping
 * of IRQs of virtio devices provided by the hypervisor to interrupt vector number of CPU#0).
 *
 * References:
 *   - Local APIC: Intel SDM, Volume 3, Chapter 10
 *   - I/O APIC: https://pdos.csail.mit.edu/6.828/2016/readings/ia32/ioapic.pdf
 */

#include <stdint.h>

#include "api.h"
#include "cpu.h"
#include "pal_error.h"
#include "pal_internal.h"

#include "kernel_apic.h"
#include "kernel_memory.h"
#include "vm_callbacks.h"

#define TIMER_PERIOD_US (100 * 1000) /* 100 ms, same as default SCHED_RR interval in Linux */

extern uint64_t g_tsc_mhz;

static int memory_mark_pages_strong_uncacheable(uint64_t addr, size_t size) {
    uint64_t mark_addr = addr;
    while (mark_addr < addr + size) {
        uint64_t* pte_addr;
        int ret = memory_find_page_table_entry(mark_addr, &pte_addr);
        if (ret < 0)
            return ret;

        *pte_addr |= 1UL << 4; /* set bit 4 (PCD = Page-level cache disable) */
        invlpg(mark_addr);

        mark_addr += 4096;
    }
    return 0;
}

static void ioapic_write_reg(uint32_t offset, uint32_t val) {
    uint32_t* ioapic_regsel_addr = (uint32_t*)(IOAPIC_ADDR + 0x00);
    uint32_t* ioapic_win_addr    = (uint32_t*)(IOAPIC_ADDR + 0x10);

    vm_mmio_writel(ioapic_regsel_addr, offset);
    vm_mmio_writel(ioapic_win_addr, val);
}

__attribute__((unused))
static uint32_t ioapic_read_reg(uint32_t offset) {
    uint32_t* ioapic_regsel_addr = (uint32_t*)(IOAPIC_ADDR + 0x00);
    uint32_t* ioapic_win_addr    = (uint32_t*)(IOAPIC_ADDR + 0x10);

    vm_mmio_writel(ioapic_regsel_addr, offset);
    uint32_t val = vm_mmio_readl(ioapic_win_addr);

    /* TODO: val was read from VMM, needs to be hardened */
    return val;
}

static void ioapic_redirect_irq(uint8_t irq, uint8_t interrupt_vector) {
    /* IOREDTBL (I/O Redirection Table) regs start at offset 0x10; each reg is comprised of 2 32-bit
     * ints -- we do not use the high 32 bits (which specify APIC ID), they are all-zeros */
    uint32_t offset = irq * 2 + 0x10;

    /* Redirection Table entry format: bits 63:56 -- APIC ID, 55:17 -- reserved, 16 -- interrupt
     * mask (r/w), 15 -- trigger mode (r/w), 14 -- remote IRR status (r/o), 13 - polarity (r/w), 12
     * -- delivery status (r/o), 11 -- destination mode (r/w), 10:8 -- delivery mode (r/w), 7:0 --
     * assigned interrupt vector (r/w).
     *
     * Out of these fields, we care about:
     *   - bits 63:56 -- APIC ID, currently set to zero (means CPU#0), see also bit 11
     *   - bit 15     -- trigger mode, set to "edge sensitive" (zero), virtio implies edge
     *   - bit 11     -- destination mode, currently set to zero (means "physical mode for APIC ID")
     *   - bits 10:8  -- delivery mode, currently `000` (means "Fixed", delivers interrupt to CPU)
     *   - bits 7:0   -- interrupt vector on which the device IRQs are delivered by the CPU
     */
    uint32_t val = interrupt_vector;
    ioapic_write_reg(offset, val);
}

static void lapic_enable(void) {
    /* set up spurious interrupt register: with IRQ 39, APIC enabled */
    vm_shared_wrmsr(MSR_INSECURE_IA32_LAPIC_SPURIOUS_INTERRUPT_VECTOR, 39 | 0x100);
}

/* note that LAPIC timer is out of scope of e.g. Intel TDX, as TDX doesn't virtualize timer MSRs; in
 * other words, we must consider timer operations as insecure */
static int lapic_timer_init(void) {
    assert(g_tsc_mhz);

    uint32_t words[CPUID_WORD_NUM];
    cpuid(FEATURE_FLAGS_LEAF, 0, words);
    if (!(words[CPUID_WORD_ECX] & (1 << 24))) {
        /* TSC deadline timer is not available */
        return -PAL_ERROR_DENIED;
    }

    /* set up LVT timer: with IRQ 32, in TSC-Deadline mode (bit 18 set), not masked */
    vm_shared_wrmsr(MSR_INSECURE_IA32_LAPIC_LVT_TIMER, 32 | 0x40000);

    /* arm the timer for the first time */
    uint64_t future_tsc = get_tsc() + TIMER_PERIOD_US * g_tsc_mhz;
    vm_shared_wrmsr(MSR_INSECURE_IA32_TSC_DEADLINE, future_tsc);
    return 0;
}

void lapic_timer_rearm(void) {
    uint64_t future_tsc = get_tsc() + TIMER_PERIOD_US * g_tsc_mhz;
    vm_shared_wrmsr(MSR_INSECURE_IA32_TSC_DEADLINE, future_tsc);
    lapic_signal_interrupt_complete();
}

void lapic_signal_interrupt_complete(void) {
    /* write End-Of-Interrupt reg of LAPIC (according to x2APIC spec, 0 is the only valid value) */
    wrmsr(MSR_IA32_LAPIC_EOI, 0);
}

int apic_init(void) {
    /* IOAPIC initialization */
    int ret = memory_mark_pages_strong_uncacheable(IOAPIC_ADDR, IOAPIC_SIZE);
    if (ret < 0)
        return ret;

    /* all device IRQs are multiplexed on the same CPU interrupt vector 64; we assume that device
     * IRQs span 0 to 31 */
    for (uint8_t irq = 0; irq < 32; irq++)
        ioapic_redirect_irq(irq, /*interrupt_vector=*/64);

    /* LAPIC initialization (in x2APIC mode); note that LAPIC should be already enabled and in
     * x2APIC mode, so no need to check or modify the IA32_APIC_BASE MSR */
    lapic_enable();

    return lapic_timer_init();
}
