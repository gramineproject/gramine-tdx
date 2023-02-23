/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Declarations for local and I/O APICs. */

#pragma once

/* We rely on the hypervisor to put the IOAPIC at predefined 0xFEC00000, 16KB memory region. Note
 * that this memory region should be UC (strong uncacheable), so we mark the corresponding page
 * tables as UC -- by setting bit PCD in a corresponding page-table entry. */
#define IOAPIC_ADDR 0xfec00000
#define IOAPIC_SIZE 0x4000

/* We rely on the hypervisor to set up x2APIC (the only mode supported by Intel TDX). In x2APIC, we
 * use reads/writes to MSRs (in contrast to xAPIC with its MMIO region). */
#define MSR_INSECURE_IA32_LAPIC_SPURIOUS_INTERRUPT_VECTOR 0x80f
#define MSR_INSECURE_IA32_LAPIC_LVT_TIMER                 0x832
#define MSR_IA32_LAPIC_EOI                                0x80b

/* Convenience MSR to specify at which TSC value to generate next timer interrupt */
#define MSR_INSECURE_IA32_TSC_DEADLINE 0x000006E0

void lapic_signal_interrupt_complete(void);
void lapic_timer_rearm(void);

int apic_init(void);
