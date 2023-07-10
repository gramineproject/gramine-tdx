/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Declarations for hardware/software interrupts, Interrupt Descriptor Table and its entries.
 * Also declares Task State Segment required for interrupts happenning during ring-3 execution. */

#pragma once

#include <stdint.h>

#include "cpu.h"
#include "spinlock.h"

#define INTERRUPT_STACK_SIZE      0x4000
#define INTERRUPT_XSAVE_AREA_SIZE 0x4000 /* 16KB, should be enough for current XSAVE areas */

/* Registers for ISR pushed on the stack by hardware + `isr_x()` prologues */
struct isr_regs {
    /* pointer to FP regs (aka XSAVE area), pushed by ISRs in *.S */
    void* fpregs;

    /* all GPRs except those pushed by the CPU, pushed by ISRs in *.S */
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rax;
    uint64_t rcx;

    uint64_t int_number;               /* pushed by ISRs in *.S */
    uint64_t error_code;               /* pushed by the CPU or dummy by ISRs in *.S */
    uint64_t rip, cs, rflags, rsp, ss; /* pushed by the CPU (CS and SS are 16-bit values) */
} __attribute__((packed));

/* Interrupt Descriptor Table gate (we only use interrupt gates, no trap gates and task gates --
 * i.e., all interrupt handlers are executed with IF flag cleared aka "interrupts disabled") */
struct idt_gate {
    uint16_t isr_addr_low;  /* linear address of Interrupt Service Routine, bits 0-15 */
    uint16_t code_selector; /* set by *.S */
    uint8_t  ist_offset;    /* Interrupt Stack Table offset (always 1 meaning IST1), set by *.S */
    uint8_t  flags;         /* set by *.S to 10001110b */
    uint16_t isr_addr_mid;  /* linear address of Interrupt Service Routine, bits 16-31 */
    uint32_t isr_addr_high; /* linear address of Interrupt Service Routine, bits 32-63 */
    uint32_t _reserved;
} __attribute__((packed));

/* Interrupt Descriptor Table (currently set in *.S and unused in C) */
struct idt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

/* 64-bit-mode Task State Segment (currently set in *.S and unused in C) */
struct tss_64bitmode {
    uint32_t _reserved0;
    uint64_t rsp0_unused;
    uint64_t rsp1_unused;
    uint64_t rsp2_unused;
    uint64_t _reserved1;
    uint64_t ist1;
    uint64_t ist2_unused;
    uint64_t ist3_unused;
    uint64_t ist4_unused;
    uint64_t ist5_unused;
    uint64_t ist6_unused;
    uint64_t ist7_unused;
    uint64_t _reserved2;
    uint16_t _reserved3;
    uint16_t iomap_base_unused; /* set to 104 in *.S -- the size of this TSS struct */
} __attribute__((packed));

/* 64-bit-mode TSS segment descriptor (partially set in *.S and finished in C) */
struct tss_64bitmode_segment_descriptor {
    uint16_t limit_low_16bits;
    uint16_t base_low_16bits;
    uint8_t  base_low_8bits;
    uint8_t  p_dpl_type;
    uint8_t  flags_limit_high_8bits;
    uint8_t  base_mid_8bits;
    uint32_t base_high_32bits;
    uint32_t _reserved2;
} __attribute__((packed));

static inline void spinlock_lock_disable_irq(spinlock_t* lock) {
    cli();
    spinlock_lock(lock);
}

static inline void spinlock_unlock_enable_irq(spinlock_t* lock) {
    spinlock_unlock(lock);
    sti();
}

static inline noreturn void triple_fault(void) {
    /* This IDT has a limit of 1 byte, hence #UD with this IDT loaded will result in #DF then triple
     * fault. In a microvm, a triple fault shuts down QEMU nicely. */
    static const char invalid_idtr[10] = {0};

    __asm__ volatile(
#ifdef C_NO_3F
        "hlt; jmp .\n"
#endif
        "lgdt %0; ud2\n"
        : : "m"(invalid_idtr));
    __builtin_unreachable();
}

void isr_c(struct isr_regs* regs);
int interrupts_init(void);
