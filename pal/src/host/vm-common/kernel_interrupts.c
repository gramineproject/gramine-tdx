/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Hardware/software interrupts. See also the bootloader code.
 *
 * Notes on multi-core synchronization:
 *   - processing different interrupt numbers in isr_c() requires different sync techniques, see
 *     comments in that func for more details
 *   - all other funcs are used only at init, no sync required
 */

#include <stdint.h>

#include "api.h"
#include "cpu.h"
#include "pal_error.h"
#include "pal_internal.h"

#include "kernel_apic.h"
#include "kernel_interrupts.h"
#include "kernel_memory.h"
#include "kernel_multicore.h"
#include "kernel_pci.h"
#include "kernel_sched.h"
#include "kernel_time.h"
#include "kernel_virtio.h"
#include "vm_callbacks.h"

/* Interrupt Service Routines (ISRs) are defined in the *.S */
extern void isr_0(void);
extern void isr_1(void);
extern void isr_2(void);
extern void isr_3(void);
extern void isr_4(void);
extern void isr_5(void);
extern void isr_6(void);
extern void isr_7(void);
extern void isr_8(void);
extern void isr_9(void);
extern void isr_10(void);
extern void isr_11(void);
extern void isr_12(void);
extern void isr_13(void);
extern void isr_14(void);
extern void isr_15(void);
extern void isr_16(void);
extern void isr_17(void);
extern void isr_18(void);
extern void isr_19(void);
extern void isr_20(void);
extern void isr_32(void);
extern void isr_33(void);
extern void isr_64(void);
extern void isr_spurious(void);

/* can be accessed without atomics as there is only one CPU (BSP) that modifies it (at boot time),
 * and afterwards it is read-only */
bool g_interrupts_enabled = false;

static struct idt_gate* g_idt = NULL; /* IDT with 256 partially filled gates, see *.S */

/* A single "invalidate TLB" structure used when page table entries (PTEs) are updated by one vCPU.
 * The vCPU populates this structure with mem region to invalidate, invalidates this region itself,
 * sets `num_responses = 1` and sends an "invalidate TLB" IPI to other vCPUs via the LAPIC ICR.
 * We have a single object protected by a single lock, so if two vCPUs must update PTEs, there is a
 * performance hit of doing the two operations one after another. Also note that the whole
 * "invalidate TLB" IPI protocol must be secure against missing/spurious/extra IPIs, as ICR is
 * controlled by the untrusted host. */
struct invalidate_tlb_request_t {
    void* addr;
    size_t size;
    uint32_t num_responses; /* must be accessed atomically in interrupt handler of each vCPU */
    bool in_progress;       /* must be accessed atomically in interrupt handler of each vCPU */
};

static struct invalidate_tlb_request_t g_invalidate_tlb_request;
static spinlock_t g_invalidate_tlb_request_lock = INIT_SPINLOCK_UNLOCKED;

void isr_c(struct isr_regs* regs) {
    int ret;

    extern char gdt_start[1];
    extern char gdt_entry_kernel_cs[1];
    uint64_t kernel_cs = (uint64_t)(gdt_entry_kernel_cs - gdt_start);

    switch (regs->int_number) {
        case 14: ;
            /* below code is currently only for diagnostics; we always panic on PFs */
            uint64_t faulted_addr;
            __asm__ volatile("mov %%cr2, %%rax" : "=a"(faulted_addr));
            faulted_addr &= ~0xFFFUL;

            uint64_t* pte_addr;
            ret = memory_find_page_table_entry(faulted_addr, &pte_addr);
            if (ret < 0) {
                log_error("Panic: #PF handler failed (cannot find PTE for 0x%lx)", faulted_addr);
                triple_fault();
            }

            log_error("Panic: #PF on address 0x%lx (corresponding PTE %p with value 0x%lx)",
                      faulted_addr, pte_addr, *pte_addr);
            log_error("       error code=0x%lx rip=0x%lx rsp=0x%lx rax=0x%lx", regs->error_code,
                      regs->rip, regs->rsp, regs->rax);
            triple_fault();
            break;
        case 20:
            ret = vm_virtualization_exception(regs);
            if (ret < 0) {
                log_error("Panic: virtualization exception (#VE, vector nr. 20) failed");
                triple_fault();
            }
            break;
        case 32:
            if (get_per_cpu_data()->cpu_id == 0) {
                /* only CPU0 handles timeouts and alarms */
                notify_about_timeouts_uninterruptable();
            }
            lapic_timer_rearm();
            if (regs->cs != kernel_cs) {
                /* only reschedule if timer interrupt occurs while in userland (i.e., we use
                 * preemptive userland scheduling but cooperative kernel scheduling); note that we
                 * don't enable/disable interrupts via RFLAGS' IF because it will happen
                 * automatically during save_context / restore_context */
                sched_thread_uninterruptable(regs);
            }
            break;
        case 33: ;
            /* "invalidate TLB" IPI -- may be spurious/extra, check for this */
            if (get_per_cpu_data()->invalidate_tlb_ipi_received) {
                /* ignore extra IPI (most probably there is a malicious host) */
                break;
            }
            bool in_progress = __atomic_load_n(&g_invalidate_tlb_request.in_progress,
                                               __ATOMIC_ACQUIRE);
            if (!in_progress) {
                /* ignore spurious IPI (most probably there is a malicious host) */
                break;
            }
            uint32_t old_num_responses = __atomic_load_n(&g_invalidate_tlb_request.num_responses,
                                                         __ATOMIC_ACQUIRE);
            if (!old_num_responses) {
                /* now this is weird -- some vCPU started the protocol but num of responses is 0 */
                log_error("Panic: `invalidate TLB` IPI received, but state is inconsistent");
                triple_fault();
            }

            void* addr  = __atomic_load_n(&g_invalidate_tlb_request.addr, __ATOMIC_ACQUIRE);
            size_t size = __atomic_load_n(&g_invalidate_tlb_request.size, __ATOMIC_ACQUIRE);
            uint64_t mark_addr = (uint64_t)addr;
            while (mark_addr < (uint64_t)addr + size) {
                invlpg(mark_addr);
                mark_addr += PAGE_SIZE;
            }

            get_per_cpu_data()->invalidate_tlb_ipi_received = 1;
            __atomic_fetch_add(&g_invalidate_tlb_request.num_responses, 1, __ATOMIC_ACQ_REL);
            lapic_signal_interrupt_complete();
            break;
        case 64:
            assert(get_per_cpu_data()->cpu_id == 0);
            ret = virtio_console_isr();
            if (ret < 0)
                triple_fault();
            ret = virtio_fs_isr();
            if (ret < 0)
                triple_fault();
            ret = virtio_vsock_isr();
            if (ret < 0)
                triple_fault();
            lapic_signal_interrupt_complete();
            break;
        default:
            log_error("Panic: unhandled exception (vector nr. %lu)", regs->int_number);
            log_error("       rip=0x%lx rsp=0x%lx rax=0x%lx", regs->rip, regs->rsp, regs->rax);
            triple_fault();
    }
}

int send_invalidate_tlb_ipi_and_wait(void* addr, size_t size, bool invalidate_on_this_cpu) {
    assert(IS_ALIGNED_PTR(addr, PAGE_SIZE) && IS_ALIGNED(size, PAGE_SIZE));

    int ret;

    if (invalidate_on_this_cpu) {
        uint64_t mark_addr = (uint64_t)addr;
        while (mark_addr < (uint64_t)addr + size) {
            invlpg(mark_addr);
            mark_addr += PAGE_SIZE;
        }
    }

    if (!g_interrupts_enabled) {
        /* this func may be called from bootstrap code, before interrupts are truly enabled */
        return 0;
    }

    spinlock_lock(&g_invalidate_tlb_request_lock);

    if (g_invalidate_tlb_request.in_progress || g_invalidate_tlb_request.num_responses) {
        /* sanity check that a previous "invalidate TLB" protocol run is finished */
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    for (uint32_t i = 0; i < g_num_cpus; i++) {
        /* reset the "IPI received" flag on each vCPU */
        g_per_cpu_data[i].invalidate_tlb_ipi_received = 0;
    }

    g_invalidate_tlb_request.in_progress = true;
    g_invalidate_tlb_request.addr = addr;
    g_invalidate_tlb_request.size = size;
    g_invalidate_tlb_request.num_responses = 1; /* this vCPU already invalidated */

    uint64_t icr_ipi_request = (/*destination=all_excluding_self*/3 << 18) + /*vector=*/33;
    vm_shared_wrmsr(MSR_INSECURE_IA32_LAPIC_ICR, icr_ipi_request);

    while (__atomic_load_n(&g_invalidate_tlb_request.num_responses, __ATOMIC_ACQUIRE)
            != g_num_cpus) {
        /* waiting for other vCPUs to invalidate their TLBs and acknowledge */
        CPU_RELAX();
    }

    g_invalidate_tlb_request.num_responses = 0;
    g_invalidate_tlb_request.in_progress = false;
    ret = 0;

out:
    spinlock_unlock(&g_invalidate_tlb_request_lock);
    return ret;
}

static int idt_gate_set(uint8_t isr_number, void* isr_addr) {
    /* selector, ist offset, flags, reserved bits are filled by *.S, check them here */
    if (g_idt[isr_number].code_selector == 0 ||
            g_idt[isr_number].ist_offset != 1 ||
            g_idt[isr_number].flags != 0x8E ||
            g_idt[isr_number]._reserved != 0) {
        return -PAL_ERROR_INVAL;
	}

    uint64_t isr_addr_uint64 = (uint64_t)isr_addr;
    g_idt[isr_number].isr_addr_low  = isr_addr_uint64 & 0xFFFF;
    g_idt[isr_number].isr_addr_mid  = (isr_addr_uint64 >> 16) & 0xFFFF;
    g_idt[isr_number].isr_addr_high = (isr_addr_uint64 >> 32) & 0xFFFFFFFF;
    return 0;
}

static int tss_init(void) {
    extern struct tss_64bitmode tss_64bitmode[1];
    extern struct tss_64bitmode_segment_descriptor tss_64bitmode_desc[1];

    /* *.S must have initialized TSS already (except for interrupt stack), check it */
    struct tss_64bitmode* tss = tss_64bitmode;
    tss += get_per_cpu_data()->cpu_id;

    if (tss->rsp0_unused != 0 || tss->rsp1_unused != 0 || tss->rsp2_unused != 0)
        return -PAL_ERROR_BADADDR;
    if (tss->ist1 != 0)
        return -PAL_ERROR_BADADDR;
    if (tss->iomap_base_unused != sizeof(*tss))
        return -PAL_ERROR_BADADDR;

    /* interrupt_stack is a base address, but we want top of the stack */
    tss->ist1 = (uint64_t)get_per_cpu_data()->interrupt_stack + INTERRUPT_STACK_SIZE;

    struct tss_64bitmode_segment_descriptor* tss_desc = tss_64bitmode_desc;
    tss_desc += get_per_cpu_data()->cpu_id;

    tss_desc->base_low_16bits  = (uint64_t)tss & 0xFFFF;
    tss_desc->base_low_8bits   = ((uint64_t)tss >> 16) & 0xFF;
    tss_desc->base_mid_8bits   = ((uint64_t)tss >> 24) & 0xFF;
    tss_desc->base_high_32bits = ((uint64_t)tss >> 32) & 0xFFFFFFFF;
    tss_desc->limit_low_16bits = sizeof(*tss) & 0xFFFF;
    return 0;
}

static int idt_init(void) {
    extern struct idt_gate idt_start[256]; /* IDT from *.S */
    g_idt = (struct idt_gate*)&idt_start;

    int ret;

    if (get_per_cpu_data()->cpu_id != 0) {
        /* all CPUs share the same IDT, so enough to initialize IDT only once */
        return 0;
    }

    /* hardware interrupts */
    ret = idt_gate_set(0,  &isr_0);  /* Divide-by-zero Error (#DE) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(1,  &isr_1);  /* Debug (#DB) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(2,  &isr_2);  /* Non-maskable Interrupt (NMI) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(3,  &isr_3);  /* Breakpoint (#BP) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(4,  &isr_4);  /* Overflow (#OF) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(5,  &isr_5);  /* Bound Range Exceeded (#BR) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(6,  &isr_6);  /* Invalid Opcode (#UD) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(7,  &isr_7);  /* Device Not Available (#NM) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(8,  &isr_8);  /* Double Fault (#DF) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(9,  &isr_9);  /* <legacy> */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(10, &isr_10); /* Invalid TSS (#TS) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(11, &isr_11); /* Segment Not Present (#NP) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(12, &isr_12); /* Stack-Segment Fault (#SS) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(13, &isr_13); /* General Protection Fault (#GP) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(14, &isr_14); /* Page Fault (#PF) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(15, &isr_15); /* <reserved> */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(16, &isr_16); /* x87 FP Exception (#MF) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(17, &isr_17); /* Alignment Check (#AC) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(18, &isr_18); /* Machine Check (#MC) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(19, &isr_19); /* SIMD FP Exception (#XM) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(20, &isr_20); /* Virtualization Exception (#VE) */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(32, &isr_32); /* Local APIC timer IRQ */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(33, &isr_33); /* "Invalidate TLB" IPI interrupt */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(39, &isr_spurious);
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    ret = idt_gate_set(64, &isr_64); /* generic virtio devices IRQ */
    if (ret < 0)
        return -PAL_ERROR_BADADDR;

    return 0;
}

int interrupts_init(void) {
    extern char gdt_start[1];
    extern struct tss_64bitmode_segment_descriptor tss_64bitmode_desc[1];

    int ret;

    ret = tss_init();
    if (ret < 0)
        return ret;

    ret = idt_init();
    if (ret < 0)
        return ret;

    /* load our GDT and IDT */
    extern char gdtr[1];
    extern char idtr[1];
    __asm__ volatile("lgdt %0" :: "m"(gdtr));
    __asm__ volatile("lidt %0" :: "m"(idtr));

    /* flush TSS descriptor */
    struct tss_64bitmode_segment_descriptor* tss_desc = tss_64bitmode_desc;
    tss_desc += get_per_cpu_data()->cpu_id;
    ltr((char*)tss_desc - gdt_start);

    /* enable interrupts */
    sti();
    return 0;
}
