/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * VM callbacks notes:
 *
 * - All VM memory is shared (accessible by the hypervisor), so shared accesses reduce to normal
 *   accesses (probably with compiler barriers).
 *
 * - MMIO accesses are the same as normal memory accesses.
 *
 * - All MSRs are accessible via `wrmsr`/`rdmsr` instructions, so these accesses reduce to normal
 *   wrmsr/rdmsr.
 */

#include <stdint.h>

#include "kernel_interrupts.h"
#include "vm_callbacks.h"

void* vm_shared_memcpy(void* dest, const void* src, size_t n) {
    return memcpy(dest, src, n);
}

void* vm_shared_memset(void* s, int c, size_t n) {
    return memset(s, c, n);
}

void vm_shared_wrmsr(uint64_t msr, uint64_t value) {
    wrmsr(msr, value);
}

uint8_t vm_shared_readb(uint8_t* shared_addr) {
    return READ_ONCE(*shared_addr);
}

uint16_t vm_shared_readw(uint16_t* shared_addr) {
    return READ_ONCE(*shared_addr);
}

uint32_t vm_shared_readl(uint32_t* shared_addr) {
    return READ_ONCE(*shared_addr);
}

uint64_t vm_shared_readq(uint64_t* shared_addr) {
    return READ_ONCE(*shared_addr);
}

void vm_shared_writeb(uint8_t* shared_addr, uint8_t data) {
    WRITE_ONCE(*shared_addr, data);
    COMPILER_BARRIER();
}

void vm_shared_writew(uint16_t* shared_addr, uint16_t data) {
    WRITE_ONCE(*shared_addr, data);
    COMPILER_BARRIER();
}

void vm_shared_writel(uint32_t* shared_addr, uint32_t data) {
    WRITE_ONCE(*shared_addr, data);
    COMPILER_BARRIER();
}

void vm_shared_writeq(uint64_t* shared_addr, uint64_t data) {
    WRITE_ONCE(*shared_addr, data);
    COMPILER_BARRIER();
}

uint8_t vm_mmio_readb(uint8_t* mmio_addr) {
    return vm_shared_readb(mmio_addr);
}

uint16_t vm_mmio_readw(uint16_t* mmio_addr) {
    return vm_shared_readw(mmio_addr);
}

uint32_t vm_mmio_readl(uint32_t* mmio_addr) {
    return vm_shared_readl(mmio_addr);
}

uint64_t vm_mmio_readq(uint64_t* mmio_addr) {
    return vm_shared_readq(mmio_addr);
}

void vm_mmio_writeb(uint8_t* mmio_addr, uint8_t data) {
    vm_shared_writeb(mmio_addr, data);
}

void vm_mmio_writew(uint16_t* mmio_addr, uint16_t data) {
    vm_shared_writew(mmio_addr, data);
}

void vm_mmio_writel(uint32_t* mmio_addr, uint32_t data) {
    vm_shared_writel(mmio_addr, data);
}

void vm_mmio_writeq(uint64_t* mmio_addr, uint64_t data) {
    vm_shared_writeq(mmio_addr, data);
}

uint8_t vm_portio_readb(uint16_t port) {
    uint8_t val;
    __asm__ volatile("inb %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

uint16_t vm_portio_readw(uint16_t port) {
    uint16_t val;
    __asm__ volatile("inw %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

uint32_t vm_portio_readl(uint16_t port) {
    uint32_t val;
    __asm__ volatile("inl %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

void vm_portio_writeb(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

void vm_portio_writew(uint16_t port, uint16_t val) {
    __asm__ volatile("outw %0, %1" : : "a"(val), "Nd"(port));
}

void vm_portio_writel(uint16_t port, uint32_t val) {
    __asm__ volatile("outl %0, %1" : : "a"(val), "Nd"(port));
}

int vm_virtualization_exception(struct isr_regs* regs) {
    /* this callback is unused in normal VM (only in TDX) */
    __UNUSED(regs);
    BUG();
}
