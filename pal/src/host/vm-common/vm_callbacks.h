/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Callbacks that must be implemented by a VM-like PAL (e.g. TDX). */

#pragma once

#include <stdint.h>

#include "kernel_interrupts.h"

void* vm_shared_memcpy(void* dest, const void* src, size_t n);
void* vm_shared_memset(void* s, int c, size_t n);
void vm_shared_wrmsr(uint64_t msr, uint64_t value);

uint8_t vm_shared_readb(uint8_t* shared_addr);
uint16_t vm_shared_readw(uint16_t* shared_addr);
uint32_t vm_shared_readl(uint32_t* shared_addr);
uint64_t vm_shared_readq(uint64_t* shared_addr);

void vm_shared_writeb(uint8_t* shared_addr, uint8_t data);
void vm_shared_writew(uint16_t* shared_addr, uint16_t data);
void vm_shared_writel(uint32_t* shared_addr, uint32_t data);
void vm_shared_writeq(uint64_t* shared_addr, uint64_t data);

uint8_t vm_mmio_readb(uint8_t* mmio_addr);
uint16_t vm_mmio_readw(uint16_t* mmio_addr);
uint32_t vm_mmio_readl(uint32_t* mmio_addr);
uint64_t vm_mmio_readq(uint64_t* mmio_addr);

void vm_mmio_writeb(uint8_t* mmio_addr, uint8_t data);
void vm_mmio_writew(uint16_t* mmio_addr, uint16_t data);
void vm_mmio_writel(uint32_t* mmio_addr, uint32_t data);
void vm_mmio_writeq(uint64_t* mmio_addr, uint64_t data);

uint8_t vm_portio_readb(uint16_t port);
uint16_t vm_portio_readw(uint16_t port);
uint32_t vm_portio_readl(uint16_t port);

void vm_portio_writeb(uint16_t port, uint8_t val);
void vm_portio_writew(uint16_t port, uint16_t val);
void vm_portio_writel(uint16_t port, uint32_t val);

int vm_virtualization_exception(struct isr_regs* regs);
