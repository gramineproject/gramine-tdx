/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Declarations for PCI bus.
 *
 * Terminology:
 *   - bdf = bus-device-function triple (bus: bits 23-16, device: bits 15-11, func: bits 10-8)
 *
 * Partially based on https://github.com/bonzini/qboot.
 */

#pragma once

#include <stdint.h>

#include "kernel_virtio.h"
#include "vm_callbacks.h"

/* hard-code to 3GB, so that our used PCI BARs' MMIO space spawns [3GB, 3GB+16MB) */
#define PCI_MMIO_START_ADDR 0xC0000000UL
#define PCI_MMIO_END_ADDR   0xC1000000UL

#define PCI_CONFIG_SPACE_ADDR_IO_PORT 0xCF8
#define PCI_CONFIG_SPACE_DATA_IO_PORT 0xCFC

#define PCI_VENDOR_ID      0x00
#define PCI_DEVICE_ID      0x02
#define PCI_COMMAND        0x04
#define PCI_STATUS         0x06
#define PCI_CLASS_DEVICE   0x0a
#define PCI_HEADER_TYPE    0x0e
#define PCI_BAR0           0x10
#define PCI_BAR1           0x14
#define PCI_BAR2           0x18
#define PCI_BAR3           0x1c
#define PCI_BAR4           0x20
#define PCI_BAR5           0x24
#define PCI_CAP_POINTER    0x34
#define PCI_INTERRUPT_LINE 0x3c
#define PCI_INTERRUPT_PIN  0x3d
#define PCI_TOLUD          0xb0

/* PCI_CLASS_DEVICE */
#define PCI_CLASS_STORAGE_IDE 0x0101

/* PCI_HEADER_TYPE */
#define PCI_HEADER_TYPE_MULTI_FUNCTION 0x80

/* PCI_VENDOR_ID / PCI_DEVICE_ID */
#define PCI_VENDOR_ID_INTEL          0x8086
#define PCI_DEVICE_ID_INTEL_Q35_MCH  0x29c0
#define PCI_VENDOR_ID_VIRTIO         0x1af4
#define PCI_DEVICE_ID_CONSOLE_LEGACY 0x1003
#define PCI_DEVICE_ID_CONSOLE        0x1043
#define PCI_DEVICE_ID_VSOCK          0x1053
#define PCI_DEVICE_ID_FS             0x105a

/* VIRTIO_PCI_CAP_CFG_TYPE */
#define VIRTIO_PCI_CAP_COMMON_CFG        1
#define VIRTIO_PCI_CAP_NOTIFY_CFG        2
#define VIRTIO_PCI_CAP_ISR_CFG           3
#define VIRTIO_PCI_CAP_DEVICE_CFG        4
#define VIRTIO_PCI_CAP_PCI_CFG           5
#define VIRTIO_PCI_CAP_SHARED_MEMORY_CFG 8
#define VIRTIO_PCI_CAP_VENDOR_CFG        9

static inline void pci_config_writel(uint16_t bdf, uint32_t addr, uint32_t val) {
    vm_portio_writel(PCI_CONFIG_SPACE_ADDR_IO_PORT, 0x80000000 | (bdf << 8) | (addr & 0xfc));
    vm_portio_writel(PCI_CONFIG_SPACE_DATA_IO_PORT, val);
}

static inline void pci_config_writew(uint16_t bdf, uint32_t addr, uint16_t val) {
    vm_portio_writel(PCI_CONFIG_SPACE_ADDR_IO_PORT, 0x80000000 | (bdf << 8) | (addr & 0xfc));
    vm_portio_writew(PCI_CONFIG_SPACE_DATA_IO_PORT | (addr & 2), val);
}

static inline void pci_config_writeb(uint16_t bdf, uint32_t addr, uint8_t val) {
    vm_portio_writel(PCI_CONFIG_SPACE_ADDR_IO_PORT, 0x80000000 | (bdf << 8) | (addr & 0xfc));
    vm_portio_writeb(PCI_CONFIG_SPACE_DATA_IO_PORT | (addr & 3), val);
}

static inline uint32_t pci_config_readl(uint16_t bdf, uint32_t addr) {
    vm_portio_writel(PCI_CONFIG_SPACE_ADDR_IO_PORT, 0x80000000 | (bdf << 8) | (addr & 0xfc));
    return vm_portio_readl(PCI_CONFIG_SPACE_DATA_IO_PORT);
}

static inline uint16_t pci_config_readw(uint16_t bdf, uint32_t addr) {
    vm_portio_writel(PCI_CONFIG_SPACE_ADDR_IO_PORT, 0x80000000 | (bdf << 8) | (addr & 0xfc));
    return vm_portio_readw(PCI_CONFIG_SPACE_DATA_IO_PORT | (addr & 2));
}

static inline uint8_t pci_config_readb(uint16_t bdf, uint32_t addr) {
    vm_portio_writel(PCI_CONFIG_SPACE_ADDR_IO_PORT, 0x80000000 | (bdf << 8) | (addr & 0xfc));
    return vm_portio_readb(PCI_CONFIG_SPACE_DATA_IO_PORT | (addr & 3));
}

int pci_init(void);
