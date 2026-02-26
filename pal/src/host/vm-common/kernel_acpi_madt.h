/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)

struct acpi_header {
    uint8_t  signature[4];
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    uint8_t  oem_id[6];
    uint8_t  oem_table_id[8];
    uint32_t oem_revision;
    uint8_t  creator_id[4];
    uint32_t creator_revision;
};

/* Multiple APIC Description Table (MADT) and its associated Interrupt Controller Structures */
#define ACPI_MADT_LOCAL_APIC_TYPE 0
struct acpi_madt_local_apic {
    uint8_t  type;   /* ACPI_MADT_LOCAL_APIC_TYPE */
    uint8_t  length;
    uint8_t  processor_uid;
    uint8_t  apic_id;
    uint32_t flags;  /* bit 0 - enabled, bit 1 - online capable */
};

#define ACPI_MADT_IO_APIC_TYPE 1
struct acpi_madt_io_apic {
    uint8_t  type;   /* ACPI_MADT_IO_APIC_TYPE */
    uint8_t  length;
    uint8_t  io_apic_id;
    uint8_t  reserved;
    uint32_t io_apic_addr;
    uint32_t global_system_interrupt_base;
};

#define ACPI_MADT_LOCAL_X2APIC_TYPE 9
struct acpi_madt_local_x2apic {
    uint8_t  type;   /* ACPI_MADT_LOCAL_X2APIC_TYPE */
    uint8_t  length;
    uint16_t reserved;
    uint32_t x2apic_id;
    uint32_t flags;  /* bit 0 - enabled, bit 1 - online capable */
    uint32_t acpi_id;
};

#define ACPI_MADT_MP_WAKEUP_TYPE 0x10
struct acpi_madt_mp_wakeup {
    uint8_t  type;            /* ACPI_MADT_MP_WAKEUP_TYPE */
    uint8_t  length;          /* must be 16 */
    uint16_t mailbox_version; /* must be 0 */
    uint32_t reserved;        /* must be 0 */
    uint64_t mailbox_addr;    /* physical address of the mailbox page; must be 4K aligned */
};

struct acpi_madt_unknown {
    uint8_t  type;
    uint8_t  length;
};

#define ACPI_MADT_SIGNATURE "APIC"
struct acpi_madt {
    struct acpi_header header;
    uint32_t apic_addr;
    uint32_t flags;
    uint8_t  entries[];
};

#pragma pack(pop)

int extract_multicore_info_from_hobs(void* hob_list_addr, void** out_mailbox_addr,
                                     uint8_t* out_apic_ids, size_t* inout_apic_ids_size);
