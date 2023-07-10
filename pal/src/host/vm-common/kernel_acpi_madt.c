/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains helpers to find the ACPI MADT table and extract multi-core information from
 * it, to be able to run the Application Processors (APs) initialization routines. This is required
 * in the Intel TDX case (which doesn't use INIT-SIPI-SIPI but instead uses an MP Mailbox).
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
#include "kernel_hob.h"

int extract_multicore_info_from_hobs(void* hob_list_addr, void** out_mailbox_addr,
                                     uint8_t* out_apic_ids, size_t* inout_apic_ids_size) {
    size_t apic_ids_max_size = *inout_apic_ids_size;
    size_t apic_ids_idx = 0;

    EFI_HOB_GENERIC_HEADER* hob;
    for (hob = hob_list_addr; !END_OF_HOB_LIST(hob); hob = GET_NEXT_HOB(hob)) {
        uint16_t type = GET_HOB_TYPE(hob);
        if (type != EFI_HOB_TYPE_GUID_EXTENSION)
            continue;

        EFI_HOB_GUID_TYPE* ext_hob = (EFI_HOB_GUID_TYPE*)hob;
        EFI_GUID* ext_hob_name = &ext_hob->Name;
        if (!HOB_GUID_EQUAL(ext_hob_name, &EFI_HOB_ACPI_TABLE_GUID))
            continue;

        EFI_HOB_ACPI_TABLE* acpi_hob = (EFI_HOB_ACPI_TABLE*)ext_hob;
        if (memcmp(acpi_hob->AcpiTable, ACPI_MADT_SIGNATURE, sizeof(ACPI_MADT_SIGNATURE) - 1))
            continue;

        struct acpi_madt* madt = (struct acpi_madt*)acpi_hob->AcpiTable;
        struct acpi_madt_unknown* madt_entry = (struct acpi_madt_unknown*)madt->entries;
        while ((uintptr_t)madt_entry < (uintptr_t)madt + madt->header.length) {
            if (madt_entry->type == ACPI_MADT_LOCAL_APIC_TYPE) {
                struct acpi_madt_local_apic* madt_local_apic;
                madt_local_apic = (struct acpi_madt_local_apic*)madt_entry;

                if (madt_local_apic->flags & 1) {
                    /* bit 0 (Processor Enabled) is set, can use this CPU */
                    if (apic_ids_idx == apic_ids_max_size)
                        return -PAL_ERROR_OVERFLOW;
                    out_apic_ids[apic_ids_idx++] = madt_local_apic->apic_id;
                }
            }

            if (madt_entry->type == ACPI_MADT_MP_WAKEUP_TYPE) {
                struct acpi_madt_mp_wakeup* madt_mp_wakeup;
                madt_mp_wakeup = (struct acpi_madt_mp_wakeup*)madt_entry;

                if (madt_mp_wakeup->length != 16 || madt_mp_wakeup->mailbox_version != 0) {
                    /* sanity checks fail */
                    return -PAL_ERROR_INVAL;
                }
                *out_mailbox_addr = (void*)madt_mp_wakeup->mailbox_addr;
            }

            madt_entry = (struct acpi_madt_unknown*)((uintptr_t)madt_entry + madt_entry->length);
        }
    }

    *inout_apic_ids_size = apic_ids_idx;
    return 0;
}
