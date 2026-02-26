/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "api.h"

#pragma pack(push, 1)

/* basic UEFI types; note that UEFI integers are little endian */
typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
} EFI_GUID;

typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint32_t EFI_BOOT_MODE;

typedef enum {
    EfiReservedMemoryType,
    EfiLoaderCode,
    EfiLoaderData,
    EfiBootServicesCode,
    EfiBootServicesData,
    EfiRuntimeServicesCode,
    EfiRuntimeServicesData,
    EfiConventionalMemory,
    EfiUnusableMemory,
    EfiACPIReclaimMemory,
    EfiACPIMemoryNVS,
    EfiMemoryMappedIO,
    EfiMemoryMappedIOPortSpace,
    EfiPalCode,
    EfiPersistentMemory,
    EfiMaxMemoryType
} EFI_MEMORY_TYPE;

/* Section 5.2 "HOB Generic Header" from UEFI Platform Initialiation spec, Volume 3 */
#define EFI_HOB_TYPE_HANDOFF              0x0001
#define EFI_HOB_TYPE_MEMORY_ALLOCATION    0x0002
#define EFI_HOB_TYPE_RESOURCE_DESCRIPTOR  0x0003
#define EFI_HOB_TYPE_GUID_EXTENSION       0x0004
#define EFI_HOB_TYPE_FV                   0x0005
#define EFI_HOB_TYPE_CPU                  0x0006
#define EFI_HOB_TYPE_MEMORY_POOL          0x0007
#define EFI_HOB_TYPE_FV2                  0x0009
#define EFI_HOB_TYPE_LOAD_PEIM_UNUSED     0x000A
#define EFI_HOB_TYPE_UEFI_CAPSULE         0x000B
#define EFI_HOB_TYPE_FV3                  0x000C
#define EFI_HOB_TYPE_UNUSED               0xFFFE
#define EFI_HOB_TYPE_END_OF_HOB_LIST      0xFFFF

typedef struct {
    uint16_t HobType;
    uint16_t HobLength;
    uint32_t Reserved;
} EFI_HOB_GENERIC_HEADER;

/* Section 5.3 "PHIT HOB" from UEFI Platform Initialiation spec, Volume 3 */
#define EFI_HOB_HANDOFF_TABLE_VERSION 0x0009

typedef struct {
    EFI_HOB_GENERIC_HEADER  Header;
    uint32_t                Version;
    EFI_BOOT_MODE           BootMode;
    EFI_PHYSICAL_ADDRESS    EfiMemoryTop;
    EFI_PHYSICAL_ADDRESS    EfiMemoryBottom;
    EFI_PHYSICAL_ADDRESS    EfiFreeMemoryTop;
    EFI_PHYSICAL_ADDRESS    EfiFreeMemoryBottom;
    EFI_PHYSICAL_ADDRESS    EfiEndOfHobList;
} EFI_HOB_HANDOFF_INFO_TABLE;

/* Section 5.4 "Memory Allocation HOB" from UEFI Platform Initialiation spec, Volume 3 */
typedef struct {
    EFI_GUID              Name;
    EFI_PHYSICAL_ADDRESS  MemoryBaseAddress;
    uint64_t              MemoryLength;
    EFI_MEMORY_TYPE       MemoryType;
    uint8_t               Reserved[4];
} EFI_HOB_MEMORY_ALLOCATION_HEADER;

typedef struct {
    EFI_HOB_GENERIC_HEADER            Header;
    EFI_HOB_MEMORY_ALLOCATION_HEADER  AllocDescriptor;
    /* Additional (memory-alloc-specific) data goes here */
} EFI_HOB_MEMORY_ALLOCATION;

#define EFI_HOB_MEMORY_ALLOC_STACK_GUID \
    ((EFI_GUID){ 0x4ed4bf27, 0x4092, 0x42e9, { 0x80, 0x7d, 0x52, 0x7b, 0x1d, 0x0, 0xc9, 0xbd } })
typedef struct {
    EFI_HOB_GENERIC_HEADER            Header;
    EFI_HOB_MEMORY_ALLOCATION_HEADER  AllocDescriptor;
} EFI_HOB_MEMORY_ALLOCATION_STACK;

#define EFI_HOB_MEMORY_ALLOC_BSP_STORE_GUID \
    ((EFI_GUID){ 0x564b33cd, 0xc92a, 0x4593, { 0x90, 0xbf, 0x24, 0x73, 0xe4, 0x3c, 0x63, 0x22 } })
typedef struct {
    EFI_HOB_GENERIC_HEADER            Header;
    EFI_HOB_MEMORY_ALLOCATION_HEADER  AllocDescriptor;
} EFI_HOB_MEMORY_ALLOCATION_BSP_STORE;

#define EFI_HOB_MEMORY_ALLOC_MODULE_GUID \
    ((EFI_GUID){ 0xf8e21975, 0x899, 0x4f58, { 0xa4, 0xbe, 0x55, 0x25, 0xa9, 0xc6, 0xd7, 0x7a } })
typedef struct {
    EFI_HOB_GENERIC_HEADER            Header;
    EFI_HOB_MEMORY_ALLOCATION_HEADER  MemoryAllocationHeader;
    EFI_GUID                          ModuleName;
    EFI_PHYSICAL_ADDRESS              EntryPoint;
} EFI_HOB_MEMORY_ALLOCATION_MODULE;

/* Section 5.5 "Resource Descriptor HOB" from UEFI Platform Initialiation spec, Volume 3 */
typedef uint32_t EFI_RESOURCE_TYPE;
#define EFI_RESOURCE_SYSTEM_MEMORY          0x00000000
#define EFI_RESOURCE_MEMORY_MAPPED_IO       0x00000001
#define EFI_RESOURCE_IO                     0x00000002
#define EFI_RESOURCE_FIRMWARE_DEVICE        0x00000003
#define EFI_RESOURCE_MEMORY_MAPPED_IO_PORT  0x00000004
#define EFI_RESOURCE_MEMORY_RESERVED        0x00000005
#define EFI_RESOURCE_IO_RESERVED            0x00000006
#define EFI_RESOURCE_MAX_MEMORY_TYPE        0x00000007

typedef uint32_t EFI_RESOURCE_ATTRIBUTE_TYPE;
/* following attributes are used to describe settings */
#define EFI_RESOURCE_ATTRIBUTE_PRESENT                  0x00000001
#define EFI_RESOURCE_ATTRIBUTE_INITIALIZED              0x00000002
#define EFI_RESOURCE_ATTRIBUTE_TESTED                   0x00000004
#define EFI_RESOURCE_ATTRIBUTE_UNACCEPTED               0x00000007
#define EFI_RESOURCE_ATTRIBUTE_READ_PROTECTED           0x00000080
#define EFI_RESOURCE_ATTRIBUTE_WRITE_PROTECTED          0x00000100
#define EFI_RESOURCE_ATTRIBUTE_EXECUTION_PROTECTED      0x00000200
#define EFI_RESOURCE_ATTRIBUTE_PERSISTENT               0x00800000
#define EFI_RESOURCE_ATTRIBUTE_MORE_RELIABLE            0x02000000
/* following attributes are used to describe capabilities */
#define EFI_RESOURCE_ATTRIBUTE_SINGLE_BIT_ECC           0x00000008
#define EFI_RESOURCE_ATTRIBUTE_MULTIPLE_BIT_ECC         0x00000010
#define EFI_RESOURCE_ATTRIBUTE_ECC_RESERVED_1           0x00000020
#define EFI_RESOURCE_ATTRIBUTE_ECC_RESERVED_2           0x00000040
#define EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE              0x00000400
#define EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE        0x00000800
#define EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE  0x00001000
#define EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE     0x00002000
#define EFI_RESOURCE_ATTRIBUTE_16_BIT_IO                0x00004000
#define EFI_RESOURCE_ATTRIBUTE_32_BIT_IO                0x00008000
#define EFI_RESOURCE_ATTRIBUTE_64_BIT_IO                0x00010000
#define EFI_RESOURCE_ATTRIBUTE_UNCACHED_EXPORTED        0x00020000
#define EFI_RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTED      0x00040000
#define EFI_RESOURCE_ATTRIBUTE_READ_PROTECTABLE         0x00100000
#define EFI_RESOURCE_ATTRIBUTE_WRITE_PROTECTABLE        0x00200000
#define EFI_RESOURCE_ATTRIBUTE_EXECUTION_PROTECTABLE    0x00400000
#define EFI_RESOURCE_ATTRIBUTE_PERSISTABLE              0x01000000
#define EFI_RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTABLE    0x00080000
/* following attributes are used to describe TDX-specific settings */
#define EFI_RESOURCE_ATTRIBUTE_ENCRYPTED                0x04000000

typedef struct {
    EFI_HOB_GENERIC_HEADER       Header;
    EFI_GUID                     Owner;
    EFI_RESOURCE_TYPE            ResourceType;
    EFI_RESOURCE_ATTRIBUTE_TYPE  ResourceAttribute;
    EFI_PHYSICAL_ADDRESS         PhysicalStart;
    uint64_t                     ResourceLength;
} EFI_HOB_RESOURCE_DESCRIPTOR;

/* Section 5.6 "GUID Extension HOB" from UEFI Platform Initialiation spec, Volume 3 */
typedef struct {
    EFI_HOB_GENERIC_HEADER  Header;
    EFI_GUID                Name;
    /* GUID specific data goes here */
} EFI_HOB_GUID_TYPE;

/* below HOBs are TD-Shim-specific */
#define EFI_HOB_ACPI_TABLE_GUID \
    ((EFI_GUID){ 0x6a0c5870, 0xd4ed, 0x44f4, {0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0xc, 0x8d } })
typedef struct {
    EFI_HOB_GENERIC_HEADER  Header;
    EFI_GUID                Name;
    /* ACPI table, started with Signature; length in AcpiTable shall match length in HOB Header */
    uint8_t                 AcpiTable[];
} EFI_HOB_ACPI_TABLE;

#define EFI_HOB_E820_TABLE_GUID \
    ((EFI_GUID){ 0x8f8072ea, 0x3486, 0x4b47, {0x86, 0xa7, 0x23, 0x53, 0xb8, 0x8a, 0x87, 0x73 } })
#define E820_ADDRESS_RANGE_MEMORY   1
#define E820_ADDRESS_RANGE_RESERVED 2
#define E820_ADDRESS_RANGE_ACPI     3
#define E820_ADDRESS_RANGE_NVS      4
typedef struct {
    uint64_t  Address;
    uint64_t  Size;
    uint32_t  Type;
} E820_TABLE_ENTRY;
typedef struct {
    EFI_HOB_GENERIC_HEADER  Header;
    EFI_GUID                Name;
    /* one E820 table containing multiple E820 entries */
    E820_TABLE_ENTRY        E820Table[];
} EFI_HOB_E820_TABLE;

#define EFI_HOB_PAYLOAD_INFO_GUID \
    ((EFI_GUID){ 0xb96fa412, 0x461f, 0x4be3, {0x8c, 0xd, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0 } })
typedef enum {
    PayloadImageTypeExecutablePayload, /* ELF executable image (uses a payload HOB) */
    PayloadImageTypeBzImage,           /* bzImage, follows the Linux boot protocol */
    PayloadImageTypeVmLinux,           /* vmLinux, follows the Linux boot protocol */
    PayloadImageTypeRawVmLinux,        /* VMM-loaded vmLinux, follows the Linux boot protocol */
} PAYLOAD_IMAGE_TYPE;
typedef struct {
    EFI_HOB_GENERIC_HEADER  Header;
    EFI_GUID                Name;
    uint32_t                ImageType;  /* PAYLOAD_IMAGE_TYPE */
    uint32_t                Reserved;
    uint64_t                Entrypoint; /* guest physical address of the payload entrypoint */
} EFI_HOB_PAYLOAD_INFO_TABLE;

/* Section 5.7 "Firmware Volume HOB" from UEFI Platform Initialiation spec, Volume 3 */
typedef struct {
    EFI_HOB_GENERIC_HEADER  Header;
    EFI_PHYSICAL_ADDRESS    BaseAddress;
    uint64_t                Length;
} EFI_HOB_FIRMWARE_VOLUME;

typedef struct {
    EFI_HOB_GENERIC_HEADER  Header;
    EFI_PHYSICAL_ADDRESS    BaseAddress;
    uint64_t                Length;
    EFI_GUID                FvName;
    EFI_GUID                FileName;
} EFI_HOB_FIRMWARE_VOLUME2;

typedef struct {
    EFI_HOB_GENERIC_HEADER  Header;
    EFI_PHYSICAL_ADDRESS    BaseAddress;
    uint64_t                Length;
    uint32_t                AuthenticationStatus;
    bool                    ExtractedFv;
    EFI_GUID                FvName;
    EFI_GUID                FileName;
} EFI_HOB_FIRMWARE_VOLUME3;

/* Section 5.8 "CPU HOB" from UEFI Platform Initialiation spec, Volume 3 */
typedef struct {
    EFI_HOB_GENERIC_HEADER  Header;
    uint8_t                 SizeOfMemorySpace;
    uint8_t                 SizeOfIoSpace;
    uint8_t                 Reserved[6];
} EFI_HOB_CPU;

/* Section 5.9 "Memory Pool HOB" from UEFI Platform Initialiation spec, Volume 3 */
typedef struct {
    EFI_HOB_GENERIC_HEADER  Header;
} EFI_HOB_MEMORY_POOL;

#pragma pack(pop)

#define GET_HOB_TYPE(hob)           (((EFI_HOB_GENERIC_HEADER*)hob)->HobType)
#define GET_HOB_LENGTH(hob)         (((EFI_HOB_GENERIC_HEADER*)hob)->HobLength)
#define GET_NEXT_HOB(hob)           (void*)((uint8_t*)hob + GET_HOB_LENGTH(hob))
#define END_OF_HOB_LIST(hob)        (GET_HOB_TYPE(hob) == (uint16_t)EFI_HOB_TYPE_END_OF_HOB_LIST)
#define GET_GUID_HOB_DATA(hob)      (void*)((uint8_t*)hob + sizeof(EFI_HOB_GUID_TYPE))
#define GET_GUID_HOB_DATA_SIZE(hob) (uint16_t)(GET_HOB_LENGTH(hob) - sizeof(EFI_HOB_GUID_TYPE))

/* this function is used in very early boot stages when Address Sanitizer is not yet initialized */
__attribute_no_sanitize_address
static inline bool HOB_GUID_EQUAL(const EFI_GUID* guid1, const EFI_GUID* guid2) {
  uint64_t guid1_low  = *((const uint64_t*)guid1);
  uint64_t guid2_low  = *((const uint64_t*)guid2);
  uint64_t guid1_high = *((const uint64_t*)guid1 + 1);
  uint64_t guid2_high = *((const uint64_t*)guid2 + 1);
  return guid1_low == guid2_low && guid1_high == guid2_high;
}
